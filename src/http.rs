// Guarded HTTP fetch layer
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// Every outbound HTTP request in this crate goes through `get_guarded`, which
// provides two protections that `reqwest` does not give us by default:
//
//   1. SSRF containment.  `reqwest`'s default redirect policy silently follows
//      up to 10 `Location:` hops to *any* address.  That would let a hostile or
//      compromised RDAP server bounce us into internal infrastructure (cloud
//      metadata endpoints, localhost admin ports, RFC 1918 hosts) — bypassing
//      any check applied only to the URL we originally asked for.  We therefore
//      disable automatic redirects at the client level (see
//      `crate::build_reqwest_client`) and follow them here instead, applying
//      `validate_untrusted_url` to every hop.
//
//   2. A response body size cap.  RDAP responses are small JSON documents; an
//      unbounded `bytes()` read would let a hostile server (or a redirect to a
//      large file) exhaust memory.
//
// Note on trust boundaries: the *first* URL of a request is chosen by the user
// (`--server`, `--rir`, or a bootstrap entry) and is deliberately NOT subjected
// to the public-address check — pointing the tool at an internal mirror or at
// `http://127.0.0.1:8080` in tests is a legitimate, explicit choice.  Every
// subsequent hop is chosen by a remote server and is therefore untrusted.

use anyhow::{Context, Result, anyhow};
use std::net::IpAddr;

/// Maximum bytes accepted from any single HTTP response body (8 MiB).
///
/// RDAP responses are small; this only exists to bound a hostile or
/// misconfigured server, not to constrain legitimate traffic.
pub(crate) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum HTTP 3xx hops followed for a single logical request.
pub(crate) const MAX_HTTP_REDIRECTS: usize = 5;

/// A completed HTTP response with its body already read (and size-capped).
#[derive(Debug)]
pub(crate) struct Fetched {
    pub status: reqwest::StatusCode,
    pub body: Vec<u8>,
}

impl Fetched {
    /// Body as UTF-8, lossily decoded — used only for error messages.
    pub fn body_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Returns true if `ip` is a public, globally-routable address.
///
/// Excludes loopback, private (RFC 1918), link-local, carrier-grade NAT
/// (RFC 6598), unique-local (IPv6 ULA), multicast, and unspecified ranges.
pub(crate) fn is_globally_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| !is_globally_routable(&IpAddr::V4(v4))))
        }
    }
}

/// Resolve `host` and confirm every candidate address is publicly routable.
///
/// Note: this is a pre-flight check. `reqwest` performs its own resolution
/// when it connects, so a low-TTL DNS-rebinding attacker could in principle
/// return a public address here and a private one microseconds later. Closing
/// that fully would require pinning the resolved address into the connection,
/// which reqwest only supports per-client, not per-request. The check still
/// blocks the realistic cases (literal private addresses, hostnames that
/// simply resolve into private space).
pub(crate) async fn host_is_safe(host: &str, port: u16) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_globally_routable(&ip);
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let mut saw_any = false;
            for addr in addrs {
                saw_any = true;
                if !is_globally_routable(&addr.ip()) {
                    return false;
                }
            }
            saw_any
        }
        Err(_) => false,
    }
}

/// Validate a URL that was chosen by a remote server (a redirect `Location`
/// or an RDAP `links` href) rather than by the user.
///
/// Requires HTTPS and a host that resolves solely to public addresses.
pub(crate) async fn validate_untrusted_url(url: &reqwest::Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(anyhow!("refusing non-https target: {url}"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("refusing target with no host: {url}"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    if !host_is_safe(host, port).await {
        return Err(anyhow!("refusing target at a non-public address: {url}"));
    }
    Ok(())
}

/// Read a response body, refusing anything over `MAX_RESPONSE_BYTES`.
async fn read_capped(mut resp: reqwest::Response, url: &reqwest::Url) -> Result<Vec<u8>> {
    // Fast path: trust an explicit oversized Content-Length and bail early.
    if let Some(len) = resp.content_length()
        && len > MAX_RESPONSE_BYTES as u64
    {
        return Err(anyhow!(
            "response from {url} declares {len} bytes, over the {MAX_RESPONSE_BYTES}-byte limit"
        ));
    }
    let mut out = Vec::new();
    // Content-Length can be absent or a lie, so enforce the cap while reading.
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("Failed to read response body from {url}"))?
    {
        if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!(
                "response from {url} exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// GET `url`, following HTTP 3xx redirects manually so that every hop past the
/// first is checked by `validate_untrusted_url`, and capping the body size.
///
/// Non-2xx statuses are returned to the caller (with the body) rather than
/// treated as errors, so each caller can format its own diagnostics.
pub(crate) async fn get_guarded(
    http: &reqwest::Client,
    url: reqwest::Url,
    accept: Option<&str>,
) -> Result<Fetched> {
    let mut url = url;
    let mut hops = 0usize;

    loop {
        let mut req = http.get(url.clone());
        if let Some(accept) = accept {
            req = req.header(reqwest::header::ACCEPT, accept);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("Failed to GET {url}"))?;

        let status = resp.status();
        if status.is_redirection() {
            if hops >= MAX_HTTP_REDIRECTS {
                return Err(anyhow!(
                    "too many HTTP redirects (> {MAX_HTTP_REDIRECTS}) starting at {url}"
                ));
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(location) = location {
                let next = url.join(&location).with_context(|| {
                    format!("Invalid redirect Location '{location}' from {url}")
                })?;
                // The redirect target is chosen by a remote server: untrusted.
                validate_untrusted_url(&next).await?;
                url = next;
                hops += 1;
                continue;
            }
            // 3xx with no usable Location — fall through and report as-is.
        }

        let body = read_capped(resp, &url).await?;
        return Ok(Fetched { status, body });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_globally_routable_rejects_private_and_special_ranges() {
        let blocked = [
            "127.0.0.1",        // loopback
            "10.0.0.1",         // RFC 1918
            "172.16.0.1",       // RFC 1918
            "192.168.1.1",      // RFC 1918
            "169.254.169.254",  // link-local / cloud metadata
            "100.64.0.1",       // carrier-grade NAT
            "0.0.0.0",          // unspecified
            "::1",              // IPv6 loopback
            "fe80::1",          // IPv6 link-local
            "fc00::1",          // IPv6 unique-local
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ];
        for ip in blocked {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(!is_globally_routable(&addr), "{ip} should be blocked");
        }
    }

    #[test]
    fn test_is_globally_routable_allows_public_addresses() {
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(is_globally_routable(&addr), "{ip} should be allowed");
        }
    }

    #[tokio::test]
    async fn test_validate_untrusted_url_rejects_non_https() {
        let url = reqwest::Url::parse("http://example.com/x").unwrap();
        let err = validate_untrusted_url(&url).await.unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    /// End-to-end regression for the SSRF bypass: a server that answers with
    /// `302 Location: <internal address>` must NOT be followed. Before the
    /// guard existed, reqwest's default policy chased this automatically and
    /// happily returned the internal service's body as a lookup result.
    #[tokio::test]
    async fn test_get_guarded_refuses_redirect_to_internal_address() {
        use tokio::io::AsyncWriteExt;

        // Stand-in for an internal service that must never be reached.
        let victim = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let victim_addr = victim.local_addr().unwrap();
        let victim_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = std::sync::Arc::clone(&victim_hits);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = victim.accept().await {
                hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nSECRET")
                    .await;
            }
        });

        // Hostile "RDAP server" that redirects into the internal service.
        let evil = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let evil_addr = evil.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = evil.accept().await {
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{victim_addr}/latest/meta-data/\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let url = reqwest::Url::parse(&format!("http://{evil_addr}/ip/8.8.8.8")).unwrap();
        let err = get_guarded(&http, url, None).await.unwrap_err();

        assert!(
            err.to_string().contains("non-https") || err.to_string().contains("non-public"),
            "redirect into internal space must be refused, got: {err}"
        );
        assert_eq!(
            victim_hits.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the internal service must never be contacted"
        );
    }

    #[tokio::test]
    async fn test_get_guarded_enforces_response_size_cap() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let over = MAX_RESPONSE_BYTES + 1;
                let _ = sock
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {over}\r\n\r\n").as_bytes(),
                    )
                    .await;
            }
        });
        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}/big")).unwrap();
        let err = get_guarded(&http, url, None).await.unwrap_err();
        assert!(err.to_string().contains("limit"), "got: {err}");
    }

    #[tokio::test]
    async fn test_validate_untrusted_url_rejects_private_literal() {
        let url = reqwest::Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
        let err = validate_untrusted_url(&url).await.unwrap_err();
        assert!(err.to_string().contains("non-public"));
    }
}
