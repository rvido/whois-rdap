// Smart Redirect Follower (Feature 3)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// RDAP responses may contain a `links` array pointing to related or
// authoritative sub-registry resources.  This module inspects the `links`
// field and, if it finds a URL with rel="related" or rel="self" that points
// to a different host, fetches that URL and returns the richer result.
//
// Design constraints:
//   - Maximum `max_hops` hops (default 1, CLI-configurable up to 3).
//   - `href` is borrowed as `&str` from the parsed JSON Value — zero-copy
//     during link extraction.  Only one `reqwest::Url` is allocated per hop.
//   - If the followed URL returns an error the original JSON is returned as-is.

use anyhow::{Context, Result};
use serde_json::Value;
use std::net::IpAddr;

/// Follow RDAP `links` in a response JSON up to `max_hops` times.
///
/// Returns the final (richest) JSON value obtained, plus the href of the
/// last successfully-fetched hop (`None` if no redirect was followed) — the
/// caller needs this to report which server the data actually came from,
/// since it can differ from the server that was originally queried.  If no
/// useful link is found, or if following fails, the original `json` is
/// returned unchanged.
///
/// # Arguments
/// * `http`     — shared reqwest client (connection pool is reused)
/// * `json`     — already-parsed RDAP response
/// * `max_hops` — how many redirect hops to follow (0 = no redirect)
pub async fn follow_links(
    http: &reqwest::Client,
    json: Value,
    max_hops: u8,
) -> (Value, Option<String>) {
    if max_hops == 0 {
        return (json, None);
    }

    // Extract the current response URL (from "self" link) to detect same-host
    // links we don't need to follow.
    let self_href = extract_self_href(&json);

    if let Some(href) = find_follow_href(&json, self_href) {
        match fetch_href(http, href).await {
            Ok(next_json) => {
                // Recurse for additional hops; decrement counter.
                let href = href.to_string();
                let (final_json, deeper_href) =
                    Box::pin(follow_links(http, next_json, max_hops - 1)).await;
                return (final_json, Some(deeper_href.unwrap_or(href)));
            }
            Err(e) => {
                eprintln!("redirect: failed to follow '{}': {e}", href);
            }
        }
    }

    (json, None)
}

// ── Internals ────────────────────────────────────────────────────────────────

/// Extract the "self" href from the links array, if present.
fn extract_self_href(json: &Value) -> Option<&str> {
    json.get("links")
        .and_then(|v| v.as_array())
        .and_then(|links| {
            links.iter().find_map(|link| {
                let rel = link.get("rel").and_then(|v| v.as_str())?;
                if rel.eq_ignore_ascii_case("self") {
                    link.get("href").and_then(|v| v.as_str())
                } else {
                    None
                }
            })
        })
}

/// True if `mime` is the RDAP JSON media type, ignoring case and any
/// trailing parameters (e.g. `"Application/RDAP+JSON;charset=UTF-8"`).
fn is_rdap_json_type(mime: &str) -> bool {
    mime.split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .eq_ignore_ascii_case("application/rdap+json")
}

/// Find the best href to follow from the links array.
///
/// Priority:
///   1. `rel="related"` with `type="application/rdap+json"`
///   2. `rel="alternate"` with `type="application/rdap+json"`
///
/// We skip links whose `href` matches `self_href` (same resource, no-op).
fn find_follow_href<'a>(json: &'a Value, self_href: Option<&str>) -> Option<&'a str> {
    let links = json.get("links").and_then(|v| v.as_array())?;

    // Preferred: rel=related, type=application/rdap+json
    links.iter().find_map(|link| {
        let rel = link.get("rel").and_then(|v| v.as_str())?;
        let mime = link.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let href = link.get("href").and_then(|v| v.as_str())?;

        if is_rdap_json_type(mime)
            && (rel.eq_ignore_ascii_case("related") || rel.eq_ignore_ascii_case("alternate"))
            && Some(href) != self_href
        {
            Some(href)
        } else {
            None
        }
    })
}

/// Returns true if `ip` is a public, globally-routable address.
///
/// Excludes loopback, private (RFC 1918), link-local, carrier-grade NAT
/// (RFC 6598), unique-local (IPv6 ULA), multicast, and unspecified ranges.
fn is_globally_routable(ip: &IpAddr) -> bool {
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
/// Used to block SSRF via a `links` href pointing at internal
/// infrastructure (e.g. a cloud metadata endpoint or localhost) — the RDAP
/// server we followed a redirect from is not a trusted party.
async fn host_is_safe(host: &str, port: u16) -> bool {
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

/// Fetch a URL and decode the response as RDAP JSON.
async fn fetch_href(http: &reqwest::Client, href: &str) -> Result<Value> {
    let url =
        reqwest::Url::parse(href).with_context(|| format!("Invalid redirect href: {href}"))?;

    if url.scheme() != "https" {
        return Err(anyhow::anyhow!(
            "Refusing to follow non-https redirect: {href}"
        ));
    }
    let host = url
        .host_str()
        .with_context(|| format!("Redirect href has no host: {href}"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    if !host_is_safe(host, port).await {
        return Err(anyhow::anyhow!(
            "Refusing to follow redirect to non-public address: {href}"
        ));
    }

    let resp = http
        .get(url)
        .header("Accept", "application/rdap+json, application/json")
        .send()
        .await
        .with_context(|| format!("Failed to GET redirect: {href}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(anyhow::anyhow!(
            "Redirect server returned {status} for {href}"
        ));
    }

    resp.json::<Value>()
        .await
        .with_context(|| format!("Failed to decode redirect JSON from {href}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_no_links_returns_original() {
        let val = json!({"handle": "EXAMPLE"});
        // No links → find_follow_href returns None
        assert!(find_follow_href(&val, None).is_none());
    }

    #[test]
    fn test_finds_related_rdap_link() {
        let val = json!({
            "links": [
                {
                    "rel": "self",
                    "type": "application/rdap+json",
                    "href": "https://rdap.iana.org/domain/com"
                },
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.verisign.com/com/v1/domain/google.com"
                }
            ]
        });
        let self_href = extract_self_href(&val);
        let href = find_follow_href(&val, self_href);
        assert_eq!(
            href,
            Some("https://rdap.verisign.com/com/v1/domain/google.com")
        );
    }

    #[test]
    fn test_skips_self_link() {
        let val = json!({
            "links": [
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.iana.org/domain/com"
                }
            ]
        });
        // self_href matches the only related link → should not follow
        let href = find_follow_href(&val, Some("https://rdap.iana.org/domain/com"));
        assert!(href.is_none());
    }

    #[test]
    fn test_finds_related_link_with_charset_and_case_variant_type() {
        let val = json!({
            "links": [
                {
                    "rel": "related",
                    "type": "Application/RDAP+JSON;charset=UTF-8",
                    "href": "https://rdap.verisign.com/com/v1/domain/google.com"
                }
            ]
        });
        let href = find_follow_href(&val, None);
        assert_eq!(
            href,
            Some("https://rdap.verisign.com/com/v1/domain/google.com")
        );
    }

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
        let allowed = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"];
        for ip in allowed {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(is_globally_routable(&addr), "{ip} should be allowed");
        }
    }

    #[tokio::test]
    async fn test_fetch_href_rejects_non_https_scheme() {
        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let err = fetch_href(&http, "http://example.com/rdap/domain/example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    #[tokio::test]
    async fn test_fetch_href_rejects_private_ip_literal() {
        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let err = fetch_href(&http, "https://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("non-public"));
    }

    #[test]
    fn test_extract_self_href() {
        let val = json!({
            "links": [
                {"rel": "self", "href": "https://example.com/rdap/ip/1.2.3.4"},
                {"rel": "up",   "href": "https://example.com/rdap/ip/1.2.3.0/24"}
            ]
        });
        assert_eq!(
            extract_self_href(&val),
            Some("https://example.com/rdap/ip/1.2.3.4")
        );
    }
}
