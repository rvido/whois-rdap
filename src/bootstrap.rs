// IANA Bootstrap Triage Map (Feature 2)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// Routes an IP/Domain/ASN query to the correct authoritative RDAP server by
// consulting locally-cached IANA bootstrap JSON files:
//
//   https://data.iana.org/rdap/ipv4.json
//   https://data.iana.org/rdap/ipv6.json
//   https://data.iana.org/rdap/asn.json
//   https://data.iana.org/rdap/dns.json
//
// The map lives in-process as three sorted prefix arrays. Lookup is a linear
// scan for the longest covering prefix (O(N), zero heap allocation) — the
// IANA bootstrap files list at most a few hundred prefixes/ranges each, so
// this is dominated by the network round-trip that follows, not by the scan.
// The bootstrap JSON files are cached to `$XDG_CACHE_HOME/whois-rdap/bootstrap/`
// and refreshed when their on-disk mtime exceeds BOOTSTRAP_TTL_SECS.

use anyhow::{Context, Result, anyhow};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Deserialize;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// How long (seconds) bootstrap files stay valid before re-download.
/// IANA updates these files infrequently; 24 h is the recommended polling
/// interval per RFC 9224 §9.1.
pub const BOOTSTRAP_TTL_SECS: u64 = 86_400;

const IANA_IPV4_URL: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_IPV6_URL: &str = "https://data.iana.org/rdap/ipv6.json";
const IANA_ASN_URL: &str = "https://data.iana.org/rdap/asn.json";
const IANA_DNS_URL: &str = "https://data.iana.org/rdap/dns.json";

// ── Internal serde model (only used during parsing, not retained) ────────────

#[derive(Deserialize)]
struct BootstrapFile {
    services: Vec<(Vec<String>, Vec<String>)>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// In-memory routing table built from IANA bootstrap JSON.
///
/// All three prefix arrays are kept sorted (by start address / range start),
/// though lookups currently do a linear scan for the longest covering
/// prefix — see the module docs above for why that's fine here.
/// The stored base-URL strings are `Box<str>` (single heap allocation per
/// entry, never cloned — callers receive a `&str` reference).
pub struct BootstrapMap {
    ipv4: Vec<(Ipv4Net, Box<str>)>,
    ipv6: Vec<(Ipv6Net, Box<str>)>,
    asn: Vec<(RangeInclusive<u32>, Box<str>)>,
    /// Lowercase A-label TLD (or longer suffix) → base URL.
    dns: Vec<(Box<str>, Box<str>)>,
}

impl BootstrapMap {
    /// Load bootstrap maps from on-disk cache, refreshing stale files via HTTP.
    ///
    /// `http` is only used when a file is missing or older than `BOOTSTRAP_TTL_SECS`.
    pub async fn load(http: &reqwest::Client, force_refresh: bool) -> Result<Self> {
        let cache_dir = bootstrap_cache_dir()?;
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .with_context(|| {
                format!("Cannot create bootstrap cache dir: {}", cache_dir.display())
            })?;

        // Refresh stale or missing files, tolerating a failed refresh when a
        // usable (if stale) copy is already on disk — see `refresh_or_keep_stale`.
        // Each download is parsed before it replaces the on-disk copy, so a
        // bad response (an HTML error page served with 200, a truncated body)
        // can never overwrite a good file.
        let ipv4 = load_one(
            http,
            &cache_dir.join("ipv4.json"),
            IANA_IPV4_URL,
            force_refresh,
            parse_ipv4_bootstrap,
        )
        .await?;
        let ipv6 = load_one(
            http,
            &cache_dir.join("ipv6.json"),
            IANA_IPV6_URL,
            force_refresh,
            parse_ipv6_bootstrap,
        )
        .await?;
        let asn = load_one(
            http,
            &cache_dir.join("asn.json"),
            IANA_ASN_URL,
            force_refresh,
            parse_asn_bootstrap,
        )
        .await?;
        let dns = load_one(
            http,
            &cache_dir.join("dns.json"),
            IANA_DNS_URL,
            force_refresh,
            parse_dns_bootstrap,
        )
        .await?;

        Ok(Self {
            ipv4,
            ipv6,
            asn,
            dns,
        })
    }

    /// Longest-prefix-match lookup shared by `find_ip` and `find_ip_prefix`.
    ///
    /// Returns the most specific covering delegation together with its RDAP
    /// base URL, so neither caller has to repeat the scan.
    fn find_ip_entry(&self, ip: IpAddr) -> Option<(IpNet, &str)> {
        match ip {
            IpAddr::V4(v4) => self
                .ipv4
                .iter()
                .filter(|(net, _)| net.contains(&v4))
                .max_by_key(|(net, _)| net.prefix_len())
                .map(|(net, url)| (IpNet::V4(*net), url.as_ref())),
            IpAddr::V6(v6) => self
                .ipv6
                .iter()
                .filter(|(net, _)| net.contains(&v6))
                .max_by_key(|(net, _)| net.prefix_len())
                .map(|(net, url)| (IpNet::V6(*net), url.as_ref())),
        }
    }

    /// Find the RDAP base URL for an IP address.
    ///
    /// Uses longest-prefix-match: the most specific covering prefix wins.
    /// Returns `None` if no entry covers the address (should not happen for
    /// public IPs — IANA covers the full unicast space).
    pub fn find_ip(&self, ip: IpAddr) -> Option<&str> {
        self.find_ip_entry(ip).map(|(_, url)| url)
    }

    /// Find the covering bootstrap delegation prefix for an IP address (the
    /// same longest-prefix-match `find_ip` uses, but returning the prefix
    /// itself rather than its RDAP URL).
    ///
    /// Useful as a real allocation boundary for grouping/collapsing
    /// concurrent lookups — much coarser than an individual RDAP
    /// allocation, but far more accurate than a fixed-width heuristic.
    pub fn find_ip_prefix(&self, ip: IpAddr) -> Option<IpNet> {
        self.find_ip_entry(ip).map(|(net, _)| net)
    }

    /// Find the RDAP base URL for an Autonomous System Number.
    pub fn find_asn(&self, asn: u32) -> Option<&str> {
        self.asn
            .iter()
            .find(|(range, _)| range.contains(&asn))
            .map(|(_, url)| url.as_ref())
    }

    /// Find the RDAP base URL for a domain name (A-label form).
    ///
    /// Matches the longest bootstrap entry that is a whole-label suffix of
    /// `domain` (RFC 9224 §4), so "example.co.uk" prefers a "co.uk" entry
    /// over "uk", and "notuk" never matches "uk".
    pub fn find_domain(&self, domain: &str) -> Option<&str> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.dns
            .iter()
            .filter(|(suffix, _)| {
                domain == **suffix
                    || domain
                        .strip_suffix(&**suffix)
                        .is_some_and(|rest| rest.ends_with('.'))
            })
            .max_by_key(|(suffix, _)| suffix.len())
            .map(|(_, url)| url.as_ref())
    }
}

// ── Bootstrap file management ────────────────────────────────────────────────

fn bootstrap_cache_dir() -> Result<PathBuf> {
    let base = crate::default_cache_base()?;
    Ok(base.join("bootstrap"))
}

/// Make sure `path` holds a fresh, valid bootstrap file and return it parsed.
///
/// If the download fails, or returns something `parse` rejects, an existing
/// on-disk copy is used instead (stale if need be). Losing the network should
/// degrade bootstrap routing to "slightly out of date", not to "no routing at
/// all" — IANA delegations change rarely, so a stale map is far better than
/// none.
async fn load_one<T>(
    http: &reqwest::Client,
    path: &std::path::Path,
    url: &str,
    force: bool,
    parse: fn(&[u8]) -> Result<T>,
) -> Result<T> {
    // A fresh on-disk copy that still parses needs no network at all. A fresh
    // copy that does NOT parse (e.g. written by an older version without this
    // check) is treated as missing and re-downloaded.
    if !force && is_fresh(path) {
        match read_and_parse(path, parse) {
            Ok(v) => return Ok(v),
            Err(e) => eprintln!(
                "bootstrap: cached {} is unusable ({e:#}); re-downloading",
                path.display()
            ),
        }
    }

    match download(http, url, parse).await {
        Ok((bytes, parsed)) => {
            if let Err(e) = write_atomic(path, &bytes) {
                // Still usable for this run; just not persisted.
                eprintln!("bootstrap: could not save {} ({e:#})", path.display());
            }
            Ok(parsed)
        }
        Err(e) if path.exists() => {
            eprintln!("bootstrap: refresh of {url} failed ({e:#}); using stale cached copy");
            read_and_parse(path, parse)
        }
        Err(e) => Err(e),
    }
}

fn is_fresh(path: &std::path::Path) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
        return false;
    };
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::MAX);
    age < Duration::from_secs(BOOTSTRAP_TTL_SECS)
}

fn read_and_parse<T>(path: &std::path::Path, parse: fn(&[u8]) -> Result<T>) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    parse(&bytes).with_context(|| format!("Cannot parse {}", path.display()))
}

/// Download `url` and parse it; returns the raw bytes (to persist) and the
/// parsed value. Nothing is written unless parsing succeeded.
async fn download<T>(
    http: &reqwest::Client,
    url: &str,
    parse: fn(&[u8]) -> Result<T>,
) -> Result<(Vec<u8>, T)> {
    let parsed_url =
        reqwest::Url::parse(url).with_context(|| format!("Invalid bootstrap URL: {url}"))?;
    let fetched = crate::http::get_guarded(http, parsed_url, None).await?;
    if !fetched.status.is_success() {
        return Err(anyhow!(
            "Bootstrap server returned {} for {url}",
            fetched.status
        ));
    }
    let parsed =
        parse(&fetched.body).with_context(|| format!("Invalid bootstrap data from {url}"))?;
    Ok((fetched.body, parsed))
}

/// Write via a per-process temp file + rename, so concurrent runs never
/// interleave writes and readers never see a half-written file.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)
        .with_context(|| format!("Cannot write bootstrap temp file: {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("Cannot rename bootstrap file: {}", path.display())
    })
}

// ── Parsers (no allocation of intermediate Strings beyond what's kept) ───────

fn parse_ipv4_bootstrap(data: &[u8]) -> Result<Vec<(Ipv4Net, Box<str>)>> {
    let parsed: BootstrapFile =
        serde_json::from_slice(data).context("Invalid IPv4 bootstrap JSON")?;
    let mut out = Vec::with_capacity(parsed.services.len());
    for (prefixes, urls) in &parsed.services {
        let url = best_url(urls).ok_or_else(|| anyhow!("IPv4 bootstrap entry has no URLs"))?;
        for prefix in prefixes {
            let net: Ipv4Net = prefix
                .parse()
                .with_context(|| format!("Bad IPv4 prefix in bootstrap: {prefix}"))?;
            out.push((net, url.into()));
        }
    }
    out.sort_by(|(a, _), (b, _)| {
        a.addr()
            .cmp(&b.addr())
            .then(a.prefix_len().cmp(&b.prefix_len()))
    });
    Ok(out)
}

fn parse_ipv6_bootstrap(data: &[u8]) -> Result<Vec<(Ipv6Net, Box<str>)>> {
    let parsed: BootstrapFile =
        serde_json::from_slice(data).context("Invalid IPv6 bootstrap JSON")?;
    let mut out = Vec::with_capacity(parsed.services.len());
    for (prefixes, urls) in &parsed.services {
        let url = best_url(urls).ok_or_else(|| anyhow!("IPv6 bootstrap entry has no URLs"))?;
        for prefix in prefixes {
            let net: Ipv6Net = prefix
                .parse()
                .with_context(|| format!("Bad IPv6 prefix in bootstrap: {prefix}"))?;
            out.push((net, url.into()));
        }
    }
    out.sort_by_key(|(net, _)| net.addr());
    Ok(out)
}

fn parse_asn_bootstrap(data: &[u8]) -> Result<Vec<(RangeInclusive<u32>, Box<str>)>> {
    let parsed: BootstrapFile =
        serde_json::from_slice(data).context("Invalid ASN bootstrap JSON")?;
    let mut out = Vec::with_capacity(parsed.services.len());
    for (ranges, urls) in &parsed.services {
        let url = best_url(urls).ok_or_else(|| anyhow!("ASN bootstrap entry has no URLs"))?;
        for range_str in ranges {
            let (start, end) = parse_asn_range(range_str)
                .with_context(|| format!("Bad ASN range in bootstrap: {range_str}"))?;
            out.push((start..=end, url.into()));
        }
    }
    out.sort_by_key(|(range, _)| *range.start());
    Ok(out)
}

fn parse_dns_bootstrap(data: &[u8]) -> Result<Vec<(Box<str>, Box<str>)>> {
    let parsed: BootstrapFile =
        serde_json::from_slice(data).context("Invalid DNS bootstrap JSON")?;
    let mut out = Vec::new();
    for (suffixes, urls) in &parsed.services {
        let url = best_url(urls).ok_or_else(|| anyhow!("DNS bootstrap entry has no URLs"))?;
        for suffix in suffixes {
            let suffix = suffix.trim_matches('.').to_ascii_lowercase();
            if !suffix.is_empty() {
                out.push((suffix.into_boxed_str(), url.into()));
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!("DNS bootstrap has no entries"));
    }
    Ok(out)
}

/// Prefer HTTPS URLs; fall back to any URL.
fn best_url(urls: &[String]) -> Option<&str> {
    urls.iter()
        .find(|u| u.starts_with("https://"))
        .or_else(|| urls.first())
        .map(String::as_str)
}

/// Parse "12345-67890" or "12345" into (start, end).
fn parse_asn_range(s: &str) -> Result<(u32, u32)> {
    if let Some((lo, hi)) = s.split_once('-') {
        let start: u32 = lo
            .trim()
            .parse()
            .with_context(|| format!("Bad ASN start: {lo}"))?;
        let end: u32 = hi
            .trim()
            .parse()
            .with_context(|| format!("Bad ASN end: {hi}"))?;
        Ok((start, end))
    } else {
        let n: u32 = s.trim().parse().with_context(|| format!("Bad ASN: {s}"))?;
        Ok((n, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_map() -> BootstrapMap {
        use ipnet::{Ipv4Net, Ipv6Net};
        BootstrapMap {
            ipv4: vec![
                (
                    "0.0.0.0/0".parse::<Ipv4Net>().unwrap(),
                    "https://fallback.example".into(),
                ),
                (
                    "8.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                    "https://arin.example".into(),
                ),
                (
                    "8.8.0.0/16".parse::<Ipv4Net>().unwrap(),
                    "https://google.example".into(),
                ),
            ],
            ipv6: vec![(
                "2001:db8::/32".parse::<Ipv6Net>().unwrap(),
                "https://ripe.example".into(),
            )],
            asn: vec![
                (1..=9999, "https://arin.example".into()),
                (15169..=15169, "https://google.example".into()),
            ],
            dns: vec![
                ("com".into(), "https://verisign.example/com/v1/".into()),
                ("uk".into(), "https://nominet.example/".into()),
                ("co.uk".into(), "https://co-uk.example/".into()),
            ],
        }
    }

    #[test]
    fn test_find_ip_longest_match() {
        let map = make_map();
        // 8.8.8.8 is in both 8.0.0.0/8 AND 8.8.0.0/16 — should pick /16 (longer)
        let result = map.find_ip("8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(result, Some("https://google.example"));
    }

    #[test]
    fn test_find_ip_prefix_returns_longest_matching_net() {
        let map = make_map();
        let result = map.find_ip_prefix("8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(result, Some("8.8.0.0/16".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_find_ip_prefix_v6() {
        let map = make_map();
        let result = map.find_ip_prefix("2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(result, Some("2001:db8::/32".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn test_find_ip_fallback() {
        let map = make_map();
        // 192.168.1.1 only matches 0.0.0.0/0
        let result = map.find_ip("192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(result, Some("https://fallback.example"));
    }

    #[test]
    fn test_find_asn() {
        let map = make_map();
        assert_eq!(map.find_asn(15169), Some("https://google.example"));
        assert_eq!(map.find_asn(100), Some("https://arin.example"));
        assert_eq!(map.find_asn(99999), None);
    }

    #[test]
    fn test_parse_asn_range() {
        assert_eq!(parse_asn_range("100-200").unwrap(), (100, 200));
        assert_eq!(parse_asn_range("15169").unwrap(), (15169, 15169));
    }

    #[test]
    fn test_find_domain_matches_whole_label_suffix() {
        let map = make_map();
        assert_eq!(
            map.find_domain("google.com"),
            Some("https://verisign.example/com/v1/")
        );
        assert_eq!(
            map.find_domain("GOOGLE.COM."),
            Some("https://verisign.example/com/v1/")
        );
        assert_eq!(
            map.find_domain("com"),
            Some("https://verisign.example/com/v1/")
        );
        // "notcom" must not match the "com" entry.
        assert_eq!(map.find_domain("example.notcom"), None);
    }

    #[test]
    fn test_find_domain_prefers_longest_suffix() {
        let map = make_map();
        assert_eq!(map.find_domain("bbc.co.uk"), Some("https://co-uk.example/"));
        assert_eq!(
            map.find_domain("example.org.uk"),
            Some("https://nominet.example/")
        );
    }

    #[test]
    fn test_parse_dns_bootstrap() {
        let data = br#"{"services":[[["COM","net"],["http://x.example/","https://y.example/"]]]}"#;
        let parsed = parse_dns_bootstrap(data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(&*parsed[0].0, "com");
        assert_eq!(&*parsed[0].1, "https://y.example/");
    }

    /// Regression: a bad download (e.g. an HTML error page served with 200)
    /// used to be written to disk before parsing, disabling bootstrap routing
    /// until the file aged out. Parsers must reject it so it is never saved.
    #[test]
    fn test_parsers_reject_non_json_payloads() {
        let html = b"<html><body>Service Unavailable</body></html>";
        assert!(parse_ipv4_bootstrap(html).is_err());
        assert!(parse_ipv6_bootstrap(html).is_err());
        assert!(parse_asn_bootstrap(html).is_err());
        assert!(parse_dns_bootstrap(html).is_err());
        assert!(parse_dns_bootstrap(br#"{"services":[]}"#).is_err());
    }

    #[test]
    fn test_read_and_parse_falls_back_cleanly_on_corrupt_file() {
        let dir = std::env::temp_dir().join(format!("whois-rdap-boot-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dns.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(read_and_parse(&path, parse_dns_bootstrap).is_err());
        write_atomic(&path, br#"{"services":[[["com"],["https://y.example/"]]]}"#).unwrap();
        assert_eq!(read_and_parse(&path, parse_dns_bootstrap).unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
