// IANA Bootstrap Triage Map (Feature 2)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// Routes an IP/Domain/ASN query to the correct authoritative RDAP server by
// consulting locally-cached IANA bootstrap JSON files:
//
//   https://data.iana.org/rdap/ipv4.json
//   https://data.iana.org/rdap/ipv6.json
//   https://data.iana.org/rdap/asn.json
//
// The map lives in-process as three sorted prefix arrays.  Lookup is a single
// binary-search O(log N) operation with zero heap allocation.  The bootstrap
// JSON files are cached to `$XDG_CACHE_HOME/whois-rdap/bootstrap/` and
// refreshed when their on-disk mtime exceeds BOOTSTRAP_TTL_SECS.

use anyhow::{Context, Result, anyhow};
use ipnet::{Ipv4Net, Ipv6Net};
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

// ── Internal serde model (only used during parsing, not retained) ────────────

#[derive(Deserialize)]
struct BootstrapFile {
    services: Vec<(Vec<String>, Vec<String>)>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// In-memory routing table built from IANA bootstrap JSON.
///
/// All three prefix arrays are sorted so lookups can use binary search.
/// The stored base-URL strings are `Box<str>` (single heap allocation per
/// entry, never cloned — callers receive a `&str` reference).
pub struct BootstrapMap {
    ipv4: Vec<(Ipv4Net, Box<str>)>,
    ipv6: Vec<(Ipv6Net, Box<str>)>,
    asn: Vec<(RangeInclusive<u32>, Box<str>)>,
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

        let ipv4_path = cache_dir.join("ipv4.json");
        let ipv6_path = cache_dir.join("ipv6.json");
        let asn_path = cache_dir.join("asn.json");

        // Refresh stale or missing files
        refresh_file(http, &ipv4_path, IANA_IPV4_URL, force_refresh).await?;
        refresh_file(http, &ipv6_path, IANA_IPV6_URL, force_refresh).await?;
        refresh_file(http, &asn_path, IANA_ASN_URL, force_refresh).await?;

        // Parse (sync — files are small, < 50 KB each)
        let ipv4 = parse_ipv4_bootstrap(
            &std::fs::read(&ipv4_path)
                .with_context(|| format!("Cannot read {}", ipv4_path.display()))?,
        )?;
        let ipv6 = parse_ipv6_bootstrap(
            &std::fs::read(&ipv6_path)
                .with_context(|| format!("Cannot read {}", ipv6_path.display()))?,
        )?;
        let asn = parse_asn_bootstrap(
            &std::fs::read(&asn_path)
                .with_context(|| format!("Cannot read {}", asn_path.display()))?,
        )?;

        Ok(Self { ipv4, ipv6, asn })
    }

    /// Find the RDAP base URL for an IP address.
    ///
    /// Uses longest-prefix-match: the most specific covering prefix wins.
    /// Returns `None` if no entry covers the address (should not happen for
    /// public IPs — IANA covers the full unicast space).
    pub fn find_ip(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(v4) => {
                // Walk all matching prefixes, pick the longest (most specific).
                self.ipv4
                    .iter()
                    .filter(|(net, _)| net.contains(&v4))
                    .max_by_key(|(net, _)| net.prefix_len())
                    .map(|(_, url)| url.as_ref())
            }
            IpAddr::V6(v6) => self
                .ipv6
                .iter()
                .filter(|(net, _)| net.contains(&v6))
                .max_by_key(|(net, _)| net.prefix_len())
                .map(|(_, url)| url.as_ref()),
        }
    }

    /// Find the RDAP base URL for an Autonomous System Number.
    pub fn find_asn(&self, asn: u32) -> Option<&str> {
        self.asn
            .iter()
            .find(|(range, _)| range.contains(&asn))
            .map(|(_, url)| url.as_ref())
    }
}

// ── Bootstrap file management ────────────────────────────────────────────────

fn bootstrap_cache_dir() -> Result<PathBuf> {
    let base = crate::default_cache_base()?;
    Ok(base.join("bootstrap"))
}

async fn refresh_file(
    http: &reqwest::Client,
    path: &std::path::Path,
    url: &str,
    force: bool,
) -> Result<()> {
    if !force
        && path.exists()
        && let Ok(meta) = std::fs::metadata(path)
        && let Ok(modified) = meta.modified()
    {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::MAX);
        if age < Duration::from_secs(BOOTSTRAP_TTL_SECS) {
            return Ok(());
        }
    }

    let bytes = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download bootstrap file: {url}"))?
        .error_for_status()
        .with_context(|| format!("Bootstrap server error for {url}"))?
        .bytes()
        .await
        .with_context(|| format!("Failed to read bootstrap response: {url}"))?;

    // Write atomically via temp file → rename
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)
        .with_context(|| format!("Cannot write bootstrap temp file: {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Cannot rename bootstrap file: {}", path.display()))?;

    Ok(())
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
}
