// Parallel Bulk Lookup (Feature 1)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// Executes N RDAP lookups concurrently using `futures::stream::buffer_unordered`.
// Only `concurrency` responses are in-flight (and in memory) at any one time —
// results are streamed to the writer as they complete (NDJSON format), so the
// full result set is never buffered.
//
// Target strings are parsed lazily from the iterator; the caller owns the
// buffering strategy (file lines, stdin, argv).

use crate::{RdapAsnResult, RdapClient, RdapDomainResult, RdapResult};
use anyhow::Result;
use futures::StreamExt;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Configuration context for concurrent bulk lookups.
pub struct BulkContext {
    pub http: reqwest::Client,
    pub cache: Option<crate::cache::Cache>,
    pub bootstrap: Option<Arc<crate::bootstrap::BootstrapMap>>,
    pub timeout: Duration,
    pub max_redirects: u8,
    pub cache_ttl_ip: u64,
    pub cache_ttl_domain: u64,
    pub cache_ttl_asn: u64,
    pub server: Option<String>,
    pub rir: Option<crate::RdapRegistry>,
}

/// One resolved RDAP result (tagged union).
pub enum BulkRecord {
    Ip(String, RdapResult),
    Domain(String, RdapDomainResult),
    Asn(u32, RdapAsnResult),
    Error(String, String), // (target, error message)
}

impl BulkRecord {
    /// Serialize the record as a compact NDJSON line (no trailing newline).
    pub fn to_ndjson(&self) -> Vec<u8> {
        match self {
            BulkRecord::Ip(target, r) => serde_json::to_vec(&serde_json::json!({
                "query": target,
                "type": "ip",
                "organization": r.organization,
                "country_code": r.country_code,
                "cidrs": r.cidrs,
                "as_number": r.as_number,
            }))
            .unwrap_or_default(),

            BulkRecord::Domain(target, r) => serde_json::to_vec(&serde_json::json!({
                "query": target,
                "type": "domain",
                "handle": r.handle,
                "organization": r.organization,
                "registrar": r.registrar,
                "country_code": r.country_code,
                "nameservers": r.nameservers,
                "status": r.status,
            }))
            .unwrap_or_default(),

            BulkRecord::Asn(asn, r) => serde_json::to_vec(&serde_json::json!({
                "query": format!("AS{asn}"),
                "type": "asn",
                "organization": r.organization,
                "country_code": r.country_code,
                "range": r.range.map(|(s, e)| format!("AS{s}-AS{e}")),
            }))
            .unwrap_or_default(),

            BulkRecord::Error(target, msg) => serde_json::to_vec(&serde_json::json!({
                "query": target,
                "error": msg,
            }))
            .unwrap_or_default(),
        }
    }
}

// ── Query type detection (mirrors main.rs, kept local to avoid coupling) ─────

enum Target {
    Ip(std::net::IpAddr),
    Domain(String),
    Asn(u32),
}

fn parse_target(s: &str) -> Target {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Target::Ip(ip);
    }
    let trimmed = s.trim();
    let digits = if trimmed.len() > 2 && trimmed[..2].eq_ignore_ascii_case("AS") {
        &trimmed[2..]
    } else {
        trimmed
    };
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = digits.parse::<u32>() {
            return Target::Asn(n);
        }
    }
    Target::Domain(trimmed.to_ascii_lowercase())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run bulk RDAP lookups and stream NDJSON lines to `writer`.
///
/// # Arguments
/// * `ctx`         — bulk lookup configuration context (HTTP, Cache, Bootstrap Map)
/// * `targets`     — iterator of query strings; consumed lazily
/// * `concurrency` — max in-flight concurrent lookups (bounded)
/// * `writer`      — output sink; receives one JSON line per result
///
/// Results are emitted in completion order (fastest first).
pub async fn bulk_lookup<I, W>(
    ctx: Arc<BulkContext>,
    targets: I,
    concurrency: usize,
    writer: &mut W,
) -> Result<()>
where
    I: Iterator<Item = String>,
    W: Write,
{
    let stream = futures::stream::iter(targets.map(|raw| {
        let ctx = Arc::clone(&ctx);
        async move { lookup_one(&ctx, raw).await }
    }))
    .buffer_unordered(concurrency);

    tokio::pin!(stream);

    while let Some(record) = stream.next().await {
        let line = record.to_ndjson();
        writer.write_all(&line)?;
        writer.write_all(b"\n")?;
    }

    Ok(())
}

async fn lookup_one(ctx: &BulkContext, raw: String) -> BulkRecord {
    let target = parse_target(&raw);

    // 1. Cache hit path (IP range-aware, domain/ASN exact match)
    if let Some(ref cache) = ctx.cache {
        match &target {
            Target::Ip(ip) => {
                if let Ok(Some(cached)) = cache.get_ip(*ip) {
                    let res = crate::parse_ip_response(cached);
                    return BulkRecord::Ip(raw, res);
                }
            }
            Target::Domain(domain) => {
                let key = crate::cache::key_domain(domain);
                if let Ok(Some(cached)) = cache.get(&key) {
                    let res = crate::parse_domain_response(domain, cached);
                    return BulkRecord::Domain(raw, res);
                }
            }
            Target::Asn(asn) => {
                let key = crate::cache::key_asn(*asn);
                if let Ok(Some(cached)) = cache.get(&key) {
                    let res = crate::parse_asn_response(*asn, cached);
                    return BulkRecord::Asn(*asn, res);
                }
            }
        }
    }

    // 2. Cache miss -> network lookup
    let base_url = resolve_base_url(ctx, &target);
    let client = match RdapClient::for_custom_with_client(&base_url, ctx.http.clone()) {
        Ok(c) => c,
        Err(e) => return BulkRecord::Error(raw, e.to_string()),
    };

    match target {
        Target::Ip(ip) => match client.lookup_ip(ip).await {
            Ok(res) => {
                // Follow redirects
                let followed =
                    crate::redirect::follow_links(&ctx.http, res.raw.clone(), ctx.max_redirects)
                        .await;
                let res = if followed != res.raw {
                    crate::parse_ip_response(followed)
                } else {
                    res
                };
                // Write cache
                if let Some(ref cache) = ctx.cache {
                    let range_bounds = res.range.as_ref().and_then(|(s, e)| {
                        Some((s.parse::<IpAddr>().ok()?, e.parse::<IpAddr>().ok()?))
                    });
                    let key = crate::cache::key_ip(&ip);
                    cache.insert_ip_background(key, &res.raw, range_bounds, ctx.cache_ttl_ip);
                }
                BulkRecord::Ip(raw, res)
            }
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
        Target::Domain(domain) => match client.lookup_domain(&domain).await {
            Ok(res) => {
                // Follow redirects
                let followed =
                    crate::redirect::follow_links(&ctx.http, res.raw.clone(), ctx.max_redirects)
                        .await;
                let res = if followed != res.raw {
                    crate::parse_domain_response(&domain, followed)
                } else {
                    res
                };
                // Write cache
                if let Some(ref cache) = ctx.cache {
                    let key = crate::cache::key_domain(&domain);
                    cache.insert_background(key, &res.raw, ctx.cache_ttl_domain);
                }
                BulkRecord::Domain(raw, res)
            }
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
        Target::Asn(asn) => match client.lookup_asn(asn).await {
            Ok(res) => {
                // Write cache
                if let Some(ref cache) = ctx.cache {
                    let key = crate::cache::key_asn(asn);
                    cache.insert_background(key, &res.raw, ctx.cache_ttl_asn);
                }
                BulkRecord::Asn(asn, res)
            }
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
    }
}

fn resolve_base_url(ctx: &BulkContext, target: &Target) -> String {
    // 1. Explicit --server wins
    if let Some(ref s) = ctx.server {
        return s.clone();
    }
    // 2. Explicit --rir wins
    if let Some(reg) = ctx.rir {
        return reg.base_url().to_string();
    }
    // 3. Bootstrap triage
    if let Some(ref map) = ctx.bootstrap {
        let found = match target {
            Target::Ip(ip) => map.find_ip(*ip),
            Target::Asn(asn) => map.find_asn(*asn),
            Target::Domain(_) => None, // Domain bootstrap not in scope
        };
        if let Some(url) = found {
            return url.to_string();
        }
    }
    // 4. Static defaults
    match target {
        Target::Ip(_) => crate::RdapRegistry::RIPE.base_url().to_string(),
        Target::Domain(_) | Target::Asn(_) => crate::RdapRegistry::IANA.base_url().to_string(),
    }
}

// ── Helper: read targets from a file or stdin ─────────────────────────────────

/// Read targets from `path`.  Pass `"-"` to read from stdin.
///
/// Lines are returned lazily via a `Vec<String>` (file is typically small).
/// Blank lines and lines starting with `#` are skipped.
pub async fn read_targets_file(path: &str) -> Result<Vec<String>> {
    use tokio::io::BufReader;

    let lines: Vec<String> = if path == "-" {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        collect_lines(&mut reader).await?
    } else {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| anyhow::anyhow!("Cannot open file '{}': {}", path, e))?;
        let mut reader = tokio::io::BufReader::new(file);
        collect_lines(&mut reader).await?
    };

    Ok(lines)
}

async fn collect_lines<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<String>> {
    use tokio::io::AsyncBufReadExt;
    let mut lines = Vec::new();
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        let trimmed = buf.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed.to_string());
        }
    }
    Ok(lines)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RdapAsnResult, RdapDomainResult, RdapResult};
    use serde_json::{Value, json};

    // ── helpers to build minimal result structs without network ───────────────

    fn make_ip_result(org: &str, cc: &str, cidr: &str) -> RdapResult {
        RdapResult {
            organization: Some(org.to_string()),
            country_code: Some(cc.to_string()),
            cidrs: vec![cidr.to_string()],
            range: Some(("1.0.0.0".to_string(), "1.0.0.255".to_string())),
            as_number: Some(12345),
            raw: json!({}),
        }
    }

    fn make_domain_result(handle: &str, registrar: &str) -> RdapDomainResult {
        RdapDomainResult {
            handle: handle.to_string(),
            organization: Some("Example Org".to_string()),
            registrar: Some(registrar.to_string()),
            country_code: Some("US".to_string()),
            nameservers: vec!["ns1.example.com".to_string()],
            status: vec!["active".to_string()],
            raw: json!({}),
        }
    }

    fn make_asn_result(org: &str, range: (u32, u32)) -> RdapAsnResult {
        RdapAsnResult {
            asn: range.0,
            organization: Some(org.to_string()),
            country_code: Some("US".to_string()),
            range: Some(range),
            raw: json!({}),
        }
    }

    fn parse_ndjson(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("BulkRecord::to_ndjson must produce valid JSON")
    }

    // ── BulkRecord::to_ndjson ─────────────────────────────────────────────────

    #[test]
    fn test_ip_record_ndjson_fields() {
        let rec = BulkRecord::Ip(
            "8.8.8.8".to_string(),
            make_ip_result("Google LLC", "US", "8.8.8.0/24"),
        );
        let j = parse_ndjson(&rec.to_ndjson());

        assert_eq!(j["query"], "8.8.8.8");
        assert_eq!(j["type"], "ip");
        assert_eq!(j["organization"], "Google LLC");
        assert_eq!(j["country_code"], "US");
        assert!(
            j["cidrs"]
                .as_array()
                .unwrap()
                .contains(&json!("8.8.8.0/24"))
        );
        assert_eq!(j["as_number"], 12345);
    }

    #[test]
    fn test_ip_record_ndjson_no_trailing_newline() {
        let rec = BulkRecord::Ip(
            "1.2.3.4".to_string(),
            make_ip_result("Org", "DE", "1.0.0.0/8"),
        );
        let bytes = rec.to_ndjson();
        assert!(
            !bytes.ends_with(b"\n"),
            "to_ndjson must not append a newline (bulk_lookup adds it)"
        );
    }

    #[test]
    fn test_domain_record_ndjson_fields() {
        let rec = BulkRecord::Domain(
            "google.com".to_string(),
            make_domain_result("GOOGLE.COM", "MarkMonitor Inc."),
        );
        let j = parse_ndjson(&rec.to_ndjson());

        assert_eq!(j["query"], "google.com");
        assert_eq!(j["type"], "domain");
        assert_eq!(j["handle"], "GOOGLE.COM");
        assert_eq!(j["registrar"], "MarkMonitor Inc.");
        assert_eq!(j["country_code"], "US");
        assert!(
            j["nameservers"]
                .as_array()
                .unwrap()
                .contains(&json!("ns1.example.com"))
        );
        assert!(j["status"].as_array().unwrap().contains(&json!("active")));
    }

    #[test]
    fn test_asn_record_ndjson_fields() {
        let rec = BulkRecord::Asn(15169, make_asn_result("Google LLC", (15169, 15169)));
        let j = parse_ndjson(&rec.to_ndjson());

        assert_eq!(j["query"], "AS15169");
        assert_eq!(j["type"], "asn");
        assert_eq!(j["organization"], "Google LLC");
        assert_eq!(j["country_code"], "US");
        // range formatted as "AS{start}-AS{end}"
        assert_eq!(j["range"], "AS15169-AS15169");
    }

    #[test]
    fn test_asn_record_ndjson_range_block() {
        let rec = BulkRecord::Asn(64500, make_asn_result("Test Block", (64496, 64511)));
        let j = parse_ndjson(&rec.to_ndjson());
        assert_eq!(j["range"], "AS64496-AS64511");
    }

    #[test]
    fn test_error_record_ndjson_fields() {
        let rec = BulkRecord::Error("bad.input".into(), "connection timeout".into());
        let j = parse_ndjson(&rec.to_ndjson());
        assert_eq!(j["query"], "bad.input");
        assert_eq!(j["error"], "connection timeout");
    }

    #[test]
    fn test_error_record_ndjson_has_no_type_field() {
        // Error records intentionally omit "type" to distinguish them
        let rec = BulkRecord::Error("x".into(), "err".into());
        let j = parse_ndjson(&rec.to_ndjson());
        assert!(
            j.get("type").is_none() || j["type"].is_null(),
            "Error records must not carry a 'type' field"
        );
    }

    // ── parse_target detection ────────────────────────────────────────────────

    #[test]
    fn test_parse_target_ip() {
        assert!(matches!(
            parse_target("8.8.8.8"),
            Target::Ip(ip) if ip.to_string() == "8.8.8.8"
        ));
    }

    #[test]
    fn test_parse_target_ipv6() {
        assert!(matches!(
            parse_target("2001:4860:4860::8888"),
            Target::Ip(_)
        ));
    }

    #[test]
    fn test_parse_target_asn_prefix() {
        assert!(matches!(parse_target("AS15169"), Target::Asn(15169)));
    }

    #[test]
    fn test_parse_target_asn_prefix_lowercase() {
        // "as" prefix should also work (case-insensitive check in parse_target)
        assert!(matches!(parse_target("as15169"), Target::Asn(15169)));
    }

    #[test]
    fn test_parse_target_asn_bare() {
        assert!(matches!(parse_target("15169"), Target::Asn(15169)));
    }

    #[test]
    fn test_parse_target_domain() {
        assert!(matches!(
            parse_target("google.com"),
            Target::Domain(d) if d == "google.com"
        ));
    }

    #[test]
    fn test_parse_target_domain_normalised_to_lowercase() {
        // parse_target normalises domains to ascii-lowercase
        assert!(matches!(
            parse_target("GOOGLE.COM"),
            Target::Domain(d) if d == "google.com"
        ));
    }

    #[test]
    fn test_parse_target_empty_string_is_domain() {
        // Degenerate input: empty string is classified as Domain (not panicking)
        assert!(matches!(parse_target(""), Target::Domain(_)));
    }

    // ── collect_lines (blank/comment skipping) ────────────────────────────────

    #[tokio::test]
    async fn test_collect_lines_skips_blanks_and_comments() {
        // Build a tokio BufReader from an in-memory byte buffer
        let input = b"8.8.8.8\n\n# comment\n  \nAS15169\n# another comment\ngoogle.com\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();

        assert_eq!(lines, vec!["8.8.8.8", "AS15169", "google.com"]);
    }

    #[tokio::test]
    async fn test_collect_lines_trims_whitespace() {
        let input = b"  8.8.8.8  \n\t google.com\t\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();

        assert_eq!(lines, vec!["8.8.8.8", "google.com"]);
    }

    #[tokio::test]
    async fn test_collect_lines_empty_input() {
        let input: &[u8] = b"";
        let reader = tokio::io::BufReader::new(input);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();
        assert!(lines.is_empty());
    }

    #[tokio::test]
    async fn test_collect_lines_only_comments() {
        let input = b"# line 1\n# line 2\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();
        assert!(lines.is_empty());
    }

    #[tokio::test]
    async fn test_collect_lines_no_trailing_newline() {
        // File without trailing newline must still parse the last line
        let input = b"8.8.8.8\ngoogle.com";
        let reader = tokio::io::BufReader::new(&input[..]);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();
        assert_eq!(lines, vec!["8.8.8.8", "google.com"]);
    }

    // ── read_targets_file with a real temp file ───────────────────────────────

    #[tokio::test]
    async fn test_read_targets_file_skips_blanks_and_comments() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rdap_bulk_test_{}.txt", std::process::id()));
        let content = "8.8.8.8\n# comment\n\nAS15169\ngoogle.com\n";
        std::fs::write(&path, content).unwrap();

        let targets = read_targets_file(path.to_str().unwrap()).await.unwrap();
        assert_eq!(targets, vec!["8.8.8.8", "AS15169", "google.com"]);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_read_targets_file_missing_returns_error() {
        let result = read_targets_file("/tmp/rdap_nonexistent_12345.txt").await;
        assert!(result.is_err(), "Missing file must return Err");
    }

    // ── bulk_lookup streaming output ──────────────────────────────────────────
    //
    // We cannot make real RDAP network calls in tests, but we CAN verify that:
    //   - The streaming loop emits one line per target
    //   - Each line is valid JSON
    //   - Errors are gracefully written as error records (not panics)
    //
    // We use a fake RdapClient that is pointed at a deliberately unreachable
    // URL so every lookup results in a connection error → BulkRecord::Error.

    #[tokio::test]
    async fn test_bulk_lookup_streams_one_ndjson_line_per_target() {
        crate::install_ring_provider();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let ctx = Arc::new(BulkContext {
            http,
            cache: None,
            bootstrap: None,
            timeout: std::time::Duration::from_millis(50),
            max_redirects: 0,
            cache_ttl_ip: 3600,
            cache_ttl_domain: 3600,
            cache_ttl_asn: 3600,
            server: Some("http://127.0.0.1:1".to_string()),
            rir: None,
        });

        let targets = vec![
            "8.8.8.8".to_string(),
            "google.com".to_string(),
            "AS15169".to_string(),
        ];

        let mut output = Vec::<u8>::new();
        bulk_lookup(ctx, targets.into_iter(), 2, &mut output)
            .await
            .expect("bulk_lookup must not return Err even when all lookups fail");

        // Each line must be valid JSON
        let lines: Vec<&str> = output
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| std::str::from_utf8(l).unwrap())
            .collect();

        assert_eq!(lines.len(), 3, "Must emit exactly one JSON line per target");

        for line in &lines {
            let parsed: Value = serde_json::from_str(line)
                .unwrap_or_else(|_| panic!("Each line must be valid JSON, got: {line}"));
            assert!(
                parsed.get("query").is_some(),
                "Every NDJSON line must have a 'query' field, got: {parsed}"
            );
            // On connection failure all records are Error records
            assert!(
                parsed.get("error").is_some(),
                "Unreachable server must produce error records, got: {parsed}"
            );
        }
    }

    #[tokio::test]
    async fn test_bulk_lookup_output_ends_with_newline() {
        crate::install_ring_provider();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let ctx = Arc::new(BulkContext {
            http,
            cache: None,
            bootstrap: None,
            timeout: std::time::Duration::from_millis(50),
            max_redirects: 0,
            cache_ttl_ip: 3600,
            cache_ttl_domain: 3600,
            cache_ttl_asn: 3600,
            server: Some("http://127.0.0.1:1".to_string()),
            rir: None,
        });

        let mut output = Vec::<u8>::new();
        bulk_lookup(
            ctx,
            std::iter::once("8.8.8.8".to_string()),
            1,
            &mut output,
        )
        .await
        .unwrap();

        assert!(
            output.ends_with(b"\n"),
            "bulk_lookup output must end with a newline"
        );
    }

    #[tokio::test]
    async fn test_bulk_lookup_empty_targets_produces_no_output() {
        crate::install_ring_provider();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let ctx = Arc::new(BulkContext {
            http,
            cache: None,
            bootstrap: None,
            timeout: std::time::Duration::from_millis(50),
            max_redirects: 0,
            cache_ttl_ip: 3600,
            cache_ttl_domain: 3600,
            cache_ttl_asn: 3600,
            server: Some("http://127.0.0.1:1".to_string()),
            rir: None,
        });

        let mut output = Vec::<u8>::new();
        bulk_lookup(ctx, std::iter::empty(), 4, &mut output)
            .await
            .unwrap();

        assert!(output.is_empty(), "No targets must produce no output");
    }
}
