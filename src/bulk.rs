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

use crate::{QueryTarget, RdapAsnResult, RdapClient, RdapDomainResult, RdapResult, classify_query};
use anyhow::Result;
use futures::StreamExt;
use serde_json::Value;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

/// In-flight query state for SingleFlight request collapsing.
#[derive(Clone, Debug)]
pub enum QueryState {
    Pending,
    Ready((String, Result<Value, String>)),
}

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
    /// Plain `std::sync::Mutex` (not `tokio::sync::Mutex`): every critical
    /// section here is a quick HashMap operation with no `.await` inside it,
    /// so a synchronous lock is safe and lets `ActiveQueryGuard`'s `Drop`
    /// impl clean up orphaned entries on task cancellation (Drop can't await).
    pub active_queries:
        StdMutex<std::collections::HashMap<String, tokio::sync::watch::Sender<QueryState>>>,
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
                "organization": r.organization.as_deref().unwrap_or("Unknown"),
                "country_code": r.country_code,
                "cidrs": r.cidrs,
                "as_number": r.as_number,
            }))
            .unwrap_or_default(),

            BulkRecord::Domain(target, r) => serde_json::to_vec(&serde_json::json!({
                "query": target,
                "type": "domain",
                "handle": r.handle,
                "organization": r.organization.as_deref().unwrap_or("Unknown"),
                "registrar": r.registrar,
                "country_code": r.country_code,
                "nameservers": r.nameservers,
                "status": r.status,
            }))
            .unwrap_or_default(),

            BulkRecord::Asn(asn, r) => serde_json::to_vec(&serde_json::json!({
                "query": format!("AS{asn}"),
                "type": "asn",
                "organization": r.organization.as_deref().unwrap_or("Unknown"),
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

impl BulkContext {
    /// Finish an active query by sending its result to all waiters and removing it from the map.
    pub fn finish_query(&self, key: &str, result: (String, Result<Value, String>)) {
        let mut active = self
            .active_queries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = active.remove(key) {
            let _ = tx.send(QueryState::Ready(result));
        }
    }
}

/// RAII cleanup for a SingleFlight initiator's entry in `active_queries`.
///
/// `lookup_one` normally removes its own entry via `BulkContext::finish_query`
/// once the network lookup completes. But if the enclosing task is dropped
/// before that point (e.g. a library caller wraps `bulk_lookup` in
/// `tokio::select!`/`tokio::time::timeout`), `finish_query` never runs, and
/// the orphaned `watch::Sender` would leave every future query for the same
/// group key waiting on `rx.changed()` forever. This guard is created only
/// by the initiator (the task that inserted the entry) and, on drop, removes
/// the entry and wakes any waiters with an error result so they fall back to
/// their own network lookup instead of hanging. If `finish_query` already
/// ran, the entry is already gone and this is a no-op.
struct ActiveQueryGuard<'a> {
    ctx: &'a BulkContext,
    key: String,
}

impl<'a> Drop for ActiveQueryGuard<'a> {
    fn drop(&mut self) {
        let mut active = self
            .ctx
            .active_queries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = active.remove(&self.key) {
            let _ = tx.send(QueryState::Ready((
                self.key.clone(),
                Err("query cancelled before completion".to_string()),
            )));
        }
    }
}

fn get_group_key(target: &QueryTarget) -> String {
    match target {
        QueryTarget::Ip(ip) => match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Group by /16 to collapse queries within the same broad provider block
                format!("group:ipv4:{}.{}", octets[0], octets[1])
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // Group by /48 for IPv6
                format!(
                    "group:ipv6:{:x}:{:x}:{:x}",
                    segments[0], segments[1], segments[2]
                )
            }
        },
        QueryTarget::Domain(domain) => {
            format!("group:domain:{}", domain)
        }
        QueryTarget::Asn(asn) => {
            format!("group:asn:{}", asn)
        }
    }
}

async fn lookup_one(ctx: &BulkContext, raw: String) -> BulkRecord {
    let target = classify_query(&raw);
    let cache_key = match &target {
        QueryTarget::Ip(ip) => crate::cache::key_ip(ip),
        QueryTarget::Domain(domain) => crate::cache::key_domain(domain),
        QueryTarget::Asn(asn) => crate::cache::key_asn(*asn),
    };
    let group_key = get_group_key(&target);

    // 1. Cache hit path (IP range-aware, domain/ASN exact match)
    if let Some(ref cache) = ctx.cache {
        match &target {
            QueryTarget::Ip(ip) => {
                if let Ok(Some(cached)) = cache.get_ip(*ip) {
                    let res = crate::parse_ip_response(cached);
                    return BulkRecord::Ip(raw, res);
                }
            }
            QueryTarget::Domain(domain) => {
                if let Ok(Some(cached)) = cache.get(&cache_key) {
                    let res = crate::parse_domain_response(domain, cached);
                    return BulkRecord::Domain(raw, res);
                }
            }
            QueryTarget::Asn(asn) => {
                if let Ok(Some(cached)) = cache.get(&cache_key) {
                    let res = crate::parse_asn_response(*asn, cached);
                    return BulkRecord::Asn(*asn, res);
                }
            }
        }
    }

    // 2. Check/Register in-flight request (SingleFlight collapsing by prefix group key)
    let rx = {
        let mut active = ctx.active_queries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = active.get(&group_key) {
            Some(tx.subscribe())
        } else {
            let (tx, _) = tokio::sync::watch::channel(QueryState::Pending);
            active.insert(group_key.clone(), tx);
            None // We are the initiator
        }
    };

    // Only the initiator (the task that just inserted the map entry) owns a
    // cleanup guard — if this task is cancelled before finish_query runs,
    // the guard's Drop impl removes the orphaned entry and unblocks waiters.
    let _guard = rx.is_none().then(|| ActiveQueryGuard {
        ctx,
        key: group_key.clone(),
    });

    if let Some(mut rx) = rx {
        // We are a waiter. Wait for the initiator to complete.
        loop {
            if let QueryState::Ready((ref initiator_key, ref res)) = *rx.borrow() {
                // If it's an exact target match, we reuse the initiator's result (success or failure) directly.
                if cache_key == *initiator_key {
                    match res {
                        Ok(val) => match &target {
                            QueryTarget::Ip(_) => {
                                return BulkRecord::Ip(raw, crate::parse_ip_response(val.clone()));
                            }
                            QueryTarget::Domain(domain) => {
                                return BulkRecord::Domain(
                                    raw,
                                    crate::parse_domain_response(domain, val.clone()),
                                );
                            }
                            QueryTarget::Asn(asn) => {
                                return BulkRecord::Asn(
                                    *asn,
                                    crate::parse_asn_response(*asn, val.clone()),
                                );
                            }
                        },
                        Err(err) => {
                            return BulkRecord::Error(raw, err.clone());
                        }
                    }
                }

                // The initiator completed successfully. Re-check the database cache
                // to see if the returned range (or exact match) covers our IP.
                if res.is_ok()
                    && let Some(ref cache) = ctx.cache
                {
                    match &target {
                        QueryTarget::Ip(ip) => {
                            if let Ok(Some(cached)) = cache.get_ip(*ip) {
                                return BulkRecord::Ip(raw, crate::parse_ip_response(cached));
                            }
                        }
                        QueryTarget::Domain(domain) => {
                            if let Ok(Some(cached)) = cache.get(&cache_key) {
                                return BulkRecord::Domain(
                                    raw,
                                    crate::parse_domain_response(domain, cached),
                                );
                            }
                        }
                        QueryTarget::Asn(asn) => {
                            if let Ok(Some(cached)) = cache.get(&cache_key) {
                                return BulkRecord::Asn(
                                    *asn,
                                    crate::parse_asn_response(*asn, cached),
                                );
                            }
                        }
                    }
                }
                // If it's still a cache miss (e.g. they are in different allocations in the same /16),
                // break out and proceed to execute our own network query.
                break;
            }
            if rx.changed().await.is_err() {
                break;
            }
        }
    }

    // 3. We are the initiator (or waiter whose leader range didn't cover us) -> network lookup
    let base_url = crate::resolve_base_url(
        &target,
        ctx.server.as_deref(),
        ctx.rir,
        ctx.bootstrap.as_deref(),
    );
    let client = match RdapClient::for_custom_with_client(&base_url, ctx.http.clone()) {
        Ok(c) => c,
        Err(e) => {
            let err_msg = e.to_string();
            ctx.finish_query(&group_key, (cache_key.clone(), Err(err_msg.clone())));
            return BulkRecord::Error(raw, err_msg);
        }
    };

    let result = match &target {
        QueryTarget::Ip(ip) => match client.lookup_ip(*ip).await {
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
                // Write cache — awaited so the write has landed before we
                // broadcast completion (step 5), otherwise waiters that
                // re-check the cache immediately after being woken can race
                // ahead of this still-in-flight spawn_blocking write and see
                // a spurious miss.
                if let Some(ref cache) = ctx.cache {
                    let range_bounds = res.range.as_ref().and_then(|(s, e)| {
                        Some((s.parse::<IpAddr>().ok()?, e.parse::<IpAddr>().ok()?))
                    });
                    let _ = cache
                        .insert_ip_background(
                            cache_key.clone(),
                            &res.raw,
                            range_bounds,
                            ctx.cache_ttl_ip,
                        )
                        .await;
                }
                Ok(res.raw)
            }
            Err(e) => Err(e.to_string()),
        },
        QueryTarget::Domain(domain) => match client.lookup_domain(domain).await {
            Ok(res) => {
                // Follow redirects
                let followed =
                    crate::redirect::follow_links(&ctx.http, res.raw.clone(), ctx.max_redirects)
                        .await;
                let res = if followed != res.raw {
                    crate::parse_domain_response(domain, followed)
                } else {
                    res
                };
                // Write cache — awaited, see comment above.
                if let Some(ref cache) = ctx.cache {
                    let _ = cache
                        .insert_background(cache_key.clone(), &res.raw, ctx.cache_ttl_domain)
                        .await;
                }
                Ok(res.raw)
            }
            Err(e) => Err(e.to_string()),
        },
        QueryTarget::Asn(asn) => match client.lookup_asn(*asn).await {
            Ok(res) => {
                // Write cache — awaited, see comment above.
                if let Some(ref cache) = ctx.cache {
                    let _ = cache
                        .insert_background(cache_key.clone(), &res.raw, ctx.cache_ttl_asn)
                        .await;
                }
                Ok(res.raw)
            }
            Err(e) => Err(e.to_string()),
        },
    };

    // 4. Resolve our own return value
    let record = match &result {
        Ok(val) => match &target {
            QueryTarget::Ip(_) => BulkRecord::Ip(raw, crate::parse_ip_response(val.clone())),
            QueryTarget::Domain(domain) => {
                BulkRecord::Domain(raw, crate::parse_domain_response(domain, val.clone()))
            }
            QueryTarget::Asn(asn) => {
                BulkRecord::Asn(*asn, crate::parse_asn_response(*asn, val.clone()))
            }
        },
        Err(err) => BulkRecord::Error(raw, err.clone()),
    };

    // 5. Broadcast to waiters and clean up active map
    ctx.finish_query(&group_key, (cache_key, result));

    record
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
        // Strip both whole-line comments ("# ...") and inline trailing
        // comments ("1.1.1.1  # Cloudflare"), per the documented targets
        // file format — target strings never legitimately contain '#'.
        let line = buf.trim();
        let target = line
            .split_once('#')
            .map_or(line, |(before, _)| before.trim());
        if !target.is_empty() {
            lines.push(target.to_string());
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

    // ── classify_query detection (shared with main.rs, see lib.rs) ────────────

    #[test]
    fn test_classify_query_ip() {
        assert!(matches!(
            classify_query("8.8.8.8"),
            QueryTarget::Ip(ip) if ip.to_string() == "8.8.8.8"
        ));
    }

    #[test]
    fn test_classify_query_ipv6() {
        assert!(matches!(
            classify_query("2001:4860:4860::8888"),
            QueryTarget::Ip(_)
        ));
    }

    #[test]
    fn test_classify_query_asn_prefix() {
        assert!(matches!(classify_query("AS15169"), QueryTarget::Asn(15169)));
    }

    #[test]
    fn test_classify_query_asn_prefix_lowercase() {
        // "as" prefix should also work (case-insensitive check)
        assert!(matches!(classify_query("as15169"), QueryTarget::Asn(15169)));
    }

    #[test]
    fn test_classify_query_asn_bare() {
        assert!(matches!(classify_query("15169"), QueryTarget::Asn(15169)));
    }

    #[test]
    fn test_classify_query_domain() {
        assert!(matches!(
            classify_query("google.com"),
            QueryTarget::Domain(d) if d == "google.com"
        ));
    }

    #[test]
    fn test_classify_query_domain_normalised_to_lowercase() {
        assert!(matches!(
            classify_query("GOOGLE.COM"),
            QueryTarget::Domain(d) if d == "google.com"
        ));
    }

    #[test]
    fn test_classify_query_empty_string_is_domain() {
        // Degenerate input: empty string is classified as Domain (not panicking)
        assert!(matches!(classify_query(""), QueryTarget::Domain(_)));
    }

    #[test]
    fn test_classify_query_multibyte_leading_char_does_not_panic() {
        // Regression: byte-slicing at a fixed offset (old bug) panicked on
        // any query whose first character is multi-byte UTF-8.
        assert!(matches!(
            classify_query("日本語.jp"),
            QueryTarget::Domain(_)
        ));
        assert!(matches!(classify_query("İstanbul"), QueryTarget::Domain(_)));
    }

    #[test]
    fn test_classify_query_trims_leading_whitespace_before_as_prefix() {
        // Regression: a leading space must not defeat "AS" prefix stripping.
        assert!(matches!(
            classify_query(" AS15169"),
            QueryTarget::Asn(15169)
        ));
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
    async fn test_collect_lines_strips_inline_trailing_comments() {
        // README documents "1.1.1.1     # Cloudflare" as valid syntax — the
        // trailing comment must be stripped, not treated as part of the target.
        let input = b"1.1.1.1     # Cloudflare\nAS15169 # Google\ngoogle.com\n";
        let reader = tokio::io::BufReader::new(&input[..]);
        tokio::pin!(reader);
        let lines = collect_lines(&mut reader).await.unwrap();

        assert_eq!(lines, vec!["1.1.1.1", "AS15169", "google.com"]);
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
            active_queries: StdMutex::new(std::collections::HashMap::new()),
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
            active_queries: StdMutex::new(std::collections::HashMap::new()),
        });

        let mut output = Vec::<u8>::new();
        bulk_lookup(ctx, std::iter::once("8.8.8.8".to_string()), 1, &mut output)
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
            active_queries: StdMutex::new(std::collections::HashMap::new()),
        });

        let mut output = Vec::<u8>::new();
        bulk_lookup(ctx, std::iter::empty(), 4, &mut output)
            .await
            .unwrap();

        assert!(output.is_empty(), "No targets must produce no output");
    }

    #[tokio::test]
    async fn test_bulk_lookup_collapses_duplicate_network_requests() {
        crate::install_ring_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a background task to count connection attempts.
        // Since all requests collapse into one, there should be exactly ONE connection accepted.
        let conn_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let conn_count_clone = Arc::clone(&conn_count);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                conn_count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Send a dummy HTTP 404 response to satisfy the reqwest client
                use tokio::io::AsyncWriteExt;
                let _ = socket
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .unwrap();
        let ctx = Arc::new(BulkContext {
            http,
            cache: None,
            bootstrap: None,
            timeout: std::time::Duration::from_millis(500),
            max_redirects: 0,
            cache_ttl_ip: 3600,
            cache_ttl_domain: 3600,
            cache_ttl_asn: 3600,
            server: Some(format!("http://{}", addr)),
            rir: None,
            active_queries: StdMutex::new(std::collections::HashMap::new()),
        });

        // 10 duplicate queries running with high concurrency
        let targets = vec!["8.8.8.8".to_string(); 10];
        let mut output = Vec::<u8>::new();
        bulk_lookup(ctx, targets.into_iter(), 10, &mut output)
            .await
            .unwrap();

        // The connections accepted by our TCP listener must be exactly 1!
        let count = conn_count.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            count, 1,
            "Expected exactly 1 network query due to SingleFlight collapsing, but got {}",
            count
        );
    }
}
