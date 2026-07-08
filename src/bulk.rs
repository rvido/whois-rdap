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
use std::sync::Arc;

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
/// * `client`      — shared RDAP client (cloned cheaply per task)
/// * `targets`     — iterator of query strings; consumed lazily
/// * `concurrency` — max in-flight concurrent lookups (bounded)
/// * `writer`      — output sink; receives one JSON line per result
///
/// Results are emitted in completion order (fastest first).
pub async fn bulk_lookup<I, W>(
    client: Arc<RdapClient>,
    targets: I,
    concurrency: usize,
    writer: &mut W,
) -> Result<()>
where
    I: Iterator<Item = String>,
    W: Write,
{
    let stream = futures::stream::iter(targets.map(|raw| {
        let client = Arc::clone(&client);
        async move { lookup_one(&client, raw).await }
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

async fn lookup_one(client: &RdapClient, raw: String) -> BulkRecord {
    match parse_target(&raw) {
        Target::Ip(ip) => match client.lookup_ip(ip).await {
            Ok(r) => BulkRecord::Ip(raw, r),
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
        Target::Domain(domain) => match client.lookup_domain(&domain).await {
            Ok(r) => BulkRecord::Domain(raw, r),
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
        Target::Asn(asn) => match client.lookup_asn(asn).await {
            Ok(r) => BulkRecord::Asn(asn, r),
            Err(e) => BulkRecord::Error(raw, e.to_string()),
        },
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

async fn collect_lines<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<String>> {
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

    #[test]
    fn test_parse_target_ip() {
        assert!(matches!(
            parse_target("8.8.8.8"),
            Target::Ip(ip) if ip.to_string() == "8.8.8.8"
        ));
    }

    #[test]
    fn test_parse_target_ipv6() {
        assert!(matches!(parse_target("2001:4860:4860::8888"), Target::Ip(_)));
    }

    #[test]
    fn test_parse_target_asn_prefix() {
        assert!(matches!(parse_target("AS15169"), Target::Asn(15169)));
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
    fn test_error_record_ndjson() {
        let rec = BulkRecord::Error("bad".into(), "not found".into());
        let json: serde_json::Value = serde_json::from_slice(&rec.to_ndjson()).unwrap();
        assert_eq!(json["query"], "bad");
        assert_eq!(json["error"], "not found");
    }
}
