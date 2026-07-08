// A command-line tool to query RDAP servers for IP, Domain, and ASN information.
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::{ArgGroup, Parser, ValueHint};

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use whois_rdap::{
    RdapClient, RdapRegistry,
    bulk::{bulk_lookup, read_targets_file},
    cache::{Cache, key_asn, key_domain, key_ip},
    redirect::follow_links,
};


// ── CLI definition ─────────────────────────────────────────────────────────

/// RDAP whois-like client: returns registration details for an IP, Domain, or ASN.
///
/// Query type is auto-detected:
///   IP   →  8.8.8.8  /  2001:4860::1
///   ASN  →  AS15169  /  15169
///   Domain → google.com
#[derive(Parser, Debug)]
#[command(name = "whois-rdap", version, author, about)]
#[command(group(
    ArgGroup::new("server_choice")
        .args(&["rir", "server"])
        .multiple(false)
))]
struct Args {
    /// One or more IP addresses, domain names, or AS numbers to look up.
    /// Omit when using --file.
    #[arg(value_hint = ValueHint::Other, num_args = 0..)]
    query: Vec<String>,

    /// Pick a known RDAP server (RIR/Registry) from a curated list.
    /// Values: ripe, arin, apnic, lacnic, afrinic, iana
    #[arg(long)]
    rir: Option<RdapRegistry>,

    /// Use a custom RDAP server base URL (overrides --rir and bootstrap triage).
    /// Example: https://rdap.arin.net/registry
    #[arg(long, value_hint = ValueHint::Url)]
    server: Option<String>,

    /// List all known servers and exit.
    #[arg(long, action)]
    list_servers: bool,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Print successful lookup output as compact JSON (one line per result).
    #[arg(long, action)]
    json: bool,

    // ── Bulk options ──────────────────────────────────────────────────────
    /// Read lookup targets from a file (one per line).  Use "-" for stdin.
    /// Blank lines and lines starting with "#" are ignored.
    #[arg(long, value_hint = ValueHint::FilePath)]
    file: Option<String>,

    /// Max concurrent lookups when processing multiple targets (default: 8).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    // ── Bootstrap options ─────────────────────────────────────────────────
    /// Skip IANA bootstrap triage; use --rir or --server explicitly.
    #[arg(long, action)]
    no_bootstrap: bool,

    /// Force re-download of IANA bootstrap maps even if still fresh.
    #[arg(long, action)]
    refresh_bootstrap: bool,

    // ── Cache options ─────────────────────────────────────────────────────
    /// Disable local SQLite result cache (always query the RDAP server).
    #[arg(long, action)]
    no_cache: bool,

    /// TTL in seconds for cached IP results (default: 86400 = 24 h).
    #[arg(long, default_value_t = whois_rdap::cache::DEFAULT_TTL_IP_SECS)]
    cache_ttl_ip: u64,

    /// TTL in seconds for cached domain results (default: 28800 = 8 h).
    #[arg(long, default_value_t = whois_rdap::cache::DEFAULT_TTL_DOMAIN_SECS)]
    cache_ttl_domain: u64,

    /// TTL in seconds for cached ASN results (default: 86400 = 24 h).
    #[arg(long, default_value_t = whois_rdap::cache::DEFAULT_TTL_ASN_SECS)]
    cache_ttl_asn: u64,

    // ── Redirect options ──────────────────────────────────────────────────
    /// Max RDAP link hops to follow (0 = disabled, default: 1, max: 3).
    #[arg(long, default_value_t = 1)]
    max_redirects: u8,
}

// ── Query type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryType {
    Ip,
    Domain,
    Asn,
}

fn detect_query_type(query: &str) -> QueryType {
    if query.parse::<IpAddr>().is_ok() {
        return QueryType::Ip;
    }
    let trimmed = query.trim();
    let digits = if trimmed.len() > 2 && trimmed[..2].eq_ignore_ascii_case("AS") {
        &trimmed[2..]
    } else {
        trimmed
    };
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        return QueryType::Asn;
    }
    QueryType::Domain
}

fn parse_query_asn(query: &str) -> Result<u32> {
    let trimmed = query.trim();
    let digits = if trimmed.len() > 2 && trimmed[..2].eq_ignore_ascii_case("AS") {
        &trimmed[2..]
    } else {
        trimmed
    };
    digits
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid AS number: '{}'", query))
}

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_servers {
        print_servers();
        return Ok(());
    }

    let timeout = Duration::from_secs(args.timeout);

    // ── Collect targets ────────────────────────────────────────────────────
    let mut targets: Vec<String> = args.query.clone();
    if let Some(ref path) = args.file {
        let mut file_targets = read_targets_file(path).await?;
        targets.append(&mut file_targets);
    }

    if targets.is_empty() {
        eprintln!("Error: no query targets provided. Pass a query or use --file.");
        std::process::exit(1);
    }

    // ── Open cache (unless --no-cache) ────────────────────────────────────
    let cache: Option<Cache> = if args.no_cache {
        None
    } else {
        match Cache::open() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("cache: failed to open ({e}); running without cache");
                None
            }
        }
    };

    // ── Bootstrap triage (resolve server URL) ─────────────────────────────
    // We resolve once at the start. For bulk with mixed query types this will
    // use the triage map per-query inside bulk_lookup via RdapClient's base URL.
    // For single queries we resolve it here.
    let bootstrap_map = if !args.no_bootstrap && args.server.is_none() && args.rir.is_none() {
        // Build a minimal reqwest client for bootstrap download only.
        let boot_http = build_http_client(timeout)?;
        match whois_rdap::bootstrap::BootstrapMap::load(&boot_http, args.refresh_bootstrap).await {
            Ok(map) => Some(Arc::new(map)),
            Err(e) => {
                eprintln!("bootstrap: failed to load ({e}); falling back to default servers");
                None
            }
        }
    } else {
        None
    };

    let stdout = std::io::stdout();

    // ── Multi-target: bulk mode ────────────────────────────────────────────
    if targets.len() > 1 || args.file.is_some() {
        // For bulk, we use a single client. Bootstrap is best-effort per target
        // inside the task, but for simplicity we use a generic base.
        // Use RIPE as a sane default; the user should supply --server for bulk
        // domain/ASN queries or rely on the bootstrap map (future enhancement:
        // per-target client resolution).
        let base_url = resolve_base_url(&args, None, &bootstrap_map, QueryType::Ip);
        let client = Arc::new(RdapClient::for_custom(&base_url, timeout)?);
        let mut writer = stdout.lock();
        bulk_lookup(client, targets.into_iter(), args.concurrency, &mut writer).await?;
        return Ok(());
    }

    // ── Single query ───────────────────────────────────────────────────────
    let query = &targets[0];
    let query_type = detect_query_type(query);
    let base_url = resolve_base_url(&args, Some(query), &bootstrap_map, query_type);
    let client = RdapClient::for_custom(&base_url, timeout)?;
    let max_redirects = args.max_redirects.min(3);

    let mut handle = stdout.lock();

    match query_type {
        QueryType::Ip => {
            let ip: IpAddr = query
                .parse()
                .map_err(|_| anyhow!("Invalid IP address: {}", query))?;
            let cache_key = key_ip(&ip);
            let ttl = args.cache_ttl_ip;

            // Cache read
            if let Some(ref c) = cache {
                if let Ok(Some(cached)) = c.get(&cache_key) {
                    let res = whois_rdap::RdapResult {
                        organization: cached.get("organization").and_then(|v| v.as_str()).map(str::to_owned),
                        country_code: cached.get("country_code").and_then(|v| v.as_str()).map(str::to_owned),
                        cidrs: cached.get("cidrs").and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                            .unwrap_or_default(),
                        range: extract_cached_ip_range(&cached),
                        as_number: cached.get("as_number").and_then(|v| v.as_u64()).map(|n| n as u32),
                        raw: cached,
                    };
                    print_ip_result(&mut handle, ip, &base_url, &res, args.json)?;
                    return Ok(());
                }
            }

            match client.lookup_ip(ip).await {
                Ok(res) => {
                    // Follow RDAP links for richer data
                    let raw = follow_links(client.http_client(), res.raw, max_redirects).await;
                    let res = rebuild_ip_result(raw);

                    if let Some(ref c) = cache {
                        c.insert_background(cache_key, &res.raw, ttl);
                    }
                    print_ip_result(&mut handle, ip, &base_url, &res, args.json)?;
                }
                Err(e) => return handle_error(e),
            }
        }

        QueryType::Domain => {
            let domain = query.to_ascii_lowercase();
            let cache_key = key_domain(&domain);
            let ttl = args.cache_ttl_domain;

            if let Some(ref c) = cache {
                if let Ok(Some(cached)) = c.get(&cache_key) {
                    let res = rebuild_domain_result_from_cache(&domain, &cached);
                    print_domain_result(&mut handle, &base_url, &res, args.json)?;
                    return Ok(());
                }
            }

            match client.lookup_domain(&domain).await {
                Ok(res) => {
                    let raw = follow_links(client.http_client(), res.raw.clone(), max_redirects).await;
                    let res = if raw.is_object() && raw != res.raw {
                        rebuild_domain_result_from_full(&domain, raw)
                    } else {
                        res
                    };
                    if let Some(ref c) = cache {
                        c.insert_background(cache_key, &res.raw, ttl);
                    }
                    print_domain_result(&mut handle, &base_url, &res, args.json)?;
                }
                Err(e) => return handle_error(e),
            }
        }

        QueryType::Asn => {
            let asn = parse_query_asn(query)?;
            let cache_key = key_asn(asn);
            let ttl = args.cache_ttl_asn;

            if let Some(ref c) = cache {
                if let Ok(Some(cached)) = c.get(&cache_key) {
                    let res = rebuild_asn_result_from_cache(asn, &cached);
                    print_asn_result(&mut handle, &base_url, &res, args.json)?;
                    return Ok(());
                }
            }

            match client.lookup_asn(asn).await {
                Ok(res) => {
                    if let Some(ref c) = cache {
                        c.insert_background(cache_key, &res.raw, ttl);
                    }
                    print_asn_result(&mut handle, &base_url, &res, args.json)?;
                }
                Err(e) => return handle_error(e),
            }
        }
    }

    Ok(())
}

// ── URL resolution ─────────────────────────────────────────────────────────

fn resolve_base_url(
    args: &Args,
    query: Option<&str>,
    bootstrap: &Option<Arc<whois_rdap::bootstrap::BootstrapMap>>,
    query_type: QueryType,
) -> String {
    // 1. Explicit --server wins
    if let Some(ref s) = args.server {
        return s.clone();
    }
    // 2. Explicit --rir wins
    if let Some(reg) = args.rir {
        return reg.base_url().to_string();
    }
    // 3. Bootstrap triage
    if let (Some(map), Some(q)) = (bootstrap, query) {
        let found = match query_type {
            QueryType::Ip => q.parse::<IpAddr>().ok().and_then(|ip| map.find_ip(ip)),
            QueryType::Asn => {
                let digits = if q.len() > 2 && q[..2].eq_ignore_ascii_case("AS") { &q[2..] } else { q };
                digits.parse::<u32>().ok().and_then(|asn| map.find_asn(asn))
            }
            QueryType::Domain => None, // Domain bootstrap not in scope
        };
        if let Some(url) = found {
            return url.to_string();
        }
    }
    // 4. Static defaults
    match query_type {
        QueryType::Ip => RdapRegistry::RIPE.base_url().to_string(),
        QueryType::Domain | QueryType::Asn => RdapRegistry::IANA.base_url().to_string(),
    }
}

fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    // Install ring provider (idempotent — RdapClient::for_custom does the same).
    // We reach into the lib's bootstrap loader via a temporary RdapClient to
    // avoid duplicating the ring installation logic.
    // Use a throwaway RdapClient just to trigger ring installation.
    let _ = RdapClient::for_custom("https://rdap.iana.org", timeout)?;
    Ok(reqwest::Client::builder()
        .user_agent("rdap-client/0.3 (Rust)")
        .timeout(timeout)
        .build()?)
}

// ── Result rebuilders (from cached raw JSON) ───────────────────────────────

/// Extract a string-pair range used in RdapResult (IP range: "1.2.3.0" - "1.2.3.255").
fn extract_cached_ip_range(v: &serde_json::Value) -> Option<(String, String)> {
    let start = v.get("range_start").and_then(|x| x.as_str())?.to_owned();
    let end = v.get("range_end").and_then(|x| x.as_str())?.to_owned();
    Some((start, end))
}

/// Extract a u32-pair range used in RdapAsnResult.
fn extract_cached_asn_range(v: &serde_json::Value) -> Option<(u32, u32)> {
    let start = v.get("range_start").and_then(|x| x.as_u64())? as u32;
    let end = v.get("range_end").and_then(|x| x.as_u64())? as u32;
    Some((start, end))
}

fn rebuild_ip_result(raw: serde_json::Value) -> whois_rdap::RdapResult {
    let organization = raw.get("organization").and_then(|v| v.as_str()).map(str::to_owned);
    let country_code = raw.get("country_code").and_then(|v| v.as_str()).map(str::to_owned);
    let cidrs = raw.get("cidrs").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let range = extract_cached_ip_range(&raw);
    let as_number = raw.get("as_number").and_then(|v| v.as_u64()).map(|n| n as u32);
    whois_rdap::RdapResult { organization, country_code, cidrs, range, as_number, raw }
}

fn rebuild_domain_result_from_cache(domain: &str, cached: &serde_json::Value) -> whois_rdap::RdapDomainResult {
    whois_rdap::RdapDomainResult {
        handle: cached.get("handle").and_then(|v| v.as_str()).unwrap_or(domain).to_owned(),
        organization: cached.get("organization").and_then(|v| v.as_str()).map(str::to_owned),
        registrar: cached.get("registrar").and_then(|v| v.as_str()).map(str::to_owned),
        country_code: cached.get("country_code").and_then(|v| v.as_str()).map(str::to_owned),
        nameservers: cached.get("nameservers").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default(),
        status: cached.get("status").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default(),
        raw: cached.clone(),
    }
}

fn rebuild_domain_result_from_full(domain: &str, raw: serde_json::Value) -> whois_rdap::RdapDomainResult {
    // Re-extract fields from raw RDAP JSON using library extractors via lookup_domain logic.
    // For simplicity, we defer to creating a minimal struct here; a deeper extraction
    // would call the library's private helpers — keeping it decoupled.
    whois_rdap::RdapDomainResult {
        handle: raw.get("ldhName").or_else(|| raw.get("handle"))
            .and_then(|v| v.as_str()).unwrap_or(domain).to_owned(),
        organization: None,
        registrar: None,
        country_code: None,
        nameservers: Vec::new(),
        status: Vec::new(),
        raw,
    }
}

fn rebuild_asn_result_from_cache(asn: u32, cached: &serde_json::Value) -> whois_rdap::RdapAsnResult {
    whois_rdap::RdapAsnResult {
        asn,
        organization: cached.get("organization").and_then(|v| v.as_str()).map(str::to_owned),
        country_code: cached.get("country_code").and_then(|v| v.as_str()).map(str::to_owned),
        range: extract_cached_asn_range(cached),
        raw: cached.clone(),
    }
}

// ── Print helpers ──────────────────────────────────────────────────────────

fn print_ip_result<W: Write>(
    w: &mut W,
    ip: IpAddr,
    server: &str,
    res: &whois_rdap::RdapResult,
    as_json: bool,
) -> Result<()> {
    if as_json {
        let out = serde_json::json!({
            "ip": ip.to_string(),
            "rdap_server": server,
            "organization": res.organization,
            "country_code": res.country_code,
            "as_number": res.as_number.map(|n| format!("AS{n}")),
            "cidrs": res.cidrs,
            "range": res.range.as_ref().map(|(s, e)| serde_json::json!({"start": s, "end": e})),
        });
        serde_json::to_writer(&mut *w, &out)?;
        writeln!(w)?;
    } else {
        writeln!(w, "IP:           {}", ip)?;
        writeln!(w, "RDAP Server:  {}", server)?;
        writeln!(w, "Organization: {}", res.organization.as_deref().unwrap_or("Unknown"))?;
        if let Some(ref cc) = res.country_code { writeln!(w, "Country Code: {}", cc)?; }
        if let Some(n) = res.as_number { writeln!(w, "AS Number:    AS{}", n)?; }
        if !res.cidrs.is_empty() { writeln!(w, "CIDR(s):      {}", res.cidrs.join(", "))?; }
        if let Some((ref s, ref e)) = res.range { writeln!(w, "Range:        {} - {}", s, e)?; }
        if res.cidrs.is_empty() && res.range.is_none() {
            writeln!(w, "CIDR/Range:   Not found in RDAP response")?;
        }
    }
    Ok(())
}

fn print_domain_result<W: Write>(
    w: &mut W,
    server: &str,
    res: &whois_rdap::RdapDomainResult,
    as_json: bool,
) -> Result<()> {
    if as_json {
        let out = serde_json::json!({
            "domain": res.handle,
            "rdap_server": server,
            "organization": res.organization,
            "registrar": res.registrar,
            "country_code": res.country_code,
            "nameservers": res.nameservers,
            "status": res.status,
        });
        serde_json::to_writer(&mut *w, &out)?;
        writeln!(w)?;
    } else {
        writeln!(w, "Domain:       {}", res.handle)?;
        writeln!(w, "RDAP Server:  {}", server)?;
        writeln!(w, "Organization: {}", res.organization.as_deref().unwrap_or("Unknown"))?;
        if let Some(ref r) = res.registrar { writeln!(w, "Registrar:    {}", r)?; }
        if let Some(ref cc) = res.country_code { writeln!(w, "Country Code: {}", cc)?; }
        if !res.nameservers.is_empty() {
            writeln!(w, "Name Servers: {}", res.nameservers.join(", "))?;
        }
        if !res.status.is_empty() {
            writeln!(w, "Status:       {}", res.status.join(", "))?;
        }
    }
    Ok(())
}

fn print_asn_result<W: Write>(
    w: &mut W,
    server: &str,
    res: &whois_rdap::RdapAsnResult,
    as_json: bool,
) -> Result<()> {
    if as_json {
        let out = serde_json::json!({
            "asn": format!("AS{}", res.asn),
            "rdap_server": server,
            "organization": res.organization,
            "country_code": res.country_code,
            "range": res.range.map(|(s, e)| serde_json::json!({"start": s, "end": e})),
        });
        serde_json::to_writer(&mut *w, &out)?;
        writeln!(w)?;
    } else {
        writeln!(w, "ASN:          AS{}", res.asn)?;
        writeln!(w, "RDAP Server:  {}", server)?;
        writeln!(w, "Organization: {}", res.organization.as_deref().unwrap_or("Unknown"))?;
        if let Some(ref cc) = res.country_code { writeln!(w, "Country Code: {}", cc)?; }
        if let Some((s, e)) = res.range {
            if s == e {
                writeln!(w, "AS Number:    AS{}", s)?;
            } else {
                writeln!(w, "AS Range:     AS{} - AS{}", s, e)?;
            }
        }
    }
    Ok(())
}

fn handle_error(e: anyhow::Error) -> Result<()> {
    eprintln!("Error: {e}");
    eprintln!("Tip: If the target belongs to another registry/RIR, try one of:");
    for (reg, label, base) in RdapRegistry::all() {
        eprintln!(
            "  --rir {:<8} ({:<16}) {}",
            format!("{:?}", reg).to_lowercase(),
            label,
            base
        );
    }
    std::process::exit(1);
}

fn print_servers() {
    println!("Known RDAP servers:");
    for (reg, label, base) in RdapRegistry::all() {
        println!(
            "  {:<8}  {:<18}  {}",
            format!("{:?}", reg).to_lowercase(),
            format!("({})", label),
            base
        );
    }
    println!();
    println!("Use one with:  whois-rdap --rir <name> <QUERY>");
    println!("Or provide a custom server:  whois-rdap --server <URL> <QUERY>");
}
