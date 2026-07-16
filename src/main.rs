// A command-line tool to query RDAP servers for IP, Domain, and ASN information.
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::Result;
use clap::{ArgGroup, Parser, ValueHint};

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use whois_rdap::{
    QueryTarget, RdapClient, RdapRegistry, build_reqwest_client,
    bulk::{bulk_lookup, read_targets_file},
    cache::{Cache, key_asn, key_domain, key_ip},
    classify_query,
    redirect::follow_links,
    resolve_base_url,
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

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
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
        let boot_http = build_reqwest_client(timeout)?;
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
        let http = build_reqwest_client(timeout)?;
        let ctx = Arc::new(whois_rdap::bulk::BulkContext {
            http,
            cache,
            bootstrap: bootstrap_map,
            timeout,
            max_redirects: args.max_redirects.min(3),
            cache_ttl_ip: args.cache_ttl_ip,
            cache_ttl_domain: args.cache_ttl_domain,
            cache_ttl_asn: args.cache_ttl_asn,
            server: args.server.clone(),
            rir: args.rir,
            active_queries: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let mut writer = stdout.lock();
        bulk_lookup(ctx, targets.into_iter(), args.concurrency, &mut writer).await?;
        return Ok(());
    }

    // ── Single query ───────────────────────────────────────────────────────
    let query = &targets[0];
    let target = classify_query(query);
    let base_url = resolve_base_url(
        &target,
        args.server.as_deref(),
        args.rir,
        bootstrap_map.as_deref(),
    );
    let client = RdapClient::for_custom(&base_url, timeout)?;
    let max_redirects = args.max_redirects.min(3);

    let mut handle = stdout.lock();

    match target {
        QueryTarget::Ip(ip) => {
            let cache_key = key_ip(&ip);
            let ttl = args.cache_ttl_ip;

            // Cache read — range-aware: any IP within a previously cached
            // RDAP allocation (e.g. 20.33.0.0–20.128.255.255) hits here
            // without a network round-trip, even for a different IP in that range.
            if let Some(ref c) = cache
                && let Ok(Some(cached)) = c.get_ip(ip)
            {
                let res = whois_rdap::parse_ip_response(cached);
                print_ip_result(&mut handle, ip, &base_url, &res, args.json)?;
                return Ok(());
            }

            match client.lookup_ip(ip).await {
                Ok(res) => {
                    // Optionally follow RDAP links for richer data.
                    // If follow_links returns a different JSON, re-extract.
                    // If unchanged (no useful link found), keep the already-
                    // extracted res — do NOT rebuild from raw.
                    let followed =
                        follow_links(client.http_client(), res.raw.clone(), max_redirects).await;
                    let res = if followed != res.raw {
                        whois_rdap::parse_ip_response(followed)
                    } else {
                        res
                    };

                    // Store range bounds so future lookups for any IP in the
                    // same allocation are served from cache (no network call).
                    if let Some(ref c) = cache {
                        let range_bounds = res.range.as_ref().and_then(|(s, e)| {
                            Some((s.parse::<IpAddr>().ok()?, e.parse::<IpAddr>().ok()?))
                        });
                        c.insert_ip_background(cache_key, &res.raw, range_bounds, ttl);
                    }
                    print_ip_result(&mut handle, ip, &base_url, &res, args.json)?;
                }
                Err(e) => return handle_error(e),
            }
        }

        QueryTarget::Domain(domain) => {
            let cache_key = key_domain(&domain);
            let ttl = args.cache_ttl_domain;

            if let Some(ref c) = cache
                && let Ok(Some(cached)) = c.get(&cache_key)
            {
                let res = whois_rdap::parse_domain_response(&domain, cached);
                print_domain_result(&mut handle, &base_url, &res, args.json)?;
                return Ok(());
            }

            match client.lookup_domain(&domain).await {
                Ok(res) => {
                    let followed =
                        follow_links(client.http_client(), res.raw.clone(), max_redirects).await;
                    let res = if followed != res.raw {
                        whois_rdap::parse_domain_response(&domain, followed)
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

        QueryTarget::Asn(asn) => {
            let cache_key = key_asn(asn);
            let ttl = args.cache_ttl_asn;

            if let Some(ref c) = cache
                && let Ok(Some(cached)) = c.get(&cache_key)
            {
                let res = whois_rdap::parse_asn_response(asn, cached);
                print_asn_result(&mut handle, &base_url, &res, args.json)?;
                return Ok(());
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
            "organization": res.organization.as_deref().unwrap_or("Unknown"),
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
        writeln!(
            w,
            "Organization: {}",
            res.organization.as_deref().unwrap_or("Unknown")
        )?;
        if let Some(ref cc) = res.country_code {
            writeln!(w, "Country Code: {}", cc)?;
        }
        if let Some(n) = res.as_number {
            writeln!(w, "AS Number:    AS{}", n)?;
        }
        if !res.cidrs.is_empty() {
            writeln!(w, "CIDR(s):      {}", res.cidrs.join(", "))?;
        }
        if let Some((ref s, ref e)) = res.range {
            writeln!(w, "Range:        {} - {}", s, e)?;
        }
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
            "organization": res.organization.as_deref().unwrap_or("Unknown"),
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
        writeln!(
            w,
            "Organization: {}",
            res.organization.as_deref().unwrap_or("Unknown")
        )?;
        if let Some(ref r) = res.registrar {
            writeln!(w, "Registrar:    {}", r)?;
        }
        if let Some(ref cc) = res.country_code {
            writeln!(w, "Country Code: {}", cc)?;
        }
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
            "organization": res.organization.as_deref().unwrap_or("Unknown"),
            "country_code": res.country_code,
            "range": res.range.map(|(s, e)| serde_json::json!({"start": s, "end": e})),
        });
        serde_json::to_writer(&mut *w, &out)?;
        writeln!(w)?;
    } else {
        writeln!(w, "ASN:          AS{}", res.asn)?;
        writeln!(w, "RDAP Server:  {}", server)?;
        writeln!(
            w,
            "Organization: {}",
            res.organization.as_deref().unwrap_or("Unknown")
        )?;
        if let Some(ref cc) = res.country_code {
            writeln!(w, "Country Code: {}", cc)?;
        }
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
