// A command-line tool to query RDAP servers for IP, Domain, and ASN information.
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::{ArgGroup, Parser, ValueHint};

use std::net::IpAddr;
use std::time::Duration;
use whois_rdap::{RdapClient, RdapRegistry};

/// RDAP whois-like client: returns registration details for an IP, Domain, or ASN.
#[derive(Parser, Debug)]
#[command(name = "rdap-whois", version, author, about)]
#[command(group(
    ArgGroup::new("server_choice")
        .args(&["rir", "server"])
        .multiple(false)
))]
struct Args {
    /// IP address, Domain name, or AS number to look up (e.g. 8.8.8.8, google.com, or AS15169)
    #[arg(value_hint = ValueHint::Other)]
    query: String,

    /// Pick a known RDAP server (RIR/Registry) from a curated list.
    ///
    /// Values: ripe, arin, apnic, lacnic, afrinic, iana
    #[arg(long)]
    rir: Option<RdapRegistry>,

    /// Use a custom RDAP server base URL (overrides --rir).
    /// Example: https://rdap.arin.net/rdap
    #[arg(long, value_hint = ValueHint::Url)]
    server: Option<String>,

    /// List all known servers and exit.
    #[arg(long, action)]
    list_servers: bool,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Print successful lookup output as a compact JSON string.
    #[arg(long, action)]
    json: bool,
}

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
    let digits = if trimmed.to_ascii_uppercase().starts_with("AS") {
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
    let digits = if trimmed.to_ascii_uppercase().starts_with("AS") {
        &trimmed[2..]
    } else {
        trimmed
    };
    digits
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid AS number: '{}'", query))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_servers {
        print_servers();
        return Ok(());
    }

    let query_type = detect_query_type(&args.query);

    // Decide which base URL to use, and remember it as a string for printing
    let base_url = if let Some(custom) = args.server.as_deref() {
        custom.to_string()
    } else if let Some(reg) = args.rir {
        reg.base_url().to_string()
    } else {
        // Dynamic default: use IANA for domains/ASNs (to support redirects), RIPE for IPs
        let default_rir = match query_type {
            QueryType::Ip => RdapRegistry::RIPE,
            QueryType::Domain | QueryType::Asn => RdapRegistry::IANA,
        };
        default_rir.base_url().to_string()
    };

    let timeout = Duration::from_secs(args.timeout);
    let client = RdapClient::for_custom(&base_url, timeout)?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    use std::io::Write;

    match query_type {
        QueryType::Ip => {
            let ip: IpAddr = args
                .query
                .parse()
                .map_err(|_| anyhow!("Invalid IP address: {}", args.query))?;

            match client.lookup_ip(ip).await {
                Ok(res) => {
                    if args.json {
                        let range = res.range.map(|(start, end)| AddrRange { start, end });
                        let as_number = res.as_number.map(|num| format!("AS{}", num));
                        let out = JsonResponseIp {
                            ip: ip.to_string(),
                            rdap_server: base_url,
                            organization: res.organization.unwrap_or_else(|| "Unknown".to_string()),
                            country_code: res.country_code,
                            as_number,
                            cidrs: res.cidrs,
                            range,
                        };
                        serde_json::to_writer(&mut handle, &out)?;
                        writeln!(handle)?;
                    } else {
                        writeln!(handle, "IP: {}", ip)?;
                        writeln!(handle, "RDAP Server: {}", base_url)?;
                        writeln!(
                            handle,
                            "Organization: {}",
                            res.organization.as_deref().unwrap_or("Unknown")
                        )?;

                        if let Some(country_code) = res.country_code {
                            writeln!(handle, "Country Code: {}", country_code)?;
                        }

                        if let Some(as_num) = res.as_number {
                            writeln!(handle, "AS Number: AS{}", as_num)?;
                        }

                        if !res.cidrs.is_empty() {
                            writeln!(handle, "CIDR(s): {}", res.cidrs.join(", "))?;
                        }
                        if let Some((ref start, ref end)) = res.range {
                            writeln!(handle, "Range: {} - {}", start, end)?;
                        }
                        if res.cidrs.is_empty() && res.range.is_none() {
                            writeln!(handle, "CIDR/Range: Not found in RDAP response")?;
                        }
                    }
                }
                Err(e) => return handle_error(e),
            }
        }
        QueryType::Domain => {
            match client.lookup_domain(&args.query).await {
                Ok(res) => {
                    if args.json {
                        let out = JsonResponseDomain {
                            domain: res.handle,
                            rdap_server: base_url,
                            organization: res.organization.unwrap_or_else(|| "Unknown".to_string()),
                            registrar: res.registrar,
                            country_code: res.country_code,
                            nameservers: res.nameservers,
                            status: res.status,
                        };
                        serde_json::to_writer(&mut handle, &out)?;
                        writeln!(handle)?;
                    } else {
                        writeln!(handle, "Domain: {}", res.handle)?;
                        writeln!(handle, "RDAP Server: {}", base_url)?;
                        writeln!(
                            handle,
                            "Organization: {}",
                            res.organization.as_deref().unwrap_or("Unknown")
                        )?;

                        if let Some(registrar) = res.registrar {
                            writeln!(handle, "Registrar: {}", registrar)?;
                        }

                        if let Some(country_code) = res.country_code {
                            writeln!(handle, "Country Code: {}", country_code)?;
                        }

                        if !res.nameservers.is_empty() {
                            writeln!(handle, "Name Server(s): {}", res.nameservers.join(", "))?;
                        }

                        if !res.status.is_empty() {
                            writeln!(handle, "Status: {}", res.status.join(", "))?;
                        }
                    }
                }
                Err(e) => return handle_error(e),
            }
        }
        QueryType::Asn => {
            let asn = parse_query_asn(&args.query)?;
            match client.lookup_asn(asn).await {
                Ok(res) => {
                    if args.json {
                        let range = res.range.map(|(start, end)| AsnRange { start, end });
                        let out = JsonResponseAsn {
                            asn: format!("AS{}", res.asn),
                            rdap_server: base_url,
                            organization: res.organization.unwrap_or_else(|| "Unknown".to_string()),
                            country_code: res.country_code,
                            range,
                        };
                        serde_json::to_writer(&mut handle, &out)?;
                        writeln!(handle)?;
                    } else {
                        writeln!(handle, "ASN: AS{}", res.asn)?;
                        writeln!(handle, "RDAP Server: {}", base_url)?;
                        writeln!(
                            handle,
                            "Organization: {}",
                            res.organization.as_deref().unwrap_or("Unknown")
                        )?;

                        if let Some(country_code) = res.country_code {
                            writeln!(handle, "Country Code: {}", country_code)?;
                        }

                        if let Some((start, end)) = res.range {
                            if start == end {
                                writeln!(handle, "AS Number: AS{}", start)?;
                            } else {
                                writeln!(handle, "AS Range: AS{} - AS{}", start, end)?;
                            }
                        }
                    }
                }
                Err(e) => return handle_error(e),
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
    println!("Use one with:  rdap-whois --rir <name> <Query>");
    println!("Or provide a custom server with:  rdap-whois --server <URL> <Query>");
}

#[derive(serde::Serialize)]
struct JsonResponseIp {
    ip: String,
    rdap_server: String,
    organization: String,
    country_code: Option<String>,
    as_number: Option<String>,
    cidrs: Vec<String>,
    range: Option<AddrRange>,
}

#[derive(serde::Serialize)]
struct JsonResponseDomain {
    domain: String,
    rdap_server: String,
    organization: String,
    registrar: Option<String>,
    country_code: Option<String>,
    nameservers: Vec<String>,
    status: Vec<String>,
}

#[derive(serde::Serialize)]
struct JsonResponseAsn {
    asn: String,
    rdap_server: String,
    organization: String,
    country_code: Option<String>,
    range: Option<AsnRange>,
}

#[derive(serde::Serialize)]
struct AddrRange {
    start: String,
    end: String,
}

#[derive(serde::Serialize)]
struct AsnRange {
    start: u32,
    end: u32,
}
