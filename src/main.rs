// A simple command-line tool to query RDAP servers for IP address information.
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::{ArgGroup, Parser, ValueHint};

use std::net::IpAddr;
use std::time::Duration;
use whois_rdap::{RdapClient, RdapRegistry};

/// RDAP whois-like client: returns organization and CIDR/range for an IP.
#[derive(Parser, Debug)]
#[command(name = "rdap-whois", version, author, about)]
#[command(group(
    ArgGroup::new("server_choice")
        .args(&["rir", "server"])
        .multiple(false)
))]
struct Args {
    /// IPv4 or IPv6 address to look up (e.g., 193.0.0.1 or 2001:67c:2e8::1)
    #[arg(value_hint = ValueHint::Other)]
    ip: String,

    /// Pick a known RDAP server (RIR) from a curated list.
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_servers {
        print_servers();
        return Ok(());
    }

    // Parse IP early for better error messages
    let ip: IpAddr = args
        .ip
        .parse()
        .map_err(|_| anyhow!("Invalid IP address: {}", args.ip))?;

    // Decide which base URL to use, and remember it as a string for printing
    let base_url = if let Some(custom) = args.server.as_deref() {
        custom.to_string()
    } else if let Some(reg) = args.rir {
        reg.base_url().to_string() // <- uses RdapRegistry::base_url()
    } else {
        RdapRegistry::RIPE.base_url().to_string()
    };

    let timeout = Duration::from_secs(args.timeout);
    let client = RdapClient::for_custom(&base_url, timeout)?;

    // Perform lookup
    match client.lookup_ip(ip).await {
        Ok(res) => {
            use std::io::Write;
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();

            if args.json {
                let range = res.range.map(|(start, end)| AddrRange { start, end });
                let as_number = res.as_number.map(|num| format!("AS{}", num));
                let out = JsonResponse {
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
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Tip: If the IP belongs to another RIR, try one of:");
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
    }

    Ok(())
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
    println!("Use one with:  rdap-whois --rir <name> <IP>");
    println!("Or provide a custom server with:  rdap-whois --server <URL> <IP>");
}

#[derive(serde::Serialize)]
struct JsonResponse {
    ip: String,
    rdap_server: String,
    organization: String,
    country_code: Option<String>,
    as_number: Option<String>,
    cidrs: Vec<String>,
    range: Option<AddrRange>,
}

#[derive(serde::Serialize)]
struct AddrRange {
    start: String,
    end: String,
}
