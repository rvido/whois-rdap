// A simple command-line tool to query RDAP servers for IP address information.
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::{ArgGroup, Parser, ValueHint};
use serde_json::{Map, Value};
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
            if args.json {
                let mut out = Map::new();
                out.insert("ip".to_string(), Value::String(ip.to_string()));
                out.insert("rdap_server".to_string(), Value::String(base_url));
                out.insert(
                    "organization".to_string(),
                    Value::String(res.organization.unwrap_or_else(|| "Unknown".to_string())),
                );

                if let Some(country_code) = res.country_code {
                    out.insert("country_code".to_string(), Value::String(country_code));
                }

                if let Some(as_num) = res.as_number {
                    out.insert("as_number".to_string(), Value::String(format!("AS{}", as_num)));
                }

                if !res.cidrs.is_empty() {
                    out.insert(
                        "cidrs".to_string(),
                        Value::String(res.cidrs.join(", ")),
                    );
                }

                if let Some((start, end)) = res.range {
                    out.insert("range".to_string(), Value::String(format!("{} - {}", start, end)));
                }

                if !out.contains_key("cidrs") && !out.contains_key("range") {
                    out.insert(
                        "cidr_range".to_string(),
                        Value::String("Not found in RDAP response".to_string()),
                    );
                }

                println!("{}", serde_json::to_string(&out)?);
            } else {
                println!("IP: {}", ip);
                println!("RDAP Server: {}", base_url); // <- print the string, not the client
                println!(
                    "Organization: {}",
                    res.organization.as_deref().unwrap_or("Unknown")
                );

                if let Some(country_code) = res.country_code {
                    println!("Country Code: {}", country_code);
                }

                if let Some(as_num) = res.as_number {
                    println!("AS Number: AS{}", as_num);
                }

                if !res.cidrs.is_empty() {
                    println!("CIDR(s): {}", res.cidrs.join(", "));
                }
                if let Some((ref start, ref end)) = res.range {
                    println!("Range: {} - {}", start, end);
                }
                if res.cidrs.is_empty() && res.range.is_none() {
                    println!("CIDR/Range: Not found in RDAP response");
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
