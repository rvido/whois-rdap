# RDAP Whois Client

A simple command-line tool and library to query RDAP servers for IP address, Domain name, and Autonomous System Number (ASN) information. This is a Rust-based alternative to the traditional `whois` command, providing structured information like organization, CIDR, registrar, name servers, and ranges.

## Features

- Look up IPv4 and IPv6 addresses.
- Look up Domain Names (e.g., `google.com`).
- Look up Autonomous System Numbers (e.g., `AS15169` or `15169`).
- Auto-detect query types (IP, Domain, or ASN) based on the query input.
- Choose from a list of well-known RDAP servers (RIRs/Registries) or use a custom URL.
- Support dynamic default bootstrap registries (`iana` for domains and ASNs, `ripe` for IPs).
- Timeout configuration.
- Lists known RDAP servers.
- JSON output support.

## Installation

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)

### Building from source

1.  Clone the repository:
    ```sh
    git clone <repository-url>
    cd whois-rdap
    ```

2.  Build the project:
    ```sh
    cargo build --release
    ```
    The executable will be in `target/release/whois-rdap`.

## Usage

```
whois-rdap [OPTIONS] <QUERY>
```

### Examples

-   Look up an IP with the default registry (`RIPE`):
    ```sh
    ./target/release/whois-rdap 8.8.8.8
    ```

-   Look up an ASN using the dynamic default bootstrap registry (`IANA`):
    ```sh
    ./target/release/whois-rdap AS15169
    ```

-   Look up a domain using a custom registry (e.g., Verisign for `.com` domains):
    ```sh
    ./target/release/whois-rdap --server https://rdap.verisign.com/com/v1 google.com
    ```

-   Look up an IP using a specific RIR:
    ```sh
    ./target/release/whois-rdap --rir arin 2606:4700:4700::1111
    ```

-   List all known servers:
    ```sh
    ./target/release/whois-rdap --list-servers
    ```

-   Print a domain lookup as a compact JSON string:
    ```sh
    ./target/release/whois-rdap --server https://rdap.verisign.com/com/v1 --json google.com
    ```

### Options

-   `<QUERY>`: The IP address, domain name, or AS number to look up.
-   `--rir <RIR>`: Pick a known RDAP server. (e.g., `ripe`, `arin`, `apnic`, `lacnic`, `afrinic`, `iana`)
-   `--server <URL>`: Use a custom RDAP server base URL.
-   `--list-servers`: List all known servers and exit.
-   `--json`: Print successful lookup output as a compact JSON string.
-   `--timeout <SECONDS>`: Request timeout in seconds (default: 15).
-   `-h, --help`: Print help information.
-   `-V, --version`: Print version information.

## Library Usage

`whois-rdap` can also be used as a high-performance, async-native Rust library. The core `RdapClient` is designed for production workloads, implementing zero-allocation parsing passes during JSON traversal and safe internal connection pooling.

Add to your `Cargo.toml`:
```toml
[dependencies]
whois-rdap = { path = "." } # Or version "0.2.0" when published
tokio = { version = "1", features = ["full"] }
```

### Programmatic Example

```rust
use whois_rdap::{RdapClient, RdapRegistry};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Construct a client. RdapClient is thread-safe (Send + Sync)
    // and is designed to be cloned and reused across tasks.
    let client = RdapClient::for_registry(RdapRegistry::IANA, Duration::from_secs(10))?;

    // 1. IP Lookup
    let ip_res = client.lookup_ip("8.8.8.8".parse()?).await?;
    println!("IP Org: {}", ip_res.organization.unwrap_or_default());

    // 2. Domain Lookup
    // Querying .com registry directly (requires registry specific server URL)
    let domain_client = RdapClient::for_custom("https://rdap.verisign.com/com/v1", Duration::from_secs(5))?;
    let domain_res = domain_client.lookup_domain("google.com").await?;
    println!("Domain Registrar: {}", domain_res.registrar.unwrap_or_default());
    println!("Name Servers: {:?}", domain_res.nameservers);

    // 3. ASN Lookup
    let asn_client = RdapClient::for_custom("https://rdap.arin.net/bootstrap", Duration::from_secs(5))?;
    let asn_res = asn_client.lookup_asn(15169).await?;
    println!("ASN Org: {}", asn_res.organization.unwrap_or_default());
    
    Ok(())
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
