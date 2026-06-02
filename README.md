# RDAP Whois Client

A simple command-line tool to query RDAP servers for IP address information. This is a Rust-based alternative to the traditional `whois` command, providing more structured information like organization, CIDR, and AS number.

## Features

- Look up IPv4 and IPv6 addresses.
- Choose from a list of well-known RDAP servers (RIRs).
- Use a custom RDAP server URL.
- Timeout configuration.
- Lists known RDAP servers.

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
rdap-whois [OPTIONS] <IP>
```

### Examples

-   Look up an IP with the default RIR (RIPE):
    ```sh
    ./target/release/whois-rdap 8.8.8.8
    ```

-   Look up an IP using a specific RIR:
    ```sh
    ./target/release/whois-rdap --rir arin 2606:4700:4700::1111
    ```

-   Use a custom RDAP server:
    ```sh
    ./target/release/whois-rdap --server https://rdap.example.com/rdap 192.0.2.1
    ```

-   List all known servers:
    ```sh
    ./target/release/whois-rdap --list-servers
    ```

-   Print a successful lookup as a compact JSON string:
    ```sh
    ./target/release/whois-rdap --json 8.8.8.8
    ```

### Options

-   `<IP>`: The IPv4 or IPv6 address to look up.
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
whois-rdap = { path = "." } # Or version "0.1.1" when published
tokio = { version = "1", features = ["full"] }
```

### Programmatic Example

```rust
use whois_rdap::{RdapClient, RdapRegistry};
use std::time::Duration;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Construct a client. RdapClient is thread-safe (Send + Sync)
    // and is designed to be cloned and reused across tasks.
    let client = RdapClient::for_registry(RdapRegistry::ARIN, Duration::from_secs(10))?;

    let ip: IpAddr = "8.8.8.8".parse()?;
    let res = client.lookup_ip(ip).await?;

    println!("Organization: {}", res.organization.unwrap_or_default());
    println!("CIDRs: {:?}", res.cidrs);
    if let Some((start, end)) = res.range {
        println!("IP Range: {} - {}", start, end);
    }
    
    Ok(())
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

