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

### Options

-   `<IP>`: The IPv4 or IPv6 address to look up.
-   `--rir <RIR>`: Pick a known RDAP server. (e.g., `ripe`, `arin`, `apnic`, `lacnic`, `afrinic`, `iana`)
-   `--server <URL>`: Use a custom RDAP server base URL.
-   `--list-servers`: List all known servers and exit.
-   `--timeout <SECONDS>`: Request timeout in seconds (default: 15).
-   `-h, --help`: Print help information.
-   `-V, --version`: Print version information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
