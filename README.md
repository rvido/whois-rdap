# RDAP Whois Client

A fast, production-ready command-line tool and Rust library for querying RDAP servers for IP address, Domain name, and Autonomous System Number (ASN) information. Built with zero-copy JSON parsing, IANA bootstrap routing, local SQLite caching, and parallel bulk lookups.

## Features

- **Auto-detect** query type: IP, Domain, or ASN
- **IANA Bootstrap Triage** — auto-routes to the correct RIR/registry using IANA bootstrap maps (no manual `--rir` needed). Maps are cached on disk for 24 hours (per RFC 9224).
- **SQLite Result Cache** — avoids redundant network lookups with configurable TTLs:
  - IP results: **24 hours** (RIR allocations are very stable)
  - Domain results: **8 hours** (domain records change infrequently)
  - ASN results: **24 hours** (AS assignments are nearly permanent)
- **Smart Redirect Following** — traverses RDAP `links` arrays to follow sub-registry pointers for richer results (e.g., IANA → Verisign for `.com` domains)
- **Parallel Bulk Lookup** — process thousands of targets from a file or stdin with bounded concurrency (`--file`, `--concurrency`)
- **IPv4 and IPv6** support
- **JSON output** (compact, or NDJSON in bulk mode)
- **Custom RIR/server** override
- **Connection pooling** and **TLS reuse** via `reqwest` + `ring` (lightweight, no aws-lc-sys)
- Zero-copy JSON traversal — parsed fields are borrowed from the response buffer

## Installation

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable, 1.80+)

### Build from source

```sh
git clone <repository-url>
cd whois-rdap
cargo build --release
```

The executable is at `target/release/whois-rdap`.

## Usage

```
whois-rdap [OPTIONS] [QUERY]...
```

Query type is auto-detected:

| Input | Type |
|---|---|
| `8.8.8.8` | IPv4 |
| `2001:4860::1` | IPv6 |
| `AS15169` or `15169` | ASN |
| `google.com` | Domain |

### Examples

```sh
# Single IP (auto-routed via IANA bootstrap to the correct RIR)
whois-rdap 8.8.8.8

# Single domain
whois-rdap google.com

# Single ASN
whois-rdap AS15169

# Force a specific RIR
whois-rdap --rir arin 8.8.8.8

# Custom server URL
whois-rdap --server https://rdap.verisign.com/com/v1 google.com

# JSON output
whois-rdap --json 8.8.8.8

# Bulk lookup from a file (8 concurrent, NDJSON output)
whois-rdap --file targets.txt

# Bulk lookup from stdin
echo -e "8.8.8.8\nAS15169\ngoogle.com" | whois-rdap --file -

# Bump concurrency for faster bulk processing
whois-rdap --file big_list.txt --concurrency 16

# Skip cache for a fresh result
whois-rdap --no-cache 8.8.8.8

# Force refresh IANA bootstrap maps
whois-rdap --refresh-bootstrap 8.8.8.8

# List all known servers
whois-rdap --list-servers
```

### All Options

| Flag | Default | Description |
|---|---|---|
| `[QUERY]...` | — | One or more targets (IP, domain, ASN) |
| `--file <PATH>` | — | Read targets from file (use `-` for stdin) |
| `--concurrency <N>` | `8` | Max concurrent lookups in bulk mode |
| `--rir <NAME>` | — | Use a known registry: `ripe`, `arin`, `apnic`, `lacnic`, `afrinic`, `iana` |
| `--server <URL>` | — | Custom RDAP server base URL |
| `--timeout <SECS>` | `15` | Request timeout per lookup |
| `--json` | — | Compact JSON output (NDJSON in bulk mode) |
| `--no-cache` | — | Skip SQLite cache read/write |
| `--cache-ttl-ip <SECS>` | `86400` | Cache TTL for IP results (24 h) |
| `--cache-ttl-domain <SECS>` | `28800` | Cache TTL for domain results (8 h) |
| `--cache-ttl-asn <SECS>` | `86400` | Cache TTL for ASN results (24 h) |
| `--no-bootstrap` | — | Skip IANA bootstrap triage |
| `--refresh-bootstrap` | — | Re-download IANA bootstrap maps now |
| `--max-redirects <N>` | `1` | Max RDAP link hops to follow (0–3) |
| `--list-servers` | — | List all known servers and exit |

### Cache Location

Results are cached at `$XDG_CACHE_HOME/whois-rdap/cache.db` (usually `~/.cache/whois-rdap/cache.db`).

Bootstrap maps are stored at `$XDG_CACHE_HOME/whois-rdap/bootstrap/`.

## Library Usage

`whois-rdap` is also a high-performance async-native Rust library. `RdapClient` is `Send + Sync` and designed to be shared across tasks.

```toml
[dependencies]
whois-rdap = { path = "." }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Programmatic Example

```rust
use std::sync::Arc;
use std::time::Duration;
use whois_rdap::{RdapClient, RdapRegistry};
use whois_rdap::cache::{Cache, key_ip, DEFAULT_TTL_IP_SECS};
use whois_rdap::bulk::bulk_lookup;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Single lookup ─────────────────────────────────────────────────────
    let client = RdapClient::for_registry(RdapRegistry::IANA, Duration::from_secs(10))?;

    let ip_res = client.lookup_ip("8.8.8.8".parse()?).await?;
    println!("IP Org: {}", ip_res.organization.unwrap_or_default());

    let domain_client = RdapClient::for_custom(
        "https://rdap.verisign.com/com/v1",
        Duration::from_secs(5),
    )?;
    let domain_res = domain_client.lookup_domain("google.com").await?;
    println!("Registrar: {}", domain_res.registrar.unwrap_or_default());

    let asn_res = client.lookup_asn(15169).await?;
    println!("ASN Org: {}", asn_res.organization.unwrap_or_default());

    // ── Cache ─────────────────────────────────────────────────────────────
    let cache = Cache::open()?;
    let ip: std::net::IpAddr = "8.8.8.8".parse()?;
    if let Some(cached) = cache.get(&key_ip(&ip))? {
        println!("(from cache) org: {}", cached["organization"]);
    }

    // ── Bulk parallel lookup ──────────────────────────────────────────────
    let shared_client = Arc::new(RdapClient::for_registry(RdapRegistry::RIPE, Duration::from_secs(10))?);
    let targets = vec!["8.8.8.8".to_string(), "AS15169".to_string(), "google.com".to_string()];
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    bulk_lookup(shared_client, targets.into_iter(), 4, &mut out).await?;

    Ok(())
}
```

## Architecture

```
src/
  lib.rs        — public API: RdapClient, result types, JSON extractors
  bootstrap.rs  — IANA bootstrap routing (IPv4/IPv6/ASN prefix tables)
  cache.rs      — SQLite TTL cache (WAL, zero-copy read path)
  redirect.rs   — RDAP link follower (rel=related hop chasing)
  bulk.rs       — parallel bulk executor (buffer_unordered)
  main.rs       — CLI wiring
```

### Hot-path (single lookup)

```
query → bootstrap triage (O(log N), zero alloc)
      → SQLite cache read (single indexed SELECT, zero-copy BLOB parse)
          HIT → return immediately
          MISS → HTTP GET (connection pool reuse)
              → redirect follow (optional, 1 hop default)
              → SQLite write (spawn_blocking, non-blocking to caller)
              → return result
```

### Memory footprint at 8× concurrency

| Component | Heap |
|---|---|
| Bootstrap map | < 200 KB |
| SQLite page cache | ≤ 1 MB |
| 8× in-flight responses | ~400 KB |
| **Total** | **< 2 MB** |

## License

MIT License — see [LICENSE](LICENSE) for details.
