# whois-rdap

A fast, production-ready command-line tool and Rust library for querying RDAP
(Registration Data Access Protocol) servers for IP address, Domain, and
Autonomous System Number (ASN) information.

Built for correctness and scale: IANA bootstrap routing, persistent SQLite
result cache, smart redirect following, and parallel bulk lookups — all with a
< 2 MB memory footprint at full concurrency.

---

## Features

| Feature | Description |
|---|---|
| **Auto-detect** | Query type is inferred from the input (IP / Domain / ASN) |
| **Bootstrap triage** | Routes automatically to the correct RIR via IANA bootstrap maps (RFC 9224) |
| **SQLite cache** | Avoids redundant lookups; TTL-based expiry per query type |
| **Redirect following** | Chases RDAP `links` for richer sub-registry data |
| **Parallel bulk** | Process thousands of targets from a file or stdin (bounded concurrency) |
| **IPv4 & IPv6** | Full dual-stack support |
| **JSON / NDJSON** | Compact JSON output for single queries; NDJSON stream for bulk |
| **Lightweight TLS** | Uses `ring` (pure Rust, ~200 KB) instead of `aws-lc-sys` (~1.2 MB) |
| **Zero-copy reads** | Cache hit path: SQLite BLOB → `serde_json::from_slice` (no `String` copy) |

---

## Installation

### Requirements

- [Rust](https://www.rust-lang.org/tools/install) stable 1.80+
- No system dependencies (SQLite is compiled from source via `rusqlite/bundled`)

### Build from source

```sh
git clone <repository-url>
cd whois-rdap

# Quick build (debug)
make debug

# Optimised release binary (LTO, stripped, size-optimised)
make release
```

The release binary is at `target/release/whois-rdap`.

### Install to `~/.local/bin`

```sh
make install
```

Override the prefix:

```sh
make install PREFIX=/usr/local
```

---

## Quick start

```sh
# Single IP — auto-routed to the correct RIR via IANA bootstrap
whois-rdap 8.8.8.8

# Single domain
whois-rdap google.com

# Single ASN
whois-rdap AS15169

# Compact JSON output
whois-rdap --json 8.8.8.8

# Bulk lookup from a file (8 concurrent, NDJSON output)
whois-rdap --file targets.txt

# Bulk lookup from stdin
echo -e "8.8.8.8\nAS15169\ngoogle.com" | whois-rdap --file -

# Bump concurrency for high-volume batches
whois-rdap --file big_list.txt --concurrency 32

# Skip cache for a guaranteed-fresh result
whois-rdap --no-cache 8.8.8.8

# Force re-download of IANA bootstrap maps
whois-rdap --refresh-bootstrap 8.8.8.8
```

---

## Usage

```
whois-rdap [OPTIONS] [QUERY]...
```

Query type is auto-detected from the input:

| Input | Detected as |
|---|---|
| `8.8.8.8` | IPv4 |
| `2001:4860:4860::8888` | IPv6 |
| `AS15169` or `15169` | ASN |
| `google.com` | Domain |

---

## CLI Options

### Core

| Flag | Default | Description |
|---|---|---|
| `[QUERY]...` | — | One or more targets (IP, domain, ASN) |
| `--rir <NAME>` | — | Force a known registry: `ripe`, `arin`, `apnic`, `lacnic`, `afrinic`, `iana` |
| `--server <URL>` | — | Custom RDAP server base URL (overrides `--rir` and bootstrap) |
| `--timeout <SECS>` | `15` | Request timeout per lookup |
| `--json` | off | Compact JSON output (NDJSON in bulk mode) |
| `--list-servers` | — | Print all known servers and exit |

### Bulk mode

| Flag | Default | Description |
|---|---|---|
| `--file <PATH>` | — | Read targets from file, one per line (use `-` for stdin) |
| `--concurrency <N>` | `8` | Max in-flight lookups |

Targets file format: one target per line; blank lines and `#` comments are
ignored.

```
# North America
8.8.8.8
AS15169

# Europe
1.1.1.1     # Cloudflare
```

### Bootstrap triage

| Flag | Default | Description |
|---|---|---|
| `--no-bootstrap` | off | Disable IANA bootstrap; use `--rir` / `--server` explicitly |
| `--refresh-bootstrap` | off | Force re-download of IANA bootstrap maps |

Bootstrap maps are cached for **24 hours** per RFC 9224 at:
`$XDG_CACHE_HOME/whois-rdap/bootstrap/` (usually `~/.cache/whois-rdap/bootstrap/`).

### Result cache

| Flag | Default | Description |
|---|---|---|
| `--no-cache` | off | Disable SQLite cache (always query the RDAP server) |
| `--cache-ttl-ip <SECS>` | `86400` | TTL for IP results (24 h) |
| `--cache-ttl-domain <SECS>` | `28800` | TTL for domain results (8 h) |
| `--cache-ttl-asn <SECS>` | `86400` | TTL for ASN results (24 h) |

**Why these TTLs?**
- IP / ASN allocations are very stable — RIR databases rarely change within 24 h.
- Domain registrations can change (registrar transfers, NS updates) — 8 h balances freshness vs. server load.

Cache location: `$XDG_CACHE_HOME/whois-rdap/cache.db`
(usually `~/.cache/whois-rdap/cache.db`)

### Redirect following

| Flag | Default | Description |
|---|---|---|
| `--max-redirects <N>` | `1` | RDAP link hops to follow (0 = off, max 3) |

RDAP responses sometimes include `links` arrays pointing to sub-registries
with richer data. Setting `--max-redirects 1` (default) follows one hop;
`--max-redirects 0` disables this entirely.

---

## Makefile

All common tasks are wrapped in a [Makefile](Makefile):

```sh
make help          # Show all targets
```

### Build

```sh
make               # → same as make release
make release       # Optimised binary (LTO, stripped, opt-level=z)
make debug         # Debug binary (fast compile, debug info)
```

### Test

```sh
make test          # Full test suite (parallel)
make test-verbose  # Full suite with live stdout
make test-unit     # Library unit tests only
make test-one NAME=test_parse_ip_response_arin_format  # Single test
```

### Code quality

```sh
make lint          # cargo clippy -D warnings
make fmt           # rustfmt all source files
make fmt-check     # Check formatting without modifying files
make ci            # fmt-check + lint + test  (CI gate)
```

### Documentation

```sh
make doc           # Build rustdoc and open in browser
make doc-build     # Build rustdoc only
```

### Install / uninstall

```sh
make install                    # → ~/.local/bin/whois-rdap
make install PREFIX=/usr/local  # → /usr/local/bin/whois-rdap
make uninstall                  # Remove installed binary
```

### Clean

```sh
make clean         # Remove target/ (Cargo build artefacts)
make clean-cache   # Remove ~/.cache/whois-rdap/ (SQLite cache + bootstrap maps)
make clean-all     # Both of the above
```

### Run shortcuts

```sh
make run ARGS="8.8.8.8 --json"         # Debug binary
make run-release ARGS="--file list.txt" # Release binary
```

### Variables

| Variable | Default | Description |
|---|---|---|
| `PREFIX` | `~/.local` | Installation prefix |
| `CARGO_FLAGS` | — | Extra flags forwarded to `cargo` |
| `TEST_THREADS` | `nproc` | Parallelism for `cargo test` |

---

## Library usage

`whois-rdap` is also an async-native Rust library. `RdapClient` is `Send + Sync`
and designed to be shared across tasks behind an `Arc`.

```toml
[dependencies]
whois-rdap = { path = "." }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Single lookup

```rust
use std::time::Duration;
use whois_rdap::{RdapClient, RdapRegistry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = RdapClient::for_registry(RdapRegistry::IANA, Duration::from_secs(10))?;

    // IP lookup
    let ip_res = client.lookup_ip("8.8.8.8".parse()?).await?;
    println!("Org: {}", ip_res.organization.unwrap_or_default());
    println!("CIDRs: {:?}", ip_res.cidrs);

    // Domain lookup
    let domain_client = RdapClient::for_custom(
        "https://rdap.verisign.com/com/v1",
        Duration::from_secs(5),
    )?;
    let domain_res = domain_client.lookup_domain("google.com").await?;
    println!("Registrar: {}", domain_res.registrar.unwrap_or_default());

    // ASN lookup
    let asn_res = client.lookup_asn(15169).await?;
    println!("ASN Org: {}", asn_res.organization.unwrap_or_default());

    Ok(())
}
```

### Parse functions (cache / redirect roundtrip)

After retrieving raw RDAP JSON (e.g. from the SQLite cache or from following a
redirect link), use the public parse helpers to extract typed fields.
**Never read `raw["organization"]` directly** — the RDAP schema does not store
extracted fields as top-level keys.

```rust
use whois_rdap::{parse_ip_response, parse_domain_response, parse_asn_response};

// Reconstruct a typed result from any raw RDAP JSON Value
let res = parse_ip_response(raw_json);
println!("{}", res.organization.unwrap_or_default());
```

### Parallel bulk lookup

```rust
use std::sync::Arc;
use std::time::Duration;
use whois_rdap::{RdapClient, RdapRegistry};
use whois_rdap::bulk::bulk_lookup;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Arc::new(
        RdapClient::for_registry(RdapRegistry::RIPE, Duration::from_secs(10))?
    );
    let targets = vec!["8.8.8.8".to_string(), "AS15169".to_string(), "google.com".to_string()];

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    bulk_lookup(client, targets.into_iter(), /* concurrency */ 4, &mut out).await?;
    Ok(())
}
```

Output is one NDJSON line per target:

```jsonl
{"query":"8.8.8.8","type":"ip","organization":"Google LLC","country_code":"US","cidrs":["8.8.8.0/24"],"as_number":null}
{"query":"AS15169","type":"asn","organization":"Google LLC","country_code":"US","range":"AS15169-AS15169"}
{"query":"google.com","type":"domain","handle":"GOOGLE.COM","registrar":"MarkMonitor Inc.","nameservers":["ns1.google.com"],"status":["active"]}
```

Errors produce:

```jsonl
{"query":"bad.target","error":"connection refused"}
```

### SQLite cache

```rust
use whois_rdap::cache::{Cache, key_ip, key_domain, key_asn};

let cache = Cache::open()?;          // ~/.cache/whois-rdap/cache.db

// Read (zero-copy BLOB → Value, expired entries automatically excluded)
if let Some(raw) = cache.get(&key_ip(&"8.8.8.8".parse()?))? {
    let res = whois_rdap::parse_ip_response(raw);
    println!("{}", res.organization.unwrap_or_default());
}

// Write (non-blocking, dispatched to spawn_blocking)
let handle = cache.insert_background(key_domain("google.com"), &rdap_json, 28800);
handle.await?;
```

---

## Architecture

```
src/
  lib.rs        — RdapClient, result types, JSON extractors, public parse helpers
  bootstrap.rs  — IANA bootstrap routing (IPv4/IPv6/ASN prefix tables, O(log N))
  cache.rs      — SQLite TTL cache (WAL, zero-copy read, spawn_blocking writes)
  redirect.rs   — RDAP link follower (rel=related hop chasing, zero-copy href)
  bulk.rs       — Parallel bulk executor (buffer_unordered streaming)
  main.rs       — CLI wiring (clap, query dispatch, cache integration)
```

### Hot-path (single lookup)

```
query
  → bootstrap triage (O(log N), binary search, zero alloc)
  → SQLite cache read (indexed SELECT, zero-copy BLOB → serde_json)
      HIT  → return immediately
      MISS → HTTP GET (reqwest connection pool + TLS session reuse)
           → redirect follow (optional, 1 hop default, href zero-copy)
           → SQLite write (spawn_blocking, non-blocking to caller)
           → return result
```

### Memory footprint at 8× concurrency

| Component | Heap |
|---|---|
| Bootstrap map | < 200 KB |
| SQLite page cache | ≤ 1 MB |
| 8× in-flight HTTP responses | ~400 KB |
| **Total** | **< 2 MB** |

---

## License

MIT — see [LICENSE](LICENSE) for details.
