// SQLite Result Cache (Feature 4)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// Schema (single table, WAL mode):
//   rdap_cache(key TEXT PK, payload BLOB, fetched_at INTEGER, ttl INTEGER)
//
// Hot-path read: single indexed SELECT; payload returned as &[u8] and parsed
// with serde_json::from_slice — no intermediate String copy.
//
// Cache writes are dispatched to a tokio::task::spawn_blocking closure so the
// async caller never waits for SQLite I/O.
//
// TTL defaults (all overridable):
//   IP results    → 24 h  (RIR allocations are very stable)
//   Domain results→  8 h  (domain records can change; balances freshness)
//   ASN results   → 24 h  (AS assignments are nearly permanent)

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Default TTLs ─────────────────────────────────────────────────────────────

/// Default TTL (seconds) for cached IP lookup results: 24 hours.
pub const DEFAULT_TTL_IP_SECS: u64 = 86_400;
/// Default TTL (seconds) for cached Domain lookup results: 8 hours.
pub const DEFAULT_TTL_DOMAIN_SECS: u64 = 28_800;
/// Default TTL (seconds) for cached ASN lookup results: 24 hours.
pub const DEFAULT_TTL_ASN_SECS: u64 = 86_400;

// ── Cache key helpers ─────────────────────────────────────────────────────────

/// Build a canonical cache key for an IP lookup.
#[inline]
pub fn key_ip(ip: &std::net::IpAddr) -> String {
    format!("ip:{ip}")
}

/// Build a canonical cache key for a domain lookup.
#[inline]
pub fn key_domain(domain: &str) -> String {
    // Normalise to lowercase so "GOOGLE.COM" and "google.com" share an entry.
    format!("domain:{}", domain.to_ascii_lowercase())
}

/// Build a canonical cache key for an ASN lookup.
#[inline]
pub fn key_asn(asn: u32) -> String {
    format!("asn:{asn}")
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Shared, thread-safe SQLite cache handle.
///
/// Clone is cheap — it's just an `Arc` bump.
#[derive(Clone)]
pub struct Cache {
    conn: Arc<Mutex<Connection>>,
}

impl Cache {
    /// Open (or create) the on-disk cache at the default XDG path.
    pub fn open() -> Result<Self> {
        let path = cache_db_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create cache dir: {}", parent.display()))?;
        }
        Self::open_at(path)
    }

    /// Open a cache at an explicit path.  Use `":memory:"` in tests.
    pub fn open_at(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path).context("Cannot open cache database")?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Look up a key.  Returns `None` on cache miss or if the entry is expired.
    ///
    /// Zero-copy hot path: BLOB is parsed directly from SQLite's buffer via
    /// `row.get_ref()` + `serde_json::from_slice`, so no intermediate `String`
    /// is ever allocated.
    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        let now = unix_now();
        let conn = self.conn.lock().expect("cache mutex poisoned");

        // Single indexed SELECT; expiry check in SQL avoids loading stale rows.
        let mut stmt = conn.prepare_cached(
            "SELECT payload FROM rdap_cache \
             WHERE key = ?1 AND fetched_at + ttl > ?2",
        )?;

        let result = stmt
            .query_row((key, now as i64), |row| {
                // get_ref returns a borrow tied to the row — zero extra copy.
                let blob = row.get_ref(0)?.as_blob()?;
                // Parse while the borrow is live; Value is owned.
                serde_json::from_slice(blob).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
            })
            .optional()?;

        Ok(result)
    }

    /// Insert or replace a cache entry.
    ///
    /// Dispatched to `spawn_blocking` so the async caller is never blocked
    /// waiting for SQLite I/O.  The returned `JoinHandle` can be ignored —
    /// errors are logged to stderr.
    pub fn insert_background(
        &self,
        key: String,
        value: &Value,
        ttl: u64,
    ) -> tokio::task::JoinHandle<()> {
        // Serialise *before* spawning so we don't capture a reference to Value.
        let payload = match serde_json::to_vec(value) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cache: serialise error for '{key}': {e}");
                return tokio::task::spawn_blocking(|| {});
            }
        };
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = unix_now() as i64;
            if let Ok(conn) = cache.conn.lock() {
                let r = conn.execute(
                    "INSERT OR REPLACE INTO rdap_cache (key, payload, fetched_at, ttl) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![key, payload, now, ttl as i64],
                );
                if let Err(e) = r {
                    eprintln!("cache: write error for '{key}': {e}");
                }
            }
        })
    }

    /// Range-aware IP lookup.
    ///
    /// Checks the exact key first (`ip:<addr>`), then falls back to a range
    /// containment query: any cached IP-network entry whose `range_start ≤ ip
    /// ≤ range_end` is returned as a hit.
    ///
    /// This means that querying `20.59.128.1` after `20.59.128.0` has already
    /// been cached (and its response covers `20.33.0.0–20.128.255.255`) returns
    /// the cached entry without a network round-trip.
    ///
    /// Both IPv4 and IPv6 addresses are normalised to a 16-byte big-endian blob
    /// (IPv4 via `to_ipv6_mapped()`), which makes the BLOB comparison in SQLite
    /// numerically correct across the entire IP space.
    pub fn get_ip(&self, ip: IpAddr) -> Result<Option<Value>> {
        let key = key_ip(&ip);
        let blob = ip_to_blob(ip);
        let now = unix_now() as i64;
        let conn = self.conn.lock().expect("cache mutex poisoned");

        // Single query: exact key match first (cheapest), then range scan.
        // SQLite compares BLOBs byte-by-byte; big-endian 16-byte blobs compare
        // numerically, so `range_start <= blob AND range_end >= blob` is a
        // correct containment test for both IPv4 and IPv6.
        let mut stmt = conn.prepare_cached(
            "SELECT payload FROM rdap_cache \
             WHERE fetched_at + ttl > ?1 \
               AND (key = ?2 \
                    OR (range_start IS NOT NULL \
                        AND range_start <= ?3 \
                        AND range_end   >= ?3)) \
             ORDER BY CASE WHEN key = ?2 THEN 0 ELSE 1 END \
             LIMIT 1",
        )?;

        let result = stmt
            .query_row((now, key.as_str(), &blob[..]), |row| {
                let b = row.get_ref(0)?.as_blob()?;
                serde_json::from_slice(b).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
            })
            .optional()?;

        Ok(result)
    }

    /// Insert or replace an IP-network cache entry, storing the RDAP range
    /// bounds as 16-byte BLOBs so that future `get_ip` calls for any IP within
    /// that range will be served from cache.
    ///
    /// `range` should be `Some((start_addr, end_addr))` from the parsed RDAP
    /// `startAddress`/`endAddress` fields.  Pass `None` if the response had no
    /// range (the entry will still be cached by exact key only).
    ///
    /// Write is dispatched to `spawn_blocking`; the caller is never blocked.
    pub fn insert_ip_background(
        &self,
        key: String,
        value: &Value,
        range: Option<(IpAddr, IpAddr)>,
        ttl: u64,
    ) -> tokio::task::JoinHandle<()> {
        let payload = match serde_json::to_vec(value) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cache: serialise error for '{key}': {e}");
                return tokio::task::spawn_blocking(|| {});
            }
        };
        let range_start = range.map(|(s, _)| ip_to_blob(s).to_vec());
        let range_end   = range.map(|(_, e)| ip_to_blob(e).to_vec());
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let now = unix_now() as i64;
            if let Ok(conn) = cache.conn.lock() {
                let r = conn.execute(
                    "INSERT OR REPLACE INTO rdap_cache \
                     (key, payload, fetched_at, ttl, range_start, range_end) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![key, payload, now, ttl as i64, range_start, range_end],
                );
                if let Err(e) = r {
                    eprintln!("cache: write error for '{key}': {e}");
                }
            }
        })
    }

    /// Delete all expired entries.  Call occasionally to reclaim disk space.
    pub fn evict_expired(&self) -> Result<usize> {
        let now = unix_now() as i64;
        let conn = self.conn.lock().expect("cache mutex poisoned");
        let n = conn.execute("DELETE FROM rdap_cache WHERE fetched_at + ttl <= ?1", [now])?;
        Ok(n)
    }
}

// ── Schema init ───────────────────────────────────────────────────────────────

fn init_schema(conn: &Connection) -> Result<()> {
    // 1. Set pragmas.
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = -1024;   -- cap page cache at 1 MB
        ",
    )
    .context("Cannot set pragmas")?;

    // 2. Ensure base table exists (with or without range columns).
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS rdap_cache (
            key         TEXT    PRIMARY KEY,
            payload     BLOB    NOT NULL,
            fetched_at  INTEGER NOT NULL,  -- unix seconds
            ttl         INTEGER NOT NULL   -- seconds until expiry
        );
        ",
    )
    .context("Cannot create base cache table")?;

    // 3. Migrate existing databases to add range columns if missing.
    // ALTER TABLE ADD COLUMN errors if the column already exists; we ignore the error.
    let _ = conn.execute("ALTER TABLE rdap_cache ADD COLUMN range_start BLOB;", []);
    let _ = conn.execute("ALTER TABLE rdap_cache ADD COLUMN range_end   BLOB;", []);

    // 4. Ensure indexes exist on the migrated schema.
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS rdap_cache_expiry
            ON rdap_cache (fetched_at + ttl);
        CREATE INDEX IF NOT EXISTS rdap_cache_ranges
            ON rdap_cache (range_start, range_end)
            WHERE range_start IS NOT NULL;
        ",
    )
    .context("Cannot create indices on cache schema")?;

    Ok(())
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn cache_db_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".cache")
        });
    Ok(base.join("whois-rdap").join("cache.db"))
}

/// Current time as unix seconds (u64).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encode any IP address as a 16-byte big-endian blob.
///
/// IPv4 addresses are converted to their IPv4-mapped IPv6 form
/// (`::ffff:a.b.c.d`) before encoding.  This places all IPv4 addresses in a
/// contiguous sub-range of the 128-bit IPv6 space, so that BLOB comparisons
/// in SQLite (`range_start <= ? AND range_end >= ?`) remain numerically
/// correct for both address families without any special-casing.
///
/// Two addresses of the same family always produce the same-length blob, so
/// SQLite's byte-by-byte BLOB ordering IS numeric ordering.
pub(crate) fn ip_to_blob(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open_mem() -> Cache {
        Cache::open_at(":memory:").expect("in-memory cache")
    }

    // helper: synchronous SQL insert (bypasses insert_background for setup)
    fn raw_insert(cache: &Cache, key: &str, val: &Value, ttl: i64) {
        let conn = cache.conn.lock().unwrap();
        let now = unix_now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO rdap_cache (key, payload, fetched_at, ttl) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![key, serde_json::to_vec(val).unwrap(), now, ttl],
        )
        .unwrap();
    }

    fn raw_insert_past(cache: &Cache, key: &str, val: &Value, ttl: i64, age_secs: i64) {
        let conn = cache.conn.lock().unwrap();
        let past = unix_now() as i64 - age_secs;
        conn.execute(
            "INSERT OR REPLACE INTO rdap_cache (key, payload, fetched_at, ttl) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![key, serde_json::to_vec(val).unwrap(), past, ttl],
        )
        .unwrap();
    }

    // ── Basic get/miss ────────────────────────────────────────────────────────

    #[test]
    fn test_miss_on_empty_cache() {
        let cache = open_mem();
        assert!(cache.get("ip:8.8.8.8").unwrap().is_none());
    }

    #[test]
    fn test_miss_returns_none_not_error() {
        let cache = open_mem();
        let result = cache.get("ip:1.2.3.4");
        assert!(result.is_ok(), "get() must not error on a miss");
        assert!(result.unwrap().is_none());
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_raw_rdap_json() {
        // Store raw RDAP JSON (not pre-extracted fields) and verify retrieval
        let cache = open_mem();
        let rdap = json!({
            "objectClassName": "ip network",
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "country": "US",
            "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
            "name": "GOOGL-IPV4"
        });
        raw_insert(&cache, "ip:8.8.8.8", &rdap, 3600);
        let result = cache.get("ip:8.8.8.8").unwrap();
        assert_eq!(result, Some(rdap));
    }

    // ── TTL / expiry ──────────────────────────────────────────────────────────

    #[test]
    fn test_expired_entry_returns_none() {
        let cache = open_mem();
        let val = json!({"objectClassName": "ip network"});
        // ttl=7200, age=7201 => expired 1 s ago
        raw_insert_past(&cache, "ip:1.2.3.4", &val, 7200, 7201);
        assert!(cache.get("ip:1.2.3.4").unwrap().is_none());
    }

    #[test]
    fn test_fresh_entry_within_ttl_is_hit() {
        let cache = open_mem();
        let val = json!({"objectClassName": "autnum"});
        // ttl=1, age=0 => still fresh
        raw_insert(&cache, "asn:15169", &val, 1);
        assert!(cache.get("asn:15169").unwrap().is_some());
    }

    #[test]
    fn test_evict_expired_removes_only_stale_entries() {
        let cache = open_mem();
        let val = json!({});
        // 5 expired
        for i in 0..5 {
            raw_insert_past(&cache, &format!("ip:{i}.0.0.0"), &val, 100, 9999);
        }
        // 1 fresh
        raw_insert(&cache, "ip:keep.me", &val, 9999);

        let evicted = cache.evict_expired().unwrap();
        assert_eq!(evicted, 5);
        assert!(
            cache.get("ip:keep.me").unwrap().is_some(),
            "Fresh entry must survive eviction"
        );
    }

    // ── INSERT OR REPLACE (overwrite) ─────────────────────────────────────────

    #[tokio::test]
    async fn test_overwrite_replaces_old_value() {
        let cache = open_mem();
        let old = json!({"name": "OldOrg"});
        let new = json!({"name": "NewOrg"});
        raw_insert(&cache, "ip:1.1.1.1", &old, 3600);

        cache
            .insert_background("ip:1.1.1.1".to_string(), &new, 3600)
            .await
            .unwrap();

        let result = cache.get("ip:1.1.1.1").unwrap().expect("must be a hit");
        assert_eq!(
            result["name"], "NewOrg",
            "Second write must overwrite first"
        );
    }

    // ── insert_background async write path ────────────────────────────────────

    #[tokio::test]
    async fn test_insert_background_stores_raw_rdap_json() {
        let cache = open_mem();
        let rdap = json!({
            "objectClassName": "ip network",
            "startAddress": "20.33.0.0",
            "endAddress": "20.128.255.255",
            "country": "US",
            "cidr0_cidrs": [{"v4prefix": "20.33.0.0", "length": 16}],
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]]
            }]
        });

        cache
            .insert_background("ip:20.59.128.25".to_string(), &rdap, 86400)
            .await
            .unwrap();

        let stored = cache
            .get("ip:20.59.128.25")
            .unwrap()
            .expect("insert_background write must be readable");

        // Must store raw RDAP JSON — not pre-extracted keys
        assert!(
            stored.get("organization").is_none(),
            "Cache must store raw RDAP JSON; 'organization' is an extracted field"
        );
        assert_eq!(stored["objectClassName"], "ip network");
    }

    #[tokio::test]
    async fn test_insert_background_result_survives_parse() {
        let cache = open_mem();
        let rdap = json!({
            "objectClassName": "ip network",
            "startAddress": "20.33.0.0",
            "endAddress": "20.128.255.255",
            "country": "US",
            "cidr0_cidrs": [{"v4prefix": "20.33.0.0", "length": 16}],
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]]
            }]
        });
        cache
            .insert_background("ip:20.59.128.25".to_string(), &rdap, 86400)
            .await
            .unwrap();

        let stored = cache.get("ip:20.59.128.25").unwrap().unwrap();
        let res = crate::parse_ip_response(stored);
        assert_eq!(
            res.organization.as_deref(),
            Some("Microsoft Corporation"),
            "parse_ip_response must extract org from cached raw RDAP blob"
        );
        assert_eq!(res.country_code.as_deref(), Some("US"));
        assert!(!res.cidrs.is_empty());
    }

    // ── Clone sharing ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_clone_shares_connection() {
        let cache1 = open_mem();
        let cache2 = cache1.clone();

        let val = json!({"objectClassName": "ip network", "name": "SHARED"});
        cache1
            .insert_background("ip:10.0.0.1".to_string(), &val, 3600)
            .await
            .unwrap();

        let result = cache2.get("ip:10.0.0.1").unwrap();
        assert!(
            result.is_some(),
            "Write via clone must be visible through sibling clone"
        );
    }

    // ── Full RDAP roundtrips (write → cache → parse) ──────────────────────────

    #[tokio::test]
    async fn test_full_ip_roundtrip() {
        let cache = open_mem();
        let rdap = json!({
            "objectClassName": "ip network",
            "handle": "NET-20-33-0-0-1",
            "startAddress": "20.33.0.0",
            "endAddress": "20.128.255.255",
            "country": "US",
            "cidr0_cidrs": [
                {"v4prefix": "20.33.0.0", "length": 16},
                {"v4prefix": "20.64.0.0", "length": 10}
            ],
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]]
            }]
        });
        cache
            .insert_background("ip:20.59.128.25".to_string(), &rdap, 86400)
            .await
            .unwrap();

        let res = crate::parse_ip_response(cache.get("ip:20.59.128.25").unwrap().unwrap());
        assert_eq!(res.organization.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(res.country_code.as_deref(), Some("US"));
        assert_eq!(
            res.range,
            Some(("20.33.0.0".to_string(), "20.128.255.255".to_string()))
        );
        assert_eq!(res.cidrs.len(), 2);
    }

    #[tokio::test]
    async fn test_full_domain_roundtrip() {
        let cache = open_mem();
        let rdap = json!({
            "ldhName": "GOOGLE.COM",
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]
            }],
            "nameservers": [{"ldhName": "ns1.google.com"}, {"ldhName": "ns4.google.com"}],
            "status": ["active", "clientDeleteProhibited"]
        });
        cache
            .insert_background("domain:google.com".to_string(), &rdap, 28800)
            .await
            .unwrap();

        let res = crate::parse_domain_response(
            "google.com",
            cache.get("domain:google.com").unwrap().unwrap(),
        );
        assert_eq!(res.handle, "GOOGLE.COM");
        assert_eq!(res.registrar.as_deref(), Some("MarkMonitor Inc."));
        assert_eq!(res.nameservers, vec!["ns1.google.com", "ns4.google.com"]);
        assert!(res.status.contains(&"active".to_string()));
    }

    #[tokio::test]
    async fn test_full_asn_roundtrip() {
        let cache = open_mem();
        let rdap = json!({
            "objectClassName": "autnum",
            "startAutnum": 15169,
            "endAutnum": 15169,
            "country": "US",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]
            }]
        });
        cache
            .insert_background("asn:15169".to_string(), &rdap, 86400)
            .await
            .unwrap();

        let res = crate::parse_asn_response(15169, cache.get("asn:15169").unwrap().unwrap());
        assert_eq!(res.organization.as_deref(), Some("Google LLC"));
        assert_eq!(res.country_code.as_deref(), Some("US"));
        assert_eq!(res.range, Some((15169, 15169)));
    }

    // ── Key helpers ───────────────────────────────────────────────────────────

    #[test]
    fn test_key_helpers_ipv4() {
        assert_eq!(key_ip(&"8.8.8.8".parse().unwrap()), "ip:8.8.8.8");
    }

    #[test]
    fn test_key_helpers_ipv6() {
        assert_eq!(
            key_ip(&"2001:4860:4860::8888".parse().unwrap()),
            "ip:2001:4860:4860::8888"
        );
    }

    #[test]
    fn test_key_domain_normalises_to_lowercase() {
        assert_eq!(key_domain("GOOGLE.COM"), "domain:google.com");
        assert_eq!(key_domain("google.com"), "domain:google.com");
        assert_eq!(key_domain("Example.ORG"), "domain:example.org");
    }

    #[test]
    fn test_key_asn() {
        assert_eq!(key_asn(15169), "asn:15169");
        assert_eq!(key_asn(0), "asn:0");
        assert_eq!(key_asn(u32::MAX), format!("asn:{}", u32::MAX));
    }

    #[test]
    fn test_key_namespacing_no_collisions() {
        // Different types with the same content must produce different keys
        assert_ne!(key_asn(15169), key_domain("15169"));
        assert_ne!(key_asn(15169), key_ip(&"0.0.0.0".parse().unwrap()));
        assert_ne!(key_domain("test"), key_ip(&"0.0.0.0".parse().unwrap()));
    }

    // ── Schema / pragmas ──────────────────────────────────────────────────────

    #[test]
    fn test_cache_size_pragma_is_1mb() {
        let cache = open_mem();
        let conn = cache.conn.lock().unwrap();
        let size: i64 = conn
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(size, -1024, "cache_size must be -1024 (= 1 MiB cap)");
    }

    #[test]
    fn test_expiry_index_exists() {
        let cache = open_mem();
        let conn = cache.conn.lock().unwrap();
        let n: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
             WHERE type='index' AND name='rdap_cache_expiry'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "rdap_cache_expiry index must exist");
    }

    #[test]
    fn test_wal_mode_applied_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rdap_wal_test_{}.db", std::process::id()));
        let cache = Cache::open_at(&path).expect("open temp db");
        let conn = cache.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    // ── Default TTL constants ─────────────────────────────────────────────────

    #[test]
    fn test_default_ttl_values_and_ordering() {
        assert_eq!(DEFAULT_TTL_IP_SECS, 86_400, "IP TTL must be 24 h");
        assert_eq!(DEFAULT_TTL_DOMAIN_SECS, 28_800, "Domain TTL must be 8 h");
        assert_eq!(DEFAULT_TTL_ASN_SECS, 86_400, "ASN TTL must be 24 h");
        assert!(
            DEFAULT_TTL_DOMAIN_SECS < DEFAULT_TTL_IP_SECS,
            "Domain TTL must be shorter than IP TTL (domain records change more often)"
        );
    }

    // ── ip_to_blob encoding ───────────────────────────────────────────────────

    #[test]
    fn test_ip_to_blob_ipv4_is_16_bytes() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let blob = ip_to_blob(ip);
        assert_eq!(blob.len(), 16);
    }

    #[test]
    fn test_ip_to_blob_ipv6_is_16_bytes() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        let blob = ip_to_blob(ip);
        assert_eq!(blob.len(), 16);
    }

    #[test]
    fn test_ip_to_blob_ipv4_ordering_matches_numeric() {
        // Lower IPv4 addresses must produce a lexicographically smaller blob
        let lo: IpAddr = "20.33.0.0".parse().unwrap();
        let hi: IpAddr = "20.128.255.255".parse().unwrap();
        let mid: IpAddr = "20.59.128.1".parse().unwrap();

        let blo = ip_to_blob(lo);
        let bhi = ip_to_blob(hi);
        let bmid = ip_to_blob(mid);

        assert!(blo < bmid, "20.33.0.0 blob must be < 20.59.128.1 blob");
        assert!(bmid < bhi, "20.59.128.1 blob must be < 20.128.255.255 blob");
        assert!(blo < bhi,  "20.33.0.0 blob must be < 20.128.255.255 blob");
    }

    #[test]
    fn test_ip_to_blob_ipv4_min_max() {
        let min: IpAddr = "0.0.0.0".parse().unwrap();
        let max: IpAddr = "255.255.255.255".parse().unwrap();
        assert!(ip_to_blob(min) < ip_to_blob(max));
    }

    #[test]
    fn test_ip_to_blob_ipv4_and_ipv6_do_not_overlap() {
        // IPv4-mapped IPv6 range: ::ffff:0.0.0.0 – ::ffff:255.255.255.255
        // Pure IPv6 addresses like 2001:: are outside that range
        let ipv4_max: IpAddr = "255.255.255.255".parse().unwrap();
        let ipv6_start: IpAddr = "2001::1".parse().unwrap();
        // 2001::/16 is a completely different part of the IPv6 space from ::ffff::/96
        // (blob comparison still works because they're in different numeric ranges)
        let bv4 = ip_to_blob(ipv4_max);
        let bv6 = ip_to_blob(ipv6_start);
        // They must not be equal
        assert_ne!(bv4, bv6);
    }

    // ── get_ip: exact key match ───────────────────────────────────────────────

    #[test]
    fn test_get_ip_exact_key_hit() {
        let cache = open_mem();
        let val = json!({"objectClassName": "ip network", "name": "GOOGL"});
        raw_insert(&cache, "ip:8.8.8.8", &val, 3600);

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = cache.get_ip(ip).unwrap();
        assert_eq!(result, Some(val));
    }

    #[test]
    fn test_get_ip_exact_key_miss() {
        let cache = open_mem();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(cache.get_ip(ip).unwrap().is_none());
    }

    // ── get_ip: range containment ─────────────────────────────────────────────

    /// Core scenario from the user's question:
    /// Query 20.59.128.0 → cache the Microsoft allocation (20.33.0.0–20.128.255.255).
    /// Then query 20.59.128.1 and 20.59.129.0 → both must hit the cache without
    /// a network round-trip.
    #[tokio::test]
    async fn test_get_ip_range_hit_for_adjacent_ips_in_same_allocation() {
        let cache = open_mem();

        // Simulate caching the response for 20.59.128.0
        let rdap = json!({
            "objectClassName": "ip network",
            "startAddress": "20.33.0.0",
            "endAddress":   "20.128.255.255",
            "country": "US",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"]]]
            }]
        });

        let start: IpAddr = "20.33.0.0".parse().unwrap();
        let end:   IpAddr = "20.128.255.255".parse().unwrap();

        cache.insert_ip_background(
            "ip:20.59.128.0".to_string(),
            &rdap,
            Some((start, end)),
            86400,
        ).await.unwrap();

        // 20.59.128.1 — different IP, same allocation → must be a cache HIT
        let hit1 = cache.get_ip("20.59.128.1".parse().unwrap()).unwrap();
        assert!(hit1.is_some(),
            "20.59.128.1 is within 20.33.0.0–20.128.255.255 and must hit the cache");

        // 20.59.129.0 — yet another IP in the range → also a HIT
        let hit2 = cache.get_ip("20.59.129.0".parse().unwrap()).unwrap();
        assert!(hit2.is_some(),
            "20.59.129.0 is within 20.33.0.0–20.128.255.255 and must hit the cache");

        // Verify the returned payload is correct
        let res = crate::parse_ip_response(hit1.unwrap());
        assert_eq!(res.organization.as_deref(), Some("Microsoft Corporation"));
    }

    /// Boundary check: the range endpoints themselves must be hits.
    #[tokio::test]
    async fn test_get_ip_range_hit_at_boundaries() {
        let cache = open_mem();
        let rdap = json!({"objectClassName": "ip network", "name": "BOUNDARY-TEST"});
        let start: IpAddr = "10.0.0.0".parse().unwrap();
        let end:   IpAddr = "10.255.255.255".parse().unwrap();

        cache.insert_ip_background(
            "ip:10.0.0.1".to_string(), &rdap, Some((start, end)), 3600,
        ).await.unwrap();

        // Range start
        assert!(cache.get_ip("10.0.0.0".parse().unwrap()).unwrap().is_some(),
            "range_start itself must be a cache hit");
        // Range end
        assert!(cache.get_ip("10.255.255.255".parse().unwrap()).unwrap().is_some(),
            "range_end itself must be a cache hit");
        // Mid-point
        assert!(cache.get_ip("10.128.0.1".parse().unwrap()).unwrap().is_some(),
            "mid-range IP must be a cache hit");
    }

    /// IP just outside the range must be a miss.
    #[tokio::test]
    async fn test_get_ip_range_miss_outside_allocation() {
        let cache = open_mem();
        let rdap = json!({"objectClassName": "ip network", "name": "MSFT"});
        let start: IpAddr = "20.33.0.0".parse().unwrap();
        let end:   IpAddr = "20.128.255.255".parse().unwrap();

        cache.insert_ip_background(
            "ip:20.59.128.0".to_string(), &rdap, Some((start, end)), 86400,
        ).await.unwrap();

        // 20.32.255.255 — just before the range → miss
        assert!(cache.get_ip("20.32.255.255".parse().unwrap()).unwrap().is_none(),
            "IP before range_start must be a cache miss");

        // 20.129.0.0 — just after the range → miss
        assert!(cache.get_ip("20.129.0.0".parse().unwrap()).unwrap().is_none(),
            "IP after range_end must be a cache miss");

        // Completely different /8 → miss
        assert!(cache.get_ip("8.8.8.8".parse().unwrap()).unwrap().is_none(),
            "Unrelated IP must be a cache miss");
    }

    /// Without range bounds stored, only the exact key matches.
    #[tokio::test]
    async fn test_get_ip_no_range_only_exact_key_matches() {
        let cache = open_mem();
        let rdap = json!({"objectClassName": "ip network"});

        // Insert without range bounds
        cache.insert_ip_background(
            "ip:8.8.8.8".to_string(), &rdap, None, 3600,
        ).await.unwrap();

        // Exact key → hit
        assert!(cache.get_ip("8.8.8.8".parse().unwrap()).unwrap().is_some());

        // Any other IP → miss (no range to match)
        assert!(cache.get_ip("8.8.8.9".parse().unwrap()).unwrap().is_none());
    }

    /// Exact key takes priority over a range match from a different entry.
    #[tokio::test]
    async fn test_get_ip_exact_key_preferred_over_range_match() {
        let cache = open_mem();

        let broad_rdap  = json!({"name": "BROAD-NET"});
        let exact_rdap  = json!({"name": "EXACT-ENTRY"});

        let s: IpAddr = "10.0.0.0".parse().unwrap();
        let e: IpAddr = "10.255.255.255".parse().unwrap();

        // Broad range entry for 10.0.0.0/8
        cache.insert_ip_background(
            "ip:10.0.0.1".to_string(), &broad_rdap, Some((s, e)), 3600,
        ).await.unwrap();

        // Exact entry for 10.5.5.5
        cache.insert_ip_background(
            "ip:10.5.5.5".to_string(), &exact_rdap, None, 3600,
        ).await.unwrap();

        // 10.5.5.5 must return the exact entry, not the broad range entry
        let result = cache.get_ip("10.5.5.5".parse().unwrap()).unwrap().unwrap();
        assert_eq!(result["name"], "EXACT-ENTRY",
            "Exact key must take priority over a range match");
    }

    /// Expired range entries must not be returned even when the range matches.
    #[tokio::test]
    async fn test_get_ip_expired_range_is_a_miss() {
        let cache = open_mem();
        let rdap = json!({"objectClassName": "ip network", "name": "EXPIRED"});

        // Insert with a past timestamp (already expired)
        let start: IpAddr = "10.0.0.0".parse().unwrap();
        let end:   IpAddr = "10.255.255.255".parse().unwrap();
        {
            let conn = cache.conn.lock().unwrap();
            let past = unix_now() as i64 - 9999;
            let rs = ip_to_blob(start).to_vec();
            let re = ip_to_blob(end).to_vec();
            conn.execute(
                "INSERT OR REPLACE INTO rdap_cache \
                 (key, payload, fetched_at, ttl, range_start, range_end) \
                 VALUES (?1, ?2, ?3, 100, ?4, ?5)",
                rusqlite::params![
                    "ip:10.0.0.1",
                    serde_json::to_vec(&rdap).unwrap(),
                    past,
                    rs,
                    re
                ],
            ).unwrap();
        }

        // Any IP in range — must be a miss because the entry is expired
        assert!(cache.get_ip("10.5.5.5".parse().unwrap()).unwrap().is_none(),
            "Expired range entry must not be returned");
    }

    // ── ip_to_blob: IPv6 range containment ───────────────────────────────────

    #[tokio::test]
    async fn test_get_ip_range_works_for_ipv6() {
        let cache = open_mem();
        let rdap = json!({"objectClassName": "ip network", "name": "GOOGLE-IPV6"});

        // Google's 2001:4860::/32 allocation
        let start: IpAddr = "2001:4860::".parse().unwrap();
        let end:   IpAddr = "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();

        cache.insert_ip_background(
            "ip:2001:4860:4860::8888".to_string(),
            &rdap,
            Some((start, end)),
            86400,
        ).await.unwrap();

        // Another address in the same /32 → hit
        let hit = cache.get_ip("2001:4860:4860::8844".parse().unwrap()).unwrap();
        assert!(hit.is_some(), "IPv6 range containment must work");

        // Address outside the range → miss
        let miss = cache.get_ip("2001:db8::1".parse().unwrap()).unwrap();
        assert!(miss.is_none(), "IPv6 address outside range must be a miss");
    }
}
