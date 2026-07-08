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
    // WAL for concurrent readers; NORMAL sync is fast and crash-safe enough.
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = -1024;   -- cap page cache at 1 MB
        CREATE TABLE IF NOT EXISTS rdap_cache (
            key        TEXT    PRIMARY KEY,
            payload    BLOB    NOT NULL,
            fetched_at INTEGER NOT NULL,  -- unix seconds
            ttl        INTEGER NOT NULL   -- seconds until expiry
        );
        CREATE INDEX IF NOT EXISTS rdap_cache_expiry
            ON rdap_cache (fetched_at + ttl);
    ",
    )
    .context("Cannot initialise cache schema")
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
}
