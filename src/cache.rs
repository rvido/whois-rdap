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
                serde_json::from_slice(blob)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    ))
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
        let n = conn.execute(
            "DELETE FROM rdap_cache WHERE fetched_at + ttl <= ?1",
            [now],
        )?;
        Ok(n)
    }
}

// ── Schema init ───────────────────────────────────────────────────────────────

fn init_schema(conn: &Connection) -> Result<()> {
    // WAL for concurrent readers; NORMAL sync is fast and crash-safe enough.
    conn.execute_batch("
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
    ").context("Cannot initialise cache schema")
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

    #[test]
    fn test_miss_on_empty_cache() {
        let cache = open_mem();
        assert!(cache.get("ip:8.8.8.8").unwrap().is_none());
    }

    #[test]
    fn test_roundtrip() {
        let cache = open_mem();
        let val = json!({"organization": "Google LLC", "country_code": "US"});
        let conn = cache.conn.lock().unwrap();
        let now = unix_now() as i64;
        conn.execute(
            "INSERT INTO rdap_cache (key, payload, fetched_at, ttl) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["ip:8.8.8.8", serde_json::to_vec(&val).unwrap(), now, 3600_i64],
        ).unwrap();
        drop(conn);
        let result = cache.get("ip:8.8.8.8").unwrap();
        assert_eq!(result, Some(val));
    }

    #[test]
    fn test_expired_entry_returns_none() {
        let cache = open_mem();
        let val = json!({"organization": "Old Org"});
        let conn = cache.conn.lock().unwrap();
        // Insert with fetched_at = now - 7201, ttl = 7200 → already expired
        let past = unix_now() as i64 - 7201;
        conn.execute(
            "INSERT INTO rdap_cache (key, payload, fetched_at, ttl) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["ip:1.2.3.4", serde_json::to_vec(&val).unwrap(), past, 7200_i64],
        ).unwrap();
        drop(conn);
        assert!(cache.get("ip:1.2.3.4").unwrap().is_none());
    }

    #[test]
    fn test_evict_expired() {
        let cache = open_mem();
        let conn = cache.conn.lock().unwrap();
        let past = unix_now() as i64 - 9999;
        for i in 0..5 {
            conn.execute(
                "INSERT INTO rdap_cache (key, payload, fetched_at, ttl) VALUES (?1, ?2, ?3, 100)",
                rusqlite::params![format!("ip:{i}.0.0.0"), b"{}".to_vec(), past],
            ).unwrap();
        }
        drop(conn);
        let evicted = cache.evict_expired().unwrap();
        assert_eq!(evicted, 5);
    }

    #[test]
    fn test_key_helpers() {
        assert_eq!(key_ip(&"8.8.8.8".parse().unwrap()), "ip:8.8.8.8");
        assert_eq!(key_domain("GOOGLE.COM"), "domain:google.com");
        assert_eq!(key_asn(15169), "asn:15169");
    }
}
