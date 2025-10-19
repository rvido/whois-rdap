// Rust RDAP client library to query RDAP servers for IP address information.
// Copyright (c) 2025 Richard Vidal Dorsch. Licensed under the MIT license.

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

/// Well-known RDAP registries (RIRs + IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdapRegistry {
    /// RIPE NCC (Europe, Middle East, parts of Central Asia)
    RIPE,
    /// ARIN (USA, Canada, parts of Caribbean)
    ARIN,
    /// APNIC (Asia Pacific)
    APNIC,
    /// LACNIC (Latin America and Caribbean)
    LACNIC,
    /// AFRINIC (Africa)
    AFRINIC,
    /// IANA bootstrap (can be used to discover authoritative RIR)
    IANA,
}

impl FromStr for RdapRegistry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ripe" => Ok(Self::RIPE),
            "arin" => Ok(Self::ARIN),
            "apnic" => Ok(Self::APNIC),
            "lacnic" => Ok(Self::LACNIC),
            "afrinic" => Ok(Self::AFRINIC),
            "iana" => Ok(Self::IANA),
            _ => Err(anyhow!("Unknown registry: {}", s)),
        }
    }
}

impl RdapRegistry {
    /// Base URL for the registry (no trailing slash).
    pub fn base_url(self) -> &'static str {
        match self {
            RdapRegistry::RIPE => "https://rdap.db.ripe.net",
            RdapRegistry::ARIN => "https://rdap.arin.net/rdap",
            RdapRegistry::APNIC => "https://rdap.apnic.net",
            RdapRegistry::LACNIC => "https://rdap.lacnic.net/rdap",
            RdapRegistry::AFRINIC => "https://rdap.afrinic.net/rdap",
            RdapRegistry::IANA => "https://rdap.iana.org",
        }
    }

    /// A user-friendly label.
    pub fn label(self) -> &'static str {
        match self {
            RdapRegistry::RIPE => "RIPE NCC",
            RdapRegistry::ARIN => "ARIN",
            RdapRegistry::APNIC => "APNIC",
            RdapRegistry::LACNIC => "LACNIC",
            RdapRegistry::AFRINIC => "AFRINIC",
            RdapRegistry::IANA => "IANA (bootstrap)",
        }
    }

    /// List all registries with their labels and base URLs.
    pub fn all() -> &'static [(RdapRegistry, &'static str, &'static str)] {
        &[
            (RdapRegistry::RIPE, "RIPE NCC", "https://rdap.db.ripe.net"),
            (RdapRegistry::ARIN, "ARIN", "https://rdap.arin.net/rdap"),
            (RdapRegistry::APNIC, "APNIC", "https://rdap.apnic.net"),
            (
                RdapRegistry::LACNIC,
                "LACNIC",
                "https://rdap.lacnic.net/rdap",
            ),
            (
                RdapRegistry::AFRINIC,
                "AFRINIC",
                "https://rdap.afrinic.net/rdap",
            ),
            (
                RdapRegistry::IANA,
                "IANA (bootstrap)",
                "https://rdap.iana.org",
            ),
        ]
    }
}

/// Result of an RDAP IP lookup.
#[derive(Debug, Clone)]
pub struct RdapResult {
    /// Best-effort organization name, if found.
    pub organization: Option<String>,
    /// CIDR(s) if provided via cidr0_cidrs or similar fields.
    pub cidrs: Vec<String>,
    /// Inclusive IP range (start, end), if present.
    pub range: Option<(String, String)>,
    /// Autonomous System Number, if available.
    pub as_number: Option<u32>,
    /// Full raw RDAP JSON (for callers who need more fields).
    pub raw: Value,
}

/// Reusable RDAP client.
#[derive(Clone, Debug)]
pub struct RdapClient {
    http: reqwest::Client,
    base: String,
}

impl RdapClient {
    /// Construct a client for a known registry with a timeout.
    pub fn for_registry(registry: RdapRegistry, timeout: Duration) -> Result<Self> {
        Self::for_custom(registry.base_url(), timeout)
    }

    /// Construct a client for a custom server URL (e.g., internal mirror).
    pub fn for_custom(base_url: &str, timeout: Duration) -> Result<Self> {
        let base = trim_trailing_slash(base_url).to_string();
        let http = reqwest::Client::builder()
            .user_agent("rdap-client/0.1 (Rust)")
            .timeout(timeout)
            .build()?;
        Ok(Self { http, base })
    }

    /// Lookup an IP (v4 or v6) and extract org + CIDRs + range.
    ///
    /// Queries: `{base}/ip/{ip}`
    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<RdapResult> {
        let url = format!("{}/ip/{}", self.base, ip);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to GET {}", url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "RDAP server returned status {}.\nBody: {}",
                status,
                truncate(&body, 2000)
            ));
        }

        let json: Value = resp.json().await.context("Failed to decode RDAP JSON")?;
        let organization = extract_org(&json);
        let cidrs = extract_cidrs(&json);
        let range = extract_range(&json);
        let as_number = extract_as_number(&json);

        Ok(RdapResult {
            organization,
            cidrs,
            range,
            as_number,
            raw: json,
        })
    }
}

/* --------------------------- Helpers & extractors -------------------------- */

fn trim_trailing_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

/// Extract AS number from RDAP response.
/// Looks for AS numbers in autnums field or entity references.
fn extract_as_number(root: &Value) -> Option<u32> {
    // Check for arin_originas0_originautnums (ARIN specific)
    if let Some(origin_autnums) = root
        .get("arin_originas0_originautnums")
        .and_then(|v| v.as_array())
    {
        for autnum in origin_autnums {
            if let Some(as_num) = autnum.as_u64() {
                return Some(as_num as u32);
            }
        }
    }

    // Check for cidr0_cidrs with AS number information
    if let Some(cidrs) = root.get("cidr0_cidrs").and_then(|v| v.as_array()) {
        for cidr in cidrs {
            if let Some(as_num) = cidr.get("autnum").and_then(|h| h.as_u64()) {
                return Some(as_num as u32);
            }
        }
    }

    // First check if there's an "autnums" field directly
    if let Some(autnums) = root.get("autnums").and_then(|v| v.as_array()) {
        for autnum in autnums {
            if let Some(as_num) = autnum.get("handle").and_then(|h| h.as_str()) {
                if let Some(parsed) = parse_as_number(as_num) {
                    return Some(parsed);
                }
            }
            // Also check the startAutnum field which contains the actual AS number
            if let Some(as_num) = autnum.get("startAutnum").and_then(|h| h.as_u64()) {
                return Some(as_num as u32);
            }
        }
    }

    // Check in entities for AS number references
    if let Some(entities) = root.get("entities").and_then(|v| v.as_array()) {
        for entity in entities {
            // Check handle field for AS numbers (format like "AS1234")
            if let Some(handle) = entity.get("handle").and_then(|h| h.as_str()) {
                if let Some(parsed) = parse_as_number(handle) {
                    return Some(parsed);
                }
            }

            // Check if entity has autnums
            if let Some(autnums) = entity.get("autnums").and_then(|v| v.as_array()) {
                for autnum in autnums {
                    if let Some(as_num) = autnum.get("handle").and_then(|h| h.as_str()) {
                        if let Some(parsed) = parse_as_number(as_num) {
                            return Some(parsed);
                        }
                    }
                    if let Some(as_num) = autnum.get("startAutnum").and_then(|h| h.as_u64()) {
                        return Some(as_num as u32);
                    }
                }
            }

            // Recursively check nested entities
            if let Some(nested_entities) = entity.get("entities").and_then(|v| v.as_array()) {
                for nested_entity in nested_entities {
                    if let Some(handle) = nested_entity.get("handle").and_then(|h| h.as_str()) {
                        if let Some(parsed) = parse_as_number(handle) {
                            return Some(parsed);
                        }
                    }
                }
            }
        }
    }

    // Check in remarks for AS number mentions
    if let Some(remarks) = root.get("remarks").and_then(|v| v.as_array()) {
        for remark in remarks {
            if let Some(descriptions) = remark.get("description").and_then(|d| d.as_array()) {
                for desc in descriptions {
                    if let Some(text) = desc.as_str() {
                        // Look for AS numbers in text like "AS15169" or "originated by AS15169"
                        if let Some(as_num) = extract_as_from_text(text) {
                            return Some(as_num);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Parse AS number from strings like "AS1234", "1234", etc.
fn parse_as_number(s: &str) -> Option<u32> {
    // Handle "AS1234" format
    if let Some(stripped) = s.strip_prefix("AS") {
        return stripped.parse().ok();
    }

    // Handle plain number format
    s.parse().ok()
}

/// Extract AS number from text descriptions
fn extract_as_from_text(text: &str) -> Option<u32> {
    use std::str::FromStr;

    // Look for patterns like "AS15169", "originated by AS15169", etc.
    for word in text.split_whitespace() {
        if let Some(stripped) = word.strip_prefix("AS") {
            // Remove any trailing punctuation
            let cleaned = stripped
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();
            if let Ok(as_num) = u32::from_str(&cleaned) {
                return Some(as_num);
            }
        }
    }

    None
}

/// Prefer entities with roles like "registrant", "org", "administrative".
fn extract_org(root: &Value) -> Option<String> {
    let entities = root.get("entities")?.as_array()?;

    // Role preference order (most relevant first)
    let role_rank = [
        "registrant",
        "org",
        "administrative",
        "owner",
        "technical",
        "abuse",
        "sponsoring registrar",
    ];

    // Build candidates with rank and org value
    let mut candidates: Vec<(usize, String)> = Vec::new();

    for ent in entities {
        let roles = ent
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let Some(org_str) = extract_vcard_name_or_org(ent) {
            let rank = roles
                .iter()
                .filter_map(|r| role_rank.iter().position(|&wanted| wanted == r))
                .min()
                .unwrap_or(role_rank.len());
            candidates.push((rank, org_str));
        } else if let Some(handle) = ent.get("handle").and_then(|h| h.as_str()) {
            let rank = roles
                .iter()
                .filter_map(|r| role_rank.iter().position(|&wanted| wanted == r))
                .min()
                .unwrap_or(role_rank.len());
            candidates.push((rank, handle.to_string()));
        }
    }

    // Pick the best-ranked
    candidates.sort_by_key(|(rank, _)| *rank);
    candidates
        .into_iter()
        .map(|(_, s)| s)
        .find(|s| !s.is_empty())
}

/// Extract a human-friendly name from vCard (prefer "fn", then "org")
fn extract_vcard_name_or_org(ent: &Value) -> Option<String> {
    let vcard = ent.get("vcardArray")?.as_array()?;
    if vcard.len() < 2 {
        return None;
    }
    let items = vcard.get(1)?.as_array()?;

    let mut fn_name: Option<String> = None;
    let mut org_name: Option<String> = None;

    for item in items {
        // Typical vCard field: ["fn", {}, "text", "Example Org"]
        // OR: ["org", {}, "text", "Example Org"]
        if let Some(field) = item.get(0).and_then(|v| v.as_str()) {
            let val = item
                .get(3)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if val.is_empty() {
                continue;
            }
            match field {
                "fn" if fn_name.is_none() => fn_name = Some(val),
                "org" if org_name.is_none() => org_name = Some(val),
                _ => {}
            }
        }
    }

    fn_name.or(org_name)
}

/// Extract CIDRs using the "cidr0_cidrs" extension if present.
/// Commonly used by ARIN/RIPE for precise coverage.
fn extract_cidrs(root: &Value) -> Vec<String> {
    let mut out = Vec::new();

    if let Some(arr) = root.get("cidr0_cidrs").and_then(|v| v.as_array()) {
        for cidr in arr {
            // Two forms observed: { "v4prefix": "192.0.2.0", "length": 24 }
            // or { "v6prefix": "2001:db8::", "length": 32 }
            if let Some(prefix) = cidr.get("v4prefix").and_then(|v| v.as_str()) {
                if let Some(len) = cidr.get("length").and_then(|v| v.as_u64()) {
                    out.push(format!("{}/{}", prefix, len));
                }
            } else if let Some(prefix) = cidr.get("v6prefix").and_then(|v| v.as_str()) {
                if let Some(len) = cidr.get("length").and_then(|v| v.as_u64()) {
                    out.push(format!("{}/{}", prefix, len));
                }
            }
        }
    }

    // Fallback: sometimes "handle" looks like a CIDR (rare)
    if out.is_empty() {
        if let Some(handle) = root.get("handle").and_then(|h| h.as_str()) {
            if looks_like_cidr(handle) {
                out.push(handle.to_string());
            }
        }
    }

    out
}

fn looks_like_cidr(s: &str) -> bool {
    s.contains('/') && (s.chars().filter(|&c| c == '/').count() == 1)
}

/// Extract range from "startAddress" and "endAddress"
fn extract_range(root: &Value) -> Option<(String, String)> {
    let start = root.get("startAddress").and_then(|v| v.as_str())?;
    let end = root.get("endAddress").and_then(|v| v.as_str())?;
    Some((start.to_string(), end.to_string()))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… ({} chars truncated)", &s[..max], s.len() - max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_as_number() {
        assert_eq!(parse_as_number("AS15169"), Some(15169));
        assert_eq!(parse_as_number("15169"), Some(15169));
        assert_eq!(parse_as_number("AS0"), Some(0));
        assert_eq!(parse_as_number("invalid"), None);
        assert_eq!(parse_as_number("AS"), None);
    }

    #[test]
    fn test_extract_as_from_text() {
        assert_eq!(extract_as_from_text("originated by AS15169"), Some(15169));
        assert_eq!(
            extract_as_from_text("This network is AS12345 managed"),
            Some(12345)
        );
        assert_eq!(extract_as_from_text("AS15169."), Some(15169)); // with punctuation
        assert_eq!(extract_as_from_text("no AS number here"), None);
    }

    #[test]
    fn test_extract_as_number_from_json() {
        // Test with arin_originas0_originautnums
        let json = json!({
            "arin_originas0_originautnums": [15169]
        });
        assert_eq!(extract_as_number(&json), Some(15169));

        // Test with entity handle
        let json = json!({
            "entities": [{
                "handle": "AS15169",
                "roles": ["registrant"]
            }]
        });
        assert_eq!(extract_as_number(&json), Some(15169));

        // Test with no AS number
        let json = json!({
            "entities": [{
                "handle": "GOOGLE",
                "roles": ["registrant"]
            }]
        });
        assert_eq!(extract_as_number(&json), None);
    }
}
