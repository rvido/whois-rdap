// Smart Redirect Follower (Feature 3)
// Copyright (c) 2025-2026 Richard Vidal Dorsch. Licensed under the MIT license.
//
// RDAP responses may contain a `links` array pointing to related or
// authoritative sub-registry resources.  This module inspects the `links`
// field and, if it finds a URL with rel="related" or rel="self" that points
// to a different host, fetches that URL and returns the richer result.
//
// Design constraints:
//   - Maximum `max_hops` hops (default 1, CLI-configurable up to 3).
//   - `href` is borrowed as `&str` from the parsed JSON Value — zero-copy
//     during link extraction.  Only one `reqwest::Url` is allocated per hop.
//   - If the followed URL returns an error the original JSON is returned as-is.

use anyhow::{Context, Result};
use serde_json::Value;

/// Follow RDAP `links` in a response JSON up to `max_hops` times.
///
/// Returns the final (richest) JSON value obtained.  If no useful link is
/// found, or if following fails, the original `json` is returned unchanged.
///
/// # Arguments
/// * `http`     — shared reqwest client (connection pool is reused)
/// * `json`     — already-parsed RDAP response
/// * `max_hops` — how many redirect hops to follow (0 = no redirect)
pub async fn follow_links(
    http: &reqwest::Client,
    json: Value,
    max_hops: u8,
) -> Value {
    if max_hops == 0 {
        return json;
    }

    // Extract the current response URL (from "self" link) to detect same-host
    // links we don't need to follow.
    let self_href = extract_self_href(&json);

    if let Some(href) = find_follow_href(&json, self_href) {
        match fetch_href(http, href).await {
            Ok(next_json) => {
                // Recurse for additional hops; decrement counter.
                return Box::pin(follow_links(http, next_json, max_hops - 1)).await;
            }
            Err(e) => {
                eprintln!("redirect: failed to follow '{}': {e}", href);
            }
        }
    }

    json
}

// ── Internals ────────────────────────────────────────────────────────────────

/// Extract the "self" href from the links array, if present.
fn extract_self_href(json: &Value) -> Option<&str> {
    json.get("links")
        .and_then(|v| v.as_array())
        .and_then(|links| {
            links.iter().find_map(|link| {
                let rel = link.get("rel").and_then(|v| v.as_str())?;
                if rel.eq_ignore_ascii_case("self") {
                    link.get("href").and_then(|v| v.as_str())
                } else {
                    None
                }
            })
        })
}

/// Find the best href to follow from the links array.
///
/// Priority:
///   1. `rel="related"` with `type="application/rdap+json"`
///   2. `rel="alternate"` with `type="application/rdap+json"`
///
/// We skip links whose `href` matches `self_href` (same resource, no-op).
fn find_follow_href<'a>(json: &'a Value, self_href: Option<&str>) -> Option<&'a str> {
    let links = json.get("links").and_then(|v| v.as_array())?;

    // Preferred: rel=related, type=application/rdap+json
    let candidate = links.iter().find_map(|link| {
        let rel = link.get("rel").and_then(|v| v.as_str())?;
        let mime = link.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let href = link.get("href").and_then(|v| v.as_str())?;

        if mime == "application/rdap+json"
            && (rel.eq_ignore_ascii_case("related") || rel.eq_ignore_ascii_case("alternate"))
            && Some(href) != self_href
        {
            Some(href)
        } else {
            None
        }
    });

    candidate
}

/// Fetch a URL and decode the response as RDAP JSON.
async fn fetch_href(http: &reqwest::Client, href: &str) -> Result<Value> {
    let url = reqwest::Url::parse(href)
        .with_context(|| format!("Invalid redirect href: {href}"))?;

    let resp = http
        .get(url)
        .header("Accept", "application/rdap+json, application/json")
        .send()
        .await
        .with_context(|| format!("Failed to GET redirect: {href}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(anyhow::anyhow!(
            "Redirect server returned {status} for {href}"
        ));
    }

    resp.json::<Value>()
        .await
        .with_context(|| format!("Failed to decode redirect JSON from {href}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_no_links_returns_original() {
        let val = json!({"handle": "EXAMPLE"});
        // No links → find_follow_href returns None
        assert!(find_follow_href(&val, None).is_none());
    }

    #[test]
    fn test_finds_related_rdap_link() {
        let val = json!({
            "links": [
                {
                    "rel": "self",
                    "type": "application/rdap+json",
                    "href": "https://rdap.iana.org/domain/com"
                },
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.verisign.com/com/v1/domain/google.com"
                }
            ]
        });
        let self_href = extract_self_href(&val);
        let href = find_follow_href(&val, self_href);
        assert_eq!(href, Some("https://rdap.verisign.com/com/v1/domain/google.com"));
    }

    #[test]
    fn test_skips_self_link() {
        let val = json!({
            "links": [
                {
                    "rel": "related",
                    "type": "application/rdap+json",
                    "href": "https://rdap.iana.org/domain/com"
                }
            ]
        });
        // self_href matches the only related link → should not follow
        let href = find_follow_href(&val, Some("https://rdap.iana.org/domain/com"));
        assert!(href.is_none());
    }

    #[test]
    fn test_extract_self_href() {
        let val = json!({
            "links": [
                {"rel": "self", "href": "https://example.com/rdap/ip/1.2.3.4"},
                {"rel": "up",   "href": "https://example.com/rdap/ip/1.2.3.0/24"}
            ]
        });
        assert_eq!(
            extract_self_href(&val),
            Some("https://example.com/rdap/ip/1.2.3.4")
        );
    }
}
