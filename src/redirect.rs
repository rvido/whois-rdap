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
/// Returns the final (richest) JSON value obtained, plus the href of the
/// last successfully-fetched hop (`None` if no redirect was followed) — the
/// caller needs this to report which server the data actually came from,
/// since it can differ from the server that was originally queried.  If no
/// useful link is found, or if following fails, the original `json` is
/// returned unchanged.
///
/// # Arguments
/// * `http`     — shared reqwest client (connection pool is reused)
/// * `json`     — already-parsed RDAP response
/// * `max_hops` — how many redirect hops to follow (0 = no redirect)
pub async fn follow_links(
    http: &reqwest::Client,
    json: Value,
    max_hops: u8,
) -> (Value, Option<String>) {
    if max_hops == 0 {
        return (json, None);
    }

    // Extract the current response URL (from "self" link) to detect same-host
    // links we don't need to follow.
    let self_href = extract_self_href(&json);

    if let Some(href) = find_follow_href(&json, self_href) {
        match fetch_href(http, href).await {
            Ok(next_json) => {
                // Recurse for additional hops; decrement counter.
                let href = href.to_string();
                let (final_json, deeper_href) =
                    Box::pin(follow_links(http, next_json, max_hops - 1)).await;
                return (final_json, Some(deeper_href.unwrap_or(href)));
            }
            Err(e) => {
                eprintln!("redirect: failed to follow '{}': {e}", href);
            }
        }
    }

    (json, None)
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

/// True if `mime` is the RDAP JSON media type, ignoring case and any
/// trailing parameters (e.g. `"Application/RDAP+JSON;charset=UTF-8"`).
fn is_rdap_json_type(mime: &str) -> bool {
    mime.split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .eq_ignore_ascii_case("application/rdap+json")
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
    links.iter().find_map(|link| {
        let rel = link.get("rel").and_then(|v| v.as_str())?;
        let mime = link.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let href = link.get("href").and_then(|v| v.as_str())?;

        if is_rdap_json_type(mime)
            && (rel.eq_ignore_ascii_case("related") || rel.eq_ignore_ascii_case("alternate"))
            && Some(href) != self_href
        {
            Some(href)
        } else {
            None
        }
    })
}

/// Fetch an RDAP `links` href and decode the response as RDAP JSON.
///
/// The href was supplied by a remote RDAP server, so it is untrusted: it must
/// be HTTPS and resolve only to public addresses. `get_guarded` re-applies the
/// same check to any HTTP redirect the target then issues.
async fn fetch_href(http: &reqwest::Client, href: &str) -> Result<Value> {
    let url =
        reqwest::Url::parse(href).with_context(|| format!("Invalid redirect href: {href}"))?;

    crate::http::validate_untrusted_url(&url)
        .await
        .with_context(|| format!("Refusing to follow redirect: {href}"))?;

    let fetched = crate::http::get_guarded(http, url, Some(crate::RDAP_ACCEPT)).await?;

    if !fetched.status.is_success() {
        let status = fetched.status;
        return Err(anyhow::anyhow!(
            "Redirect server returned {status} for {href}"
        ));
    }

    serde_json::from_slice(&fetched.body)
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
        assert_eq!(
            href,
            Some("https://rdap.verisign.com/com/v1/domain/google.com")
        );
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
    fn test_finds_related_link_with_charset_and_case_variant_type() {
        let val = json!({
            "links": [
                {
                    "rel": "related",
                    "type": "Application/RDAP+JSON;charset=UTF-8",
                    "href": "https://rdap.verisign.com/com/v1/domain/google.com"
                }
            ]
        });
        let href = find_follow_href(&val, None);
        assert_eq!(
            href,
            Some("https://rdap.verisign.com/com/v1/domain/google.com")
        );
    }

    #[tokio::test]
    async fn test_fetch_href_rejects_non_https_scheme() {
        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let err = fetch_href(&http, "http://example.com/rdap/domain/example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refusing to follow redirect"));
    }

    #[tokio::test]
    async fn test_fetch_href_rejects_private_ip_literal() {
        let http = crate::build_reqwest_client(std::time::Duration::from_secs(5)).unwrap();
        let err = fetch_href(&http, "https://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refusing to follow redirect"));
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
