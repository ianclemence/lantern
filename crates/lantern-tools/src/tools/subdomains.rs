//! Passive subdomain discovery via certificate-transparency logs.
//!
//! Modern attack-surface mapping starts here: every publicly trusted TLS
//! certificate is logged (CT, RFC 9162), and a host that was never otherwise
//! advertised still shows up the moment anyone issues it a certificate - a
//! staging box, an old marketing site, an internal tool put behind a public
//! cert by mistake. This queries crt.sh's public index, which aggregates
//! those logs; it touches no target infrastructure at all - it is a lookup
//! against a third-party's existing archive, exactly like `whois` or
//! `web_search` already are.
//!
//! What this tool returns is *candidates*, not scope: a name appearing here
//! was once certified for the domain, nothing more. It may be retired,
//! parked, or - because a cert can legitimately cover `*.other-domain.com`
//! as a SAN - naming infrastructure that was never part of this engagement
//! at all. Every result is labelled against the flow's own scope so the
//! model (and the operator reading the report) can see at a glance which
//! ones are already authorised and which would need the scope widened
//! before any other tool may touch them; nothing here grants that scope
//! itself.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

/// Hard cap on distinct names returned, so a wildly over-certified domain
/// (shared hosting, a CDN) cannot blow the token/output budget.
const MAX_RESULTS: usize = 300;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub struct SubdomainEnum;

impl Tool for SubdomainEnum {
    fn name(&self) -> &'static str {
        "subdomain_enum"
    }

    fn description(&self) -> &'static str {
        "Passive subdomain discovery for an in-scope domain via certificate-transparency \
         logs (crt.sh). Touches no target infrastructure - it is a lookup against a \
         public third-party archive, like whois or web_search. Returns candidate names \
         only, each labelled in-scope or not: a name appearing here is not itself \
         authorisation to run any other tool against it until the operator's --scope \
         covers it."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "apex or subdomain to search, must be in scope"}
            },
            "required": ["domain"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let domain = super::str_field(&input, "domain")?;
            let domain = domain.trim().trim_start_matches("*.").to_ascii_lowercase();
            if domain.is_empty() || domain.contains(|c: char| c.is_whitespace()) {
                anyhow::bail!("invalid `domain`");
            }
            ctx.check_scope(&domain)?;

            if ctx.config.offline {
                return Ok(ToolOutput::failed("subdomain_enum disabled: offline mode"));
            }

            // crt.sh's query syntax: a literal `%` wildcard-matches the CT log
            // index server-side; this is not a shell/SQL string built from
            // operator input beyond the one scope-checked domain, and no
            // interpolation happens anywhere else in the request.
            let url = format!(
                "https://crt.sh/?q=%25.{}&output=json",
                urlencode(&domain)
            );

            let resp = match ctx.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(ToolOutput::failed(format!(
                        "subdomain_enum: request to crt.sh failed: {e}"
                    )))
                }
            };
            if !resp.status().is_success() {
                let status = resp.status();
                return Ok(ToolOutput::failed(format!(
                    "subdomain_enum: crt.sh returned HTTP {status}"
                )));
            }
            let body = resp.text().await.unwrap_or_default();

            // crt.sh has, at times, emitted back-to-back JSON arrays rather
            // than one well-formed document under load; tolerate that by
            // parsing every `[...]` array found in the body independently
            // instead of failing the whole call on one malformed response.
            let mut names: BTreeSet<String> = BTreeSet::new();
            for chunk in split_json_arrays(&body) {
                if let Ok(entries) = serde_json::from_str::<Vec<CrtShEntry>>(chunk) {
                    for e in entries {
                        for line in e.name_value.split('\n') {
                            let n = line.trim().trim_start_matches("*.").to_ascii_lowercase();
                            if !n.is_empty() && n.contains('.') {
                                names.insert(n);
                            }
                        }
                    }
                }
            }

            let total_found = names.len();
            let mut in_scope = Vec::new();
            let mut out_of_scope = Vec::new();
            for n in names.into_iter().take(MAX_RESULTS) {
                if ctx.scope.allows(&n) {
                    in_scope.push(n);
                } else {
                    out_of_scope.push(n);
                }
            }

            let summary = if total_found == 0 {
                format!("subdomain_enum: no certificate-transparency records for {domain}")
            } else {
                format!(
                    "subdomain_enum: {total_found} distinct name(s) for {domain} \
                     ({} in scope, {} not){}",
                    in_scope.len(),
                    out_of_scope.len(),
                    if total_found > MAX_RESULTS {
                        format!(", capped at {MAX_RESULTS}")
                    } else {
                        String::new()
                    }
                )
            };

            let data = json!({
                "domain": domain,
                "total_found": total_found,
                "in_scope": in_scope,
                "out_of_scope_sample": out_of_scope.into_iter().take(50).collect::<Vec<_>>(),
                "source": "crt.sh (certificate transparency)",
                "note": "candidates only; a name here is not authorization to scan it",
            });

            Ok(ToolOutput::ok(summary, data))
        })
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Split a body that may contain one or more back-to-back `[...]` JSON array
/// documents into the individual array substrings, tracking bracket depth so
/// nested arrays inside objects don't trigger an early split.
fn split_json_arrays(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in body.char_indices() {
        match c {
            '[' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start.take() {
                        out.push(&body[s..=i]);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_is_conservative() {
        assert_eq!(urlencode("example.com"), "example.com");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a&b"), "a%26b");
    }

    #[test]
    fn splits_back_to_back_arrays() {
        let body = r#"[{"name_value":"a.example.com"}][{"name_value":"b.example.com"}]"#;
        let parts = split_json_arrays(body);
        assert_eq!(parts.len(), 2);
        let a: Vec<CrtShEntry> = serde_json::from_str(parts[0]).unwrap();
        assert_eq!(a[0].name_value, "a.example.com");
    }

    #[test]
    fn single_array_still_parses() {
        let body = r#"[{"name_value":"a.example.com\nb.example.com"}]"#;
        let parts = split_json_arrays(body);
        assert_eq!(parts.len(), 1);
        let entries: Vec<CrtShEntry> = serde_json::from_str(parts[0]).unwrap();
        assert_eq!(entries[0].name_value, "a.example.com\nb.example.com");
    }

    #[test]
    fn empty_or_malformed_body_yields_no_arrays() {
        assert!(split_json_arrays("").is_empty());
        assert!(split_json_arrays("not json at all").is_empty());
    }

    #[tokio::test]
    async fn domain_must_be_in_scope() {
        let ctx = super::super::test_ctx();
        let err = SubdomainEnum
            .execute(json!({"domain": "definitely-out-of-scope.invalid"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("scope"), "{err}");
    }

    #[test]
    fn rejects_malformed_domain_input() {
        assert!(super::super::str_field(&json!({}), "domain").is_err());
    }
}
