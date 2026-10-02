//! Regex-based secret detection over text the flow already has.
//!
//! The real-world case: a researcher role fetches a page or a JS bundle with
//! `http_probe`, and that response body contains a live AWS key, a Stripe
//! secret key, or a hardcoded JWT - the kind of finding that happens
//! constantly in the wild (exposed `.env` files, source maps, webpack
//! bundles shipped with secrets baked in) and that nothing else in this
//! toolset looks for. This is gitleaks/trufflehog's core idea in miniature:
//! match known credential *shapes*, not content the model has to recognise
//! itself.
//!
//! No network access, no file access, no target of any kind - this operates
//! purely on a string the caller already has, so there is nothing to scope-
//! check. Matches are masked before they ever reach the model's context, the
//! database, or a report: this tool exists to flag that a secret is present
//! and where, never to carry the live credential value any further than it
//! has to.

use crate::registry::{Tool, ToolOutput};
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

/// Text larger than this is almost certainly a whole bundle, not the
/// snippet this tool is for; keep the model fetching smaller slices instead
/// of dumping megabytes of text into one call.
const MAX_TEXT_BYTES: usize = 200_000;

/// (kind, pattern). Patterns are deliberately conservative - shape-based,
/// not a guess at validity - so a hit is "this looks like a credential",
/// worth a human or coder-role second look, not a verified live secret.
const SIGNATURES: &[(&str, &str)] = &[
    ("AWS Access Key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key (heuristic)", r#"(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#),
    ("GCP API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Slack Token", r"\bxox[abprs]-[0-9A-Za-z-]{10,48}\b"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
    ("Stripe Live Secret Key", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("Stripe Live Publishable Key", r"\bpk_live_[0-9A-Za-z]{24,}\b"),
    ("GitHub Personal Access Token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("GitHub Fine-Grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
    ("Google OAuth Client Secret (heuristic)", r#"(?i)client_secret\s*[:=]\s*["']?(GOCSPX-[0-9A-Za-z_-]{20,})["']?"#),
    ("Generic Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    ("JSON Web Token", r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    ("Private Key Block", r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----"),
    ("Generic API Key Assignment (heuristic)", r#"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["']([0-9A-Za-z_\-]{20,})["']"#),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b"),
    ("SendGrid API Key", r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"),
    ("npm Access Token", r"\bnpm_[0-9A-Za-z]{36}\b"),
];

fn compiled() -> &'static [(&'static str, Regex)] {
    static CELL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        SIGNATURES
            .iter()
            .map(|(kind, pat)| {
                (
                    *kind,
                    Regex::new(pat).unwrap_or_else(|e| panic!("bad secret_scan pattern {kind}: {e}")),
                )
            })
            .collect()
    })
}

/// Show enough of a match to confirm the type without handing the model (or
/// a log, or a report) a usable credential: first 4 and last 4 characters,
/// the middle replaced regardless of length.
fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…({} chars)…{tail}", chars.len())
}

pub struct SecretScan;

impl Tool for SecretScan {
    fn name(&self) -> &'static str {
        "secret_scan"
    }

    fn description(&self) -> &'static str {
        "Scan a block of text already obtained by another tool (an HTTP response body, a \
         fetched script, captured command output) for credential-shaped strings - AWS/GCP \
         keys, Stripe/Slack/GitHub/Twilio/SendGrid tokens, JWTs, private key blocks, bearer \
         tokens. No network or file access; operates only on text you pass in. Matches are \
         reported masked - this flags that a secret is present and its kind, never the live \
         value."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "the text to scan, up to 200 KB"},
                "source": {"type": "string", "description": "where this text came from, e.g. a URL - for the report, not required"}
            },
            "required": ["text"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        _ctx: &'a crate::ctx::ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let text = super::str_field(&input, "text")?;
            if text.len() > MAX_TEXT_BYTES {
                anyhow::bail!(
                    "text is {} bytes, the cap is {MAX_TEXT_BYTES} - scan a smaller slice",
                    text.len()
                );
            }
            let source = super::opt_str_field(&input, "source").unwrap_or_default();

            let mut findings = Vec::new();
            for (kind, re) in compiled() {
                for m in re.find_iter(&text) {
                    // The "heuristic" assignment patterns capture a group for
                    // the value; everything else matches the whole token.
                    let matched = m.as_str();
                    findings.push(json!({
                        "kind": kind,
                        "masked": mask(matched),
                        "length": matched.chars().count(),
                        "offset": m.start(),
                    }));
                    if findings.len() >= 200 {
                        break;
                    }
                }
                if findings.len() >= 200 {
                    break;
                }
            }

            let summary = if findings.is_empty() {
                format!(
                    "secret_scan: no credential-shaped strings found{}",
                    if source.is_empty() { String::new() } else { format!(" in {source}") }
                )
            } else {
                let kinds: Vec<&str> = {
                    let mut k: Vec<&str> = findings
                        .iter()
                        .filter_map(|f| f.get("kind").and_then(|v| v.as_str()))
                        .collect();
                    k.sort_unstable();
                    k.dedup();
                    k
                };
                format!(
                    "secret_scan: {} possible secret(s){} - {}",
                    findings.len(),
                    if source.is_empty() { String::new() } else { format!(" in {source}") },
                    kinds.join(", ")
                )
            };

            let ok = findings.is_empty();
            Ok(ToolOutput::new(
                summary,
                json!({"source": source, "findings": findings}),
                // `ok: false` here does not mean the call failed - it means
                // there is something worth the reflector role's attention,
                // the same convention host-tool adapters use for "ran fine,
                // but look at this."
                ok,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::test_ctx;

    #[tokio::test]
    async fn finds_an_aws_key_and_masks_it() {
        let ctx = test_ctx();
        let text = "const cfg = { key: 'AKIAABCDEFGHIJKLMNOP', region: 'us-east-1' };";
        let out = SecretScan.execute(json!({"text": text}), &ctx).await.unwrap();
        assert!(!out.ok, "a found secret marks the result for attention");
        let findings = out.data["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["kind"], "AWS Access Key ID");
        let masked = findings[0]["masked"].as_str().unwrap();
        assert!(masked.starts_with("AKIA"));
        assert!(!masked.contains("ABCDEFGHIJKLMNOP"), "full key must never appear: {masked}");
    }

    #[tokio::test]
    async fn clean_text_reports_nothing() {
        let ctx = test_ctx();
        let out = SecretScan
            .execute(json!({"text": "<html><body>hello world</body></html>"}), &ctx)
            .await
            .unwrap();
        assert!(out.ok);
        assert!(out.data["findings"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn detects_a_private_key_block_and_a_jwt() {
        let ctx = test_ctx();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n\
                     token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let out = SecretScan.execute(json!({"text": text}), &ctx).await.unwrap();
        let kinds: Vec<&str> = out.data["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["kind"].as_str())
            .collect();
        assert!(kinds.contains(&"Private Key Block"), "{kinds:?}");
        assert!(kinds.contains(&"JSON Web Token"), "{kinds:?}");
    }

    #[tokio::test]
    async fn oversized_text_is_rejected_before_scanning() {
        let ctx = test_ctx();
        let huge = "a".repeat(MAX_TEXT_BYTES + 1);
        let err = SecretScan.execute(json!({"text": huge}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
    }

    #[test]
    fn mask_never_returns_the_full_short_value() {
        assert_eq!(mask("abc"), "***");
        let m = mask("AKIAABCDEFGHIJKLMNOP");
        assert!(m.starts_with("AKIA") && m.ends_with("NOP"));
        assert!(!m.contains("BCDEFGHIJKL"));
    }
}
