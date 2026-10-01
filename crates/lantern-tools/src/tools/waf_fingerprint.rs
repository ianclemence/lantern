//! Passive WAF/CDN fingerprinting from an ordinary HTTP response.
//!
//! The real-world case this exists for: `host_nuclei` or `host_sqlmap` comes
//! back with zero findings, and that result means two completely different
//! things depending on whether a WAF sat in front of the target. A silent
//! Cloudflare/Akamai/Imperva block looks identical to "the application is
//! clean" in a tool's own output - the only way to tell them apart is to
//! check for the WAF/CDN first, which is exactly what a human pentester does
//! before trusting a scanner's "nothing found."
//!
//! This is signature matching against headers and cookies from one ordinary
//! request - no payloads, no probing, nothing a WAF would itself flag as an
//! attack. Same risk tier as `http_probe`, not gated behind `--offensive`.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;

/// (vendor, header name, value substring to match - empty means "header is
/// merely present"). Checked case-insensitively against response headers.
const HEADER_SIGNATURES: &[(&str, &str, &str)] = &[
    ("Cloudflare", "cf-ray", ""),
    ("Cloudflare", "server", "cloudflare"),
    ("Akamai", "x-akamai-transformed", ""),
    ("Akamai", "akamai-grn", ""),
    ("Akamai (Kona WAF)", "x-akamai-request-id", ""),
    ("Imperva Incapsula", "x-iinfo", ""),
    ("Imperva Incapsula", "x-cdn", "incapsula"),
    ("Sucuri", "x-sucuri-id", ""),
    ("Sucuri", "x-sucuri-cache", ""),
    ("Sucuri", "server", "sucuri"),
    ("AWS CloudFront", "x-amz-cf-id", ""),
    ("AWS CloudFront", "x-amz-cf-pop", ""),
    ("AWS WAF", "x-amzn-waf-action", ""),
    ("Fastly", "x-served-by", "cache-"),
    ("Fastly", "fastly-debug-digest", ""),
    ("F5 BIG-IP ASM", "x-waf-event-info", ""),
    ("Azure Front Door", "x-azure-ref", ""),
    ("Azure Front Door", "x-fd-edgeenvironment", ""),
    ("Google Cloud Armor / GCLB", "via", "google"),
    ("Barracuda WAF", "server", "barracuda"),
    ("StackPath", "server", "stackpath"),
    ("Cloudflare", "server", "cloudflare"),
];

/// (vendor, cookie-name substring). Checked against every `Set-Cookie` value.
const COOKIE_SIGNATURES: &[(&str, &str)] = &[
    ("Cloudflare", "__cfduid"),
    ("Cloudflare", "cf_clearance"),
    ("Imperva Incapsula", "incap_ses"),
    ("Imperva Incapsula", "visid_incap"),
    ("F5 BIG-IP", "ts01"),
    ("F5 BIG-IP", "bigipserver"),
    ("Citrix NetScaler", "ns_af"),
    ("Citrix NetScaler", "citrix_ns_id"),
    ("Barracuda WAF", "barra_counter_session"),
];

/// A 403/406 body that *names itself* - most WAF block pages do, since the
/// vendor wants the visitor to know who stopped them.
const BODY_SIGNATURES: &[(&str, &str)] = &[
    ("Cloudflare", "attention required! | cloudflare"),
    ("Cloudflare", "cloudflare ray id"),
    ("Akamai", "access denied</title>\n<style>body"),
    ("Imperva Incapsula", "incapsula incident id"),
    ("Sucuri", "sucuri website firewall"),
    ("F5 BIG-IP ASM", "the requested url was rejected"),
    ("Barracuda WAF", "you have been blocked"),
    ("ModSecurity", "mod_security"),
    ("ModSecurity", "modsecurity"),
];

pub struct WafFingerprint;

impl Tool for WafFingerprint {
    fn name(&self) -> &'static str {
        "waf_fingerprint"
    }

    fn description(&self) -> &'static str {
        "Fingerprint a WAF/CDN in front of an in-scope URL from one ordinary HTTP \
         response (headers, cookies, a block page's own self-identification) - no \
         payloads, nothing a WAF would itself flag. Run this before trusting a \
         zero-finding sqlmap/nuclei result: a silent block looks identical to a clean \
         application in that tool's own output."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "in-scope http(s) url or bare host"}
            },
            "required": ["url"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let raw = super::str_field(&input, "url")?;
            let url = super::http_probe::normalize_target(&raw);
            let authority = url
                .split("://")
                .nth(1)
                .unwrap_or(&url)
                .split('/')
                .next()
                .unwrap_or(&url);
            ctx.check_scope(authority)?;

            let resp = match ctx.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(ToolOutput::failed(format!("waf_fingerprint: request failed: {e}")))
                }
            };
            let status = resp.status().as_u16();
            let mut hits: Vec<(String, String)> = Vec::new();

            for (name, value) in resp.headers().iter() {
                let name_l = name.as_str().to_ascii_lowercase();
                let value_l = value.to_str().unwrap_or("").to_ascii_lowercase();
                if name_l == "set-cookie" {
                    for (vendor, needle) in COOKIE_SIGNATURES {
                        if value_l.contains(needle) {
                            hits.push((vendor.to_string(), format!("cookie `{needle}`")));
                        }
                    }
                }
                for (vendor, hdr, needle) in HEADER_SIGNATURES {
                    if name_l == *hdr && (needle.is_empty() || value_l.contains(needle)) {
                        hits.push((vendor.to_string(), format!("header `{hdr}`")));
                    }
                }
            }

            let body = resp.text().await.unwrap_or_default();
            let body_head: String = body.chars().take(20_000).collect();
            let body_l = body_head.to_ascii_lowercase();
            for (vendor, needle) in BODY_SIGNATURES {
                if body_l.contains(needle) {
                    hits.push((vendor.to_string(), "response body".into()));
                }
            }

            // Dedup vendor -> evidence list, keep order stable.
            let mut by_vendor: Vec<(String, Vec<String>)> = Vec::new();
            for (vendor, evidence) in hits {
                match by_vendor.iter_mut().find(|(v, _)| *v == vendor) {
                    Some((_, ev)) => {
                        if !ev.contains(&evidence) {
                            ev.push(evidence);
                        }
                    }
                    None => by_vendor.push((vendor, vec![evidence])),
                }
            }

            let summary = if by_vendor.is_empty() {
                format!(
                    "waf_fingerprint: no known WAF/CDN signature on {authority} (HTTP {status}) \
                     - absence of evidence, not evidence of absence"
                )
            } else {
                let names: Vec<String> = by_vendor
                    .iter()
                    .map(|(v, ev)| format!("{v} ({})", ev.join(", ")))
                    .collect();
                format!(
                    "waf_fingerprint: {} on {authority} (HTTP {status}) - read any \
                     zero-finding scan of this target with that in mind",
                    names.join("; ")
                )
            };

            let data = json!({
                "url": url,
                "status": status,
                "detected": by_vendor.iter().map(|(v, ev)| json!({"vendor": v, "evidence": ev})).collect::<Vec<_>>(),
            });
            Ok(ToolOutput::ok(summary, data))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_tables_have_no_empty_entries() {
        for (vendor, hdr, _) in HEADER_SIGNATURES {
            assert!(!vendor.is_empty() && !hdr.is_empty());
            assert_eq!(*hdr, hdr.to_ascii_lowercase(), "header names must be pre-lowercased");
        }
        for (vendor, needle) in COOKIE_SIGNATURES {
            assert!(!vendor.is_empty() && !needle.is_empty());
            assert_eq!(*needle, needle.to_ascii_lowercase());
        }
        for (vendor, needle) in BODY_SIGNATURES {
            assert!(!vendor.is_empty() && !needle.is_empty());
            assert_eq!(*needle, needle.to_ascii_lowercase());
        }
    }

    #[tokio::test]
    async fn out_of_scope_target_is_refused() {
        let ctx = super::super::test_ctx_scoped("10.0.0.0/8");
        let err = WafFingerprint
            .execute(json!({"url": "https://evil.example"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("scope"), "{err}");
    }

    #[test]
    fn missing_url_is_rejected() {
        assert!(super::super::str_field(&json!({}), "url").is_err());
    }
}
