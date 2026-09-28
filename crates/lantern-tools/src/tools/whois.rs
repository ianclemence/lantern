//! Minimal native WHOIS client over TCP/43 with IANA referral following.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const QUERY_LIMIT_BYTES: usize = 16 * 1024;
const HOPS: usize = 2;

/// Fields worth extracting from free-form WHOIS text.
const KEYS: &[(&str, &[&str])] = &[
    ("registrar", &["Registrar:", "registrar:"]),
    ("organization", &["OrgName:", "org-name:", "Organisation:", "Registrant Organization:"]),
    ("creation_date", &["Creation Date:", "created:", "Registered on:"]),
    ("expiry_date", &["Registry Expiry Date:", "expires:", "Expiry date:"]),
    ("updated_date", &["Updated Date:", "last-modified:"]),
    ("name_servers", &["Name Server:", "nserver:"]),
    ("registrant_country", &["Registrant Country:", "country:"]),
    ("abuse_email", &["OrgAbuseEmail:", "Registrar Abuse Contact Email:"]),
    ("status", &["Domain Status:", "state:"]),
];

async fn whois_query(server: &str, query: &str) -> anyhow::Result<String> {
    let addr = format!("{server}:43");
    let mut stream =
        tokio::time::timeout(Duration::from_secs(8), tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| anyhow::anyhow!("timeout connecting to {addr}"))?
            .map_err(|e| anyhow::anyhow!("connect {addr}: {e}"))?;

    let payload = format!("{query}\r\n");
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(payload.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("timeout writing to {addr}"))?
        .map_err(|e| anyhow::anyhow!("write {addr}: {e}"))?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    loop {
        match tokio::time::timeout(Duration::from_secs(8), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= QUERY_LIMIT_BYTES {
                    break;
                }
            }
            Ok(Err(e)) => {
                if buf.is_empty() {
                    return Err(anyhow::anyhow!("read {addr}: {e}"));
                }
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Pull the `refer:`/`whois:` server out of an IANA response.
pub fn referral(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("refer:") {
            return Some(v.trim().to_string());
        }
        if let Some(v) = lower.strip_prefix("whois:") {
            let v = v.trim();
            if !v.is_empty() && v != "whois.iana.org" {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub fn extract_fields(text: &str) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let mut lines_out: Vec<String> = Vec::new();
    for (field, keys) in KEYS {
        let mut values: Vec<String> = Vec::new();
        for line in text.lines() {
            for k in *keys {
                if let Some(v) = line.strip_prefix(k) {
                    let v = v.trim();
                    if !v.is_empty() && !values.iter().any(|x| x == v) {
                        values.push(v.chars().take(160).collect());
                    }
                }
            }
            if values.len() >= 8 {
                break;
            }
        }
        if !values.is_empty() {
            if values.len() == 1 {
                out.insert(field.to_string(), json!(values[0]));
            } else {
                out.insert(field.to_string(), json!(values));
            }
        }
    }
    // A short excerpt of the raw text for the model.
    for line in text.lines().take(6) {
        let l = line.trim();
        if !l.is_empty() {
            lines_out.push(l.chars().take(200).collect());
        }
    }
    out.insert("_excerpt".to_string(), json!(lines_out));
    serde_json::Value::Object(out)
}

pub struct Whois;

impl Tool for Whois {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn description(&self) -> &'static str {
        "WHOIS over TCP/43 for an in-scope domain or IP: registrar, registration and \
         expiry dates, name servers and status. Follows IANA referrals."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "domain name or IP, must be in scope"}
            },
            "required": ["target"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let target = super::str_field(&input, "target")?;
            ctx.check_scope(&target)?;

            let is_ip = target.parse::<std::net::IpAddr>().is_ok();
            // IPs need a registry choice; start with ARIN and follow referrals.
            let seed = if is_ip { "whois.arin.net" } else { "whois.iana.org" };

            let mut server = seed.to_string();
            let query = target.clone();
            let mut hops = 0;
            let mut raw = String::new();
            let mut trail: Vec<String> = Vec::new();

            loop {
                trail.push(server.clone());
                match whois_query(&server, &query).await {
                    Ok(text) => {
                        raw = text;
                        if hops >= HOPS {
                            break;
                        }
                        let next = if is_ip && hops == 0 {
                            referral(&raw)
                                .or_else(|| raw.lines().find_map(|l| {
                                    let ll = l.to_ascii_lowercase();
                                    ll.strip_prefix("referralserver:")
                                        .map(|v| v.trim().trim_start_matches("whois://").to_string())
                                }))
                        } else {
                            referral(&raw)
                        };
                        match next {
                            Some(s) if !trail.contains(&s) => {
                                server = s;
                                hops += 1;
                            }
                            _ => break,
                        }
                    }
                    Err(e) => {
                        if raw.is_empty() {
                            return Ok(ToolOutput::failed(format!(
                                "whois lookup for {target} failed: {e}"
                            )));
                        }
                        break;
                    }
                }
            }

            if raw.trim().is_empty() {
                return Ok(ToolOutput::failed(format!(
                    "whois returned no data for {target}"
                )));
            }

            let fields = extract_fields(&raw);
            let expiry = fields
                .get("expiry_date")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let summary = format!(
                "whois {target}: registrar={} expiry={} servers={}",
                fields
                    .get("registrar")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                expiry,
                trail.join(" -> ")
            );

            let artifact = ctx.write_artifact("whois.txt", raw.as_bytes())?;
            Ok(ToolOutput::ok(summary, json!({
                "target": target,
                "fields": fields,
                "servers": trail,
                "bytes": raw.len(),
            }))
            .with_artifacts(vec![artifact]))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_referral_and_fields() {
        let iana = "domain:       EXAMPLE.COM\nrefer:        whois.nic.example\nwhois:       whois.nic.example\n";
        assert_eq!(referral(iana).as_deref(), Some("whois.nic.example"));

        let reg = "Registrar: Example Registrar Inc\nRegistry Expiry Date: 2027-01-02T00:00:00Z\nName Server: NS1.EXAMPLE.COM\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n";
        let f = extract_fields(reg);
        assert_eq!(f["registrar"], "Example Registrar Inc");
        assert_eq!(f["expiry_date"], "2027-01-02T00:00:00Z");
        assert!(f["name_servers"].is_string() || f["name_servers"].is_array());
        assert!(f.get("_excerpt").is_some());
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = Whois
            .execute(json!({"target": "example.net"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn live_query_or_graceful_failure() {
        // Outbound 43/tcp is often filtered; either a real answer or a clean
        // failure is acceptable, a hang or panic is not.
        let ctx_scope_free = super::super::test_ctx();
        // test_ctx() allows *.example.com, which is reserved and safe to query.
        let out = Whois
            .execute(json!({"target": "example.com"}), &ctx_scope_free)
            .await;
        match out {
            Ok(o) => assert!(!o.summary.is_empty()),
            Err(e) => assert!(
                e.to_string().contains("whois") || e.to_string().contains("scope"),
                "unexpected error kind: {e}"
            ),
        }
    }
}
