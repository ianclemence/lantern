//! TLS certificate inspection using the system OpenSSL (via native-tls) and
//! x509-parser. No `openssl s_client` child process needed.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Duration;
use tokio_native_tls::native_tls;

/// Does `name` match the certificate's SAN/CN?
pub fn name_matches(name: &str, sans: &[String], subject_cn: Option<&str>) -> bool {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    let candidates: Vec<String> = sans
        .iter()
        .map(|s| s.as_str())
        .chain(subject_cn.into_iter())
        .map(|c| c.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();

    for c in candidates {
        if let Some(suffix) = c.strip_prefix("*.") {
            // Wildcard matches exactly one label, and not the apex itself.
            let name_labels: Vec<&str> = name.split('.').collect();
            let suffix_labels: Vec<&str> = suffix.split('.').collect();
            if name_labels.len() == suffix_labels.len() + 1
                && name.ends_with(&format!(".{suffix}"))
            {
                return true;
            }
        } else if c == name {
            return true;
        }
    }
    false
}

pub struct TlsInspect;

impl Tool for TlsInspect {
    fn name(&self) -> &'static str {
        "tls_inspect"
    }

    fn description(&self) -> &'static str {
        "Open a TLS connection to an in-scope host and report certificate subject, \
         issuer, validity window, SANs, signature algorithm, hostname match and \
         days until expiry."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "hostname or IP, must be in scope"},
                "port": {"type": "integer", "description": "default 443"},
                "servername": {"type": "string", "description": "SNI / expected name, defaults to host"}
            },
            "required": ["host"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let host = super::str_field(&input, "host")?;
            ctx.check_scope(&host)?;
            let port = super::opt_u64(&input, "port", 443).min(65_535) as u16;
            let servername =
                super::opt_str_field(&input, "servername").unwrap_or_else(|| host.clone());

            // Certificates are validated for parsing, not for trust: an
            // assessment tool must see expired/untrusted certs too.
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| anyhow::anyhow!("building tls connector: {e}"))?;

            let addr = format!("{host}:{port}");
            let stream = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            .map_err(|_| anyhow::anyhow!("connect to {addr} timed out"))?
            .map_err(|e| anyhow::anyhow!("connect to {addr}: {e}"))?;

            let tls = tokio_native_tls::TlsConnector::from(connector)
                .connect(&servername, stream)
                .await
                .map_err(|e| anyhow::anyhow!("tls handshake with {addr} failed: {e}"))?;

            let cert = tls
                .get_ref()
                .peer_certificate()
                .map_err(|e| anyhow::anyhow!("reading peer certificate: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("peer sent no certificate"))?
                .to_der()
                .map_err(|e| anyhow::anyhow!("reading certificate der: {e}"))?;

            let (_, parsed) = x509_parser::parse_x509_certificate(&cert)
                .map_err(|e| anyhow::anyhow!("parsing certificate: {e}"))?;

            let subject = parsed.subject().to_string();
            let issuer = parsed.issuer().to_string();
            let cn = parsed
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .map(|s| s.to_string());

            let sans: Vec<String> = parsed
                .extensions()
                .iter()
                .filter_map(|e| match e.parsed_extension() {
                    x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                        Some(san)
                    }
                    _ => None,
                })
                .flat_map(|san| {
                    san.general_names
                        .iter()
                        .filter_map(|n| match n {
                            x509_parser::extensions::GeneralName::DNSName(d) => {
                                Some(d.to_string())
                            }
                            x509_parser::extensions::GeneralName::IPAddress(ip) => {
                                Some(format!("{}", ip.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".")))
                            }
                            _ => None,
                        })
                })
                .collect();

            let not_before = parsed.validity().not_before;
            let not_after = parsed.validity().not_after;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let expires_in_days = (not_after.timestamp() - now) / 86_400;
            let started_days_ago = (now - not_before.timestamp()) / 86_400;
            let expired = now > not_after.timestamp();

            let subject_cn_str = cn.clone();
            let matched = name_matches(&servername, &sans, subject_cn_str.as_deref());
            let self_signed = subject == issuer;
            let sig_alg = parsed.signature_algorithm.algorithm.to_string();
            let key_alg = parsed.public_key().algorithm.algorithm.to_string();
            let serial = parsed.raw_serial_as_string();

            let days_left = expires_in_days;
            let summary = format!(
                "TLS {servername}:{port} - {} issued by {} ({}), expires in {days_left} day(s){}{}",
                if expired { "EXPIRED cert" } else { "valid cert" },
                short(&issuer),
                short(&subject),
                if matched { "" } else { ", HOSTNAME MISMATCH" },
                if self_signed { ", self-signed" } else { "" },
            );

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "host": host,
                    "port": port,
                    "servername": servername,
                    "subject": subject,
                    "subject_cn": cn,
                    "issuer": issuer,
                    "serial": serial,
                    "not_before": not_before.timestamp(),
                    "not_after": not_after.timestamp(),
                    "not_before_rfc3339": not_before.to_string(),
                    "not_after_rfc3339": not_after.to_string(),
                    "expired": expired,
                    "days_until_expiry": days_left,
                    "days_since_issue": started_days_ago,
                    "san_count": sans.len(),
                    "subject_alternative_names": sans,
                    "hostname_matches": matched,
                    "self_signed": self_signed,
                    "signature_algorithm": sig_alg,
                    "key_algorithm": key_alg,
                }),
            ))
        })
    }
}

/// `CN=Foo, O=Bar` -> `Foo` for compact summaries.
fn short(dn: &str) -> String {
    dn.split(',')
        .next()
        .map(|s| {
            s.trim()
                .trim_start_matches("CN=")
                .trim_start_matches("cn=")
                .to_string()
        })
        .unwrap_or_else(|| dn.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_rules() {
        let sans = vec!["*.example.com".to_string(), "example.com".to_string()];
        assert!(name_matches("api.example.com", &sans, None));
        assert!(name_matches("EXAMPLE.COM", &sans, None));
        assert!(name_matches("a.b.example.com", &sans, None) == false, "two labels");
        assert!(!name_matches("example.org", &sans, None));
        assert!(name_matches("other.test", &[], Some("other.test")));
    }

    #[test]
    fn short_dn() {
        assert_eq!(short("CN=api.example.com, O=Acme"), "api.example.com");
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = TlsInspect
            .execute(json!({"host": "example.org"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn closed_port_is_a_clean_failure() {
        let out = TlsInspect
            .execute(
                json!({"host": "127.0.0.1", "port": 1}),
                &super::super::test_ctx(),
            )
            .await;
        assert!(out.is_err(), "no listener should error, not fabricate data");
    }
}
