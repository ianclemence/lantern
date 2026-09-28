//! DNS resolution via hickory-resolver (the host has no `dig`/`host` binary).

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use serde_json::json;
use std::time::Instant;

const RECORD_TYPES: &[(&str, RecordType)] = &[
    ("A", RecordType::A),
    ("AAAA", RecordType::AAAA),
    ("MX", RecordType::MX),
    ("NS", RecordType::NS),
    ("TXT", RecordType::TXT),
    ("CNAME", RecordType::CNAME),
    ("SOA", RecordType::SOA),
];

fn build_resolver() -> anyhow::Result<Resolver<TokioConnectionProvider>> {
    Ok(Resolver::<TokioConnectionProvider>::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build())
}

pub struct DnsLookup;

impl Tool for DnsLookup {
    fn name(&self) -> &'static str {
        "dns_lookup"
    }

    fn description(&self) -> &'static str {
        "Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for an in-scope name \
         or IP. Returns records plus any addresses found."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "hostname or IP, must be in scope"},
                "types": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["A","AAAA","MX","NS","TXT","CNAME","SOA"]},
                    "description": "defaults to all supported types"
                }
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

            let requested: Vec<String> = input
                .get("types")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                        .collect()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| RECORD_TYPES.iter().map(|(n, _)| n.to_string()).collect());

            let resolver = build_resolver()?;
            let started = Instant::now();
            let mut records = serde_json::Map::new();
            let mut errors: Vec<String> = Vec::new();
            let mut addresses: Vec<String> = Vec::new();

            // IP literals short-circuit: no query needed, just scope confirmation.
            if host.parse::<std::net::IpAddr>().is_ok() {
                addresses.push(host.clone());
            } else {
                match resolver.lookup_ip(&host).await {
                    Ok(ips) => {
                        for ip in ips.iter() {
                            addresses.push(ip.to_string());
                        }
                    }
                    Err(e) => errors.push(format!("A/AAAA: {e}")),
                }
            }

            for (name, rtype) in RECORD_TYPES {
                if !requested.iter().any(|t| t == name) {
                    continue;
                }
                match resolver.lookup(host.as_str(), *rtype).await {
                    Ok(lookup) => {
                        let values: Vec<String> =
                            lookup.iter().map(|r| r.to_string()).collect();
                        if !values.is_empty() {
                            records.insert(name.to_string(), json!(values));
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        // NXDOMAIN / no-data are normal, not failures worth reporting.
                        if !msg.to_lowercase().contains("no record found")
                            && !msg.to_lowercase().contains("no match")
                        {
                            errors.push(format!("{name}: {msg}"));
                        }
                    }
                }
            }

            let elapsed = started.elapsed().as_millis() as u64;
            let found: usize = records
                .values()
                .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
                .sum();
            let summary = if found == 0 && addresses.is_empty() {
                format!("dns: no usable records for {host} ({} errors)", errors.len())
            } else {
                format!(
                    "dns for {host}: {} address(es), {} record type(s) in {elapsed} ms",
                    addresses.len(),
                    records.len()
                )
            };

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "host": host,
                    "addresses": addresses,
                    "records": records,
                    "errors": errors,
                    "duration_ms": elapsed,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_localhost() {
        let out = DnsLookup
            .execute(
                json!({"host": "localhost", "types": ["A"]}),
                &super::super::test_ctx(),
            )
            .await
            .expect("lookup");
        assert!(out.ok, "{}", out.summary);
        assert!(
            !out.data["addresses"].as_array().unwrap().is_empty(),
            "localhost should resolve: {out:?}"
        );
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = DnsLookup
            .execute(json!({"host": "google.com"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn unknown_type_is_reported_not_fatal() {
        let out = DnsLookup
            .execute(
                json!({"host": "localhost", "types": ["TXT"]}),
                &super::super::test_ctx(),
            )
            .await
            .expect("lookup");
        assert!(out.ok, "TXT absence must not be an error: {}", out.summary);
    }
}
