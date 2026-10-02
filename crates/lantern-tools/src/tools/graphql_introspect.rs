//! GraphQL schema introspection: maps the real query/mutation surface an
//! in-scope GraphQL endpoint exposes, and reports whether introspection
//! itself is enabled (most production deployments should disable it).
//! Passive: introspection is a read-only query against the schema, not
//! against application data, and this tool never calls a discovered field.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::{json, Value};

/// The standard introspection query, trimmed to what this tool actually
/// reports (type names/kinds and the query/mutation/subscription root
/// fields) rather than the full recursive field-and-arg tree every GraphQL
/// IDE requests - smaller request, smaller response, same verdict.
const INTROSPECTION_QUERY: &str = r#"{"query":"query LanternIntrospect { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}"#;

pub struct GraphQlIntrospect;

impl Tool for GraphQlIntrospect {
    fn name(&self) -> &'static str {
        "graphql_introspect"
    }

    fn description(&self) -> &'static str {
        "Query an in-scope GraphQL endpoint's introspection schema: whether introspection \
         is enabled, and if so, every named type and the query/mutation/subscription root \
         names. Passive - introspects the schema, never calls a discovered field."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "in-scope GraphQL endpoint, e.g. https://api.example.com/graphql"}
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

            let resp = match ctx
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(INTROSPECTION_QUERY)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => return Ok(ToolOutput::failed(format!("request to {url} failed: {e}"))),
            };
            let status = resp.status();
            let (text, truncated) = crate::fetch::read_capped_text(resp, 2 * 1024 * 1024).await;

            let body: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(ToolOutput::ok(
                        format!(
                            "graphql_introspect: {url} did not return JSON (status {status}) - \
                             likely not a GraphQL endpoint, or introspection is blocked upstream"
                        ),
                        json!({"url": url, "introspection_enabled": false, "status": status.as_u16()}),
                    ));
                }
            };

            if body.get("errors").is_some() && body.get("data").is_none() {
                let msg = body
                    .pointer("/errors/0/message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("introspection query rejected");
                return Ok(ToolOutput::ok(
                    format!("graphql_introspect: {url} - introspection disabled ({msg})"),
                    json!({
                        "url": url,
                        "introspection_enabled": false,
                        "status": status.as_u16(),
                        "error": msg,
                    }),
                ));
            }

            let schema = body.pointer("/data/__schema");
            let Some(schema) = schema else {
                return Ok(ToolOutput::ok(
                    format!("graphql_introspect: {url} - no `__schema` in the response (introspection likely disabled)"),
                    json!({"url": url, "introspection_enabled": false, "status": status.as_u16()}),
                ));
            };

            let query_type = schema.pointer("/queryType/name").and_then(|v| v.as_str());
            let mutation_type = schema.pointer("/mutationType/name").and_then(|v| v.as_str());
            let subscription_type =
                schema.pointer("/subscriptionType/name").and_then(|v| v.as_str());

            let type_names: Vec<String> = schema
                .get("types")
                .and_then(|v| v.as_array())
                .map(|types| {
                    types
                        .iter()
                        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
                        // GraphQL's own introspection/meta types (`__Schema`,
                        // `__Type`, ...) are implementation plumbing, not
                        // application surface worth reporting.
                        .filter(|n| !n.starts_with("__"))
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();

            let summary = format!(
                "graphql_introspect: {url} - introspection ENABLED, {} named type(s), query={}, \
                 mutation={}{}",
                type_names.len(),
                query_type.unwrap_or("none"),
                mutation_type.unwrap_or("none"),
                if truncated { " (response truncated)" } else { "" }
            );

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "url": url,
                    "introspection_enabled": true,
                    "query_type": query_type,
                    "mutation_type": mutation_type,
                    "subscription_type": subscription_type,
                    "type_count": type_names.len(),
                    "types": type_names,
                    "truncated": truncated,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = GraphQlIntrospect
            .execute(json!({"url": "https://example.org/graphql"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn reports_enabled_introspection_and_filters_meta_types() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = json!({
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "subscriptionType": Value::Null,
                            "types": [
                                {"name": "Query", "kind": "OBJECT"},
                                {"name": "Mutation", "kind": "OBJECT"},
                                {"name": "User", "kind": "OBJECT"},
                                {"name": "__Schema", "kind": "OBJECT"},
                            ]
                        }
                    }
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/graphql");
        let out = GraphQlIntrospect
            .execute(json!({"url": url}), &super::super::test_ctx())
            .await
            .unwrap();
        let _ = server.await;

        assert!(out.ok);
        assert_eq!(out.data["introspection_enabled"], true);
        assert_eq!(out.data["mutation_type"], "Mutation");
        let types = out.data["types"].as_array().unwrap();
        assert!(!types.iter().any(|t| t.as_str() == Some("__Schema")), "meta types must be filtered");
        assert_eq!(out.data["type_count"], 3);
    }

    #[tokio::test]
    async fn reports_disabled_introspection_from_a_graphql_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = json!({"errors": [{"message": "introspection is disabled"}]}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}/graphql");
        let out = GraphQlIntrospect
            .execute(json!({"url": url}), &super::super::test_ctx())
            .await
            .unwrap();
        let _ = server.await;

        assert!(out.ok);
        assert_eq!(out.data["introspection_enabled"], false);
    }
}
