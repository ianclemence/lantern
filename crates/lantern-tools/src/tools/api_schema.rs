//! OpenAPI/Swagger-schema-aware API surface mapping.
//!
//! Fetches a published OpenAPI/Swagger JSON document (never YAML - this stays
//! dependency-free rather than pulling in a YAML parser for one tool) and
//! reports the real attack surface it describes: every path/method pair, and
//! which of them declare no authentication requirement at all. Passive: it
//! only reads a document the target already serves, never calls an endpoint.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::{json, Value};

pub struct ApiSchemaScan;

/// One path+method the document describes.
struct Endpoint {
    method: String,
    path: String,
    authenticated: bool,
}

/// Walk an OpenAPI 3.x / Swagger 2.0 document's `paths` object. Both
/// generations use the same shape for this: `paths.<path>.<method>`, and an
/// operation-level `security: []` always means "no auth", overriding any
/// document-level default - that override is the one subtlety this has to
/// get right, since a document can declare a global scheme and then punch a
/// hole in it for one endpoint.
fn walk_paths(doc: &Value) -> Vec<Endpoint> {
    const METHODS: &[&str] =
        &["get", "put", "post", "delete", "options", "head", "patch", "trace"];
    let has_global_security = doc
        .get("security")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    let mut out = Vec::new();
    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return out;
    };
    for (path, item) in paths {
        let Some(item) = item.as_object() else { continue };
        for method in METHODS {
            let Some(op) = item.get(*method) else { continue };
            let authenticated = match op.get("security").and_then(|v| v.as_array()) {
                // Operation explicitly overrides: empty list means "no auth
                // required", a non-empty list means at least one scheme applies.
                Some(sec) => !sec.is_empty(),
                // No operation-level override: fall back to whatever the
                // document declares globally.
                None => has_global_security,
            };
            out.push(Endpoint {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                authenticated,
            });
        }
    }
    out
}

impl Tool for ApiSchemaScan {
    fn name(&self) -> &'static str {
        "api_schema_scan"
    }

    fn description(&self) -> &'static str {
        "Fetch and parse an in-scope OpenAPI/Swagger JSON document: every path/method \
         the API describes, and which of them declare no authentication requirement. \
         Passive - reads a published schema, calls nothing it describes."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "in-scope URL serving the OpenAPI/Swagger JSON document"}
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
                Err(e) => return Ok(ToolOutput::failed(format!("request to {url} failed: {e}"))),
            };
            if !resp.status().is_success() {
                return Ok(ToolOutput::failed(format!(
                    "{url} returned {}",
                    resp.status()
                )));
            }
            let (text, truncated) = crate::fetch::read_capped_text(resp, 4 * 1024 * 1024).await;
            let doc: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(ToolOutput::failed(format!(
                        "{url} is not valid JSON (expected OpenAPI/Swagger - YAML documents \
                         are not supported): {e}"
                    )))
                }
            };

            let version = doc
                .get("openapi")
                .or_else(|| doc.get("swagger"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            if version == "unknown" {
                return Ok(ToolOutput::failed(format!(
                    "{url} is JSON but declares neither `openapi` nor `swagger` - not a \
                     recognised API schema document"
                )));
            }

            let endpoints = walk_paths(&doc);
            let unauthenticated: Vec<&Endpoint> =
                endpoints.iter().filter(|e| !e.authenticated).collect();

            let title = doc
                .pointer("/info/title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let summary = format!(
                "api_schema_scan: {} (v{version}) - {} endpoint(s), {} with no declared \
                 authentication{}",
                if title.is_empty() { url.clone() } else { title.clone() },
                endpoints.len(),
                unauthenticated.len(),
                if truncated { " (document truncated)" } else { "" }
            );

            let endpoints_json: Vec<Value> = endpoints
                .iter()
                .map(|e| {
                    json!({"method": e.method, "path": e.path, "authenticated": e.authenticated})
                })
                .collect();

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "url": url,
                    "title": title,
                    "version": version,
                    "endpoint_count": endpoints.len(),
                    "unauthenticated_count": unauthenticated.len(),
                    "unauthenticated_endpoints": unauthenticated
                        .iter()
                        .map(|e| format!("{} {}", e.method, e.path))
                        .collect::<Vec<_>>(),
                    "endpoints": endpoints_json,
                    "truncated": truncated,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_security_applies_unless_an_operation_overrides_with_an_empty_list() {
        let doc = json!({
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/users": {
                    "get": {},
                    "post": {"security": []}
                },
                "/health": {
                    "get": {"security": []}
                }
            }
        });
        let endpoints = walk_paths(&doc);
        assert_eq!(endpoints.len(), 3);
        let get_users = endpoints.iter().find(|e| e.method == "GET" && e.path == "/users").unwrap();
        assert!(get_users.authenticated, "inherits the global requirement");
        let post_users = endpoints.iter().find(|e| e.method == "POST" && e.path == "/users").unwrap();
        assert!(!post_users.authenticated, "operation-level override to no auth");
        let health = endpoints.iter().find(|e| e.path == "/health").unwrap();
        assert!(!health.authenticated);
    }

    #[test]
    fn no_global_security_means_no_auth_unless_an_operation_declares_one() {
        let doc = json!({
            "swagger": "2.0",
            "paths": {
                "/open": {"get": {}},
                "/locked": {"get": {"security": [{"apiKey": []}]}}
            }
        });
        let endpoints = walk_paths(&doc);
        let open = endpoints.iter().find(|e| e.path == "/open").unwrap();
        assert!(!open.authenticated);
        let locked = endpoints.iter().find(|e| e.path == "/locked").unwrap();
        assert!(locked.authenticated);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = ApiSchemaScan
            .execute(json!({"url": "https://example.org/openapi.json"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_non_schema_json_and_non_json_bodies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"hello": "world"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let url = format!("http://{addr}/x");
        let out = ApiSchemaScan.execute(json!({"url": url}), &super::super::test_ctx()).await.unwrap();
        let _ = server.await;
        assert!(!out.ok, "a JSON body with no openapi/swagger field must fail");
    }
}
