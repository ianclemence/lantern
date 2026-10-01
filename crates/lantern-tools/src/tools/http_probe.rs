//! HTTP probing: status, headers, security posture, technology hints, title.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Instant;

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
];

/// Signature-based technology hints: cheap, no false dependency on a fingerprint DB.
const SIGNATURES: &[(&str, &str)] = &[
    ("wp-content/", "WordPress"),
    ("wp-includes/", "WordPress"),
    ("__NEXT_DATA__", "Next.js"),
    ("_nuxt/", "Nuxt"),
    ("csrf-token", "CSRF-token form"),
    ("XSRF-TOKEN", "XSRF cookie"),
    ("Drupal.settings", "Drupal"),
    ("Joomla!", "Joomla"),
    ("nginx", "nginx"),
    ("Apache/", "Apache"),
    ("PHPSESSID", "PHP session"),
    ("JSESSIONID", "Java session"),
    ("ASP.NET_SessionId", "ASP.NET session"),
    ("laravel_token", "Laravel"),
    ("rack.session", "Rack session"),
    ("graphql", "GraphQL"),
    ("__bootstrap", "Bootstrap"),
];

pub fn normalize_target(raw: &str) -> String {
    let t = raw.trim();
    if t.contains("://") {
        t.to_string()
    } else {
        format!("http://{t}")
    }
}

pub struct HttpProbe;

impl Tool for HttpProbe {
    fn name(&self) -> &'static str {
        "http_probe"
    }

    fn description(&self) -> &'static str {
        "Fetch an in-scope HTTP(S) URL and report status, redirect chain, security \
         headers, technology hints, page title and cookie flags."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "absolute URL or bare host, must be in scope"},
                "method": {"type": "string", "enum": ["GET", "HEAD"], "description": "default GET"},
                "path": {"type": "string", "description": "path to request, default /"},
                "max_body": {"type": "integer", "description": "bytes of body to read, default 64KiB"}
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
            let path = super::opt_str_field(&input, "path").unwrap_or_else(|| "/".into());
            let path = if path.starts_with('/') { path } else { format!("/{path}") };
            let method = super::opt_str_field(&input, "method")
                .map(|m| m.to_ascii_uppercase())
                .filter(|m| m == "GET" || m == "HEAD")
                .unwrap_or_else(|| "GET".into());
            let max_body = super::opt_u64(&input, "max_body", 64 * 1024).min(1024 * 1024);

            let base = normalize_target(&raw);
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            // Scope check on the authority, not on the path.
            let authority = url
                .split("://")
                .nth(1)
                .unwrap_or(&url)
                .split('/')
                .next()
                .unwrap_or(&url);
            ctx.check_scope(authority)?;

            let started = Instant::now();
            let req = ctx
                .http
                .request(
                    reqwest::Method::from_bytes(method.as_bytes())?,
                    &url,
                )
                .header("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
                .header("Accept-Language", "en-US,en;q=0.8");

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(ToolOutput::failed(format!("request to {url} failed: {e}")));
                }
            };

            let status = resp.status();
            let code = status.as_u16();
            let final_url = resp.url().to_string();
            let redirected = final_url.trim_end_matches('/') != url.trim_end_matches('/');

            let headers = resp.headers().clone();
            let header_str = |k: &str| {
                headers
                    .get(k)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            };

            let mut missing_security: Vec<&str> = Vec::new();
            let mut present_security: Vec<String> = Vec::new();
            for (k, label) in SECURITY_HEADERS {
                if header_str(k).is_some() {
                    present_security.push(label.to_string());
                } else {
                    missing_security.push(label);
                }
            }

            let cookies: Vec<String> = headers
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
                .collect();
            let insecure_cookies: Vec<String> = cookies
                .iter()
                .filter(|c| {
                    let lc = c.to_ascii_lowercase();
                    lc.starts_with("jsessionid") || !lc.contains("secure") || !lc.contains("httponly")
                })
                .cloned()
                .collect();

            let mut body = String::new();
            let mut body_bytes = 0usize;
            let mut body_truncated = false;
            if method == "GET" && status != reqwest::StatusCode::NO_CONTENT {
                // Bounded at the network read itself, not just truncated
                // after the fact: a hostile or compromised target serving a
                // multi-gigabyte or endlessly chunked body must never make
                // this process buffer past `max_body`, however large the
                // operator's own cap is set.
                let (text, truncated) =
                    crate::fetch::read_capped_text(resp, max_body as usize).await;
                body_bytes = text.len();
                body = text;
                body_truncated = truncated;
            }

            let title = body
                .split("<title>")
                .nth(1)
                .and_then(|s| s.split("</title>").next())
                .map(|s| s.trim().chars().take(120).collect::<String>())
                .unwrap_or_default();

            let mut tech: Vec<String> = Vec::new();
            for (sig, name) in SIGNATURES {
                if body.to_ascii_lowercase().contains(&sig.to_ascii_lowercase())
                    || header_str("server")
                        .map(|s| s.to_ascii_lowercase().contains(&sig.to_ascii_lowercase()))
                        .unwrap_or(false)
                {
                    if !tech.iter().any(|t| t == name) {
                        tech.push(name.to_string());
                    }
                }
            }
            if let Some(x) = header_str("x-powered-by") {
                tech.push(x);
            }

            let elapsed = started.elapsed().as_millis() as u64;
            let summary = format!(
                "{method} {url} -> {code} {} in {elapsed} ms{}{}",
                status.canonical_reason().unwrap_or(""),
                if title.is_empty() {
                    String::new()
                } else {
                    format!(", title=\"{title}\"")
                },
                if missing_security.is_empty() {
                    String::new()
                } else {
                    format!(", missing {}", missing_security.join("/"))
                }
            );

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "url": url,
                    "final_url": final_url,
                    "method": method,
                    "status": code,
                    "reason": status.canonical_reason(),
                    "redirected": redirected,
                    "server": header_str("server"),
                    "content_type": header_str("content-type"),
                    "content_length": header_str("content-length").and_then(|v| v.parse::<u64>().ok()),
                    "body_bytes": body_bytes,
                    "body_truncated": body_truncated,
                    "title": title,
                    "security_headers_present": present_security,
                    "security_headers_missing": missing_security,
                    "cookies": cookies.len(),
                    "insecure_cookies": insecure_cookies.len(),
                    "technologies": tech,
                    "duration_ms": elapsed,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_targets() {
        assert_eq!(normalize_target("example.com"), "http://example.com");
        assert_eq!(normalize_target("https://a.b/c"), "https://a.b/c");
    }

    #[tokio::test]
    async fn probes_local_server() {
        // Spin a tiny local HTTP server on loopback.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = "<html><head><title>Lantern Probe</title></head><body>hi</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nServer: testserver/1.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\nSet-Cookie: sid=1; Path=/\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}");
        let out = HttpProbe
            .execute(json!({"url": url}), &super::super::test_ctx())
            .await
            .expect("probe");
        let _ = server.await;

        assert!(out.ok, "{}", out.summary);
        assert_eq!(out.data["status"], 200);
        assert_eq!(out.data["title"], "Lantern Probe");
        assert!(out.data["security_headers_missing"]
            .as_array()
            .unwrap()
            .len()
            >= 4);
        assert_eq!(out.data["insecure_cookies"], 1);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = HttpProbe
            .execute(json!({"url": "https://example.org/"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }
}
