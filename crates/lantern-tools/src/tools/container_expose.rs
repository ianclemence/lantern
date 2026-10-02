//! Passive exposure checks for two classic container/orchestration
//! misconfigurations: an unauthenticated Docker daemon API (2375/2376) and a
//! Kubelet API with anonymous auth left enabled (10250). Both checks make
//! one unauthenticated read-only request - nothing here starts, stops, or
//! execs into a container, or asks the Kubelet to do anything but list what
//! is already running.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Duration;

pub struct ContainerExposeCheck;

fn valid_host(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c))
}

impl Tool for ContainerExposeCheck {
    fn name(&self) -> &'static str {
        "container_expose_check"
    }

    fn description(&self) -> &'static str {
        "Passive check for an unauthenticated Docker daemon API (2375/2376) or Kubelet \
         anonymous auth (10250) on an in-scope host. Read-only."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "docker or kubelet"},
                "host": {"type": "string", "description": "in-scope host or IP"},
                "port": {"type": "integer", "description": "default 2375 or 10250"}
            },
            "required": ["service", "host"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let service = super::str_field(&input, "service")?.to_ascii_lowercase();
            let host = super::str_field(&input, "host")?;
            if !valid_host(&host) {
                anyhow::bail!("invalid host");
            }
            ctx.check_scope(&host)?;

            match service.as_str() {
                "docker" => {
                    let port = super::opt_u64(&input, "port", 2375).min(65_535) as u16;
                    let url = format!("http://{host}:{port}/version");
                    let resp = match ctx.http.get(&url).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            return Ok(ToolOutput::ok(
                                format!("container_expose_check: docker {host}:{port} - unreachable ({e})"),
                                json!({"service": "docker", "host": host, "port": port, "exposed": false}),
                            ))
                        }
                    };
                    let status = resp.status();
                    let (text, _) = crate::fetch::read_capped_text(resp, 32 * 1024).await;
                    let exposed = status.is_success() && text.contains("\"ApiVersion\"");
                    let summary = if exposed {
                        format!(
                            "container_expose_check: docker {host}:{port} - UNAUTHENTICATED API EXPOSED \
                             (full container control, no credentials required)"
                        )
                    } else {
                        format!("container_expose_check: docker {host}:{port} - not exposed (HTTP {status})")
                    };
                    Ok(ToolOutput::ok(
                        summary,
                        json!({
                            "service": "docker",
                            "host": host,
                            "port": port,
                            "exposed": exposed,
                            "status": status.as_u16(),
                        }),
                    ))
                }
                "kubelet" => {
                    let port = super::opt_u64(&input, "port", 10250).min(65_535) as u16;
                    let url = format!("https://{host}:{port}/pods");
                    // Kubelet serves a self-signed (or cluster-internal CA)
                    // cert by default: the check is for anonymous-auth, not
                    // for certificate trust, exactly like `tls_inspect`'s own
                    // deliberate accept-invalid posture.
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .timeout(Duration::from_secs(10))
                        .user_agent(ctx.config.user_agent.clone())
                        .build()
                        .map_err(|e| anyhow::anyhow!("building tls-tolerant client: {e}"))?;
                    let resp = match client.get(&url).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            return Ok(ToolOutput::ok(
                                format!("container_expose_check: kubelet {host}:{port} - unreachable ({e})"),
                                json!({"service": "kubelet", "host": host, "port": port, "exposed": false}),
                            ))
                        }
                    };
                    let status = resp.status();
                    let (text, _) = crate::fetch::read_capped_text(resp, 64 * 1024).await;
                    let exposed = status.is_success() && text.contains("\"kind\"");
                    let summary = if exposed {
                        format!(
                            "container_expose_check: kubelet {host}:{port} - ANONYMOUS AUTH ENABLED \
                             (pod list readable with no credentials)"
                        )
                    } else if status.as_u16() == 401 || status.as_u16() == 403 {
                        format!("container_expose_check: kubelet {host}:{port} - reachable, anonymous auth rejected (HTTP {status})")
                    } else {
                        format!("container_expose_check: kubelet {host}:{port} - not exposed (HTTP {status})")
                    };
                    Ok(ToolOutput::ok(
                        summary,
                        json!({
                            "service": "kubelet",
                            "host": host,
                            "port": port,
                            "exposed": exposed,
                            "status": status.as_u16(),
                        }),
                    ))
                }
                other => anyhow::bail!("service must be docker or kubelet (got `{other}`)"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = ContainerExposeCheck
            .execute(json!({"service": "docker", "host": "evil.example.org"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_unknown_service() {
        let err = ContainerExposeCheck
            .execute(json!({"service": "swarm", "host": "127.0.0.1"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("docker or kubelet"), "got: {err}");
    }

    #[tokio::test]
    async fn detects_an_exposed_docker_daemon() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"ApiVersion": "1.44", "Version": "24.0.5"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let out = ContainerExposeCheck
            .execute(
                json!({"service": "docker", "host": "127.0.0.1", "port": port}),
                &super::super::test_ctx(),
            )
            .await
            .unwrap();
        let _ = server.await;
        assert!(out.ok);
        assert_eq!(out.data["exposed"], true);
    }
}
