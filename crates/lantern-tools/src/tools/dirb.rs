//! Directory/path discovery with the built-in wordlist.
//!
//! Two baselines are learned first (the real root and a guaranteed-missing
//! path), so soft-404 pages and "everything returns 200" servers do not flood
//! the report with noise.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const DEFAULT_CONCURRENCY: usize = 24;
const BOGUS_PATH: &str = "/lantern-does-not-exist-9f3a2b";

#[derive(Debug, Clone)]
struct Baseline {
    status: u16,
    length: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Hit {
    path: String,
    status: u16,
    length: usize,
    content_type: String,
    redirect: Option<String>,
}

async fn fetch(
    client: &reqwest::Client,
    base: &str,
    path: &str,
) -> Option<(u16, usize, String, Option<String>, String)> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();
    let len = match resp.content_length() {
        Some(l) => l as usize,
        None => resp.bytes().await.map(|b| b.len()).unwrap_or(0),
    };
    Some((status, len, ctype, location, url))
}

pub struct DirBrute;

impl Tool for DirBrute {
    fn name(&self) -> &'static str {
        "dir_bruteforce"
    }

    fn description(&self) -> &'static str {
        "Enumerate hidden paths on an in-scope web server using the built-in ~2.4k \
         wordlist (or a supplied list). Learns soft-404 behaviour first and only \
         reports genuinely different responses."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "base URL or bare host, must be in scope"},
                "paths": {"type": "array", "items": {"type": "string"},
                          "description": "optional explicit path list (max 5000), overrides the built-in list"},
                "concurrency": {"type": "integer", "description": "default 24, max 64"},
                "limit": {"type": "integer", "description": "probe at most N paths, default all"}
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
            let base = crate::tools::http_probe::normalize_target(&raw);
            let authority = base
                .split("://")
                .nth(1)
                .unwrap_or(&base)
                .split('/')
                .next()
                .unwrap_or(&base);
            ctx.check_scope(authority)?;

            let paths: Vec<String> = match input.get("paths").and_then(|v| v.as_array()) {
                Some(arr) if !arr.is_empty() => {
                    if arr.len() > 5_000 {
                        anyhow::bail!("wordlist too large: {} entries (max 5000)", arr.len());
                    }
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| {
                            let s = s.trim();
                            format!("/{}", s.trim_start_matches('/'))
                        })
                        .filter(|s| s.len() > 1)
                        .collect()
                }
                _ => {
                    let mut v: Vec<String> = crate::tools::wordlist::entries()
                        .into_iter()
                        .map(|s| {
                            if s.starts_with('/') {
                                s.to_string()
                            } else {
                                format!("/{s}")
                            }
                        })
                        .collect();
                    if let Some(limit) = input.get("limit").and_then(|v| v.as_u64()) {
                        v.truncate(limit as usize);
                    }
                    v
                }
            };
            if paths.is_empty() {
                anyhow::bail!("empty wordlist");
            }

            let concurrency = super::opt_u64(&input, "concurrency", DEFAULT_CONCURRENCY as u64)
                .clamp(1, 64) as usize;
            let started = Instant::now();

            // Baselines: the real root (to ignore trivially different pages) and a
            // guaranteed-missing path (the soft-404 signature).
            let root = fetch(&ctx.http, &base, "/").await;
            let bogus = fetch(&ctx.http, &base, BOGUS_PATH).await;
            let soft404 = bogus.as_ref().map(|(s, l, _, _, _)| Baseline {
                status: *s,
                length: *l,
            });
            let root_len = root.as_ref().map(|(_, l, _, _, _)| *l).unwrap_or(0);

            let sem = Arc::new(Semaphore::new(concurrency));
            let mut set: JoinSet<Option<Hit>> = JoinSet::new();
            let client = ctx.http.clone();

            for path in &paths {
                let path = path.clone();
                let base = base.clone();
                let sem = sem.clone();
                let client = client.clone();
                set.spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    let (status, len, ctype, redirect, _url) = fetch(&client, &base, &path).await?;
                    Some(Hit {
                        path,
                        status,
                        length: len,
                        content_type: ctype,
                        redirect,
                    })
                });
            }

            let mut hits: Vec<Hit> = Vec::new();
            let mut seen: HashSet<(u16, usize)> = HashSet::new();
            let mut errors = 0usize;

            while let Some(res) = set.join_next().await {
                match res {
                    Ok(Some(hit)) => {
                        // Drop 404s outright.
                        if hit.status == 404 || hit.status == 400 || hit.status == 0 {
                            continue;
                        }
                        // Drop soft-404 clones (same status + length as the bogus path).
                        if let Some(b) = &soft404 {
                            if hit.status == b.status && hit.length == b.length {
                                continue;
                            }
                        }
                        // Drop pages identical in size to the root landing page with 200.
                        if hit.status == 200 && hit.length == root_len && root_len > 0 {
                            continue;
                        }
                        // Cap repeated identical (status,length) pairs to avoid
                        // mass-false-positive servers flooding output.
                        let key = (hit.status, hit.length);
                        if hit.status == 200 && seen.len() > 40 && !seen.contains(&key) {
                            continue;
                        }
                        seen.insert(key);
                        hits.push(hit);
                    }
                    Ok(None) => errors += 1,
                    Err(_) => errors += 1,
                }
            }

            hits.sort_by(|a, b| a.path.cmp(&b.path));
            hits.truncate(500);

            let elapsed = started.elapsed().as_millis() as u64;
            let interesting: Vec<String> = hits
                .iter()
                .map(|h| {
                    format!(
                        "{} {} {}{}",
                        h.path,
                        h.status,
                        h.length,
                        h.redirect
                            .as_deref()
                            .map(|r| format!(" -> {r}"))
                            .unwrap_or_default()
                    )
                })
                .collect();

            let summary = format!(
                "probed {} paths on {base} in {elapsed} ms -> {} interesting ({} request errors)",
                paths.len(),
                hits.len(),
                errors
            );

            // Keep raw listing as an artifact for the report.
            let blob = interesting.join("\n");
            let artifact = ctx.write_artifact("dirb.txt", blob.as_bytes()).ok();

            let mut out = ToolOutput::ok(
                summary,
                json!({
                    "base": base,
                    "probed": paths.len(),
                    "interesting": hits,
                    "errors": errors,
                    "duration_ms": elapsed,
                    "wordlist": crate::tools::wordlist::count(),
                }),
            );
            if let Some(a) = artifact {
                out = out.with_artifacts(vec![a]);
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves `/` and `/admin`, 404s (with a uniform body) for everything else.
    async fn spawn_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();

                let (status, body) = match path.as_str() {
                    "/" => ("200 OK", "<html><title>Home</title>home page here</html>"),
                    p if p.starts_with("/admin") => {
                        ("200 OK", "<html><title>Admin</title>secret panel</html>")
                    }
                    _ => ("404 Not Found", "<html><body>not found page, uniform size</body></html>"),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn finds_real_paths_and_filters_soft_404s() {
        let addr = spawn_server().await;
        let ctx = super::super::test_ctx();
        let out = DirBrute
            .execute(
                json!({
                    "url": format!("http://{addr}"),
                    "paths": ["/admin", "/nope", "/missing"],
                    "concurrency": 4
                }),
                &ctx,
            )
            .await
            .expect("dirb");
        assert!(out.ok, "{}", out.summary);
        let hits = out.data["interesting"].as_array().unwrap();
        assert!(
            hits.iter().any(|h| h["path"] == "/admin"),
            "should find /admin: {hits:?}"
        );
        assert!(
            !hits.iter().any(|h| h["path"] == "/nope" || h["path"] == "/missing"),
            "404s must be filtered: {hits:?}"
        );
        // The soft-404 filter must not report the bogus probe itself.
        assert!(!hits.iter().any(|h| {
            h["path"].as_str().unwrap_or_default().contains("lantern-does-not")
        }));
    }

    #[tokio::test]
    async fn built_in_wordlist_is_used_when_no_paths_given() {
        let addr = spawn_server().await;
        let ctx = super::super::test_ctx();
        let out = DirBrute
            .execute(
                json!({"url": format!("http://{addr}"), "limit": 40}),
                &ctx,
            )
            .await
            .expect("dirb");
        assert_eq!(out.data["probed"], 40);
        assert!(out.summary.contains("probed 40 paths"));
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = DirBrute
            .execute(json!({"url": "https://example.org"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn oversized_custom_list_is_rejected() {
        let big: Vec<String> = (0..5100).map(|i| format!("/p{i}")).collect();
        let err = DirBrute
            .execute(
                json!({"url": "http://127.0.0.1", "paths": big}),
                &super::super::test_ctx(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }
}
