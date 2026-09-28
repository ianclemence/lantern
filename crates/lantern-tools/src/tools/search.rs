//! Web search with a configured API when a key is present, otherwise the
//! native DuckDuckGo HTML endpoint (no key, no third-party SDK).

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Instant;

const MAX_RESULTS: usize = 10;

/// Percent-decode (DuckDuckGo wraps outbound links in `uddg=`).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Pull the real destination out of a DuckDuckGo redirect URL.
pub fn unwrap_ddg(href: &str) -> String {
    if let Some(idx) = href.find("uddg=") {
        let rest = &href[idx + 5..];
        let end = rest
            .find('&')
            .map(|i| &rest[..i])
            .unwrap_or(rest);
        return percent_decode(end);
    }
    percent_decode(href)
}

/// Parse `html.duckduckgo.com/html` results.
pub fn parse_ddg_html(html: &str) -> Vec<serde_json::Value> {
    use scraper::{Html, Selector};
    let doc = Html::parse_document(html);
    let anchor = Selector::parse("a.result__a").expect("valid selector");
    let snippet_sel = Selector::parse("a.result__snippet").expect("valid selector");

    let titles: Vec<(String, String)> = doc
        .select(&anchor)
        .filter_map(|a| {
            let href = a.value().attr("href")?.to_string();
            let title = a.text().collect::<String>().trim().to_string();
            if title.is_empty() {
                return None;
            }
            Some((title, unwrap_ddg(&href)))
        })
        .collect();

    let snippets: Vec<String> = doc
        .select(&snippet_sel)
        .map(|s| s.text().collect::<String>().trim().to_string())
        .collect();

    titles
        .into_iter()
        .enumerate()
        .map(|(i, (title, url))| {
            json!({
                "title": title,
                "url": url,
                "snippet": snippets.get(i).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

/// Tavily-compatible JSON search (used only when `TAVILY_API_KEY` is set).
async fn tavily_search(
    client: &reqwest::Client,
    key: &str,
    query: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let body = json!({
        "api_key": key,
        "query": query,
        "max_results": MAX_RESULTS,
        "include_answer": false,
    });
    let resp = client
        .post("https://api.tavily.com/search")
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("search api http {status}: {}", &text.chars().take(200).collect::<String>());
    }
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    Ok(parsed
        .get("results")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .map(|r| {
                    json!({
                        "title": r.get("title").and_then(|v| v.as_str()).unwrap_or(""),
                        "url": r.get("url").and_then(|v| v.as_str()).unwrap_or(""),
                        "snippet": r.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

async fn ddg_search(client: &reqwest::Client, query: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let url = format!("https://html.duckduckgo.com/html/?q={}", encode(query));
    let resp = client
        .get(&url)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Accept-Language", "en-US,en;q=0.8")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("ddg: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("ddg http {status}");
    }
    let html = resp.text().await.unwrap_or_default();
    Ok(parse_ddg_html(&html))
}

/// Query-string encoding good enough for search terms.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            ' ' => out.push('+'),
            _ => {
                for b in c.encode_utf8(&mut [0u8; 4]).as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

pub struct WebSearch;

impl Tool for WebSearch {
    fn name(&self) -> &'static str {
        "web_search"
    }

    fn description(&self) -> &'static str {
        "Search the public web for an in-scope organization, product or hostname. \
         Uses the configured search API if a key is set, otherwise the DuckDuckGo \
         HTML endpoint. Results carry title, url and snippet."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "search terms, e.g. \"example.com login\""},
                "max_results": {"type": "integer", "description": "default 10, max 20"}
            },
            "required": ["query"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let query = super::str_field(&input, "query")?;
            if query.len() > 300 {
                anyhow::bail!("query too long (max 300 chars)");
            }
            let max = super::opt_u64(&input, "max_results", MAX_RESULTS as u64).clamp(1, 20) as usize;
            let started = Instant::now();

            if ctx.config.offline {
                return Ok(ToolOutput::failed("web search disabled: offline mode"));
            }

            let (provider, results) = match std::env::var("TAVILY_API_KEY") {
                Ok(key) if !key.is_empty() => {
                    match tavily_search(&ctx.http, &key, &query).await {
                        Ok(r) => ("tavily", r),
                        Err(e) => {
                            tracing::warn!(error = %e, "search api failed, falling back to ddg");
                            match ddg_search(&ctx.http, &query).await {
                                Ok(r) => ("duckduckgo", r),
                                Err(e2) => return Ok(ToolOutput::failed(format!("search failed: {e2}"))),
                            }
                        }
                    }
                }
                _ => match ddg_search(&ctx.http, &query).await {
                    Ok(r) => ("duckduckgo", r),
                    Err(e) => return Ok(ToolOutput::failed(format!("search failed: {e}"))),
                },
            };

            let mut results = results;
            results.truncate(max);
            let elapsed = started.elapsed().as_millis() as u64;

            let summary = if results.is_empty() {
                format!("search [{provider}] for {query}: no results in {elapsed} ms")
            } else {
                format!(
                    "search [{provider}] for {query}: {} result(s) in {elapsed} ms -> {}",
                    results.len(),
                    results
                        .iter()
                        .take(3)
                        .filter_map(|r| r.get("url").and_then(|u| u.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "query": query,
                    "provider": provider,
                    "results": results,
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
    fn decodes_ddg_redirects() {
        let wrapped = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa%3Fb%3D1&rut=abc";
        assert_eq!(unwrap_ddg(wrapped), "https://example.com/a?b=1");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(encode("a b/c"), "a+b%2Fc");
    }

    #[test]
    fn parses_result_html() {
        let html = r##"
        <div class="results">
          <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F">Example Domain</a>
          <a class="result__snippet" href="#">This domain is for use in illustrative examples.</a>
          <a class="result__a" href="https://other.test/x">Second</a>
          <a class="result__snippet" href="#">Another snippet.</a>
        </div>"##;
        let r = parse_ddg_html(html);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["url"], "https://example.com/");
        assert_eq!(r[0]["title"], "Example Domain");
        assert_eq!(r[0]["snippet"], "This domain is for use in illustrative examples.");
        assert_eq!(r[1]["url"], "https://other.test/x");
    }

    #[tokio::test]
    async fn refuses_out_of_scope_queries_gracefully() {
        // `web_search` is not scope-bound (it queries third parties), but it must
        // still refuse oversized input and run without a key.
        let ctx = super::super::test_ctx();
        let err = WebSearch
            .execute(json!({"query": "x".repeat(400)}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too long"), "got: {err}");
    }
}
