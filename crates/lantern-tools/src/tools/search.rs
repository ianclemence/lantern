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

/// NVD's public CVE keyword search: no key, one request, enough for a
/// researcher to match a product version against known CVEs.
const NVD_ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Base score out of an NVD `metrics` object (newest scheme first).
fn nvd_score(metrics: &serde_json::Value) -> Option<f64> {
    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ] {
        if let Some(score) = metrics
            .get(key)
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|e| e.get("cvssData"))
            .and_then(|d| d.get("baseScore"))
            .and_then(|v| v.as_f64())
        {
            return Some(score);
        }
    }
    None
}

/// Turn an NVD 2.0 response into the same shape as every other result,
/// worst-last so the head of the list is the most severe.
pub fn parse_nvd(text: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| anyhow::anyhow!("decoding nvd: {e}"))?;
    let Some(vulns) = parsed.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for v in vulns {
        let Some(cve) = v.get("cve") else { continue };
        let Some(id) = cve.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let desc = cve
            .get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|d| {
                d.iter()
                    .find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en"))
                    .and_then(|x| x.get("value"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("no published description");
        let score = cve.get("metrics").and_then(nvd_score);
        let title = match score {
            Some(s) => format!("{id} (cvss {s})"),
            None => id.to_string(),
        };
        let mut row = json!({
            "title": title,
            "url": format!("https://nvd.nist.gov/vuln/detail/{id}"),
            "snippet": desc,
        });
        if let Some(s) = score {
            row["score"] = json!(s);
        }
        out.push(row);
        if out.len() >= 20 {
            break;
        }
    }
    out.sort_by(|a, b| {
        row_score(b)
            .partial_cmp(&row_score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(out)
}

/// Score carried by a result row, or -1 when the catalogue published none.
pub fn row_score(row: &serde_json::Value) -> f64 {
    row.get("score").and_then(|v| v.as_f64()).unwrap_or(-1.0)
}

async fn nvd_search(
    client: &reqwest::Client,
    query: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let url = format!(
        "{NVD_ENDPOINT}?keywordSearch={}&resultsPerPage=20",
        encode(query)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("nvd: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "nvd http {status}: {}",
            text.chars().take(200).collect::<String>()
        );
    }
    let rows = parse_nvd(&text)?;
    // NVD keyword search is a loose text match: keep the CVEs that actually
    // talk about the query, and keep everything if none of them do.
    let tokens: Vec<String> = query
        .split(|c: char| !c.is_alphanumeric())
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| t.len() >= 3)
        .collect();
    if tokens.is_empty() {
        return Ok(rows);
    }
    let relevant: Vec<serde_json::Value> = rows
        .iter()
        .filter(|r| {
            let hay = format!(
                "{} {}",
                r.get("title").and_then(|v| v.as_str()).unwrap_or_default(),
                r.get("snippet").and_then(|v| v.as_str()).unwrap_or_default()
            )
            .to_ascii_lowercase();
            tokens.iter().any(|t| hay.contains(t.as_str()))
        })
        .cloned()
        .collect();
    if relevant.is_empty() {
        Ok(rows)
    } else {
        Ok(relevant)
    }
}

/// Configured search API when a key is present, otherwise DuckDuckGo.
async fn web_search(
    ctx: &ToolCtx,
    query: &str,
) -> anyhow::Result<(&'static str, Vec<serde_json::Value>)> {
    match std::env::var("TAVILY_API_KEY") {
        Ok(key) if !key.is_empty() => match tavily_search(&ctx.http, &key, query).await {
            Ok(r) => Ok(("tavily", r)),
            Err(e) => {
                tracing::warn!(error = %e, "search api failed, falling back to ddg");
                ddg_search(&ctx.http, query).await.map(|r| ("duckduckgo", r))
            }
        },
        _ => ddg_search(&ctx.http, query).await.map(|r| ("duckduckgo", r)),
    }
}

pub struct WebSearch;

impl Tool for WebSearch {
    fn name(&self) -> &'static str {
        "web_search"
    }

    fn description(&self) -> &'static str {
        "Search the public web for an in-scope organization, product or hostname. \
         mode `general` (default) searches the web; mode `vulnerability` also pulls \
         matching CVEs from the NVD catalogue with their CVSS scores and puts them \
         first. Uses the configured search API if a key is set, otherwise the \
         DuckDuckGo HTML endpoint. Results carry title, url and snippet."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "search terms, e.g. \"example.com login\""},
                "mode": {
                    "type": "string",
                    "enum": ["general", "vulnerability"],
                    "description": "`vulnerability` adds known CVEs for the query (default `general`)"
                },
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
            let mode = super::opt_str_field(&input, "mode")
                .map(|m| m.to_ascii_lowercase())
                .unwrap_or_else(|| "general".to_string());
            if mode != "general" && mode != "vulnerability" {
                anyhow::bail!("unknown mode `{mode}`; use `general` or `vulnerability`");
            }
            let started = Instant::now();

            if ctx.config.offline {
                return Ok(ToolOutput::failed("web search disabled: offline mode"));
            }

            // Vulnerability mode: known CVEs first, public writeups after.
            let mut nvd_rows = Vec::new();
            if mode == "vulnerability" {
                match nvd_search(&ctx.http, &query).await {
                    Ok(rows) => nvd_rows = rows,
                    Err(e) => tracing::warn!(error = %e, "nvd lookup failed; web results only"),
                }
                nvd_rows.truncate((max / 2).max(1));
            }
            let nvd_used = !nvd_rows.is_empty();
            let mut results = std::mem::take(&mut nvd_rows);
            let budget = max.saturating_sub(results.len());

            let provider = if budget == 0 {
                "nvd".to_string()
            } else {
                match web_search(ctx, &query).await {
                    Ok((p, mut rows)) => {
                        rows.truncate(budget);
                        results.extend(rows);
                        if nvd_used {
                            format!("nvd+{p}")
                        } else {
                            p.to_string()
                        }
                    }
                    Err(e) if nvd_used => {
                        tracing::warn!(error = %e, "web search failed; nvd results only");
                        "nvd".to_string()
                    }
                    Err(e) => return Ok(ToolOutput::failed(format!("search failed: {e}"))),
                }
            };
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
                    "mode": mode,
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

    #[tokio::test]
    async fn unknown_mode_is_named_with_its_alternatives() {
        let ctx = super::super::test_ctx();
        let err = WebSearch
            .execute(json!({"query": "apache", "mode": "cvss"}), &ctx)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("vulnerability"), "got: {msg}");
        assert!(msg.contains("general"), "got: {msg}");
    }

    #[test]
    fn parses_nvd_into_normal_results() {
        let body = r#"{
          "totalResults": 2,
          "vulnerabilities": [
            {"cve": {
              "id": "CVE-2014-0160",
              "descriptions": [{"lang": "en", "value": "TLS heartbeat read overrun in OpenSSL (Heartbleed)."}]
            }},
            {"cve": {
              "id": "CVE-2021-44228",
              "descriptions": [
                {"lang": "es", "value": "traduccion"},
                {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}
              ],
              "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]}
            }}
          ]
        }"#;
        let rows = parse_nvd(body).expect("parse");
        assert_eq!(rows.len(), 2);
        // Severity sorts first, whatever order the catalogue answered in.
        assert_eq!(rows[0]["title"], "CVE-2021-44228 (cvss 10)");
        assert_eq!(rows[0]["score"], 10.0);
        assert_eq!(rows[0]["url"], "https://nvd.nist.gov/vuln/detail/CVE-2021-44228");
        assert!(rows[0]["snippet"].as_str().unwrap().contains("Log4j2"));
        // No metrics at all: the id alone is still a usable title.
        assert_eq!(rows[1]["title"], "CVE-2014-0160");
        assert!(rows[1]["snippet"].as_str().unwrap().contains("Heartbleed"));
        assert_eq!(row_score(&rows[1]), -1.0);

        assert!(parse_nvd("not json").is_err());
        assert!(parse_nvd(r#"{"vulnerabilities": []}"#).unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "hits the live NVD catalogue; run with --ignored"]
    async fn vulnerability_mode_is_live() {
        let ctx = super::super::test_ctx();
        let out = WebSearch
            .execute(
                json!({"query": "log4j", "mode": "vulnerability", "max_results": 6}),
                &ctx,
            )
            .await
            .expect("search");
        assert!(out.ok, "{}", out.summary);
        let provider = out.data["provider"].as_str().unwrap_or_default().to_string();
        assert!(provider.contains("nvd"), "provider: {provider}");
        let rows = out.data["results"].as_array().cloned().unwrap_or_default();
        assert!(!rows.is_empty(), "expected CVEs for log4j: {:?}", out.summary);
        println!("{} | mode {}", out.summary, out.data["mode"]);
    }
}
