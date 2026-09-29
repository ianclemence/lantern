//! On-demand memory: recall what the engagement already knows, and store what
//! is worth keeping. `guide` notes are written to the shared namespace and
//! outlive the flow; every other kind stays inside the current target scope.

use crate::ctx::ToolCtx;
use crate::memory::{Memory, GLOBAL_SCOPE};
use crate::registry::{Tool, ToolOutput};
use serde_json::json;

/// Kinds a stored note may carry. A guide is shared across engagements, the
/// rest are observations about the current target.
const KINDS: &[&str] = &["guide", "note", "recon", "finding", "technique", "tool"];

pub struct MemorySearch;
pub struct MemoryStore;

impl Tool for MemorySearch {
    fn name(&self) -> &'static str {
        "memory_search"
    }

    fn description(&self) -> &'static str {
        "Recall what this engagement already learned (observations, findings, tool output) \
         plus reusable guides kept across engagements. Keyword plus semantic search: an \
         empty result means nothing matched, not that memory is broken."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "what to look for, e.g. `login form sql injection`"
                },
                "limit": {
                    "type": "integer",
                    "description": "max rows to return (default 6, capped at 20)"
                }
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
            let limit = super::opt_u64(&input, "limit", 6).clamp(1, 20) as i64;

            let rows = ctx.memory().recall_async(&query, limit).await;
            let summary = if rows.is_empty() {
                "memory: nothing matched".to_string()
            } else {
                format!(
                    "memory: {} row(s)\n{}",
                    rows.len(),
                    Memory::render(&rows)
                )
            };
            let data = json!({
                "query": &query,
                "count": rows.len(),
                "rows": rows.iter().map(|r| json!({
                    "scope": r.scope,
                    "kind": r.kind,
                    "text": r.text,
                    "hits": r.hits,
                })).collect::<Vec<_>>(),
            });
            Ok(ToolOutput::ok(summary, data))
        })
    }
}

impl Tool for MemoryStore {
    fn name(&self) -> &'static str {
        "memory_store"
    }

    fn description(&self) -> &'static str {
        "Store a note for later turns. kind `guide` goes to the shared knowledge store and \
         stays readable by every future engagement; `recon`, `finding`, `technique`, `tool` \
         or `note` stay inside the current target scope."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "the note itself, one or two sentences"},
                "kind": {
                    "type": "string",
                    "enum": KINDS,
                    "description": "what the note is (default `note`); `guide` is shared across engagements"
                }
            },
            "required": ["text"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let raw = input
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing required field `text`"))?;
            let text = raw.trim();
            if text.is_empty() {
                anyhow::bail!("nothing stored: text is empty after trimming");
            }
            let kind = super::opt_str_field(&input, "kind")
                .map(|k| k.to_ascii_lowercase())
                .unwrap_or_else(|| "note".to_string());
            if !KINDS.contains(&kind.as_str()) {
                anyhow::bail!("unknown kind `{kind}`; use one of: {}", KINDS.join(", "));
            }

            let mem = ctx.memory();
            let shared = kind == "guide";
            let id = if shared {
                mem.remember_global(&kind, &text).await
            } else {
                mem.remember(&kind, &text).await
            };
            let Some(id) = id else {
                anyhow::bail!("nothing stored: text is empty after trimming");
            };

            let scope = if shared { GLOBAL_SCOPE } else { "flow" };
            let summary = if shared {
                format!("stored [guide] in the shared knowledge store (id {id})")
            } else {
                format!("stored [{kind}] in this engagement's memory (id {id})")
            };
            let data = json!({
                "id": id,
                "kind": &kind,
                "scope": scope,
                "chars": text.chars().count(),
            });
            Ok(ToolOutput::ok(summary, data))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::test_ctx;

    #[tokio::test]
    async fn store_then_search_inside_one_flow() {
        let ctx = test_ctx();
        let stored = MemoryStore
            .execute(json!({"text": "port 8080 runs an old Tomcat", "kind": "recon"}), &ctx)
            .await
            .expect("store");
        assert!(stored.ok, "{}", stored.summary);
        assert_eq!(stored.data["scope"], "flow");

        let found = MemorySearch
            .execute(json!({"query": "8080 tomcat"}), &ctx)
            .await
            .expect("search");
        assert_eq!(found.data["count"], 1, "got: {found:?}");
        assert!(found.summary.contains("[recon]"), "{}", found.summary);
    }

    #[tokio::test]
    async fn guides_land_in_the_shared_namespace() {
        let ctx = test_ctx();
        let stored = MemoryStore
            .execute(json!({"text": "nikto: set the Host header before the scan", "kind": "guide"}), &ctx)
            .await
            .expect("store");
        assert_eq!(stored.data["scope"], "global");
        assert!(stored.summary.contains("shared"), "{}", stored.summary);

        let found = MemorySearch
            .execute(json!({"query": "nikto header"}), &ctx)
            .await
            .expect("search");
        assert_eq!(found.data["count"], 1, "got: {found:?}");
        assert_eq!(found.data["rows"][0]["scope"], "global");
    }

    #[tokio::test]
    async fn bad_input_is_rejected_before_anything_is_written() {
        let ctx = test_ctx();
        let err = MemoryStore
            .execute(json!({"text": "x", "kind": "poem"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown kind"), "got: {err}");

        let err = MemoryStore
            .execute(json!({"text": "   "}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");

        let err = MemorySearch.execute(json!({}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("query"), "got: {err}");

        let db = ctx.db.memory_count().expect("count");
        assert_eq!(db, 0, "nothing written");
    }

    #[tokio::test]
    async fn limit_is_capped_and_a_miss_is_not_an_error() {
        let ctx = test_ctx();
        let out = MemorySearch
            .execute(json!({"query": "nothing here", "limit": 500}), &ctx)
            .await
            .expect("search");
        assert!(out.ok);
        assert_eq!(out.data["count"], 0);
        assert!(out.summary.contains("nothing matched"), "{}", out.summary);
    }
}
