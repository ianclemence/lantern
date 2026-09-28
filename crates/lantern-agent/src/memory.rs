//! Cross-role memory: keyword (FTS5) plus optional local embeddings, fused in
//! Rust. Embeddings are best-effort - if Ollama is down the flow keeps running
//! on keyword search and says so.

use lantern_core::storage::models::MemoryRow;
use lantern_core::storage::Db;
use lantern_llm::Embedder;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Memory {
    db: Arc<Db>,
    scope_key: String,
    embedder: Arc<dyn Embedder>,
    /// Set when an embed attempt failed, so we stop paying for timeouts.
    embeddings_broken: AtomicBool,
}

impl Memory {
    pub fn new(db: Arc<Db>, scope_key: impl Into<String>, embedder: Arc<dyn Embedder>) -> Self {
        Self {
            db,
            scope_key: scope_key.into(),
            embedder,
            embeddings_broken: AtomicBool::new(false),
        }
    }

    pub fn scope_key(&self) -> &str {
        &self.scope_key
    }

    /// True when semantic memory is currently usable.
    pub fn semantic(&self) -> bool {
        !self.embeddings_broken.load(Ordering::Relaxed) && self.embedder.dims() > 0
    }

    /// Store one observation. Returns `None` when nothing was written.
    pub async fn remember(&self, kind: &str, text: &str) -> Option<i64> {
        let text = lantern_core::text_clip(text.trim(), 300);
        if text.is_empty() {
            return None;
        }
        let embedding = if self.semantic() {
            match self.embedder.embed(&text).await {
                Ok(v) if v.len() == self.embedder.dims() => Some(v),
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!(error = %e, "embedding failed; falling back to keyword memory");
                    self.embeddings_broken.store(true, Ordering::Relaxed);
                    None
                }
            }
        } else {
            None
        };
        self.db
            .memory_add(&self.scope_key, kind, &text, embedding.as_deref())
            .ok()
    }

    /// Keyword-only recall: synchronous, never blocks a runtime.
    pub fn recall(&self, query: &str, limit: i64) -> Vec<MemoryRow> {
        self.db
            .memory_keyword(&self.scope_key, query, limit)
            .unwrap_or_default()
    }

    /// Keyword + vector recall, merged by id.
    pub async fn recall_async(&self, query: &str, limit: i64) -> Vec<MemoryRow> {
        let mut merged: HashMap<i64, MemoryRow> = HashMap::new();
        for r in self.recall(query, limit) {
            merged.insert(r.id, r);
        }
        if self.semantic() {
            match self.embedder.embed(query).await {
                Ok(vec) => {
                    if let Ok(rows) = self.db.memory_vector(&self.scope_key, &vec, limit) {
                        for r in rows {
                            merged.entry(r.id).or_insert(r);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vector recall failed; keyword results only");
                    self.embeddings_broken.store(true, Ordering::Relaxed);
                }
            }
        }
        let mut out: Vec<MemoryRow> = merged.into_values().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.hits));
        out.truncate(limit as usize);
        for r in &out {
            let _ = self.db.memory_touch(r.id);
        }
        out
    }

    /// Render recalled rows as prompt text.
    pub fn render(rows: &[MemoryRow]) -> String {
        rows.iter()
            .map(|r| format!("- [{}] {}", r.kind, r.text))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::budget::Budget;
    use lantern_core::config::{Config, Paths};
    use lantern_core::scope::Scope;
    use lantern_llm::embed::NoEmbedder;

    fn db() -> Arc<Db> {
        let root = std::env::temp_dir().join(format!(
            "lantern-mem-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = Paths::new(root);
        config.paths.ensure().unwrap();
        Arc::new(Db::open(&config.paths.db()).unwrap())
    }

    #[tokio::test]
    async fn remembers_and_recalls_without_embeddings() {
        let db = db();
        let mem = Memory::new(db.clone(), "example.com", Arc::new(NoEmbedder));
        assert!(!mem.semantic(), "NoEmbedder must not claim semantics");
        let id = mem.remember("recon", "DNS: example.com A 93.184.216.34").await;
        assert!(id.is_some());

        let rows = mem.recall_async("example.com", 5).await;
        assert_eq!(rows.len(), 1, "keyword search must find it");
        assert!(rows[0].text.contains("93.184.216.34"));

        let rendered = Memory::render(&rows);
        assert!(rendered.starts_with("- [recon]"));

        // A different scope must not see it.
        let other = Memory::new(db, "other.test", Arc::new(NoEmbedder));
        assert!(other.recall_async("example.com", 5).await.is_empty());
    }

    #[tokio::test]
    async fn empty_text_is_not_stored() {
        let mem = Memory::new(db(), "s", Arc::new(NoEmbedder));
        assert!(mem.remember("recon", "   ").await.is_none());
        assert!(mem.recall_async("nothing", 5).await.is_empty());
    }

    #[test]
    fn budget_and_scope_fixtures() {
        let config = Config::load().unwrap();
        let budget = Budget::new(config.data_cap_bytes, 0);
        let scope = Scope::parse("example.com").unwrap();
        assert!(scope.allows("example.com"));
        assert_eq!(budget.remaining_bytes(), config.data_cap_bytes);
    }
}
