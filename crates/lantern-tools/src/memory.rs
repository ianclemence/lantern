//! Cross-role memory: keyword (FTS5) plus optional local embeddings, fused in
//! Rust. Embeddings are best-effort - if Ollama is down the flow keeps running
//! on keyword search and says so.
//!
//! Two namespaces, both read on every recall: one per engagement scope (what
//! this target taught us) and the shared [`GLOBAL_SCOPE`] where guides live,
//! so a lesson learned on one engagement reaches the next.

use lantern_core::storage::models::MemoryRow;
use lantern_core::storage::Db;
use lantern_llm::embed::Embedder;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Namespace for knowledge that outlives an engagement (guides, playbooks).
pub const GLOBAL_SCOPE: &str = "global";

/// Character budget for a note. Memory is read back into the prompt.
const NOTE_CHARS: usize = 300;
/// Guides carry a little more: they are replayed on every flow.
const GUIDE_CHARS: usize = 500;

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

    /// Store one observation in this engagement's namespace.
    /// Returns `None` when nothing was written.
    pub async fn remember(&self, kind: &str, text: &str) -> Option<i64> {
        self.store(&self.scope_key, kind, text, NOTE_CHARS).await
    }

    /// Store a note in the shared namespace: every later flow can read it.
    pub async fn remember_global(&self, kind: &str, text: &str) -> Option<i64> {
        self.store(GLOBAL_SCOPE, kind, text, GUIDE_CHARS).await
    }

    /// Keyword recall over this engagement's namespace plus the shared guides.
    pub fn recall(&self, query: &str, limit: i64) -> Vec<MemoryRow> {
        let mut merged: HashMap<i64, MemoryRow> = HashMap::new();
        for scope in self.namespaces() {
            for r in self.db.memory_keyword(scope, query, limit).unwrap_or_default() {
                merged.insert(r.id, r);
            }
        }
        let mut out: Vec<MemoryRow> = merged.into_values().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.hits));
        out.truncate(limit as usize);
        out
    }

    /// Keyword + vector recall, merged by id, over both namespaces.
    pub async fn recall_async(&self, query: &str, limit: i64) -> Vec<MemoryRow> {
        let mut merged: HashMap<i64, MemoryRow> = HashMap::new();
        for r in self.recall(query, limit) {
            merged.insert(r.id, r);
        }
        if self.semantic() {
            match self.embedder.embed(query).await {
                Ok(vec) => {
                    for scope in self.namespaces() {
                        if let Ok(rows) = self.db.memory_vector(scope, &vec, limit) {
                            for r in rows {
                                merged.entry(r.id).or_insert(r);
                            }
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

    fn namespaces(&self) -> [&str; 2] {
        [&self.scope_key, GLOBAL_SCOPE]
    }

    async fn store(
        &self,
        scope_key: &str,
        kind: &str,
        text: &str,
        max_chars: usize,
    ) -> Option<i64> {
        let text = lantern_core::text_clip(text.trim(), max_chars);
        if text.is_empty() {
            return None;
        }
        let kind = kind.trim();
        let kind = if kind.is_empty() { "note" } else { kind };
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
            .memory_add(scope_key, kind, &text, embedding.as_deref())
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut config = lantern_core::config::Config::load().unwrap();
        config.paths = lantern_core::config::Paths::new(root);
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
    async fn guides_reach_every_later_engagement() {
        let db = db();
        let first = Memory::new(db.clone(), "example.com", Arc::new(NoEmbedder));
        let id = first
            .remember_global("guide", "sqlmap: send the login form with --forms")
            .await;
        assert!(id.is_some());

        // Scoped notes stay put...
        assert!(first.remember("recon", "port 8080 open").await.is_some());
        let other = Memory::new(db.clone(), "other.test", Arc::new(NoEmbedder));
        let rows = other.recall_async("sqlmap", 5).await;
        assert_eq!(rows.len(), 1, "only the guide crosses engagements");
        assert_eq!(rows[0].scope, GLOBAL_SCOPE);
        assert!(other.recall_async("8080", 5).await.is_empty());

        // ...while the first scope still reads from both namespaces.
        assert_eq!(first.recall_async("8080", 5).await.len(), 1);
        assert_eq!(first.recall_async("sqlmap", 5).await.len(), 1);
    }

    #[tokio::test]
    async fn empty_text_is_not_stored() {
        let mem = Memory::new(db(), "s", Arc::new(NoEmbedder));
        assert!(mem.remember("recon", "   ").await.is_none());
        assert!(mem.remember_global("guide", "").await.is_none());
        assert!(mem.recall_async("nothing", 5).await.is_empty());
    }
}
