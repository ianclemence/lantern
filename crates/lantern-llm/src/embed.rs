//! Embeddings with an explicit "not available" state.
//!
//! If Ollama is reachable and the model is present we get free local semantic
//! memory. If not, the runtime falls back to keyword search and says so loudly —
//! it never pretends semantic memory is on.

use crate::provider::BoxFuture;
use anyhow::Context;
use serde::Deserialize;
use std::time::Duration;

pub trait Embedder: Send + Sync {
    fn name(&self) -> &str;
    fn dims(&self) -> usize;
    fn embed<'a>(&'a self, text: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<f32>>>;
}

/// Disabled state: callers must surface a warning, not a crash.
#[derive(Debug, Default, Clone)]
pub struct NoEmbedder;

impl Embedder for NoEmbedder {
    fn name(&self) -> &str {
        "disabled"
    }
    fn dims(&self) -> usize {
        0
    }
    fn embed<'a>(&'a self, _text: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<f32>>> {
        Box::pin(async { anyhow::bail!("semantic memory disabled: no embedding backend configured") })
    }
}

#[derive(Debug, Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<TagModel>,
}

#[derive(Debug, Deserialize)]
struct TagModel {
    name: String,
}

#[derive(Debug, Deserialize)]
struct EmbedResponse {
    #[serde(default)]
    embedding: Vec<f32>,
}

pub struct OllamaEmbedder {
    client: reqwest::Client,
    url: String,
    model: String,
    dims: usize,
}

impl OllamaEmbedder {
    pub fn new(url: impl Into<String>, model: impl Into<String>, dims: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        Self {
            client,
            url: url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            dims,
        }
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns `Some` only when the endpoint answers and the model is present.
    /// Any failure yields `None`; the caller logs the reason.
    pub async fn probe(url: &str, model: &str) -> Option<String> {
        let url = url.trim_end_matches('/');
        let tags = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(2))
            .build()
            .ok()?
            .get(format!("{url}/api/tags"))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<TagsResponse>()
            .await
            .ok()?;

        let exact = format!("{model}:latest");
        tags.models
            .iter()
            .find(|m| m.name == model || m.name == exact)
            .map(|m| m.name.clone())
    }

    pub async fn embed_text(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        let body = serde_json::json!({ "model": self.model, "prompt": text });
        let resp = self
            .client
            .post(format!("{}/api/embeddings", self.url))
            .json(&body)
            .send()
            .await
            .context("POST ollama /api/embeddings")?;

        let status = resp.status();
        let payload = crate::fetch::read_capped_text(resp, 16 * 1024 * 1024).await;
        if !status.is_success() {
            let snippet: String = payload.chars().take(200).collect();
            anyhow::bail!("ollama http {status}: {snippet}");
        }
        let parsed: EmbedResponse =
            serde_json::from_str(&payload).context("decoding ollama embedding")?;
        if parsed.embedding.is_empty() {
            anyhow::bail!("ollama returned an empty embedding");
        }
        Ok(parsed.embedding)
    }
}

impl Embedder for OllamaEmbedder {
    fn name(&self) -> &str {
        &self.model
    }
    fn dims(&self) -> usize {
        self.dims
    }
    fn embed<'a>(&'a self, text: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<f32>>> {
        Box::pin(self.embed_text(text))
    }
}

/// The embedder the configuration asks for: local Ollama when it is enabled,
/// the explicit "nothing available" state otherwise. Synchronous and cheap -
/// the client only talks to the network when it is actually used.
pub fn embedder_from(cfg: &lantern_core::config::EmbedConfig) -> std::sync::Arc<dyn Embedder> {
    match cfg.mode {
        lantern_core::config::EmbedMode::Ollama => std::sync::Arc::new(OllamaEmbedder::new(
            &cfg.url,
            &cfg.model,
            cfg.dims,
        )),
        lantern_core::config::EmbedMode::Disabled => std::sync::Arc::new(NoEmbedder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_reports_missing_model() {
        // Point at a closed port: must be None, never a panic.
        assert!(OllamaEmbedder::probe("http://127.0.0.1:1", "nomic-embed-text").await.is_none());
    }

    #[tokio::test]
    async fn disabled_embedder_errors_clearly() {
        let e = NoEmbedder;
        let err = e.embed("x").await.unwrap_err();
        assert!(err.to_string().contains("semantic memory disabled"));
    }

    #[tokio::test]
    async fn probes_live_ollama_if_present() {
        // This device runs Ollama with nomic-embed-text; tolerate absence.
        if let Some(name) =
            OllamaEmbedder::probe("http://127.0.0.1:11434", "nomic-embed-text").await
        {
            let emb = OllamaEmbedder::new("http://127.0.0.1:11434", &name, 768);
            let v = emb.embed_text("port 22 open").await.expect("embed");
            assert_eq!(v.len(), 768, "expected 768-dim vectors");
        }
    }
}
