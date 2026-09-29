//! Everything a flow needs, wired once: config, storage, budget, scope, tool
//! registry, model provider and embeddings.

use anyhow::Context as _;
use lantern_tools::memory::Memory;
use lantern_core::budget::Budget;
use lantern_core::config::{Config, EmbedMode};
use lantern_core::scope::Scope;
use lantern_core::storage::Db;
use lantern_llm::embed::{Embedder, NoEmbedder, OllamaEmbedder};
use lantern_llm::mock::MockProvider;
use lantern_llm::openai_compat::OpenAiCompat;
use lantern_llm::provider::ChatProvider;
use lantern_tools::ctx::ToolCtx;
use lantern_tools::registry::Registry;
use std::sync::Arc;
use std::time::Duration;

pub struct AgentCtx {
    pub config: Arc<Config>,
    pub db: Arc<Db>,
    pub budget: Arc<Budget>,
    pub scope: Arc<Scope>,
    pub registry: Registry,
    pub provider: Arc<dyn ChatProvider>,
    pub embedder: Arc<dyn Embedder>,
    pub dry_run: bool,
}

impl AgentCtx {
    /// Build a context. `scope_spec` is the operator's declaration for this run
    /// and is what every tool will be checked against.
    pub fn new(config: Config, scope_spec: &str, dry_run: bool) -> anyhow::Result<Self> {
        config
            .init_dirs()
            .context("creating the data root")?;
        let scope = Scope::parse(scope_spec).context("parsing scope")?;
        if scope.is_empty() {
            anyhow::bail!("scope is empty: pass at least one host, IP or CIDR");
        }

        let db = Arc::new(Db::open(&config.paths.db()).context("opening database")?);
        let existing = lantern_core::budget::dir_size(&config.paths.root);
        let budget = Arc::new(Budget::new(config.data_cap_bytes, existing));
        let registry = Registry::new(&config).context("building tool registry")?;

        let provider: Arc<dyn ChatProvider> = if dry_run {
            Arc::new(MockProvider::new())
        } else if config.offline {
            anyhow::bail!("offline mode: no model calls possible (use --dry-run for a scripted run)");
        } else if !config.has_llm_key() {
            anyhow::bail!(
                "no generation key: set DEEPSEEK_API_KEY in the environment (keys are never written to disk)"
            );
        } else {
            Arc::new(
                OpenAiCompat::new(
                    &config.llm.base_url,
                    &config.llm.model,
                    &config.llm.api_key,
                    Duration::from_secs(config.llm.timeout_secs),
                )
                .context("building model client")?,
            )
        };

        let embedder: Arc<dyn Embedder> = match config.embed.mode {
            EmbedMode::Ollama => Arc::new(OllamaEmbedder::new(
                &config.embed.url,
                &config.embed.model,
                config.embed.dims,
            )),
            EmbedMode::Disabled => Arc::new(NoEmbedder),
        };

        Ok(Self {
            config: Arc::new(config),
            db,
            budget,
            scope: Arc::new(scope),
            registry,
            provider,
            embedder,
            dry_run,
        })
    }

    /// Swap the model provider (tests, `--dry-run` with a fixed script).
    pub fn with_provider(mut self, provider: Arc<dyn ChatProvider>) -> Self {
        self.provider = provider;
        self.dry_run = true;
        self
    }

    /// Per-flow execution context handed to every tool.
    pub fn tool_ctx(&self, flow_id: Option<&str>, offensive: bool) -> anyhow::Result<ToolCtx> {
        ToolCtx::new(
            self.config.clone(),
            self.db.clone(),
            self.budget.clone(),
            self.scope.clone(),
            flow_id.map(|s| s.to_string()),
            offensive,
        )
    }

    /// Memory namespace for a flow (its declared scope string).
    pub fn memory(&self, scope_key: &str) -> Memory {
        Memory::new(self.db.clone(), scope_key, self.embedder.clone())
    }

    /// One-shot model call used by the plan phases.
    /// One-shot completion for the planning and reflection phases.
    ///
    /// A reasoning model spends the completion budget thinking before it
    /// answers: asked for 500 tokens on this host, one returned 500 reasoning
    /// tokens and an empty string, and the plan with it. So the ask carries
    /// headroom, and a blank reply is asked for once more at double the
    /// budget before the caller is told the model said nothing.
    pub async fn complete(&self, prompt: &str, max_tokens: u32) -> anyhow::Result<String> {
        let mut budget = max_tokens.saturating_mul(4).max(2_048);
        for attempt in 0..2u8 {
            let reply = self
                .provider
                .chat(
                    lantern_llm::provider::ChatRequest::new(vec![
                        lantern_llm::provider::Message::system(
                            "You are Lantern, a security assessment planner. Answer concisely.",
                        ),
                        lantern_llm::provider::Message::user(prompt),
                    ])
                    .max_tokens(budget),
                )
                .await?;
            let text = reply.text().to_string();
            if !text.trim().is_empty() {
                return Ok(text);
            }
            if attempt == 0 {
                budget = budget.saturating_mul(2).min(8_192);
            }
        }
        anyhow::bail!("model returned no content with {budget} tokens of budget")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::config::Paths;

    fn config() -> Config {
        let root = std::env::temp_dir().join(format!(
            "lantern-agentctx-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut c = Config::load().unwrap();
        c.paths = Paths::new(root);
        c
    }

    #[tokio::test]
    async fn complete_asks_again_when_thinking_eats_the_whole_budget() {
        use lantern_llm::mock::{MockProvider, Scripted};
        let mock = std::sync::Arc::new(MockProvider::with_script(vec![
            Scripted::Text(String::new()),
            Scripted::Text("1. Resolve DNS\n2. Fingerprint TLS".into()),
        ]));
        let ctx = AgentCtx::new(config(), "example.com", true)
            .unwrap()
            .with_provider(mock.clone());

        let out = ctx.complete("write the plan", 500).await.unwrap();
        assert!(out.contains("Resolve DNS"), "{out}");
        assert_eq!(
            mock.calls.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "the empty reply must be retried once"
        );
    }

    #[tokio::test]
    async fn complete_reports_a_model_that_never_answers() {
        use lantern_llm::mock::{MockProvider, Scripted};
        let mock = std::sync::Arc::new(MockProvider::with_script(vec![
            Scripted::Text(String::new()),
            Scripted::Text(String::new()),
        ]));
        let ctx = AgentCtx::new(config(), "example.com", true)
            .unwrap()
            .with_provider(mock);

        let err = ctx.complete("write the plan", 500).await.unwrap_err();
        assert!(err.to_string().contains("no content"), "{err}");
    }

    #[test]
    fn rejects_an_empty_scope() {
        let err = AgentCtx::new(config(), "  ", true)
            .err()
            .expect("empty scope must be rejected");
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[test]
    fn dry_run_needs_no_key() {
        let mut c = config();
        c.llm.api_key.clear();
        let ctx = AgentCtx::new(c, "example.com", true).unwrap();
        assert!(ctx.dry_run);
        assert_eq!(ctx.provider.name(), "mock");
        assert!(ctx.scope.allows("example.com"));
    }

    #[test]
    fn live_mode_demands_a_key() {
        let mut c = config();
        c.llm.api_key.clear();
        c.offline = false;
        let err = AgentCtx::new(c, "example.com", false)
            .err()
            .expect("live mode without a key must be rejected");
        assert!(err.to_string().contains("DEEPSEEK_API_KEY"), "got: {err}");
    }

    #[test]
    fn registry_only_exposes_allowlisted_hosts() {
        let mut c = config();
        c.allowlist = vec!["nmap".into()];
        let ctx = AgentCtx::new(c, "example.com", true).unwrap();
        assert!(ctx.registry.get("host_nmap").is_some());
        assert!(ctx.registry.get("host_sqlmap").is_none());
        assert!(ctx.registry.get("port_scan").is_some());
    }

    #[tokio::test]
    async fn tool_ctx_is_scoped_and_per_flow() {
        let ctx = AgentCtx::new(config(), "example.com, 93.184.216.0/24", true).unwrap();
        let t = ctx.tool_ctx(Some("flw_x"), false).unwrap();
        assert!(t.check_scope("example.com").is_ok());
        assert!(t.check_scope("evil.test").is_err());
        assert!(t.workdir.ends_with("flw_x"));
        assert!(!t.offensive);
    }
}
