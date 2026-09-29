//! The generation client, chosen from configuration.
//!
//! One factory so the agent and the setup wizard agree on what "ready to run"
//! means: dry-run gives the scripted provider, keyless endpoints need no key,
//! and every other failure says which value is missing and where to set it.

use anyhow::{bail, Context as _};
use lantern_core::config::Config;
use lantern_core::providers::{self, Wire};
use lantern_llm::anthropic::Anthropic;
use lantern_llm::mock::MockProvider;
use lantern_llm::openai_compat::OpenAiCompat;
use lantern_llm::provider::ChatProvider;
use std::sync::Arc;
use std::time::Duration;

/// Build the client a flow talks to. Errors are operator-facing: they name the
/// variable or the wizard step that fixes the problem.
pub fn provider_for(config: &Config, dry_run: bool) -> anyhow::Result<Arc<dyn ChatProvider>> {
    if dry_run {
        return Ok(Arc::new(MockProvider::new()));
    }
    if config.offline {
        bail!("offline mode: no model calls possible (use --dry-run for a scripted run)");
    }
    if config.llm.base_url.is_empty() {
        bail!(
            "no endpoint: provider `{}` has no base URL - run `lantern setup` or set LANTERN_LLM_BASE_URL",
            config.llm.provider
        );
    }
    if config.llm.model.is_empty() {
        bail!(
            "no model: provider `{}` has none configured - run `lantern setup` or set LANTERN_LLM_MODEL",
            config.llm.provider
        );
    }
    let preset = providers::by_id(&config.llm.provider);
    if !config.has_llm_key() && config.provider_needs_key() {
        let hint = preset
            .and_then(|p| p.key_env)
            .unwrap_or("LANTERN_LLM_API_KEY");
        bail!(
            "no generation key: set {hint} in the environment or add it with `lantern setup`"
        );
    }

    let client = match preset.map(|p| p.wire).unwrap_or(Wire::OpenAi) {
        Wire::OpenAi => Arc::new(
            OpenAiCompat::new(
                &config.llm.base_url,
                &config.llm.model,
                &config.llm.api_key,
                Duration::from_secs(config.llm.timeout_secs),
            )
            .context("building model client")?,
        ) as Arc<dyn ChatProvider>,
        Wire::Anthropic => Arc::new(
            Anthropic::new(
                &config.llm.base_url,
                &config.llm.model,
                &config.llm.api_key,
                Duration::from_secs(config.llm.timeout_secs),
            )
            .context("building model client")?,
        ) as Arc<dyn ChatProvider>,
    };
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ready-to-run configuration with the default preset filled in.
    fn config() -> Config {
        let mut c = Config::load().unwrap();
        c.offline = false;
        c.llm.provider = "deepseek".into();
        c.llm.base_url = "https://api.deepseek.com".into();
        c.llm.model = "deepseek-flash".into();
        c.llm.api_key = "sk-test".into();
        c
    }

    #[test]
    fn dry_run_needs_nothing() {
        let mut c = config();
        c.llm.api_key.clear();
        c.llm.base_url.clear();
        assert!(provider_for(&c, true).is_ok());
    }

    #[test]
    fn a_missing_key_names_the_variable_for_that_provider() {
        for (provider, key_env) in [
            ("deepseek", "DEEPSEEK_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("mistral", "MISTRAL_API_KEY"),
        ] {
            let mut c = config();
            c.llm.provider = provider.into();
            c.llm.api_key.clear();
            let err = provider_for(&c, false)
                .err()
                .expect("a keyless configuration must not build a client")
                .to_string();
            assert!(
                err.contains(key_env) && err.contains("lantern setup"),
                "{provider}: error should point at {key_env} and the wizard, got: {err}"
            );
        }
    }

    #[test]
    fn a_keyless_endpoint_needs_no_key() {
        let mut c = config();
        c.llm.provider = "ollama".into();
        c.llm.base_url = "http://127.0.0.1:11434/v1".into();
        c.llm.model = "llama3.2".into();
        c.llm.api_key.clear();
        assert!(!c.degraded(), "a local endpoint is not a degraded run");
        assert!(provider_for(&c, false).is_ok());
    }

    #[test]
    fn an_empty_model_says_which_provider_and_what_to_run() {
        let mut c = config();
        c.llm.provider = "ollama".into();
        c.llm.model.clear();
        let err = provider_for(&c, false)
                .err()
                .expect("a keyless configuration must not build a client")
                .to_string();
        assert!(err.contains("ollama") && err.contains("lantern setup"), "{err}");
    }

    #[test]
    fn every_preset_in_the_table_builds_a_client() {
        for p in providers::PROVIDERS {
            if p.base_url.is_empty() || p.default_model.is_empty() {
                // custom / local: the operator supplies these
                continue;
            }
            let mut c = config();
            c.llm.provider = p.id.into();
            c.llm.base_url = p.base_url.into();
            c.llm.model = p.default_model.into();
            c.llm.api_key = if p.key_env.is_some() {
                "sk-test".into()
            } else {
                String::new()
            };
            assert!(
                provider_for(&c, false).is_ok(),
                "preset {} did not produce a client",
                p.id
            );
        }
    }
}
