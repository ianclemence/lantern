//! Generation-provider presets: which endpoints exist, which wire format each
//! speaks, and which key variable it reads.
//!
//! A preset is only a default. Everything in here can be overridden by
//! `LANTERN_LLM_PROVIDER`, `LANTERN_LLM_BASE_URL` and `LANTERN_LLM_MODEL`, or
//! by the preferences the setup wizard writes - a preset just means the
//! operator does not have to know a base URL by heart.

/// The wire format a provider speaks. Two clients implement it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// `POST {base}/chat/completions` with a bearer key: the shape most
    /// endpoints (and every local server) speak.
    OpenAi,
    /// `POST {base}/v1/messages` with `x-api-key`.
    Anthropic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// Stable id: what `config.json` stores and `LANTERN_LLM_PROVIDER` selects.
    pub id: &'static str,
    /// How it is shown to the operator.
    pub name: &'static str,
    pub wire: Wire,
    pub base_url: &'static str,
    /// Environment variable holding the key. `None` means the endpoint is
    /// keyless (a local one).
    pub key_env: Option<&'static str>,
    /// Used when nothing else names a model. Empty when the only honest
    /// answer is "ask the endpoint what it has".
    pub default_model: &'static str,
    /// Shortlist shown when the live model list cannot be fetched.
    pub models: &'static [&'static str],
}

/// DeepSeek first: it is what this build has always defaulted to.
pub const DEFAULT_PROVIDER: &str = "deepseek";

pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "deepseek",
        name: "DeepSeek",
        wire: Wire::OpenAi,
        base_url: "https://api.deepseek.com",
        key_env: Some("DEEPSEEK_API_KEY"),
        default_model: "deepseek-flash",
        models: &["deepseek-flash", "deepseek-chat", "deepseek-reasoner"],
    },
    Provider {
        id: "openai",
        name: "OpenAI",
        wire: Wire::OpenAi,
        base_url: "https://api.openai.com/v1",
        key_env: Some("OPENAI_API_KEY"),
        default_model: "gpt-4o-mini",
        models: &["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1"],
    },
    Provider {
        id: "anthropic",
        name: "Anthropic",
        wire: Wire::Anthropic,
        base_url: "https://api.anthropic.com",
        key_env: Some("ANTHROPIC_API_KEY"),
        default_model: "claude-sonnet-4-5",
        models: &["claude-sonnet-4-5", "claude-haiku-4-5", "claude-3-5-haiku-latest"],
    },
    Provider {
        id: "gemini",
        name: "Gemini",
        wire: Wire::OpenAi,
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        key_env: Some("GEMINI_API_KEY"),
        default_model: "gemini-2.5-flash",
        models: &["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
    },
    Provider {
        id: "openrouter",
        name: "OpenRouter",
        wire: Wire::OpenAi,
        base_url: "https://openrouter.ai/api/v1",
        key_env: Some("OPENROUTER_API_KEY"),
        default_model: "deepseek/deepseek-chat",
        models: &[
            "deepseek/deepseek-chat",
            "openai/gpt-4o-mini",
            "google/gemini-2.5-flash",
        ],
    },
    Provider {
        id: "groq",
        name: "Groq",
        wire: Wire::OpenAi,
        base_url: "https://api.groq.com/openai/v1",
        key_env: Some("GROQ_API_KEY"),
        default_model: "llama-3.3-70b-versatile",
        models: &["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    },
    Provider {
        id: "mistral",
        name: "Mistral",
        wire: Wire::OpenAi,
        base_url: "https://api.mistral.ai/v1",
        key_env: Some("MISTRAL_API_KEY"),
        default_model: "mistral-small-latest",
        models: &["mistral-small-latest", "mistral-large-latest", "open-mistral-nemo"],
    },
    Provider {
        id: "xai",
        name: "xAI",
        wire: Wire::OpenAi,
        base_url: "https://api.x.ai/v1",
        key_env: Some("XAI_API_KEY"),
        default_model: "grok-4",
        models: &["grok-4", "grok-3-mini"],
    },
    Provider {
        id: "ollama",
        name: "Ollama (local)",
        wire: Wire::OpenAi,
        base_url: "http://127.0.0.1:11434/v1",
        key_env: None,
        default_model: "",
        models: &[],
    },
    // Keyless in the table: a custom endpoint may or may not ask for one. The
    // wizard stores whatever it is given under `LANTERN_LLM_API_KEY`, and a
    // remote one that does need a key says so on the first request.
    Provider {
        id: "custom",
        name: "Custom endpoint",
        wire: Wire::OpenAi,
        base_url: "",
        key_env: None,
        default_model: "",
        models: &[],
    },
];

pub fn by_id(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

pub fn default_provider() -> &'static Provider {
    by_id(DEFAULT_PROVIDER).expect("the default preset is in the table")
}

/// Every id, in menu order.
pub fn ids() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_preset_is_what_this_build_has_always_used() {
        let d = default_provider();
        assert_eq!(d.id, "deepseek");
        assert_eq!(d.base_url, "https://api.deepseek.com");
        assert_eq!(d.default_model, "deepseek-flash");
        assert_eq!(d.key_env, Some("DEEPSEEK_API_KEY"));
        assert_eq!(d.wire, Wire::OpenAi);
    }

    #[test]
    fn ids_are_unique_and_lookup_round_trips() {
        let mut seen = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert!(seen.insert(p.id), "duplicate id: {}", p.id);
            assert!(!p.name.is_empty());
            assert_eq!(by_id(p.id), Some(p), "lookup failed for {}", p.id);
        }
        assert_eq!(by_id("nope"), None);
    }

    #[test]
    fn every_endpoint_is_absolute_or_deliberately_empty() {
        for p in PROVIDERS {
            assert!(
                p.base_url.is_empty() || p.base_url.starts_with("http://") || p.base_url.starts_with("https://"),
                "{}: bad base URL {}",
                p.id,
                p.base_url
            );
            assert!(
                p.base_url.is_empty() || !p.base_url.ends_with('/'),
                "{}: base URL must not end in a slash: {}",
                p.id,
                p.base_url
            );
        }
    }

    #[test]
    fn shortlists_make_sense() {
        for p in PROVIDERS {
            assert!(
                p.default_model.is_empty() || p.models.contains(&p.default_model),
                "{}: default model {} is not in its own shortlist",
                p.id,
                p.default_model
            );
            // Keyless endpoints are the local ones: everything else names the
            // variable the wizard tells the operator to set.
            match p.key_env {
                Some(env) => assert!(
                    env.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                        && env.ends_with("_API_KEY"),
                    "{}: odd key variable {env}",
                    p.id
                ),
                None => assert!(
                    matches!(p.id, "ollama" | "custom"),
                    "only the local and custom presets are keyless"
                ),
            }
        }
    }
}
