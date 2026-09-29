//! Where the chosen provider, model and key live.
//!
//! Two files, both outside the data root, both under one directory
//! (`$XDG_CONFIG_HOME/lantern`, else `~/.config/lantern`, override with
//! `LANTERN_CONFIG_DIR`):
//!
//! * `config.json` - provider id, model, endpoint. No secrets, safe to keep
//!   under version control or copy between machines.
//! * `credentials` - the API key, created with mode `0600`. It is never echoed,
//!   never logged, never copied into the database, a trace or an artifact.
//!
//! Precedence everywhere: environment > these files > preset defaults.

use anyhow::Context as _;
use lantern_core::config::Config;
use lantern_core::providers;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// The non-secret half of the wizard's answer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

fn resolve_dir(overridden: Option<OsString>) -> PathBuf {
    if let Some(dir) = overridden {
        return PathBuf::from(dir);
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("lantern");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("lantern")
}

/// The directory both files live in.
pub fn dir() -> PathBuf {
    resolve_dir(std::env::var_os("LANTERN_CONFIG_DIR"))
}

pub fn config_file() -> PathBuf {
    dir().join("config.json")
}

pub fn credentials_file() -> PathBuf {
    dir().join("credentials")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Saved preferences, or all-`None` when nothing has been saved yet.
pub fn read_prefs() -> Prefs {
    read_json(&config_file()).unwrap_or_default()
}

/// Saved credentials as a `{ "VAR": "value" }` object, or an empty value.
pub fn read_credentials() -> serde_json::Value {
    read_json(&credentials_file()).unwrap_or(serde_json::Value::Null)
}

/// Layer preferences and credentials over an environment-resolved config.
pub fn apply(config: &mut Config) {
    let prefs = read_prefs();
    let creds = read_credentials();
    merge(config, &prefs, &creds, env_set, env_get);
}

fn env_set(key: &str) -> bool {
    std::env::var_os(key).map(|v| !v.is_empty()).unwrap_or(false)
}

fn env_get(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// The merge itself, with the environment injected so precedence is testable
/// without mutating the process environment. Environment beats file, file
/// beats the preset, and an id this build has no table for resolves to nothing
/// rather than to someone else's endpoint.
pub(crate) fn merge(
    config: &mut Config,
    prefs: &Prefs,
    creds: &serde_json::Value,
    env_set: impl Fn(&str) -> bool,
    env_get: impl Fn(&str) -> Option<String>,
) {
    let set = |k: &str| -> Option<String> {
        if env_set(k) {
            env_get(k)
        } else {
            None
        }
        .filter(|v| !v.trim().is_empty())
    };

    config.llm.provider = set("LANTERN_LLM_PROVIDER")
        .or_else(|| prefs.provider.clone().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| config.llm.provider.clone());

    let preset = providers::by_id(&config.llm.provider);

    // A saved model or endpoint belongs to the provider it was saved with: a
    // preset default must not be overwritten by another provider's leftovers.
    let saved = prefs.provider.as_deref() == Some(config.llm.provider.as_str());

    config.llm.model = set("LANTERN_LLM_MODEL")
        .or_else(|| {
            saved
                .then(|| prefs.model.clone())
                .flatten()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| preset.map(|p| p.default_model.to_string()))
        .unwrap_or_default();

    config.llm.base_url = set("LANTERN_LLM_BASE_URL")
        .or_else(|| {
            saved
                .then(|| prefs.base_url.clone())
                .flatten()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| preset.map(|p| p.base_url.to_string()))
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();

    // The key belongs to the effective provider: a key minted for one vendor
    // is never sent to another just because it sat in the environment first.
    let key_env = preset.and_then(|p| p.key_env);
    let from_env = key_env
        .and_then(|k| env_get(k))
        .or_else(|| env_get("LANTERN_LLM_API_KEY"))
        .filter(|v| !v.trim().is_empty());
    let from_file = key_env
        .and_then(|k| creds.get(k))
        .or_else(|| creds.get("LANTERN_LLM_API_KEY"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    config.llm.api_key = from_env
        .or_else(|| from_file.map(str::to_string))
        .unwrap_or_default();
}

/// Where the key currently in use came from, for `lantern doctor`.
pub fn key_source(config: &Config) -> String {
    key_source_in(config, env_set, &read_credentials())
}

pub(crate) fn key_source_in(
    config: &Config,
    env_set: impl Fn(&str) -> bool,
    creds: &serde_json::Value,
) -> String {
    let key_env = providers::by_id(&config.llm.provider).and_then(|p| p.key_env);
    if let Some(k) = key_env {
        if env_set(k) {
            return format!("{k} (environment)");
        }
    }
    if env_set("LANTERN_LLM_API_KEY") {
        return "LANTERN_LLM_API_KEY (environment)".into();
    }
    let saved = key_env
        .and_then(|k| creds.get(k))
        .or_else(|| creds.get("LANTERN_LLM_API_KEY"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if saved {
        return "credentials file".into();
    }
    if config.has_llm_key() {
        return "environment".into();
    }
    if config.provider_needs_key() {
        "NO KEY - run `lantern setup`".into()
    } else {
        "not needed (this endpoint takes no key)".into()
    }
}

/// The key a provider would read right now, without printing it.
pub fn has_key(provider_id: &str) -> bool {
    has_key_in(provider_id, env_get, &read_credentials())
}

pub(crate) fn has_key_in(
    provider_id: &str,
    env_get: impl Fn(&str) -> Option<String>,
    creds: &serde_json::Value,
) -> bool {
    let Some(preset) = providers::by_id(provider_id) else {
        return false;
    };
    if preset.key_env.is_none() {
        return true;
    }
    if preset.key_env.and_then(|k| env_get(k)).is_some() {
        return true;
    }
    preset
        .key_env
        .and_then(|k| creds.get(k))
        .or_else(|| creds.get("LANTERN_LLM_API_KEY"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// Write the non-secret half. Returns the path it wrote.
pub fn save_prefs(provider: &str, model: &str, base_url: &str) -> anyhow::Result<PathBuf> {
    save_prefs_in(
        &dir(),
        provider,
        model,
        base_url,
    )
}

pub fn save_prefs_in(
    dir: &Path,
    provider: &str,
    model: &str,
    base_url: &str,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("config.json");
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "provider": provider,
        "model": model,
        "base_url": base_url,
    }))
    .context("encoding config.json")?;
    write_file(&path, body.as_bytes())?;
    Ok(path)
}

/// Store the key for the variable a provider reads. Returns the path it wrote.
pub fn save_key(env_name: &str, key: &str) -> anyhow::Result<PathBuf> {
    save_key_in(&dir(), env_name, key)
}

pub fn save_key_in(dir: &Path, env_name: &str, key: &str) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("credentials");
    let mut creds = read_json::<serde_json::Value>(&path).unwrap_or(serde_json::Value::Null);
    if !creds.is_object() {
        creds = serde_json::json!({});
    }
    creds[env_name] = serde_json::Value::String(key.to_string());
    let body = serde_json::to_string_pretty(&creds).context("encoding credentials")?;
    write_private(&path, body.as_bytes())?;
    Ok(path)
}

fn write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

/// Same, but the file is pinned to `0600` - an existing file keeps whatever
/// mode it was created with, so the permission is set again after the open.
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::config::{EmbedConfig, EmbedMode, Paths};

    fn config() -> Config {
        Config {
            paths: Paths::new(std::env::temp_dir().join("lantern-prefs-test")),
            tools_dir: PathBuf::from("/tmp/lantern-tools"),
            nuclei_templates: PathBuf::from("/tmp/lantern-templates"),
            data_cap_bytes: 1 << 30,
            log_cap_bytes: 1 << 20,
            floor_percent: 5,
            concurrency: 3,
            task_timeout_secs: 60,
            max_output_bytes: 1 << 20,
            child_as_bytes: 1 << 30,
            child_cpu_secs: 60,
            restricted_path: "/usr/bin".into(),
            allowlist: vec!["nmap".into()],
            offensive: false,
            artifact_retention_days: 7,
            log_retention_days: 30,
            trace_retention_days: 14,
            vacuum_free_percent: 25,
            offline: false,
            token_budget: 6_000,
            summarize_at: 4_500,
            keep_recent_tokens: 1_500,
            ram_per_task_bytes: 192 * 1024 * 1024,
            llm: lantern_core::config::LlmConfig {
                provider: "deepseek".into(),
                base_url: "https://api.deepseek.com".into(),
                model: "deepseek-flash".into(),
                api_key: String::new(),
                timeout_secs: 90,
                max_output_tokens: 2_000,
                temperature: 0.2,
            },
            embed: EmbedConfig {
                mode: EmbedMode::Disabled,
                url: String::new(),
                model: String::new(),
                dims: 768,
            },
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lantern-prefs-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// No environment: only the injected closures can say otherwise.
    fn no_env(_: &str) -> bool {
        false
    }
    fn nothing(_: &str) -> Option<String> {
        None
    }
    fn one_var(name: &'static str) -> impl Fn(&str) -> bool {
        move |k| k == name
    }

    #[test]
    fn nothing_configured_keeps_the_deepseek_defaults() {
        let mut c = config();
        merge(&mut c, &Prefs::default(), &serde_json::Value::Null, no_env, nothing);
        assert_eq!(c.llm.provider, "deepseek");
        assert_eq!(c.llm.base_url, "https://api.deepseek.com");
        assert_eq!(c.llm.model, "deepseek-flash");
        assert_eq!(c.llm.api_key, "");
    }

    #[test]
    fn a_saved_provider_switches_endpoint_model_and_key_variable() {
        let mut c = config();
        let prefs = Prefs {
            provider: Some("openai".into()),
            model: Some("gpt-4o-mini".into()),
            base_url: Some("https://api.openai.com/v1/".into()),
        };
        merge(&mut c, &prefs, &serde_json::Value::Null, no_env, nothing);
        assert_eq!(c.llm.provider, "openai");
        assert_eq!(c.llm.model, "gpt-4o-mini");
        assert_eq!(c.llm.base_url, "https://api.openai.com/v1", "trailing slash trimmed");
    }

    #[test]
    fn the_key_comes_from_the_credential_file_when_the_environment_is_bare() {
        let mut c = config();
        let prefs = Prefs {
            provider: Some("mistral".into()),
            ..Prefs::default()
        };
        let creds = serde_json::json!({"MISTRAL_API_KEY": "sk-from-file"});
        merge(&mut c, &prefs, &creds, no_env, nothing);
        assert_eq!(c.llm.provider, "mistral");
        assert_eq!(c.llm.model, "mistral-small-latest", "preset default fills the gap");
        assert_eq!(c.llm.api_key, "sk-from-file");
    }

    #[test]
    fn an_environment_key_beats_the_file() {
        let mut c = config();
        let prefs = Prefs {
            provider: Some("mistral".into()),
            ..Prefs::default()
        };
        let creds = serde_json::json!({"MISTRAL_API_KEY": "sk-from-file"});
        merge(
            &mut c,
            &prefs,
            &creds,
            no_env,
            |k| (k == "MISTRAL_API_KEY").then(|| "sk-from-env".to_string()),
        );
        assert_eq!(c.llm.api_key, "sk-from-env");
    }

    #[test]
    fn one_providers_key_is_never_used_for_another() {
        let mut c = config();
        // DeepSeek's key sits in the environment, but the saved provider is
        // OpenAI: nothing in the environment names an OpenAI key.
        let prefs = Prefs {
            provider: Some("openai".into()),
            ..Prefs::default()
        };
        merge(
            &mut c,
            &prefs,
            &serde_json::Value::Null,
            no_env,
            |k| (k == "DEEPSEEK_API_KEY").then(|| "sk-deepseek".to_string()),
        );
        assert_eq!(c.llm.provider, "openai");
        assert_eq!(c.llm.api_key, "", "a foreign key must not be sent");
    }

    #[test]
    fn environment_wins_over_the_saved_model_and_provider() {
        let mut c = config();
        let prefs = Prefs {
            provider: Some("openai".into()),
            model: Some("gpt-4o".into()),
            base_url: Some("https://api.openai.com/v1".into()),
        };
        merge(
            &mut c,
            &prefs,
            &serde_json::Value::Null,
            |k| {
                matches!(
                    k,
                    "LANTERN_LLM_PROVIDER" | "LANTERN_LLM_MODEL" | "LANTERN_LLM_BASE_URL"
                )
            },
            |k| match k {
                "LANTERN_LLM_PROVIDER" => Some("groq".into()),
                "LANTERN_LLM_MODEL" => Some("llama-3.3-70b-versatile".into()),
                "LANTERN_LLM_BASE_URL" => Some("https://api.groq.com/openai/v1".into()),
                _ => None,
            },
        );
        assert_eq!(c.llm.provider, "groq");
        assert_eq!(c.llm.model, "llama-3.3-70b-versatile");
        assert_eq!(c.llm.base_url, "https://api.groq.com/openai/v1");
    }

    #[test]
    fn a_saved_model_is_ignored_when_the_provider_came_from_the_environment() {
        let mut c = config();
        let prefs = Prefs {
            provider: Some("deepseek".into()),
            model: Some("deepseek-reasoner".into()),
            base_url: None,
        };
        merge(
            &mut c,
            &prefs,
            &serde_json::Value::Null,
            |k| k == "LANTERN_LLM_PROVIDER",
            |k| (k == "LANTERN_LLM_PROVIDER").then(|| "xai".into()),
        );
        assert_eq!(c.llm.provider, "xai");
        assert_eq!(c.llm.model, "grok-4", "the preset default, not another provider's model");
        assert_eq!(c.llm.base_url, "https://api.x.ai/v1");
    }

    #[test]
    fn unknown_provider_ids_degrade_to_empty_not_to_a_guess() {
        let mut c = config();
        merge(
            &mut c,
            &Prefs {
                provider: Some("typo".into()),
                ..Prefs::default()
            },
            &serde_json::Value::Null,
            no_env,
            nothing,
        );
        assert_eq!(c.llm.provider, "typo");
        assert_eq!(c.llm.base_url, "", "the client says what is missing instead");
        assert_eq!(c.llm.model, "");
    }

    #[test]
    fn saved_files_round_trip_and_the_key_file_is_0600() {
        let dir = tmp("save");
        let path = save_prefs_in(&dir, "openai", "gpt-4o-mini", "https://api.openai.com/v1")
            .expect("config.json written");
        assert_eq!(path, dir.join("config.json"));

        let key_path = save_key_in(&dir, "OPENAI_API_KEY", "sk-secret").expect("key written");
        assert_eq!(key_path, dir.join("credentials"));
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key file must not be group or world readable");

        // Reading back: provider, model, endpoint, and a key under its variable.
        let prefs: Prefs = read_json(&path).unwrap();
        assert_eq!(
            prefs,
            Prefs {
                provider: Some("openai".into()),
                model: Some("gpt-4o-mini".into()),
                base_url: Some("https://api.openai.com/v1".into()),
            }
        );
        let creds: serde_json::Value = read_json(&key_path).unwrap();
        assert_eq!(creds["OPENAI_API_KEY"], "sk-secret");

        // A second key merges instead of replacing the first.
        save_key_in(&dir, "GROQ_API_KEY", "gsk-1").unwrap();
        let creds: serde_json::Value = read_json(&key_path).unwrap();
        assert_eq!(creds["OPENAI_API_KEY"], "sk-secret");
        assert_eq!(creds["GROQ_API_KEY"], "gsk-1");
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "re-writing must not loosen the mode");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_files_read_as_empty_and_configured_is_false() {
        let dir = tmp("missing");
        assert!(read_json::<Prefs>(&dir.join("config.json")).is_none());
        assert_eq!(read_json::<serde_json::Value>(&dir.join("credentials")), None);
        assert!(!dir.join("config.json").exists());
    }

    #[test]
    fn key_source_describes_where_the_key_came_from_without_printing_it() {
        let mut c = config();
        c.llm.provider = "ollama".into();
        assert_eq!(
            key_source_in(&c, no_env, &serde_json::Value::Null),
            "not needed (this endpoint takes no key)"
        );

        let c = config();
        assert_eq!(
            key_source_in(&c, no_env, &serde_json::Value::Null),
            "NO KEY - run `lantern setup`"
        );
        assert_eq!(
            key_source_in(&c, no_env, &serde_json::json!({"DEEPSEEK_API_KEY": "sk-x"})),
            "credentials file"
        );
        assert_eq!(
            key_source_in(&c, one_var("DEEPSEEK_API_KEY"), &serde_json::Value::Null),
            "DEEPSEEK_API_KEY (environment)"
        );

        let mut c = config();
        c.llm.provider = "openai".into();
        assert_eq!(
            key_source_in(&c, no_env, &serde_json::json!({"DEEPSEEK_API_KEY": "sk-x"})),
            "NO KEY - run `lantern setup`",
            "a key saved for another provider does not count"
        );
    }

    #[test]
    fn has_key_looks_under_the_right_variable() {
        let creds = serde_json::json!({"OPENAI_API_KEY": "sk-1", "DEEPSEEK_API_KEY": "sk-2"});
        assert!(has_key_in("ollama", nothing, &serde_json::Value::Null));
        assert!(has_key_in("openai", nothing, &creds));
        assert!(!has_key_in("groq", nothing, &creds));
        assert!(has_key_in("groq", |k| (k == "GROQ_API_KEY").then(|| "gsk".into()), &creds));
        assert!(!has_key_in("typo", nothing, &creds));
    }
}
