//! Runtime configuration.
//!
//! Everything is environment-driven and every value has a device-appropriate
//! default. API keys are read from the environment into memory only: this module
//! is never serialized to disk, and no code path writes a credential to a file.

use crate::error::{CoreError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// OpenAI-compatible endpoint.
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub max_output_tokens: u32,
    pub temperature: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedMode {
    /// Local Ollama model (preferred, free, works offline).
    Ollama,
    /// No embeddings available: keyword search only.
    Disabled,
}

#[derive(Debug, Clone)]
pub struct EmbedConfig {
    pub mode: EmbedMode,
    pub url: String,
    pub model: String,
    pub dims: usize,
}

impl EmbedConfig {
    pub fn enabled(&self) -> bool {
        self.mode == EmbedMode::Ollama
    }
}

/// Sub-directory layout of the data root.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn db(&self) -> PathBuf {
        self.root.join("lantern.db")
    }
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn artifacts(&self) -> PathBuf {
        self.root.join("artifacts")
    }
    pub fn flows(&self) -> PathBuf {
        self.root.join("flows")
    }
    pub fn reports(&self) -> PathBuf {
        self.root.join("reports")
    }
    pub fn traces(&self) -> PathBuf {
        self.root.join("traces")
    }

    pub fn ensure(&self) -> Result<()> {
        for d in [
            self.root.clone(),
            self.logs(),
            self.artifacts(),
            self.flows(),
            self.reports(),
            self.traces(),
        ] {
            std::fs::create_dir_all(&d).map_err(|e| CoreError::io(d.display().to_string(), e))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub paths: Paths,
    /// Where `lantern setup` provisions host tools it cannot get from the
    /// distribution (kept **outside** the capped data root).
    pub tools_dir: PathBuf,
    /// Default nuclei template directory (the `cves` subset).
    pub nuclei_templates: PathBuf,
    /// Hard cap on the whole data root.
    pub data_cap_bytes: u64,
    /// Hard cap on the log directory.
    pub log_cap_bytes: u64,
    /// Percentage of the filesystem that must always remain free.
    pub floor_percent: u8,
    /// Concurrent agent tasks (device sized: 3 on an 8 GB host).
    pub concurrency: usize,
    /// Per-command wall clock timeout.
    pub task_timeout_secs: u64,
    /// Per-command stdout/stderr capture limit.
    pub max_output_bytes: u64,
    /// RLIMIT_AS for child processes.
    pub child_as_bytes: u64,
    /// RLIMIT_CPU for child processes.
    pub child_cpu_secs: u64,
    /// PATH handed to child processes.
    pub restricted_path: String,
    /// Binaries the agent may execute. Anything else is rejected.
    pub allowlist: Vec<String>,
    /// Whether active-exploitation tools are permitted at all.
    pub offensive: bool,
    pub artifact_retention_days: u64,
    pub log_retention_days: u64,
    pub trace_retention_days: u64,
    /// Trigger an incremental/free-space VACUUM below this free percentage.
    pub vacuum_free_percent: u8,
    /// Refuse to run (tools that need the network) when true.
    pub offline: bool,
    /// Working context ceiling for the generation model.
    pub token_budget: usize,
    /// Summarize once the working context passes this many tokens.
    pub summarize_at: usize,
    /// Tokens of recent history kept verbatim across a summarization.
    pub keep_recent_tokens: usize,
    /// RAM allowance per concurrent task.
    pub ram_per_task_bytes: u64,
    pub llm: LlmConfig,
    pub embed: EmbedConfig,
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn env_u64(key: &str, default: u64) -> u64 {
    env_str(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    env_str(key)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match env_str(key) {
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

fn default_data_root() -> PathBuf {
    if let Some(p) = env_str("LANTERN_DATA_ROOT") {
        return PathBuf::from(p);
    }
    if let Some(xdg) = env_str("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("lantern");
    }
    let home = env_str("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".local/share/lantern")
}

fn default_tools_dir() -> PathBuf {
    if let Some(p) = env_str("LANTERN_TOOLS_DIR") {
        return PathBuf::from(p);
    }
    if let Some(xdg) = env_str("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("lantern-tools");
    }
    let home = env_str("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".local/share/lantern-tools")
}

fn default_allowlist() -> Vec<String> {
    [
        "nmap",
        "sqlmap",
        "nikto",
        "hydra",
        "tcpdump",
        "nuclei",
        "msfconsole",
        "john",
        "bwrap",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    /// Build configuration from the environment with device-sized defaults.
    pub fn load() -> Result<Self> {
        let root = default_data_root();
        let paths = Paths::new(root);
        let tools_dir = default_tools_dir();
        let nuclei_templates = env_str("LANTERN_NUCLEI_TEMPLATES")
            .map(PathBuf::from)
            .unwrap_or_else(|| tools_dir.join("share").join("nuclei-templates"));
        // Host binaries live either on the system PATH or in the tools dir that
        // `lantern setup` provisions (john is a standalone directory).
        let default_restricted_path = format!(
            "/usr/local/bin:/usr/bin:/bin:{}:{}",
            tools_dir.join("john").display(),
            tools_dir.join("bin").display()
        );

        let concurrency = env_usize("LANTERN_CONCURRENCY", 3).clamp(1, 8);
        let llm_base = env_str("LANTERN_LLM_BASE_URL").unwrap_or_else(|| "https://api.deepseek.com".into());
        let llm_key = env_str("DEEPSEEK_API_KEY")
            .or_else(|| env_str("LANTERN_LLM_API_KEY"))
            .unwrap_or_default();

        let embed_url = env_str("OLLAMA_URL").unwrap_or_else(|| "http://127.0.0.1:11434".into());
        // Semantic memory is enabled only when Ollama is configured; runtime
        // probing (see `probe_embedder`) demotes this to Disabled with a warning
        // if the endpoint turns out to be unreachable.
        let embed = EmbedConfig {
            mode: if env_bool("LANTERN_EMBED", true) {
                EmbedMode::Ollama
            } else {
                EmbedMode::Disabled
            },
            url: embed_url,
            model: env_str("OLLAMA_EMBED_MODEL").unwrap_or_else(|| "nomic-embed-text".into()),
            dims: env_usize("LANTERN_EMBED_DIMS", 768),
        };

        let token_budget = env_usize("LANTERN_TOKEN_BUDGET", 6_000);

        Ok(Self {
            paths,
            tools_dir,
            nuclei_templates,
            data_cap_bytes: env_u64("LANTERN_DATA_CAP_MB", 1_280) * 1024 * 1024,
            log_cap_bytes: env_u64("LANTERN_LOG_CAP_MB", 200) * 1024 * 1024,
            floor_percent: env_u64("LANTERN_DISK_FLOOR_PERCENT", 20).min(50) as u8,
            concurrency,
            task_timeout_secs: env_u64("LANTERN_TASK_TIMEOUT_SECS", 120),
            max_output_bytes: env_u64("LANTERN_MAX_OUTPUT_BYTES", 2 * 1024 * 1024),
            child_as_bytes: env_u64("LANTERN_CHILD_MEM_MB", 512) * 1024 * 1024,
            child_cpu_secs: env_u64("LANTERN_CHILD_CPU_SECS", 60),
            restricted_path: env_str("LANTERN_PATH").unwrap_or(default_restricted_path),
            allowlist: env_str("LANTERN_ALLOWLIST")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_else(default_allowlist),
            offensive: env_bool("LANTERN_OFFENSIVE", false),
            artifact_retention_days: env_u64("LANTERN_ARTIFACT_DAYS", 7),
            log_retention_days: env_u64("LANTERN_LOG_DAYS", 30),
            trace_retention_days: env_u64("LANTERN_TRACE_DAYS", 14),
            vacuum_free_percent: env_u64("LANTERN_VACUUM_FREE_PERCENT", 25).min(90) as u8,
            offline: env_bool("LANTERN_OFFLINE", false),
            token_budget,
            summarize_at: env_usize("LANTERN_SUMMARIZE_AT", token_budget.saturating_sub(1_500)),
            keep_recent_tokens: env_usize("LANTERN_KEEP_RECENT_TOKENS", 1_500),
            ram_per_task_bytes: env_u64("LANTERN_TASK_RAM_MB", 192) * 1024 * 1024,
            llm: LlmConfig {
                base_url: llm_base.trim_end_matches('/').to_string(),
                model: env_str("LANTERN_LLM_MODEL").unwrap_or_else(|| "deepseek-flash".into()),
                api_key: llm_key,
                timeout_secs: env_u64("LANTERN_LLM_TIMEOUT_SECS", 90),
                max_output_tokens: env_u64("LANTERN_LLM_MAX_TOKENS", 2_000) as u32,
                temperature: env_str("LANTERN_LLM_TEMPERATURE")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.2),
            },
            embed,
        })
    }

    pub fn has_llm_key(&self) -> bool {
        !self.llm.api_key.is_empty()
    }

    /// True when the agent can still operate (tools run, reports render) but no
    /// model calls will be attempted.
    pub fn degraded(&self) -> bool {
        !self.has_llm_key() && !self.offline
    }

    /// Ensure the data root exists, then return it.
    pub fn init_dirs(&self) -> Result<&Path> {
        self.paths.ensure()?;
        Ok(&self.paths.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_with_device_defaults() {
        let c = Config::load().unwrap();
        assert_eq!(c.floor_percent, 20);
        assert_eq!(c.data_cap_bytes, 1280 * 1024 * 1024);
        assert_eq!(c.log_cap_bytes, 200 * 1024 * 1024);
        assert!((1..=8).contains(&c.concurrency));
        assert!(c.allowlist.contains(&"nmap".to_string()));
        assert!(c.token_budget >= 2_000);
        assert!(c.paths.root.ends_with("lantern"));
    }

    #[test]
    fn allowlist_parsing() {
        // `default_allowlist` order is stable and shell-free.
        let a = default_allowlist();
        assert_eq!(
            a,
            vec![
                "nmap", "sqlmap", "nikto", "hydra", "tcpdump", "nuclei", "msfconsole", "john",
                "bwrap"
            ]
        );
        assert!(a.iter().all(|b| !b.contains('/') && !b.contains(' ')));
    }

    #[test]
    fn tools_dir_and_templates_are_outside_the_data_root() {
        let c = Config::load().unwrap();
        assert!(!c.tools_dir.starts_with(&c.paths.root));
        assert!(!c.nuclei_templates.starts_with(&c.paths.root));
        assert!(c.nuclei_templates.ends_with("nuclei-templates"));
        // The restricted PATH must reach both provisioning locations.
        assert!(c.restricted_path.contains(&c.tools_dir.display().to_string()));
    }

    #[test]
    fn paths_layout() {
        let p = Paths::new(PathBuf::from("/tmp/x"));
        assert!(p.db().ends_with("lantern.db"));
        assert!(p.artifacts().ends_with("artifacts"));
        assert!(p.reports().ends_with("reports"));
    }
}
