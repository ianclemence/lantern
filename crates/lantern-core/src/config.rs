//! Runtime configuration.
//!
//! This module only reads the environment: preferences and the credentials file
//! are layered on by the CLI (`prefs`) before anything runs, and nothing here
//! writes to disk. Every value falls back to a device-appropriate default, so a
//! fresh clone boots with no setup at all.

use crate::device::DeviceProfile;
use crate::error::{CoreError, Result};
use crate::providers;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Preset id: selects the wire format, the default endpoint and the key
    /// variable. `LANTERN_LLM_PROVIDER` or the preferences file set it.
    pub provider: String,
    /// Endpoint the client posts to.
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
    /// `User-Agent` every in-process HTTP fetch sends to a target
    /// (`http_probe`, `waf_fingerprint`, `dir_bruteforce`, `web_search`).
    /// Self-identifying by default - this is a deliberate reading of the
    /// same audit-first stance as everything else here (every command is
    /// logged argv-for-argv; a target's own logs seeing honest traffic is
    /// the same idea, not an oversight), and it lets a defender's SOC
    /// attribute the traffic in a detection-engineering engagement. Override
    /// it for an engagement where blending into ordinary browser traffic is
    /// itself part of what is being tested - but note what overriding this
    /// does and does not buy: host-tool adapters like `nmap`/`nikto` are not
    /// behaviourally stealthy regardless of any header (nikto in particular
    /// is a loud, signature-heavy scanner by design; `sqlmap`'s own
    /// `--random-agent` is a separate, already-enabled setting).
    pub user_agent: String,
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

/// Device-sized default for a child process's `RLIMIT_AS`: a sixteenth of
/// total RAM, clamped to a sane range. An 8 GiB host lands on the 512 MB this
/// value used to be hardcoded to; a 16 GiB host gets 1 GiB; a 2 GiB host is
/// floored at 256 MB rather than being handed an eighth of its entire memory.
fn default_child_mem_bytes(profile: &DeviceProfile) -> u64 {
    (profile.mem.total_bytes / 16).clamp(256 * 1024 * 1024, 2048 * 1024 * 1024)
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
        "testssl.sh",
        "gobuster",
        "amass",
        "GetUserSPNs.py",
        "GetNPUsers.py",
        "crackmapexec",
        "bloodhound-python",
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
        // `lantern setup` provisions (john is a standalone directory). Pip's
        // `--user` scripts (impacket, crackmapexec, bloodhound-python) land in
        // the per-user bin directory, so it joins the search path too.
        let mut default_restricted_path = format!(
            "/usr/local/bin:/usr/bin:/bin:{}:{}",
            tools_dir.join("john").display(),
            tools_dir.join("bin").display()
        );
        if let Some(home) = env_str("HOME") {
            default_restricted_path.push(':');
            default_restricted_path.push_str(&format!("{home}/.local/bin"));
        }

        // Device-sized defaults: `lantern doctor` used to compute these and
        // then throw the numbers away, leaving every box - a 4-core/8 GiB
        // target and a 64-core/256 GiB build server alike - on the same fixed
        // `concurrency=3`/`child=512 MB` regardless of what was actually
        // available. An explicit env var still wins; absent one, the profile
        // this host actually has now drives the default.
        let ram_per_task_bytes = env_u64("LANTERN_TASK_RAM_MB", 192) * 1024 * 1024;
        let profile = DeviceProfile::detect(&paths.root);
        let concurrency = match env_str("LANTERN_CONCURRENCY") {
            Some(v) => v.parse::<usize>().unwrap_or(3).clamp(1, 8),
            None => profile.recommended_concurrency(ram_per_task_bytes).clamp(1, 8),
        };
        let child_as_bytes = match env_str("LANTERN_CHILD_MEM_MB") {
            Some(v) => v.parse::<u64>().unwrap_or(512) * 1024 * 1024,
            None => default_child_mem_bytes(&profile),
        };
        // Provider first: it decides the endpoint default and which key
        // variable counts. An unknown id means the operator named something
        // this build has no table for, so every default stays empty and the
        // client reports which value is missing rather than guessing.
        let llm_provider =
            env_str("LANTERN_LLM_PROVIDER").unwrap_or_else(|| providers::DEFAULT_PROVIDER.to_string());
        let preset = providers::by_id(&llm_provider);
        let llm_base = env_str("LANTERN_LLM_BASE_URL")
            .unwrap_or_else(|| preset.map(|p| p.base_url.to_string()).unwrap_or_default());
        let llm_model = env_str("LANTERN_LLM_MODEL")
            .unwrap_or_else(|| preset.map(|p| p.default_model.to_string()).unwrap_or_default());
        let llm_key = preset
            .and_then(|p| p.key_env)
            .and_then(env_str)
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
            child_as_bytes,
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
            ram_per_task_bytes,
            user_agent: env_str("LANTERN_USER_AGENT")
                .unwrap_or_else(|| format!("lantern/{}", env!("CARGO_PKG_VERSION"))),
            llm: LlmConfig {
                provider: llm_provider,
                base_url: llm_base.trim_end_matches('/').to_string(),
                model: llm_model,
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

    /// False only for endpoints that need no key at all, such as a local
    /// server on this device.
    pub fn provider_needs_key(&self) -> bool {
        providers::by_id(&self.llm.provider)
            .map(|p| p.key_env.is_some())
            .unwrap_or(true)
    }

    /// True when the agent can still operate (tools run, reports render) but no
    /// model calls will be attempted.
    pub fn degraded(&self) -> bool {
        !self.has_llm_key() && !self.offline && self.provider_needs_key()
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
    fn user_agent_is_self_identifying_by_default_and_overridable() {
        std::env::remove_var("LANTERN_USER_AGENT");
        let c = Config::load().unwrap();
        assert!(c.user_agent.starts_with("lantern/"), "{}", c.user_agent);

        std::env::set_var("LANTERN_USER_AGENT", "Mozilla/5.0 (compatible; engagement-123)");
        let c = Config::load().unwrap();
        std::env::remove_var("LANTERN_USER_AGENT");
        assert_eq!(c.user_agent, "Mozilla/5.0 (compatible; engagement-123)");
    }

    #[test]
    fn allowlist_parsing() {
        // `default_allowlist` order is stable and shell-free.
        let a = default_allowlist();
        assert_eq!(
            a,
            vec![
                "nmap", "sqlmap", "nikto", "hydra", "tcpdump", "nuclei", "msfconsole", "john",
                "bwrap", "testssl.sh", "gobuster", "amass", "GetUserSPNs.py", "GetNPUsers.py",
                "crackmapexec", "bloodhound-python"
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
    fn child_mem_default_scales_with_ram_and_is_bounded() {
        let small = DeviceProfile {
            mem: crate::device::MemInfo { total_bytes: 1 * 1024 * 1024 * 1024, ..Default::default() },
            ..Default::default()
        };
        assert_eq!(default_child_mem_bytes(&small), 256 * 1024 * 1024, "floored, not an eighth of 1 GiB");

        let eight_gib = DeviceProfile {
            mem: crate::device::MemInfo { total_bytes: 8 * 1024 * 1024 * 1024, ..Default::default() },
            ..Default::default()
        };
        assert_eq!(
            default_child_mem_bytes(&eight_gib),
            512 * 1024 * 1024,
            "matches the value this used to be hardcoded to on the reference 8 GiB device"
        );

        let huge = DeviceProfile {
            mem: crate::device::MemInfo { total_bytes: 256 * 1024 * 1024 * 1024, ..Default::default() },
            ..Default::default()
        };
        assert_eq!(default_child_mem_bytes(&huge), 2048 * 1024 * 1024, "capped, not a 16 GiB child limit");
    }

    // `LANTERN_CONCURRENCY`/`LANTERN_CHILD_MEM_MB` are now read conditionally
    // (device-derived default only when the var is absent), where every
    // earlier env-backed setting here was an unconditional `env_u64`/`_usize`
    // with a fixed fallback. That makes these two tests order-sensitive
    // against each other under the default parallel test runner, since both
    // mutate the same process-global env vars; one lock serializes them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_vars_still_override_device_derived_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("LANTERN_CONCURRENCY", "7");
        std::env::set_var("LANTERN_CHILD_MEM_MB", "321");
        let c = Config::load().unwrap();
        std::env::remove_var("LANTERN_CONCURRENCY");
        std::env::remove_var("LANTERN_CHILD_MEM_MB");
        assert_eq!(c.concurrency, 7);
        assert_eq!(c.child_as_bytes, 321 * 1024 * 1024);
    }

    #[test]
    fn concurrency_and_child_mem_are_sane_without_any_env_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("LANTERN_CONCURRENCY");
        std::env::remove_var("LANTERN_CHILD_MEM_MB");
        let c = Config::load().unwrap();
        assert!((1..=8).contains(&c.concurrency), "got {}", c.concurrency);
        assert!(
            (256 * 1024 * 1024..=2048 * 1024 * 1024).contains(&c.child_as_bytes),
            "got {}",
            c.child_as_bytes
        );
    }

    #[test]
    fn paths_layout() {
        let p = Paths::new(PathBuf::from("/tmp/x"));
        assert!(p.db().ends_with("lantern.db"));
        assert!(p.artifacts().ends_with("artifacts"));
        assert!(p.reports().ends_with("reports"));
    }
}
