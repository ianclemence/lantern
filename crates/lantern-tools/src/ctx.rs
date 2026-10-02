//! Execution context handed to every tool: scope, budget, storage and the
//! per-flow working directory. Tools never touch the filesystem outside the
//! paths this struct hands out.

use anyhow::{bail, Context};
use lantern_core::budget::Budget;
use lantern_core::config::Config;
use lantern_core::error::CoreError;
use lantern_core::scope::Scope;
use lantern_core::storage::models::CommandRow;
use lantern_core::storage::Db;
use lantern_core::timeutil;
use lantern_llm::embed::{embedder_from, Embedder};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct ToolCtx {
    pub config: Arc<Config>,
    pub db: Arc<Db>,
    pub budget: Arc<Budget>,
    pub scope: Arc<Scope>,
    pub flow_id: Option<String>,
    pub workdir: PathBuf,
    pub offensive: bool,
    /// The operator may be asked a question: `lantern run --interactive`.
    pub interactive: bool,
    /// The plan as it currently stands. Roles amend it with `plan_patch` and
    /// later roles are handed the amended version.
    pub plan: Arc<std::sync::Mutex<Vec<String>>>,
    /// Tool invocations this flow has made. The report quotes it, so it counts
    /// attempts, failures included.
    pub tool_calls: Arc<std::sync::atomic::AtomicUsize>,
    pub http: reqwest::Client,
    pub embedder: Arc<dyn Embedder>,
}

impl ToolCtx {
    pub fn new(
        config: Arc<Config>,
        db: Arc<Db>,
        budget: Arc<Budget>,
        scope: Arc<Scope>,
        flow_id: Option<String>,
        offensive: bool,
    ) -> anyhow::Result<Self> {
        let root = config.paths.flows();
        let workdir = match &flow_id {
            Some(id) => root.join(sanitize(id)),
            None => root.join("_adhoc"),
        };
        std::fs::create_dir_all(&workdir)
            .with_context(|| format!("creating workdir {}", workdir.display()))?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .connect_timeout(std::time::Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(config.user_agent.clone())
            .build()
            .context("building http client")?;

        let embedder = embedder_from(&config.embed);

        Ok(Self {
            config,
            db,
            budget,
            scope,
            flow_id,
            workdir,
            offensive,
            interactive: false,
            plan: Arc::new(std::sync::Mutex::new(Vec::new())),
            tool_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            http,
            embedder,
        })
    }

    /// Replace the live plan (the planner's ordering, or a fresh seed).
    pub fn set_plan(&self, steps: Vec<String>) {
        *self.plan.lock().unwrap_or_else(|e| e.into_inner()) = steps;
    }

    /// The live plan as numbered text, ready for a prompt.
    pub fn plan_text(&self) -> String {
        crate::tools::plan::render_steps(&self.plan.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Record one tool invocation: the report quotes this count.
    pub fn note_tool_call(&self) {
        self.tool_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Tool invocations so far, failed ones included.
    pub fn tool_call_count(&self) -> usize {
        self.tool_calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cross-role memory for the flow this context belongs to. The namespace is
    /// the normalized scope string, which is exactly what the runtime uses, so
    /// anything a tool stores lands where role prompts read it back.
    pub fn memory(&self) -> crate::memory::Memory {
        crate::memory::Memory::new(
            self.db.clone(),
            self.scope.render(),
            self.embedder.clone(),
        )
    }

    /// Refuse any target outside the flow's declared scope.
    pub fn check_scope(&self, target: &str) -> anyhow::Result<()> {
        self.scope.require(target)?;
        Ok(())
    }

    /// Per-flow artifact directory (always under the data root).
    pub fn artifact_dir(&self) -> PathBuf {
        let dir = self.config.paths.artifacts().join(
            self.flow_id
                .clone()
                .unwrap_or_else(|| "_adhoc".to_string()),
        );
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Write bytes as a retention-tracked artifact. Path traversal is rejected
    /// and the write counts against the data-root cap.
    pub fn write_artifact(&self, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
        if name.contains("..") || name.starts_with('/') || name.contains('\0') {
            bail!("illegal artifact name: {name}");
        }
        let dir = self.artifact_dir();
        let path = dir.join(name);

        // Defence in depth: the resolved path must still be inside the data root.
        let root = &self.config.paths.root;
        if !path.starts_with(root) {
            bail!("artifact path escapes data root: {}", path.display());
        }

        let reservation = self.budget.reserve(bytes.len() as u64)?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("writing {}", path.display()))?;
        reservation.commit(bytes.len() as u64);

        let expires = timeutil::now() + (self.config.artifact_retention_days as i64) * 86_400;
        let _ = self.db.add_artifact(
            self.flow_id.as_deref(),
            "tool-output",
            &path.display().to_string(),
            bytes.len() as u64,
            expires,
        );
        Ok(path)
    }

    /// Append a command to the audit log.
    pub fn record(&self, row: &CommandRow) {
        if let Err(e) = self.db.add_command(row) {
            tracing::warn!(error = %e, "failed to record command");
        }
    }

    /// Persist a structured event for the flow timeline.
    pub fn event(&self, level: &str, kind: &str, message: &str, data: Option<serde_json::Value>) {
        let _ = self.db.add_event(
            self.flow_id.as_deref(),
            None,
            level,
            kind,
            message,
            data.as_ref(),
        );
    }

    /// Reserve a chunk of the output budget for a tool that will emit text.
    pub fn reserve(&self, bytes: u64) -> Result<(), CoreError> {
        self.budget.can_write(bytes)
    }
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Ensure a path is a regular file the operator supplied (used by tools that
/// take an input list). Directories and symlinks-to-directories are rejected.
pub fn require_input_file(path: &Path) -> anyhow::Result<u64> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("input file {} does not exist", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > 64 * 1024 * 1024 {
        bail!("input file too large ({} bytes)", meta.len());
    }
    Ok(meta.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::budget::dir_size;

    fn ctx() -> ToolCtx {
        let root = crate::tools::test_root("tctx");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = lantern_core::config::Paths::new(root);
        config.paths.ensure().unwrap();
        let db = Db::open(&config.paths.db()).unwrap();
        let budget = Budget::new(config.data_cap_bytes, 0);
        let scope = Scope::parse("10.0.0.0/8, example.com").unwrap();
        ToolCtx::new(
            Arc::new(config),
            Arc::new(db),
            Arc::new(budget),
            Arc::new(scope),
            Some("flw_test".into()),
            false,
        )
        .unwrap()
    }

    #[test]
    fn scope_is_enforced() {
        let c = ctx();
        assert!(c.check_scope("10.1.2.3").is_ok());
        assert!(c.check_scope("8.8.8.8").is_err());
        assert!(c.check_scope("example.com").is_ok());
        assert!(c.check_scope("evil.com").is_err());
    }

    #[test]
    fn artifacts_stay_inside_data_root_and_count_against_budget() {
        let c = ctx();
        let p = c.write_artifact("out.txt", &[b'x'; 1024]).unwrap();
        assert!(p.starts_with(&c.config.paths.root));
        assert!(p.exists());
        assert!(c.budget.used_bytes() >= 1024);

        assert!(c.write_artifact("../escape.txt", b"x").is_err());
        assert!(c.write_artifact("/etc/passwd", b"x").is_err());
        assert!(!c.config.paths.root.join("../escape.txt").exists());
        assert!(dir_size(&c.config.paths.root) >= 1024);
    }

    #[test]
    fn budget_rejects_oversized_artifact() {
        let root = crate::tools::test_root("tctx2");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = lantern_core::config::Paths::new(root);
        config.paths.ensure().unwrap();
        let db = Db::open(&config.paths.db()).unwrap();
        let budget = Budget::new(2048, 0);
        let c = ToolCtx::new(
            Arc::new(config),
            Arc::new(db),
            Arc::new(budget),
            Arc::new(Scope::parse("0.0.0.0/0").unwrap()),
            None,
            false,
        )
        .unwrap();
        assert!(c.write_artifact("big.bin", &[0u8; 8192]).is_err());
    }

    #[test]
    fn input_file_guard() {
        assert!(require_input_file(Path::new("/nonexistent-xyz")).is_err());
        assert!(require_input_file(Path::new("/tmp")).is_err()); // directory
    }
}
