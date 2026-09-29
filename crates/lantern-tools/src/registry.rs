//! Tool registry: typed native tools plus allowlisted host tools.

use crate::ctx::ToolCtx;
use anyhow::Context;
use lantern_core::config::Config;
use lantern_llm::provider::ToolDef;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

/// Result of a tool execution, ready to be fed back to the model.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// One-paragraph human/model-readable summary.
    pub summary: String,
    /// Structured payload for storage and reports.
    pub data: serde_json::Value,
    /// Artifact files written (all under the data root).
    pub artifacts: Vec<PathBuf>,
    pub ok: bool,
}

impl ToolOutput {
    pub fn new(summary: impl Into<String>, data: serde_json::Value, ok: bool) -> Self {
        Self {
            summary: summary.into(),
            data,
            artifacts: Vec::new(),
            ok,
        }
    }
    pub fn ok(summary: impl Into<String>, data: serde_json::Value) -> Self {
        Self::new(summary, data, true)
    }
    pub fn failed(summary: impl Into<String>) -> Self {
        Self::new(summary, json!({}), false)
    }
    pub fn with_artifacts(mut self, paths: Vec<PathBuf>) -> Self {
        self.artifacts = paths;
        self
    }
}

/// A native tool: typed input, typed output, no shell, no child process.
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    /// JSON schema for the model-facing function signature.
    fn parameters(&self) -> serde_json::Value;
    /// Active-attack tools refuse to run unless the flow was started with
    /// `--offensive`.
    fn requires_offensive(&self) -> bool {
        false
    }
    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>>;
}

/// Allowlisted host binary exposed as a tool.
#[derive(Debug, Clone)]
pub struct HostToolEntry {
    pub binary: &'static str,
    pub description: &'static str,
    pub offensive: bool,
    pub default_args: Vec<String>,
}

pub struct Registry {
    tools: Vec<Arc<dyn Tool>>,
    host: Vec<HostToolEntry>,
    allowlist: Vec<String>,
}

impl Registry {
    /// Build the registry: every native tool, plus whichever host binaries the
    /// operator allowlisted (from `LANTERN_ALLOWLIST` or the default set).
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let mut tools: Vec<Arc<dyn Tool>> = vec![
            Arc::new(crate::tools::port_scan::PortScan),
            Arc::new(crate::tools::dns::DnsLookup),
            Arc::new(crate::tools::http_probe::HttpProbe),
            Arc::new(crate::tools::tls_inspect::TlsInspect),
            Arc::new(crate::tools::whois::Whois),
            Arc::new(crate::tools::dirb::DirBrute),
            Arc::new(crate::tools::search::WebSearch),
            Arc::new(crate::tools::knowledge::MemorySearch),
            Arc::new(crate::tools::knowledge::MemoryStore),
            Arc::new(crate::tools::ask::AskOperator),
            Arc::new(crate::tools::plan::PlanPatch),
        ];
        tools.sort_by_key(|t| t.name());

        let all_host = crate::tools::host::host_tools();
        let allowlist: Vec<String> = config.allowlist.iter().cloned().collect();
        let host: Vec<HostToolEntry> = all_host
            .into_iter()
            .filter(|h| allowlist.iter().any(|a| a == h.binary))
            .collect();

        for h in &host {
            tools.push(Arc::new(crate::tools::host::HostTool {
                entry: h.clone(),
            }));
        }

        Ok(Self {
            tools,
            host,
            allowlist,
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.iter().find(|t| t.name() == name).cloned()
    }

    pub fn tools(&self) -> &[Arc<dyn Tool>] {
        &self.tools
    }

    pub fn host_tool(&self, binary: &str) -> Option<&HostToolEntry> {
        self.host.iter().find(|h| h.binary == binary)
    }

    pub fn allowlist(&self) -> &[String] {
        &self.allowlist
    }

    /// Model-facing function definitions.
    pub fn defs(&self) -> Vec<ToolDef> {
        self.tools
            .iter()
            .map(|t| ToolDef::new(t.name(), t.description(), t.parameters()))
            .collect()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.tools.iter().map(|t| t.name()).collect()
    }

    /// Validate + execute. Central choke point for scope and offensive gating.
    pub async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
        ctx: &ToolCtx,
    ) -> anyhow::Result<ToolOutput> {
        let tool = self
            .get(name)
            .with_context(|| format!("unknown tool `{name}` (available: {:?})", self.names()))?;

        if tool.requires_offensive() && !ctx.offensive {
            anyhow::bail!(
                "tool `{name}` performs active attacks and is disabled; re-run with --offensive"
            );
        }

        tracing::info!(tool = name, args = %input, "executing tool");
        let out = tool.execute(input, ctx).await?;
        ctx.event(
            if out.ok { "info" } else { "warn" },
            "tool",
            &format!("{name}: {}", out.summary),
            Some(json!({"tool": name, "ok": out.ok})),
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::budget::Budget;
    use lantern_core::scope::Scope;
    use lantern_core::storage::Db;

    fn make(offensive: bool, allow: &str) -> (Registry, ToolCtx) {
        let root = std::env::temp_dir().join(format!(
            "lantern-reg-{}-{}",
            std::process::id(),
            allow.replace(',', "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = lantern_core::config::Paths::new(root);
        config.paths.ensure().unwrap();
        config.allowlist = allow
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let db = Db::open(&config.paths.db()).unwrap();
        let budget = Budget::new(config.data_cap_bytes, 0);
        let scope = Scope::parse("0.0.0.0/0").unwrap();
        let ctx = ToolCtx::new(
            Arc::new(config.clone()),
            Arc::new(db),
            Arc::new(budget),
            Arc::new(scope),
            None,
            offensive,
        )
        .unwrap();
        (Registry::new(&config).unwrap(), ctx)
    }

    #[test]
    fn native_tools_are_always_registered_and_typed() {
        let (reg, _ctx) = make(false, "");
        for name in [
            "port_scan",
            "dns_lookup",
            "http_probe",
            "tls_inspect",
            "whois",
            "dir_bruteforce",
            "web_search",
            "memory_search",
            "memory_store",
            "ask_operator",
            "plan_patch",
        ] {
            let t = reg.get(name).unwrap_or_else(|| panic!("missing {name}"));
            assert!(!t.name().is_empty());
            assert!(!t.description().is_empty());
            assert!(t.parameters().is_object(), "{name} params must be an object");
        }
        // Sorted, deduped, model-facing defs exist.
        let defs = reg.defs();
        assert!(defs.len() >= 9);
        let mut names: Vec<_> = defs.iter().map(|d| d.name.clone()).collect();
        names.sort();
        let before = names.clone();
        names.dedup();
        assert_eq!(before, names, "duplicate tool names");
    }

    #[test]
    fn host_tools_respect_allowlist() {
        let (reg, _ctx) = make(false, "nmap,tcpdump");
        assert!(reg.host_tool("nmap").is_some());
        assert!(reg.host_tool("tcpdump").is_some());
        assert!(reg.host_tool("sqlmap").is_none(), "not allowlisted here");
        assert!(reg.get("host_nmap").is_some());
        assert!(reg.get("host_sqlmap").is_none());
    }

    #[tokio::test]
    async fn offensive_gate_blocks_active_tools() {
        let (reg, ctx) = make(false, "sqlmap,hydra");
        // Registry-level gate fires before anything is executed.
        let err = reg
            .execute("host_sqlmap", json!({"url": "http://10.0.0.1/"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--offensive"), "got: {err}");

        // With --offensive the gate opens (execution itself needs a real target,
        // so we only assert the refusal changes).
        let (reg2, ctx2) = make(true, "sqlmap,hydra");
        assert!(reg2.get("host_sqlmap").is_some());
        assert!(ctx2.offensive);
    }

    #[tokio::test]
    async fn unknown_tool_lists_alternatives() {
        let (reg, ctx) = make(false, "");
        let err = reg
            .execute("nope", json!({}), &ctx)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown tool"), "{msg}");
        assert!(msg.contains("port_scan"), "should list what exists: {msg}");
    }
}
