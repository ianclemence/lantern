//! Tool implementations. Each tool is a unit struct with typed input/output,
//! executed in-process (no shell, no child process) unless it explicitly wraps
//! an allowlisted host binary.

pub mod dirb;
pub mod dns;
pub mod host;
pub mod http_probe;
pub mod port_scan;
pub mod search;
pub mod tls_inspect;
pub mod whois;
pub mod wordlist;

/// Shared helper: pull a required string field.
pub fn str_field(input: &serde_json::Value, key: &str) -> anyhow::Result<String> {
    input
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required field `{key}`"))
}

pub fn opt_str_field(input: &serde_json::Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn opt_u64(input: &serde_json::Value, key: &str, default: u64) -> u64 {
    input
        .get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or(default)
}

/// Unique temp data root per test (process id + test thread name), so parallel
/// tests never delete each other's database.
#[cfg(test)]
pub(crate) fn test_root(prefix: &str) -> std::path::PathBuf {
    let thread = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    std::env::temp_dir().join(format!(
        "lantern-{prefix}-{}-{thread}",
        std::process::id()
    ))
}

/// Shared test fixture: per-process temp data root, full scope, read-only tools.
#[cfg(test)]
pub(crate) use crate::ctx::ToolCtx;
#[cfg(test)]
pub(crate) fn test_ctx() -> ToolCtx {
    test_ctx_scoped("0.0.0.0/0, ::0/0, localhost, *.example.com")
}

/// Same fixture with a narrow scope, so out-of-scope cases never touch the
/// network (the scope check rejects them before any socket is opened).
#[cfg(test)]
pub(crate) fn test_ctx_scoped(scope: &str) -> ToolCtx {
    use lantern_core::budget::Budget;
    use lantern_core::config::{Config, Paths};
    use lantern_core::scope::Scope;
    use lantern_core::storage::Db;
    use std::sync::Arc;

    let root = test_root("toolctx");
    let _ = std::fs::remove_dir_all(&root);
    let mut config = Config::load().expect("config");
    config.paths = Paths::new(root);
    config.paths.ensure().expect("dirs");
    let db = Db::open(&config.paths.db()).expect("db");
    let budget = Budget::new(config.data_cap_bytes, 0);
    let scope = Scope::parse(scope).expect("scope");
    ToolCtx::new(
        Arc::new(config),
        Arc::new(db),
        Arc::new(budget),
        Arc::new(scope),
        Some(format!("flw_test_{}", std::process::id())),
        true,
    )
    .expect("ctx")
}
