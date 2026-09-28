//! `lantern flows`, `report`, `tools` and `gc`.

use lantern_core::config::Config;
use lantern_core::retention;
use lantern_core::storage::Db;
use lantern_core::timeutil;
use lantern_tools::registry::Registry;
use std::path::PathBuf;

pub fn flows(config: &Config, limit: i64) -> anyhow::Result<()> {
    let db = Db::open(&config.paths.db())?;
    let flows = db.list_flows(limit)?;
    if flows.is_empty() {
        println!("no flows recorded yet (data root: {})", config.paths.root.display());
        return Ok(());
    }
    println!(
        "{:<26} {:<10} {:<28} {:<21} SCOPE",
        "FLOW", "STATUS", "TARGET", "CREATED"
    );
    for f in flows {
        println!(
            "{:<26} {:<10} {:<28} {:<21} {}",
            f.id,
            f.status,
            clip(&f.target, 28),
            timeutil::rfc3339(f.created_at),
            clip(&f.scope, 60)
        );
    }
    Ok(())
}

pub fn report(config: &Config, flow_id: &str, out: Option<PathBuf>) -> anyhow::Result<()> {
    let db = Db::open(&config.paths.db())?;
    let text = lantern_agent::report::build(&db, flow_id)?;
    match out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, text)?;
            println!("wrote {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

pub fn tools(config: &Config) -> anyhow::Result<()> {
    let registry = Registry::new(config)?;
    println!("native tools (in-process, no child process):");
    for t in registry.tools() {
        if t.name().starts_with("host_") {
            continue;
        }
        println!("  {:<16} {}", t.name(), clip(t.description(), 96));
    }
    println!("\nhost binaries (allowlisted, sandboxed, audited):");
    let any = registry.tools().iter().any(|t| t.name().starts_with("host_"));
    if !any {
        println!("  (none allowlisted - set LANTERN_ALLOWLIST)");
    }
    for t in registry.tools() {
        if !t.name().starts_with("host_") {
            continue;
        }
        let gate = if t.requires_offensive() {
            " [requires --offensive]"
        } else {
            ""
        };
        println!("  {:<16} {}{gate}", t.name(), clip(t.description(), 92));
    }
    println!("\nscope and --offensive are enforced centrally in the registry,");
    println!("before any tool body runs. There is no shell anywhere in the system.");
    Ok(())
}

pub fn gc(config: &Config) -> anyhow::Result<()> {
    let db = Db::open(&config.paths.db())?;
    let before = lantern_core::budget::dir_size(&config.paths.root);
    let budget = lantern_core::budget::Budget::new(config.data_cap_bytes, before);
    let report = retention::run(config, &db, &budget)?;
    println!("{}", report.summary());
    let after = lantern_core::budget::dir_size(&config.paths.root);
    println!(
        "data root {:.1} MB -> {:.1} MB (cap {:.1} MB, {:.1} MB of budget left)",
        before as f64 / 1_048_576.0,
        after as f64 / 1_048_576.0,
        config.data_cap_bytes as f64 / 1_048_576.0,
        config.data_cap_bytes.saturating_sub(after) as f64 / 1_048_576.0
    );
    Ok(())
}

fn clip(text: &str, max: usize) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_is_single_line_and_bounded() {
        assert_eq!(clip("a b", 10), "a b");
        assert!(clip(&"x ".repeat(80), 30).chars().count() <= 30);
        assert!(!clip("a\nb", 10).contains('\n'));
    }
}
