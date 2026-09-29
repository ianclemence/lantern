//! Deterministic report rendering. No model call: the report is assembled from
//! SQLite so it always matches what actually happened (and costs nothing).

use lantern_core::config::Config;
use lantern_core::storage::Db;
use lantern_core::timeutil;
use std::path::PathBuf;

fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Render the full markdown report for a flow.
pub fn build(db: &Db, flow_id: &str) -> anyhow::Result<String> {
    let flow = db
        .get_flow(flow_id)?
        .ok_or_else(|| anyhow::anyhow!("no such flow: {flow_id}"))?;

    let mut findings = db.findings_for_flow(flow_id)?;
    findings.sort_by_key(|f| (severity_order(&f.severity), -f.confidence.unwrap_or(0.0) as i64));

    let tasks = db.tasks_for_flow(flow_id)?;
    let commands = db.commands_for_flow(flow_id)?;
    let events = db.events_for_flow(flow_id)?;
    let artifacts: Vec<_> = db
        .all_artifacts()?
        .into_iter()
        .filter(|a| a.flow_id.as_deref() == Some(flow_id))
        .collect();

    let mut s = String::new();
    s.push_str("# Lantern assessment report\n\n");
    s.push_str(&format!("- Flow: `{}`\n", flow.id));
    s.push_str(&format!("- Target: `{}`\n", flow.target));
    s.push_str(&format!("- Scope: `{}`\n", flow.scope));
    s.push_str(&format!("- Status: {}\n", flow.status));
    s.push_str(&format!(
        "- Started: {}\n",
        timeutil::rfc3339(flow.created_at)
    ));
    s.push_str(&format!(
        "- Generated: {}\n\n",
        timeutil::rfc3339_now()
    ));

    let active = flow
        .options
        .get("offensive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let scripted = flow
        .options
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if active {
        s.push_str("> **Active testing was enabled for this flow** (`--offensive`).\n\n");
    }

    s.push_str("## Summary\n\n");
    // Counters recorded when the flow finished. Flows that predate them fall
    // back to what the rows can actually show: child processes and stages.
    let steps = flow
        .options
        .get("steps")
        .and_then(|v| v.as_u64())
        .unwrap_or(tasks.len() as u64);
    let invocations = flow
        .options
        .get("tool_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(commands.len() as u64);
    let footprint = flow.options.get("footprint");
    let counter = |key: &str| -> u64 {
        footprint
            .and_then(|f| f.get(key))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    // Token spend only appears when a run actually measured it: an older flow
    // says nothing instead of claiming it spent nothing.
    let tokens = if footprint.is_some() {
        format!(
            ", {} in / {} out tokens{}",
            lantern_core::grouped(counter("input_tokens")),
            lantern_core::grouped(counter("output_tokens")),
            if scripted { " (scripted - estimate)" } else { "" }
        )
    } else {
        String::new()
    };
    s.push_str(&format!(
        "{} finding(s), {} tool invocation(s), {} model step(s){}.\n\n",
        findings.len(),
        invocations,
        steps,
        tokens,
    ));
    if footprint.and_then(|f| f.get("budget")).is_some() {
        s.push_str(&format!(
            "Context peaked at {} of {} tokens: {} summarization(s), {} budget stop(s).\n\n",
            lantern_core::grouped(counter("peak_context")),
            lantern_core::grouped(counter("budget")),
            counter("summarizations"),
            counter("budget_stops"),
        ));
    }

    if findings.is_empty() {
        s.push_str("_No findings were recorded._\n\n");
    } else {
        s.push_str("## Findings\n\n");
        s.push_str("| # | Severity | Title | Asset | Confidence |\n|---|---|---|---|---|\n");
        for (i, f) in findings.iter().enumerate() {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                i + 1,
                f.severity,
                f.title.replace('|', "/"),
                f.asset.replace('|', "/"),
                f.confidence
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "-".into()),
            ));
        }
        s.push('\n');

        for (i, f) in findings.iter().enumerate() {
            s.push_str(&format!("### {}. [{}] {}\n\n", i + 1, f.severity, f.title));
            s.push_str(&format!("- Asset: `{}`", f.asset));
            if let Some(p) = f.port {
                s.push_str(&format!(" ({}/{})", f.proto.as_deref().unwrap_or("tcp"), p));
            }
            s.push('\n');
            if !f.description.is_empty() {
                s.push_str(&format!("- Impact: {}\n", f.description));
            }
            if let Some(e) = &f.evidence {
                s.push_str(&format!("- Evidence: {}\n", e));
            }
            if let Some(r) = &f.remediation {
                s.push_str(&format!("- Remediation: {}\n", r));
            }
            if let Some(c) = f.confidence {
                s.push_str(&format!(
                    "- Confidence: {:.2}{}\n",
                    c,
                    f.judge
                        .as_deref()
                        .map(|j| format!(" (judged by {j})"))
                        .unwrap_or_default()
                ));
            }
            s.push('\n');
        }
    }

    s.push_str("## Activity\n\n");
    if tasks.is_empty() {
        s.push_str("_No role tasks recorded._\n\n");
    } else {
        s.push_str("| Role | Status | Started |\n|---|---|---|\n");
        for t in &tasks {
            s.push_str(&format!(
                "| {} | {} | {} |\n",
                t.role,
                t.status,
                t.started_at
                    .map(timeutil::rfc3339)
                    .unwrap_or_else(|| "-".into())
            ));
        }
        s.push('\n');
    }

    s.push_str("## Commands executed\n\n");
    s.push_str(
        "Every host binary below ran with a cleared environment, a restricted PATH,\n\
         rlimits, a timeout and an output cap. There is no shell anywhere.\n\n",
    );
    if commands.is_empty() {
        s.push_str("_No host binaries were invoked._\n\n");
    } else {
        s.push_str("| Tool | Command | Exit | Duration |\n|---|---|---|---|\n");
        for c in &commands {
            let mut line = String::new();
            line.push_str(&c.binary);
            for a in &c.args {
                line.push(' ');
                if a.len() > 40 {
                    line.push_str(&format!("{}…", &a[..40]));
                } else {
                    line.push_str(a);
                }
            }
            s.push_str(&format!(
                "| {} | `{}` | {} | {} ms |\n",
                c.tool,
                line.replace('|', "/"),
                c.exit_code
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "timeout".into()),
                c.duration_ms,
            ));
        }
        s.push('\n');
    }

    if !artifacts.is_empty() {
        s.push_str("## Artifacts\n\n");
        for a in &artifacts {
            s.push_str(&format!(
                "- `{}` ({} bytes, {})\n",
                a.path,
                a.bytes,
                a.kind
            ));
        }
        s.push('\n');
    }

    s.push_str("## Notable events\n\n");
    let notable: Vec<_> = events
        .iter()
        .filter(|e| e.level != "info")
        .take(50)
        .collect();
    if notable.is_empty() {
        s.push_str("_No warnings or errors._\n");
    } else {
        for e in notable {
            s.push_str(&format!(
                "- `{}` {} — {}\n",
                timeutil::rfc3339(e.ts),
                e.level,
                e.message
            ));
        }
    }

    s.push_str(
        "\n---\n_Generated by Lantern. Scope-bounded, allowlisted, audited. \
         This tool does not exploit services; it observes and reports._\n",
    );
    Ok(s)
}

/// Write the report under `<data root>/reports/<flow>.md`.
pub fn write(config: &Config, db: &Db, flow_id: &str) -> anyhow::Result<PathBuf> {
    let text = build(db, flow_id)?;
    std::fs::create_dir_all(config.paths.reports())?;
    let path = config.paths.reports().join(format!("{flow_id}.md"));
    std::fs::write(&path, text)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::config::Paths;
    use lantern_core::storage::models::NewFinding;

    fn fixture() -> (Config, Db, String) {
        let root = std::env::temp_dir().join(format!(
            "lantern-report-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = Paths::new(root);
        config.paths.ensure().unwrap();
        let db = Db::open(&config.paths.db()).unwrap();
        let flow = db
            .create_flow(
                "flw_test",
                "example.com",
                "example.com",
                &serde_json::json!({"offensive": false}),
            )
            .unwrap();
        (config, db, flow.id)
    }

    #[test]
    fn summary_quotes_the_counters_recorded_at_completion() {
        let (_c, db, flow_id) = fixture();
        db.set_flow_stats(&flow_id, 11, 15).unwrap();

        let text = build(&db, &flow_id).unwrap();
        assert!(
            text.contains("15 tool invocation(s), 11 model step(s)"),
            "{text}"
        );
    }

    #[test]
    fn summary_falls_back_to_the_rows_when_no_counters_were_recorded() {
        let (_c, db, flow_id) = fixture();
        let text = build(&db, &flow_id).unwrap();
        assert!(
            text.contains("0 tool invocation(s), 0 model step(s)"),
            "{text}"
        );
    }

    #[test]
    fn renders_flow_findings_and_commands() {
        let (_c, db, flow_id) = fixture();
        db.add_finding(
            &flow_id,
            &NewFinding {
                title: "Missing CSP".into(),
                severity: "medium".into(),
                asset: "example.com".into(),
                port: Some(443),
                proto: Some("tcp".into()),
                description: "No Content-Security-Policy header.".into(),
                evidence: Some("header absent on /".into()),
                remediation: Some("Add a CSP header.".into()),
                confidence: Some(0.7),
                judge: None,
            },
        )
        .unwrap();

        let text = build(&db, &flow_id).unwrap();
        assert!(text.contains("# Lantern assessment report"));
        assert!(text.contains("Missing CSP"));
        assert!(text.contains("No Content-Security-Policy"));
        assert!(text.contains("| 1 | medium |"), "findings table: {text}");
        assert!(text.contains("No host binaries were invoked."));
        assert!(text.contains("no shell anywhere"));
    }

    #[test]
    fn unknown_flow_is_an_error() {
        let (_c, db, _) = fixture();
        let err = build(&db, "flw_missing").unwrap_err();
        assert!(err.to_string().contains("no such flow"));
    }

    #[test]
    fn write_creates_the_file() {
        let (config, db, flow_id) = fixture();
        let path = write(&config, &db, &flow_id).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("example.com"));
    }
}
