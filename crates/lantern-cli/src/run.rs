//! `lantern run` - the assessment flow.

use lantern_agent::{run_flow, AgentCtx, FlowOptions, RoleId};
use lantern_core::budget::{dir_size, Budget};
use lantern_core::config::Config;
use lantern_core::retention;

pub struct Args {
    pub target: String,
    pub scope: String,
    pub roles: Option<String>,
    pub offensive: bool,
    pub dry_run: bool,
    pub steps: Option<usize>,
    pub interactive: bool,
}

fn parse_roles(spec: Option<&str>) -> anyhow::Result<Vec<RoleId>> {
    let Some(spec) = spec else {
        return Ok(Vec::new()); // default pipeline
    };
    let mut out = Vec::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        match RoleId::parse(raw) {
            Some(r) => out.push(r),
            None => anyhow::bail!(
                "unknown role `{raw}` (available: {})",
                RoleId::ALL
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
    if out.is_empty() {
        anyhow::bail!("--roles was given but parsed to nothing");
    }
    Ok(out)
}

pub async fn run(config: Config, args: Args) -> anyhow::Result<()> {
    let budget = Budget::new(config.data_cap_bytes, dir_size(&config.paths.root));
    println!("{}", retention::startup_line(&config, &budget));
    if config.degraded() && !args.dry_run {
        let key_env = lantern_core::providers::by_id(&config.llm.provider)
            .and_then(|p| p.key_env)
            .unwrap_or("LANTERN_LLM_API_KEY");
        anyhow::bail!(
            "no generation key: export {key_env} (or add it with `lantern setup`), \
             or pass --dry-run for a scripted run"
        );
    }

    let roles = parse_roles(args.roles.as_deref())?;
    let agent = AgentCtx::new(config, &args.scope, args.dry_run)?;
    let scope = agent.scope.render();
    let mut opts = FlowOptions::new(&args.target, &scope)
        .offensive(args.offensive)
        .interactive(args.interactive)
        .roles(roles);
    opts.max_steps = args.steps;

    if args.interactive {
        println!("operator questions ENABLED (--interactive): roles may pause for your answer\n");
    }

    if args.offensive {
        println!(
            "active testing ENABLED (--offensive): sqlmap/hydra may run against in-scope targets\n"
        );
    } else {
        println!("active testing disabled: reconnaissance and defensive checks only\n");
    }

    let out = run_flow(&agent, opts).await?;

    // --- outcome -----------------------------------------------------------
    let status = agent
        .db
        .get_flow(&out.flow_id)?
        .map(|f| f.status)
        .unwrap_or_else(|| "unknown".into());
    println!(
        "flow {} {} in {:.1}s ({} model step(s))",
        out.flow_id,
        status,
        out.elapsed_ms as f64 / 1000.0,
        out.steps
    );
    for r in &out.roles {
        let mark = if r.error.is_some() { "!" } else { "+" };
        println!(
            "  {mark} {:<13} {:>2} step(s), {} finding(s): {}",
            r.role.as_str(),
            r.steps,
            r.findings,
            one_line(&r.summary, 110)
        );
    }
    println!("\nfindings: {}", out.findings);
    match &out.report {
        Some(p) => println!("report  : {}", p.display()),
        None => println!("report  : NOT WRITTEN (see warnings)"),
    }
    if !out.warnings.is_empty() {
        println!("warnings:");
        for w in &out.warnings {
            println!("  - {w}");
        }
    }
    Ok(())
}

fn one_line(text: &str, max: usize) -> String {
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
    fn role_list_parses_and_rejects() {
        assert!(parse_roles(None).unwrap().is_empty(), "default pipeline");
        let r = parse_roles(Some("researcher, pentester")).unwrap();
        assert_eq!(r, vec![RoleId::Researcher, RoleId::Pentester]);
        let err = parse_roles(Some("wizard")).err().expect("must reject");
        assert!(err.to_string().contains("unknown role"));
        assert!(err.to_string().contains("reflector"), "lists valid roles");
        assert!(parse_roles(Some(" , ")).is_err());
    }

    #[test]
    fn one_line_truncates() {
        assert_eq!(one_line("short", 10), "short");
        assert!(one_line(&"word ".repeat(50), 20).chars().count() <= 20);
        assert!(!one_line("a\nb", 10).contains('\n'), "flattens newlines");
    }
}
