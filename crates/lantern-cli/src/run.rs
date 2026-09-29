//! `lantern run` - the assessment flow.

use lantern_agent::{run_flow, AgentCtx, FlowOptions, FlowOutcome, Footprint, RoleId};
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

pub(crate) fn parse_roles(spec: Option<&str>) -> anyhow::Result<Vec<RoleId>> {
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
    print_outcome(&agent, &out)
}

/// Shared outcome block: `run` and `ask` report a finished flow identically.
pub(crate) fn print_outcome(agent: &AgentCtx, out: &FlowOutcome) -> anyhow::Result<()> {
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
    println!("{}", model_line(agent.dry_run, out.footprint, rate_from_env()));
    println!("{}", context_line(out.footprint, agent.config.token_budget));
    if !out.warnings.is_empty() {
        println!("warnings:");
        for w in &out.warnings {
            println!("  - {w}");
        }
    }
    Ok(())
}

pub(crate) fn one_line(text: &str, max: usize) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// What the run cost the model account.
///
/// Tokens are always printed: the endpoint reports them on every reply. Money
/// is printed only when the operator has said what a token costs here, because
/// a rate recalled from memory would be a fiction wearing a dollar sign.
fn model_line(dry_run: bool, f: Footprint, rate: Option<(f64, f64)>) -> String {
    let (input, output) = (
        lantern_core::grouped(f.input_tokens),
        lantern_core::grouped(f.output_tokens),
    );
    if dry_run {
        return format!(
            "model   : {input} in / {output} out tokens (scripted - estimate, nothing billed)"
        );
    }
    if f.input_tokens == 0 && f.output_tokens == 0 {
        return "model   : usage not reported by this endpoint".to_string();
    }
    match rate {
        Some((in_rate, out_rate)) => format!(
            "model   : {input} in / {output} out tokens - ${:.4}",
            f.input_tokens as f64 / 1_000_000.0 * in_rate
                + f.output_tokens as f64 / 1_000_000.0 * out_rate
        ),
        None => format!("model   : {input} in / {output} out tokens"),
    }
}

/// How hard the context budget was pushed. A peak sitting at the cap, or any
/// budget stop at all, is the signal that `LANTERN_TOKEN_BUDGET` cut a role
/// short rather than letting it finish.
fn context_line(f: Footprint, budget: usize) -> String {
    format!(
        "context : peak {} / {} tokens, {} summarization(s), {} budget stop(s)",
        lantern_core::grouped(f.peak_context as u64),
        lantern_core::grouped(budget as u64),
        f.summarizations,
        f.budget_stops
    )
}

fn rate_from_env() -> Option<(f64, f64)> {
    parse_rate(
        std::env::var("LANTERN_PRICE_INPUT_PER_MTOK")
            .ok()
            .as_deref(),
        std::env::var("LANTERN_PRICE_OUTPUT_PER_MTOK")
            .ok()
            .as_deref(),
    )
}

/// USD per million tokens, both directions or neither: one rate alone would
/// let the missing half be invented.
fn parse_rate(input: Option<&str>, output: Option<&str>) -> Option<(f64, f64)> {
    let input: f64 = input?.trim().parse().ok()?;
    let output: f64 = output?.trim().parse().ok()?;
    if input.is_finite() && output.is_finite() && input >= 0.0 && output >= 0.0 {
        Some((input, output))
    } else {
        None
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

    fn footprint() -> Footprint {
        Footprint {
            input_tokens: 41_208,
            output_tokens: 9_872,
            peak_context: 4_812,
            summarizations: 1,
            budget_stops: 0,
        }
    }

    #[test]
    fn money_is_only_claimed_when_a_rate_was_supplied() {
        let plain = model_line(false, footprint(), None);
        assert!(plain.contains("41,208 in / 9,872 out tokens"), "{plain}");
        assert!(!plain.contains('$'), "no price without a rate: {plain}");

        let priced = model_line(false, footprint(), Some((0.27, 1.10)));
        // 41,208 * $0.27/M + 9,872 * $1.10/M
        assert!(priced.contains("$0.0220"), "{priced}");
    }

    #[test]
    fn a_scripted_run_never_claims_a_spend() {
        let line = model_line(true, footprint(), Some((1.0, 1.0)));
        assert!(line.contains("estimate"), "{line}");
        assert!(line.contains("nothing billed"), "{line}");

        let unmeasured = model_line(false, Footprint::default(), None);
        assert!(unmeasured.contains("not reported"), "{unmeasured}");
    }

    #[test]
    fn a_rate_needs_both_halves() {
        assert_eq!(parse_rate(Some("0.27"), Some("1.10")), Some((0.27, 1.10)));
        assert_eq!(
            parse_rate(Some("0.27"), None),
            None,
            "half a rate must not become a whole price"
        );
        assert_eq!(parse_rate(None, Some("1.10")), None);
        assert_eq!(parse_rate(Some("free"), Some("1.10")), None);
        assert_eq!(parse_rate(Some("-1"), Some("1.10")), None);
        assert_eq!(parse_rate(Some(" 0.5 "), Some(" 0 ")), Some((0.5, 0.0)));
    }

    #[test]
    fn the_context_line_reports_what_the_budget_is_tuned_from() {
        let f = Footprint {
            peak_context: 5_900,
            summarizations: 2,
            budget_stops: 1,
            ..Footprint::default()
        };
        let line = context_line(f, 6_000);
        assert!(line.contains("peak 5,900 / 6,000 tokens"), "{line}");
        assert!(line.contains("2 summarization(s), 1 budget stop(s)"), "{line}");
    }
}
