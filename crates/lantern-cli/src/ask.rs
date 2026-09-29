//! `lantern ask` - the assessment flow, instructed in natural language.
//!
//! `lantern run` takes flags; `lantern ask` takes an instruction. The prompt
//! may be a sentence ("check TLS on example.com") or a whole assessment
//! framework: it is stored verbatim with the flow and travels condensed into
//! every role objective, so the model acts on the operator's words instead of
//! a fixed mission string.
//!
//! Authority never moves with the words. Scope and target still come from the
//! flags, and `--offensive` still grants active testing - the prompt can only
//! restrain it, never grant it (see `lantern_agent::intent`).

use lantern_agent::{intent, run_flow, AgentCtx, FlowOptions};
use lantern_core::budget::{dir_size, Budget};
use lantern_core::config::Config;
use lantern_core::retention;
use std::io::IsTerminal as _;
use std::path::PathBuf;

pub struct Args {
    pub prompt: Option<String>,
    pub file: Option<PathBuf>,
    pub target: String,
    pub scope: String,
    pub roles: Option<String>,
    pub offensive: bool,
    pub dry_run: bool,
    pub steps: Option<usize>,
    pub interactive: bool,
}

/// Anything far beyond a long framework prompt is a paste accident, not an
/// instruction. The framework in the walkthrough is ~15 KB.
const MAX_PROMPT_BYTES: usize = 128 * 1024;

fn check_len(text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        anyhow::bail!("empty instruction: say what to assess");
    }
    if text.len() > MAX_PROMPT_BYTES {
        anyhow::bail!(
            "instruction is {} bytes (cap {}): pass a file with --file or trim it",
            text.len(),
            MAX_PROMPT_BYTES
        );
    }
    Ok(())
}

fn load_prompt(args: &Args) -> anyhow::Result<String> {
    if let Some(p) = &args.prompt {
        check_len(p)?;
        return Ok(p.trim().to_string());
    }
    if let Some(f) = &args.file {
        let text = std::fs::read_to_string(f)
            .map_err(|e| anyhow::anyhow!("reading {}: {e:#}", f.display()))?;
        check_len(&text)?;
        return Ok(text.trim().to_string());
    }
    if std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no instruction: pass --prompt \"...\", --file framework.md, or pipe it on stdin"
        );
    }
    let mut text = String::new();
    use std::io::Read as _;
    std::io::stdin()
        .take((MAX_PROMPT_BYTES + 1) as u64)
        .read_to_string(&mut text)?;
    check_len(&text)?;
    Ok(text.trim().to_string())
}

/// Advisory only: `--target` is the authority, the contract's TARGETS line is
/// the cross-check. Warns when the two name different things.
pub(crate) fn target_warning(flag_target: &str, contract_targets: &[String]) -> Option<String> {
    if contract_targets.is_empty() {
        return None;
    }
    let want = flag_target.trim().to_ascii_lowercase();
    let matches = contract_targets.iter().any(|t| {
        let t = t.to_ascii_lowercase();
        t.contains(&want) || want.contains(&t)
    });
    if matches {
        return None;
    }
    Some(format!(
        "--target `{flag_target}` is the authority; the contract lists {}",
        contract_targets.join(", ")
    ))
}

pub async fn run(config: Config, args: Args) -> anyhow::Result<()> {
    let prompt = load_prompt(&args)?;
    let parsed = intent::parse_intent(&prompt);
    let (effective_offensive, gate_warning) = intent::resolve_offensive(args.offensive, &parsed);

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

    // --- intent card -------------------------------------------------------
    // Three lines saying what was understood, before anything runs.
    println!("instruction : {}", crate::run::one_line(&prompt, 100));
    println!(
        "intent      : {}",
        if parsed.defensive_only {
            "reconnaissance only (the prompt restrains it)"
        } else if parsed.wants_offensive {
            "active testing requested"
        } else {
            "as instructed"
        }
    );
    let contract = parsed.contract.present();
    if contract.is_empty() {
        println!("contract    : none declared (TARGETS etc. all empty)");
    } else {
        let shown: Vec<String> = contract
            .iter()
            .take(4)
            .map(|(k, v)| format!("{k}={}", crate::run::one_line(v, 60)))
            .collect();
        let more = if contract.len() > 4 {
            format!(" (+{} more)", contract.len() - 4)
        } else {
            String::new()
        };
        println!("contract    : {}{more}", shown.join(", "));
    }
    if let Some(w) = target_warning(&args.target, &parsed.contract.target_list()) {
        println!("note        : {w}");
    }
    if let Some(w) = &gate_warning {
        println!("note        : {w}");
    }
    if effective_offensive {
        println!(
            "\nactive testing ENABLED (--offensive): gated tools may run against in-scope targets\n"
        );
    } else {
        println!("\nactive testing disabled: reconnaissance and defensive checks only\n");
    }
    if !parsed.roles_hint.is_empty() && args.roles.is_none() {
        let names: Vec<_> = parsed.roles_hint.iter().map(|r| r.as_str()).collect();
        println!(
            "vocabulary points at {} - running the full pipeline anyway \
             (pass --roles to narrow it)\n",
            names.join(", ")
        );
    }

    let roles = crate::run::parse_roles(args.roles.as_deref())?;
    let agent = AgentCtx::new(config, &args.scope, args.dry_run)?;
    let scope = agent.scope.render();
    let mut opts = FlowOptions::new(&args.target, &scope)
        .offensive(effective_offensive)
        .interactive(args.interactive)
        .roles(roles);
    opts.max_steps = args.steps;
    opts.directive = Some(prompt);

    if args.interactive {
        println!("operator questions ENABLED (--interactive): roles may pause for your answer\n");
    }

    let out = run_flow(&agent, opts).await?;
    crate::run::print_outcome(&agent, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_check_passes_when_they_agree() {
        assert!(target_warning("shop.example.com", &["shop.example.com".into()]).is_none());
        assert!(target_warning("x", &[]).is_none(), "no contract, no warning");
        // A URL flag against a bare contract host is the same place.
        assert!(target_warning(
            "https://shop.example.com/login",
            &["shop.example.com".into()]
        )
        .is_none());
    }

    #[test]
    fn target_check_names_both_sides_when_they_differ() {
        let w = target_warning("a.example.com", &["b.example.com".into()]).unwrap();
        assert!(w.contains("a.example.com"), "{w}");
        assert!(w.contains("b.example.com"), "{w}");
        assert!(w.contains("authority"), "{w}");
    }

    #[test]
    fn prompt_length_is_bounded() {
        assert!(check_len("  check TLS  ").is_ok());
        assert!(check_len("   ").is_err(), "blank is not an instruction");
        assert!(check_len(&"x".repeat(MAX_PROMPT_BYTES + 1)).is_err());
    }
}
