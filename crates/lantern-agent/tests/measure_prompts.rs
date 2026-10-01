//! What a model call costs before the conversation has said anything.
//!
//! The budget (`LANTERN_TOKEN_BUDGET`, 6,000 by default) only counts the
//! working set: the system prompt and the tool schemas are on top of it, on
//! every single request. This test measures both so prompt bloat is caught
//! here instead of at the end of a bill, and prints the numbers with
//! `cargo test --test measure_prompts -- --nocapture`.
//!
//! Tool schemas are scoped to each role's own `focus` (`Registry::defs_for`),
//! matching what `run_role` actually sends - not the whole registry. That
//! matters here specifically: a flat "every tool, every role" measurement
//! means the fixed overhead grows every time *any* tool is added, even one
//! only the pentester role ever sees, and this test would eventually fail
//! for a researcher-only addition that costs the researcher role nothing.

use lantern_agent::prompts;
use lantern_agent::roles::roles;
use lantern_core::config::Config;
use lantern_tools::registry::Registry;

#[test]
fn the_fixed_overhead_of_a_call_stays_small() {
    let cfg = Config::load().unwrap();
    let reg = Registry::new(&cfg).unwrap();
    let all = reg.defs();
    println!(
        "registry     : {} tools total (not all sent to every role - see below)",
        all.len()
    );

    let scope = "example.com, 104.20.23.154/32, 172.66.147.243/32";
    let mut worst = 0usize;
    for r in roles() {
        let defs = reg.defs_for(r.focus);
        let schema: usize = defs.iter().map(|d| (d.wire().to_string().len() + 3) / 4).sum();
        let system = prompts::system(
            r,
            "example.com",
            scope,
            false,
            lantern_agent::intent::EngagementProfile::General,
        );
        let sys_tokens = (system.len() + 3) / 4;
        let overhead = schema + sys_tokens;
        worst = worst.max(overhead);
        println!(
            "role {:11}: {:>4} tool(s) focused (~{:>4} tokens) + {:>4} tokens system \
             = {:>4} tokens before the first word",
            r.id.as_str(),
            defs.len(),
            schema,
            sys_tokens,
            overhead
        );
    }

    // The conversation has to own most of the budget: schemas plus system
    // prompt must leave at least a third of the default 6,000 for what the
    // role actually says and sees.
    assert!(
        worst <= 4_000,
        "the fixed overhead of a call is now {worst} tokens - either shrink the \
         prompts, narrow a role's focus, or move LANTERN_TOKEN_BUDGET"
    );
    assert!(!all.is_empty(), "the registry lost its tools");
}

#[test]
fn role_scoped_schemas_are_never_larger_than_the_full_registry() {
    // Confirms defs_for is actually doing its job here, not just compiling:
    // every role's scoped schema cost must be <= what sending everything
    // would have cost, and strictly less for any role with a real focus list.
    let cfg = Config::load().unwrap();
    let reg = Registry::new(&cfg).unwrap();
    let all_tokens: usize = reg
        .defs()
        .iter()
        .map(|d| (d.wire().to_string().len() + 3) / 4)
        .sum();
    for r in roles() {
        let scoped_tokens: usize = reg
            .defs_for(r.focus)
            .iter()
            .map(|d| (d.wire().to_string().len() + 3) / 4)
            .sum();
        assert!(scoped_tokens <= all_tokens, "{} exceeded the full registry cost", r.id);
        if !r.focus.is_empty() {
            assert!(
                scoped_tokens < all_tokens,
                "{} has a focus list but was sent every tool's schema anyway",
                r.id
            );
        }
    }
}
