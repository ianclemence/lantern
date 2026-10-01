//! What a model call costs before the conversation has said anything.
//!
//! The budget (`LANTERN_TOKEN_BUDGET`, 6,000 by default) only counts the
//! working set: the system prompt and the tool schemas are on top of it, on
//! every single request. This test measures both so prompt bloat is caught
//! here instead of at the end of a bill, and prints the numbers with
//! `cargo test --test measure_prompts -- --nocapture`.

use lantern_agent::prompts;
use lantern_agent::roles::roles;
use lantern_core::config::Config;
use lantern_tools::registry::Registry;

#[test]
fn the_fixed_overhead_of_a_call_stays_small() {
    let cfg = Config::load().unwrap();
    let reg = Registry::new(&cfg).unwrap();
    let defs = reg.defs();
    let schema: usize = defs
        .iter()
        .map(|d| (d.wire().to_string().len() + 3) / 4)
        .sum();

    println!(
        "tool schemas : {} tools, {} chars (~{} tokens) sent on every request",
        defs.len(),
        defs.iter().map(|d| d.wire().to_string().len()).sum::<usize>(),
        schema
    );

    let scope = "example.com, 104.20.23.154/32, 172.66.147.243/32";
    let mut worst = 0usize;
    for r in roles() {
        let system = prompts::system(
            r,
            "example.com",
            scope,
            false,
            lantern_agent::intent::EngagementProfile::General,
        );
        let overhead = schema + (system.len() + 3) / 4;
        worst = worst.max(overhead);
        println!(
            "system {:11}: {:>4} tokens, {} tools focused, {:>4} tokens before the first word",
            r.id.as_str(),
            (system.len() + 3) / 4,
            r.focus.len(),
            overhead
        );
    }

    // The conversation has to own most of the budget: schemas plus system
    // prompt must leave at least a third of the default 6,000 for what the
    // role actually says and sees.
    assert!(
        worst <= 4_000,
        "the fixed overhead of a call is now {worst} tokens - either shrink the \
         prompts or move LANTERN_TOKEN_BUDGET"
    );
    assert!(!defs.is_empty(), "the registry lost its tools");
}
