//! `delegate_task`: one bounded, auditable sub-investigation a role can spin
//! off mid-flow, rather than the fixed pipeline's only unit of work being a
//! whole role.
//!
//! This is registered like any other tool - so it shows up in `lantern
//! tools`, carries a normal JSON schema, and is scope/offensive-gated the
//! same way - but it has no real body here. The actual sub-conversation
//! needs to call the model, which this crate has no access to
//! (`lantern-tools` does not depend on the orchestration loop in
//! `lantern-agent`); `lantern_agent::runtime::role_loop` intercepts a call
//! to this tool *before* it ever reaches `Registry::execute` and runs the
//! bounded sub-loop itself.
//!
//! `execute` here exists purely as a fail-closed safety net: if some future
//! code path ever calls the registry directly with this tool name instead
//! of going through that interception, it refuses rather than silently
//! doing nothing or - worse - attempting something unbounded. The real
//! safety properties (no recursive delegation, the tool subset a delegated
//! sub-task gets can never exceed what the calling role already had, a hard
//! cap on steps per call and in total across one role's invocation) live in
//! `runtime.rs`, next to the model calls they bound, and are documented and
//! tested there.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;

/// Hard ceiling on one delegated sub-task's own step budget. The caller may
/// ask for less; it can never get more by asking.
pub const MAX_STEPS_PER_CALL: usize = 5;

/// Hard ceiling on total delegated steps across every `delegate_task` call
/// within one role's own invocation - stops a role multiplying its own step
/// budget unboundedly by calling this repeatedly.
pub const TOTAL_STEP_BUDGET: usize = 10;

pub struct DelegateTask;

impl Tool for DelegateTask {
    fn name(&self) -> &'static str {
        "delegate_task"
    }

    fn description(&self) -> &'static str {
        "Spin off one bounded, focused sub-investigation and get back a condensed summary - \
         useful when your own objective has a distinct sub-question worth its own short tool-\
         calling loop (e.g. \"confirm this one finding with a fresh request\" or \"enumerate \
         just this one thing in more depth\") rather than doing it inline. The sub-task shares \
         your scope and --offensive grant exactly - it can never reach beyond them - and can \
         only use tools from the `tools` list you give it, which can only be tools you \
         yourself already have. It cannot delegate again: this tool is never available inside \
         a delegated sub-task. Capped at 5 steps per call, 10 total across every delegation \
         you make this turn."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "objective": {
                    "type": "string",
                    "description": "what the sub-task should find out or verify, as a self-contained instruction"
                },
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "which of your own tools the sub-task may use (a subset of what you have - naming one you don't have is refused)"
                },
                "max_steps": {
                    "type": "integer",
                    "description": "1-5, default 3"
                }
            },
            "required": ["objective", "tools"]
        })
    }

    fn execute<'a>(
        &'a self,
        _input: serde_json::Value,
        _ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            anyhow::bail!(
                "delegate_task must run through the calling role's own tool-calling loop \
                 (lantern_agent::runtime::role_loop intercepts it); reaching this body means \
                 that interception was skipped, so it refuses rather than doing anything \
                 unbounded"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_invocation_fails_closed() {
        let ctx = super::super::test_ctx();
        let err = DelegateTask
            .execute(json!({"objective": "x", "tools": []}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("role_loop"), "{err}");
    }

    #[test]
    fn schema_requires_objective_and_tools() {
        let p = DelegateTask.parameters();
        let required: Vec<&str> = p["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required.contains(&"objective"));
        assert!(required.contains(&"tools"));
    }
}
