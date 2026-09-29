//! The live plan: a `Vec<String>` shared with every tool context, so a role
//! that discovers reality disagrees can amend it and later roles read the
//! amended version.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;

/// Longest step the plan will hold, in characters.
const STEP_CHARS: usize = 200;

/// One plan step: single line (the plan is line-based), trimmed, capped.
fn clip_step(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= STEP_CHARS {
        return flat;
    }
    let head: String = flat.chars().take(STEP_CHARS - 3).collect();
    format!("{head}...")
}

/// Split plan text into steps, dropping the printed numbering.
pub fn steps_from_plan_text(text: &str) -> Vec<String> {
    text.lines()
        .map(strip_numbering)
        .filter(|s| !s.is_empty())
        .collect()
}

fn strip_numbering(line: &str) -> String {
    let t = line.trim();
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 && digits < t.len() {
        let rest = &t[digits..];
        if let Some(body) = rest.strip_prefix('.').or_else(|| rest.strip_prefix(')')) {
            let body = body.trim();
            if !body.is_empty() {
                return body.to_string();
            }
        }
    }
    t.to_string()
}

/// Steps back into numbered plan text.
pub fn render_steps(steps: &[String]) -> String {
    steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{}. {s}", i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct PlanPatch;

impl Tool for PlanPatch {
    fn name(&self) -> &'static str {
        "plan_patch"
    }

    fn description(&self) -> &'static str {
        "Amend the assessment plan: add a step the plan missed, or drop one that \
         reconnaissance has made pointless. Give `add`, `drop` (1-based), or both. \
         Later roles are given the plan as it now stands, so this is how a plan gets \
         corrected once facts disagree with it."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "add": {
                    "type": "string",
                    "description": "one new step, e.g. \"test the exposed jmx-console with host_john\""
                },
                "drop": {
                    "type": "integer",
                    "description": "1-based number of the step to remove"
                }
            }
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let add = super::opt_str_field(&input, "add");
            let remove_idx = super::opt_u64(&input, "drop", 0) as usize;
            if add.is_none() && remove_idx == 0 {
                anyhow::bail!("give `add`, `drop`, or both");
            }

            let mut steps = ctx.plan.lock().unwrap_or_else(|e| e.into_inner());
            let mut dropped = None;
            if remove_idx != 0 {
                if remove_idx > steps.len() {
                    anyhow::bail!(
                        "no step {remove_idx} - the plan has {} step(s)",
                        steps.len()
                    );
                }
                if steps.len() == 1 && add.is_none() {
                    anyhow::bail!("the plan cannot be emptied; add a step instead");
                }
                dropped = Some(steps.remove(remove_idx - 1));
            }
            let added = add.map(|a| clip_step(&a));
            if let Some(a) = &added {
                steps.push(a.clone());
            }

            let plan = render_steps(&steps);
            let summary = if dropped.is_some() || added.is_some() {
                format!("plan updated:\n{plan}")
            } else {
                plan.clone()
            };
            let after: Vec<String> = steps.clone();
            drop(steps);
            Ok(ToolOutput::ok(
                summary,
                json!({
                    "plan": plan,
                    "steps": after,
                    "dropped": dropped,
                    "added": added,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::test_ctx;

    #[test]
    fn numbering_round_trips() {
        let text = "1. Resolve DNS\n2) Fingerprint TLS\n\n   3. Scan ports\ncheck headers";
        let steps = steps_from_plan_text(text);
        assert_eq!(
            steps,
            vec![
                "Resolve DNS".to_string(),
                "Fingerprint TLS".to_string(),
                "Scan ports".to_string(),
                "check headers".to_string(),
            ]
        );
        assert_eq!(
            render_steps(&steps),
            "1. Resolve DNS\n2. Fingerprint TLS\n3. Scan ports\n4. check headers"
        );
        // Rendering then re-parsing is a fixed point.
        assert_eq!(steps_from_plan_text(&render_steps(&steps)), steps);
        assert!(steps_from_plan_text("").is_empty());
    }

    #[tokio::test]
    async fn adding_and_dropping_renumbers_the_plan() {
        let ctx = test_ctx();
        ctx.set_plan(vec!["alpha".into(), "beta".into()]);

        let out = PlanPatch
            .execute(json!({"add": "  gamma  "}), &ctx)
            .await
            .expect("add");
        assert_eq!(out.data["plan"], "1. alpha\n2. beta\n3. gamma");
        assert_eq!(out.data["added"], "gamma");
        assert!(out.summary.contains("plan updated"), "{}", out.summary);

        let out = PlanPatch
            .execute(json!({"drop": 1}), &ctx)
            .await
            .expect("drop");
        assert_eq!(out.data["plan"], "1. beta\n2. gamma");
        assert_eq!(out.data["dropped"], "alpha");
        assert_eq!(ctx.plan_text(), "1. beta\n2. gamma");
    }

    #[tokio::test]
    async fn nonsense_input_is_refused_with_a_reason() {
        let ctx = test_ctx();
        ctx.set_plan(vec!["only step".into()]);

        let err = PlanPatch.execute(json!({}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("add"), "got: {err}");

        let err = PlanPatch.execute(json!({"drop": 9}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("1 step"), "got: {err}");

        let err = PlanPatch
            .execute(json!({"drop": 1}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("emptied"), "got: {err}");

        let out = PlanPatch
            .execute(json!({"drop": 1, "add": "start over"}), &ctx)
            .await
            .expect("drop and add");
        assert_eq!(out.data["plan"], "1. start over");
    }

    #[tokio::test]
    async fn a_long_step_is_clipped() {
        let ctx = test_ctx();
        let out = PlanPatch
            .execute(json!({"add": "x".repeat(400)}), &ctx)
            .await
            .expect("add");
        let plan = out.data["plan"].as_str().expect("plan");
        assert!(plan.chars().count() < 230, "len {}", plan.chars().count());
    }
}
