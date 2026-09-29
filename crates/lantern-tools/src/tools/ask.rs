//! The one place a role can stop and ask the person at the keyboard.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::time::Duration;

/// Scripted answer for unattended runs: set it and no terminal is needed.
const ANSWER_ENV: &str = "LANTERN_OPERATOR_ANSWER";
/// Longest an interactive question waits before it gives up and lets the flow
/// carry on without an answer.
const WAIT: Duration = Duration::from_secs(300);

pub struct AskOperator;

impl Tool for AskOperator {
    fn name(&self) -> &'static str {
        "ask_operator"
    }

    fn description(&self) -> &'static str {
        "Ask the person running this assessment and wait for their reply. Only when the \
         flow genuinely cannot decide alone: which credentials to try, whether something \
         found is in scope, permission before an intrusive step. Returns an empty answer \
         when nobody replies. Requires --interactive."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "one question, stated with the options the operator should pick from"
                },
                "options": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "suggested answers, e.g. [\"try the credentials\", \"skip\"]"
                }
            },
            "required": ["question"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            if !ctx.interactive {
                anyhow::bail!(
                    "operator prompts are disabled; re-run with --interactive (or set \
                     {ANSWER_ENV} for an unattended answer)"
                );
            }

            let question = super::str_field(&input, "question")?;
            let options: Vec<String> = input
                .get("options")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .take(6)
                        .collect()
                })
                .unwrap_or_default();

            // Unattended answer first: the operator already decided.
            if let Some(answer) = std::env::var(ANSWER_ENV)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
            {
                return Ok(ToolOutput::ok(
                    format!("operator: {answer}"),
                    json!({
                        "question": &question,
                        "answer": answer,
                        "source": "scripted",
                    }),
                ));
            }

            println!("\n? {question}");
            for (i, o) in options.iter().enumerate() {
                println!("  {}) {o}", i + 1);
            }
            let waited = tokio::time::timeout(WAIT, tokio::task::spawn_blocking(|| {
                let mut line = String::new();
                match std::io::stdin().read_line(&mut line) {
                    Ok(_) => line.trim().to_string(),
                    Err(_) => String::new(),
                }
            }))
            .await;

            let answer = match waited {
                Ok(Ok(line)) => line,
                _ => String::new(), // EOF, error or timeout: carry on unanswered
            };
            if answer.is_empty() {
                return Ok(ToolOutput::failed(format!(
                    "no answer from the operator for: {question}"
                )));
            }
            Ok(ToolOutput::ok(
                format!("operator: {answer}"),
                json!({
                    "question": &question,
                    "answer": answer,
                    "source": "terminal",
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::test_ctx;

    // The terminal path reads stdin and must never run under a test harness,
    // so everything here stays on the deterministic branches: the gate, input
    // validation and the scripted answer. `echo "try admin" | lantern run
    // ... --interactive` covers the stdin branch by hand.
    #[tokio::test]
    async fn gate_validation_and_scripted_answer() {
        std::env::set_var(ANSWER_ENV, " try the admin login ");

        // The flag is checked first, so a leftover environment variable can
        // never make a non-interactive run answer itself.
        let ctx = test_ctx();
        let err = AskOperator
            .execute(json!({"question": "go ahead?"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--interactive"), "got: {err}");

        // Question is mandatory even when an answer is already scripted.
        let mut ctx = test_ctx();
        ctx.interactive = true;
        let err = AskOperator
            .execute(json!({"options": ["skip"]}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("question"), "got: {err}");

        // With the flag, the scripted answer comes back verbatim.
        let out = AskOperator
            .execute(
                json!({"question": "credentials?", "options": ["skip", "try admin"]}),
                &ctx,
            )
            .await
            .expect("answer");
        assert!(out.ok, "{}", out.summary);
        assert_eq!(out.data["answer"], "try the admin login");
        assert_eq!(out.data["source"], "scripted");

        std::env::remove_var(ANSWER_ENV);
    }
}
