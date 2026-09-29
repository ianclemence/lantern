//! Offline computation for the coder role: a Python script, run once, with no
//! way out. The script is data written to a file; the binary and its argv are
//! fixed by this code, so the model never names a program or a flag.
//!
//! Isolation is bubblewrap: the network namespace is empty (nothing to reach)
//! and the filesystem is mounted read-only except a scratch `/tmp`, so a
//! script cannot touch a target or rewrite anything on the host. rlimits,
//! the timeout, the output cap and the audit row all come from `exec`.

use crate::ctx::ToolCtx;
use crate::exec::{self, ExecRequest};
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Largest script we will store as an artifact or hand to the sandbox.
const MAX_CODE_BYTES: usize = 20_000;
/// Script files are named `code_<epoch>_<seq>.py` so two runs never collide.
static SEQ: AtomicU32 = AtomicU32::new(0);

pub struct CodeRun;

impl Tool for CodeRun {
    fn name(&self) -> &'static str {
        "code_run"
    }

    fn description(&self) -> &'static str {
        "Run one Python script to compute something from data the flow already has: \
         parse captured output, score a wordlist, build and compare candidate payloads. \
         The sandbox has no network access and a read-only filesystem: only this \
         flow's own directory is writable, so it can never reach a target or change \
         anything else - use the recon and verification tools for that. stdout is \
         returned, the script itself is kept as an artifact."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "the whole script: standard library only, no network, scratch files go in the working directory"
                }
            },
            "required": ["code"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let raw = input
                .get("code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing required field `code`"))?;
            let code = raw.trim();
            if code.is_empty() {
                anyhow::bail!("`code` is empty after trimming");
            }
            if code.len() > MAX_CODE_BYTES {
                anyhow::bail!(
                    "script is {} bytes, the cap is {MAX_CODE_BYTES} - keep it small and \
                     let the recon tools fetch the data",
                    code.len()
                );
            }

            // The script is stored as an artifact (budget-tracked, retained with
            // the flow) and only ever read by the sandbox.
            let name = format!(
                "code_{}_{}.py",
                lantern_core::timeutil::now(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let path = ctx.write_artifact(&name, code.as_bytes())?;
            let script = path.display().to_string();
            let cwd = ctx.workdir.display().to_string();

            // Fixed argv: the model supplied only the file contents.
            let args: Vec<String> = vec![
                "--unshare-net".into(),
                "--die-with-parent".into(),
                "--ro-bind".into(),
                "/".into(),
                "/".into(),
                "--bind".into(),
                cwd.clone(),
                cwd.clone(),
                "--chdir".into(),
                cwd.clone(),
                "python3".into(),
                "-I".into(),
                "-S".into(),
                "-B".into(),
                script,
            ];

            let out = exec::run(
                ExecRequest {
                    tool: self.name(),
                    binary: "bwrap",
                    args: &args,
                    timeout: Duration::from_secs(ctx.config.task_timeout_secs),
                    max_output_bytes: ctx.config.max_output_bytes,
                    offensive: false,
                },
                ctx,
            )
            .await?;

            let exit = out.exit_code.unwrap_or(-1);
            let stdout = lantern_core::text_clip(&out.stdout, 400);
            let stderr = lantern_core::text_clip(&out.stderr, 200);
            let data = json!({
                "exit_code": exit,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": out.duration_ms,
                "script": name,
                "sandbox": "no network, read-only filesystem, flow directory writable",
                "timed_out": out.timed_out,
            });

            if out.timed_out {
                return Ok(ToolOutput::new(
                    format!(
                        "script killed after {}s\nSTDOUT: {stdout}",
                        ctx.config.task_timeout_secs
                    ),
                    data,
                    false,
                ));
            }
            if exit != 0 {
                return Ok(ToolOutput::new(
                    format!("script exited {exit}\nSTDERR: {stderr}\nSTDOUT: {stdout}"),
                    data,
                    false,
                ));
            }
            let head = out.stdout.lines().next().unwrap_or("").to_string();
            Ok(ToolOutput::ok(
                if head.is_empty() {
                    format!("script finished in {} ms (no output)", out.duration_ms)
                } else {
                    format!("script finished in {} ms: {head}", out.duration_ms)
                },
                data,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::test_ctx;
    use serde_json::json;

    /// Skip when the sandbox launcher is not installed: the tool must fail
    /// closed rather than run unprotected, and on such hosts the honest
    /// behaviour to assert is that refusal.
    fn have_sandbox(ctx: &ToolCtx) -> bool {
        exec::resolve_binary(
            "bwrap",
            &ctx.config.restricted_path,
            &ctx.config.allowlist,
        )
        .is_ok()
    }

    #[tokio::test]
    async fn a_trivial_script_runs_and_keeps_its_source() {
        let ctx = test_ctx();
        if !have_sandbox(&ctx) {
            return;
        }
        let out = CodeRun
            .execute(
                json!({"code":
                    "print(sum(range(10)))\nopen('scratch.txt','w').write('hi')"}),
                &ctx,
            )
            .await
            .expect("run");
        assert!(out.ok, "{}", out.summary);
        assert_eq!(out.data["exit_code"], 0);
        assert!(out.summary.contains("45"), "{}", out.summary);

        // The flow directory is the one writable place.
        assert!(ctx.workdir.join("scratch.txt").exists());

        // The script is retained with the flow, budget-tracked.
        let script = out.data["script"].as_str().expect("script name");
        assert!(ctx.artifact_dir().join(script).exists(), "{script}");
    }

    #[tokio::test]
    async fn the_sandbox_cannot_reach_the_network_or_write_the_disk() {
        let ctx = test_ctx();
        if !have_sandbox(&ctx) {
            return;
        }

        // No route exists inside the empty network namespace.
        let out = CodeRun
            .execute(
                json!({"code":
                    "import socket\n\
                     socket.create_connection((\"1.1.1.1\", 443), 5)"}),
                &ctx,
            )
            .await
            .expect("run");
        assert!(!out.ok, "a connection must not succeed: {}", out.summary);
        assert!(
            out.data["stderr"].as_str().unwrap_or_default().contains("rror"),
            "stderr: {}",
            out.data["stderr"]
        );

        // The host filesystem is mounted read-only.
        let out = CodeRun
            .execute(
                json!({"code": "open('/etc/lantern_probe', 'w').write('x')"}),
                &ctx,
            )
            .await
            .expect("run");
        assert!(!out.ok, "writing the host fs must fail: {}", out.summary);
        assert!(!std::path::Path::new("/etc/lantern_probe").exists());
    }

    #[tokio::test]
    async fn input_is_validated_before_anything_spawns() {
        let ctx = test_ctx();

        let err = CodeRun.execute(json!({}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("code"), "got: {err}");

        let err = CodeRun.execute(json!({"code": "   "}), &ctx).await.unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");

        let err = CodeRun
            .execute(json!({"code": "x".repeat(MAX_CODE_BYTES + 1)}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {err}");

        // Nothing was written for a rejected script.
        let leftovers = std::fs::read_dir(ctx.artifact_dir())
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 0, "artifacts written for rejected input");
    }
}
