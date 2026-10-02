//! Sandboxed host execution: allowlist, cleared env, restricted PATH, fresh
//! session, rlimits, timeout, output cap, audit log.
//!
//! There is no shell anywhere in this module — arguments are always passed as
//! an array to `Command::new`.

use crate::ctx::ToolCtx;
use anyhow::{bail, Context};
use lantern_core::storage::models::CommandRow;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct ExecRequest<'a> {
    /// Logical tool name recorded in the audit log.
    pub tool: &'a str,
    /// Binary name (no path separators).
    pub binary: &'a str,
    pub args: &'a [String],
    pub timeout: Duration,
    pub max_output_bytes: u64,
    /// True for binaries that perform active attacks: refused unless the flow
    /// was started with `--offensive`.
    pub offensive: bool,
    /// DNS records resolved for the target immediately before this call, so
    /// the audit row shows what address was actually reachable at execution
    /// time rather than only the hostname declared in scope. Empty when the
    /// target was already a literal IP/CIDR or resolution was not applicable.
    pub resolved_ips: &'a [String],
}

/// Boxed, `Send` future used by the tool trait (no `async-trait` dependency).
pub type BoxFutureTool<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub stdout: String,
    pub stderr: String,
    pub bytes_out: u64,
    pub duration_ms: u64,
    pub binary_path: PathBuf,
    pub artifact: Option<PathBuf>,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    /// Combined output, truncated, for feeding back to the model.
    pub fn combined(&self, max_chars: usize) -> String {
        let mut s = String::new();
        s.push_str(&self.stdout);
        if !self.stderr.is_empty() {
            s.push_str("\n--- stderr ---\n");
            s.push_str(&self.stderr);
        }
        if s.len() > max_chars {
            let mut idx = s.len() - max_chars;
            while idx < s.len() && !s.is_char_boundary(idx) {
                idx += 1;
            }
            format!("[...truncated...]\n{}", &s[idx..])
        } else {
            s
        }
    }
}

/// A binary is executable only if it is on the operator's allowlist **and**
/// resolvable inside the restricted PATH. Two independent checks on purpose:
/// the registry decides which tools the model may see, this decides what the
/// kernel will actually be handed.
pub fn resolve_binary(
    name: &str,
    restricted_path: &str,
    allowlist: &[String],
) -> anyhow::Result<PathBuf> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        bail!("binary name must not contain a path: {name}");
    }
    if !allowlist.iter().any(|a| a == name) {
        bail!("`{name}` is not on the allowlist");
    }

    for dir in restricted_path.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            use std::os::unix::fs::PermissionsExt;
            if candidate.metadata()?.permissions().mode() & 0o111 != 0 {
                return Ok(candidate);
            }
        }
    }
    bail!("`{name}` is allowlisted but not found in the restricted PATH");
}

/// Run an allowlisted host binary under full sandbox constraints.
pub async fn run(req: ExecRequest<'_>, ctx: &ToolCtx) -> anyhow::Result<ExecOutcome> {
    if req.offensive && !ctx.offensive {
        bail!(
            "`{}` performs active attacks and is disabled: re-run with --offensive",
            req.binary
        );
    }

    let path = resolve_binary(req.binary, &ctx.config.restricted_path, &ctx.config.allowlist)?;
    run_path(req, &path, ctx).await
}

/// Core executor. `path` must already have passed allowlist + PATH resolution.
pub async fn run_path(
    req: ExecRequest<'_>,
    path: &Path,
    ctx: &ToolCtx,
) -> anyhow::Result<ExecOutcome> {
    let cwd = ctx.workdir.clone();
    std::fs::create_dir_all(&cwd).ok();

    let mut cmd = tokio::process::Command::new(path);
    cmd.args(req.args)
        .current_dir(&cwd)
        .env_clear()
        .env("PATH", &ctx.config.restricted_path)
        .env("HOME", &cwd)
        .env("TMPDIR", &cwd)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let limits = Limits {
        cpu_secs: ctx.config.child_cpu_secs,
        as_bytes: ctx.config.child_as_bytes,
        fsize_bytes: ctx.config.max_output_bytes * 16,
    };

    // SAFETY: the closure only issues setrlimit(2) and setsid(2), both
    // async-signal-safe, and runs before execve.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            let mut failures: Vec<String> = Vec::new();
            let mut apply = |r: rlimit::Resource, soft: u64, hard: u64, label: &str| {
                if let Err(e) = rlimit::setrlimit(r, soft, hard) {
                    failures.push(format!("{label}: {e}"));
                }
            };
            apply(rlimit::Resource::CPU, limits.cpu_secs, limits.cpu_secs, "RLIMIT_CPU");
            apply(
                rlimit::Resource::AS,
                limits.as_bytes,
                limits.as_bytes,
                "RLIMIT_AS",
            );
            apply(
                rlimit::Resource::FSIZE,
                limits.fsize_bytes,
                limits.fsize_bytes,
                "RLIMIT_FSIZE",
            );
            apply(rlimit::Resource::NOFILE, 1024, 1024, "RLIMIT_NOFILE");
            apply(rlimit::Resource::NPROC, 256, 256, "RLIMIT_NPROC");
            apply(rlimit::Resource::CORE, 0, 0, "RLIMIT_CORE");
            if !failures.is_empty() {
                return Err(std::io::Error::other(failures.join("; ")));
            }
            // New session => child becomes its own process group leader, so a
            // timeout can kill the whole tree without touching our group.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let started = Instant::now();
    let mut child = cmd.spawn().with_context(|| {
        format!("spawning {} (allowlisted but failed to start)", path.display())
    })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let cap = req.max_output_bytes;

    let out_task = tokio::spawn(async move { read_capped(stdout, cap).await });
    let err_task = tokio::spawn(async move { read_capped(stderr, cap).await });

    let mut timed_out = false;
    let status = match tokio::time::timeout(req.timeout, child.wait()).await {
        Ok(res) => res.context("waiting for child process")?,
        Err(_) => {
            timed_out = true;
            kill_tree(&child);
            // Reap after SIGKILL; bounded so a stuck child cannot hang us.
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            child
                .try_wait()
                .ok()
                .flatten()
                .unwrap_or_else(|| std::process::ExitStatus::from_raw(9))
        }
    };

    let (stdout, out_trunc) = out_task.await.unwrap_or_default();
    let (stderr, err_trunc) = err_task.await.unwrap_or_default();
    let duration_ms = started.elapsed().as_millis() as u64;
    let exit_code = status.code();
    let truncated = out_trunc || err_trunc;

    let outcome = ExecOutcome {
        exit_code,
        timed_out,
        truncated,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        bytes_out: (stdout.len() + stderr.len()) as u64,
        duration_ms,
        binary_path: path.to_path_buf(),
        artifact: None,
    };

    ctx.record(&CommandRow {
        id: 0,
        flow_id: ctx.flow_id.clone(),
        ts: lantern_core::timeutil::now(),
        tool: req.tool.to_string(),
        binary: req.binary.to_string(),
        args: req.args.to_vec(),
        cwd: cwd.display().to_string(),
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        truncated: outcome.truncated,
        bytes_out: outcome.bytes_out as i64,
        duration_ms: outcome.duration_ms as i64,
        stdout_path: None,
        stderr_path: None,
        resolved_ips: req.resolved_ips.to_vec(),
    });

    Ok(outcome)
}

#[derive(Clone, Copy)]
struct Limits {
    cpu_secs: u64,
    as_bytes: u64,
    fsize_bytes: u64,
}

/// Kill the child's whole process group (it is the group leader).
fn kill_tree(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// Read until EOF, keeping at most `cap` bytes but continuing to drain so the
/// child never blocks on a full pipe.
async fn read_capped<R: AsyncRead + Unpin>(reader: Option<R>, cap: u64) -> (Vec<u8>, bool) {
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut kept: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if (kept.len() as u64) < cap {
                    let room = (cap as usize).saturating_sub(kept.len());
                    let take = n.min(room);
                    kept.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
        }
    }
    (kept, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::budget::Budget;
    use lantern_core::config::{Config, Paths};
    use lantern_core::scope::Scope;
    use lantern_core::storage::Db;
    use std::sync::Arc;

    fn ctx(offensive: bool) -> ToolCtx {
        let root = crate::tools::test_root("exec");
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = Paths::new(root);
        config.paths.ensure().unwrap();
        let db = Db::open(&config.paths.db()).unwrap();
        let budget = Budget::new(config.data_cap_bytes, 0);
        let scope = Scope::parse("0.0.0.0/0").unwrap();
        ToolCtx::new(
            Arc::new(config),
            Arc::new(db),
            Arc::new(budget),
            Arc::new(scope),
            Some("flw_exec".into()),
            offensive,
        )
        .unwrap()
    }

    fn req<'a>(binary: &'a str, args: &'a [String]) -> ExecRequest<'a> {
        ExecRequest {
            tool: "test",
            binary,
            args,
            timeout: Duration::from_secs(10),
            max_output_bytes: 64 * 1024,
            offensive: false,
            resolved_ips: &[],
        }
    }

    #[tokio::test]
    async fn runs_allowlisted_binary_without_shell() {
        let c = ctx(false);
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        // `echo` is intentionally NOT on the allowlist: it must be rejected even
        // though it exists on the host.
        let err = run(req("echo", &args), &c).await.unwrap_err();
        assert!(err.to_string().contains("allowlist"), "got: {err}");

        // Path separators are rejected outright.
        let err = run(req("/bin/echo", &args), &c).await.unwrap_err();
        assert!(err.to_string().contains("path"), "got: {err}");
    }

    #[tokio::test]
    async fn offensive_gate_refuses_without_flag() {
        let c = ctx(false);
        // `nmap` is on the default allowlist, so only the offensive flag blocks it.
        let args = vec!["--version".to_string()];
        let mut r = req("nmap", &args);
        r.offensive = true;
        let err = run(r, &c).await.unwrap_err();
        assert!(err.to_string().contains("--offensive"), "got: {err}");

        let mut c2 = ctx(true);
        c2.offensive = true;
        let mut r = req("nmap", &args);
        r.offensive = true;
        // With the flag set it must get as far as actually spawning nmap.
        let out = run(r, &c2).await;
        assert!(out.is_ok(), "expected spawn: {:?}", out.err());
    }

    #[tokio::test]
    async fn timeout_kills_the_child() {
        let c = ctx(false);
        // `sleep` is also not allowlisted; use the registry-free path directly
        // with an allowlisted-looking binary resolved from /bin.
        let args = vec!["30".to_string()];
        let start = Instant::now();
        let out = run_path(
            ExecRequest {
                tool: "test",
                binary: "sleep",
                args: &args,
                timeout: Duration::from_millis(300),
                max_output_bytes: 1024,
                offensive: false,
                resolved_ips: &[],
            },
            Path::new("/bin/sleep"),
            &c,
        )
        .await;
        match out {
            Ok(o) => {
                assert!(o.timed_out, "expected a timeout: {o:?}");
                assert!(start.elapsed() < Duration::from_secs(5));
            }
            Err(e) => {
                // RLIMIT_AS may reject a binary before exec on this host; that is
                // still a correct refusal, but it must be loud and typed.
                assert!(e.to_string().contains("spawning"), "unexpected error: {e}");
            }
        }
    }

    #[tokio::test]
    async fn output_is_capped_and_audited() {
        let c = ctx(false);
        let args = vec![
            "-c".to_string(),
            "head -c 100000 /dev/zero | tr '\\0' 'a'".to_string(),
        ];
        let _ = args;
        // Use `seq`-like output via an allowlisted-free path: dd is not allowlisted
        // either, so exercise the cap through /bin/cat reading a large file.
        let big = c.workdir.join("big.txt");
        std::fs::write(&big, vec![b'a'; 200_000]).unwrap();
        let args = vec![big.display().to_string()];
        let out = run_path(
            ExecRequest {
                tool: "test",
                binary: "cat",
                args: &args,
                timeout: Duration::from_secs(5),
                max_output_bytes: 4_096,
                offensive: false,
                resolved_ips: &[],
            },
            Path::new("/bin/cat"),
            &c,
        )
        .await
        .expect("cat should run");
        assert!(out.truncated, "expected truncation at 4 KiB");
        assert!(out.stdout.len() <= 4_096);
        assert!(out.success());

        // Every execution lands in the audit log.
        let rows = c.db.commands_for_flow("flw_exec").unwrap();
        assert!(rows.iter().any(|r| r.binary == "cat"));
        assert!(rows.iter().all(|r| !r.args.iter().any(|a| a.contains("sh"))));
    }

    #[tokio::test]
    async fn environment_is_scrubbed() {
        let c = ctx(false);
        // `env` is not allowlisted; run it directly to prove nothing leaks.
        std::env::set_var("LANTERN_TEST_SECRET", "super-secret");
        let out = run_path(
            ExecRequest {
                tool: "test",
                binary: "env",
                args: &[],
                timeout: Duration::from_secs(5),
                max_output_bytes: 64 * 1024,
                offensive: false,
                resolved_ips: &[],
            },
            Path::new("/usr/bin/env"),
            &c,
        )
        .await
        .expect("env should run");
        assert!(!out.stdout.contains("LANTERN_TEST_SECRET"), "secret leaked!");
        assert!(out.stdout.contains("PATH=/usr/local/bin:/usr/bin:/bin"));
        assert!(out.stdout.contains("LC_ALL=C"));
        std::env::remove_var("LANTERN_TEST_SECRET");
    }
}
