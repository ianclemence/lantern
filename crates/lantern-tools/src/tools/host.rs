//! Allowlisted host binaries exposed as tools.
//!
//! Each adapter builds its argument array itself: the model never supplies raw
//! command-line flags, so there is no way to smuggle `-oN /etc/x` through.
//! Every call is scope-checked, sandboxed (see `exec`), timed out and audited.

use crate::ctx::ToolCtx;
use crate::exec::{self, ExecRequest};
use crate::registry::{HostToolEntry, Tool, ToolOutput};
use serde_json::json;
use std::time::Duration;

/// nikto's own `-maxtime`, kept under the adapter's 300 s timeout so the scan
/// reports what it found instead of being killed mid-run.
const NIKTO_MAXTIME_SECS: u64 = 240;

/// All host binaries Lantern knows how to drive. Only the ones present in the
/// operator's allowlist end up in the registry.
pub fn host_tools() -> Vec<HostToolEntry> {
    vec![
        HostToolEntry {
            binary: "nmap",
            description: "Nmap TCP service scan of an in-scope host (connect scan, no root).",
            offensive: false,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "nikto",
            description: "Nikto web-server misconfiguration scan against an in-scope host.",
            offensive: false,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "tcpdump",
            description: "Capture N packets on an in-scope interface to a pcap artifact (needs CAP_NET_RAW).",
            offensive: false,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "sqlmap",
            description: "ACTIVE: sqlmap SQL-injection testing against an in-scope URL. Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "hydra",
            description: "ACTIVE: hydra password spraying against an in-scope service. Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "nuclei",
            description: "ACTIVE: nuclei CVE template scan of an in-scope URL (local template set). Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "msfconsole",
            description: "ACTIVE: run one module (use/set/run|check) against an in-scope host. Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "john",
            description: "ACTIVE: offline hash cracking with john (wordlist, optional rules). Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
    ]
}

/// Extract the authority (host) from a URL for scope checking.
fn authority_of(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    no_scheme
        .split('/')
        .next()
        .unwrap_or(no_scheme)
        .rsplit('@')
        .next()
        .unwrap_or(no_scheme)
        .to_string()
}

fn split_host_port(auth: &str) -> (String, Option<u16>) {
    if let Some(rest) = auth.strip_prefix('[') {
        // [v6]:port
        let (h, p) = rest.split_once(']').unwrap_or((rest, ""));
        return (
            h.to_string(),
            p.strip_prefix(':').and_then(|x| x.parse().ok()),
        );
    }
    match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse().ok(),
        ),
        _ => (auth.to_string(), None),
    }
}

/// The model-facing wrapper. One struct, dispatch on `entry.binary`.
pub struct HostTool {
    pub entry: HostToolEntry,
}

impl HostTool {
    fn build_args(
        &self,
        input: &serde_json::Value,
        ctx: &ToolCtx,
    ) -> anyhow::Result<Vec<String>> {
        match self.entry.binary {
            "nmap" => {
                let host = super::str_field(input, "host")?;
                let mut args = vec![
                    "-sT".into(),
                    "-Pn".into(),
                    "-T4".into(),
                    "--open".into(),
                    "-oN".into(),
                    "-".into(),
                ];
                if let Some(ports) = super::opt_str_field(input, "ports") {
                    if !ports.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-' || c == ' ')
                    {
                        anyhow::bail!("invalid `ports` for nmap");
                    }
                    args.push("-p".into());
                    args.push(ports);
                } else {
                    args.push("--top-ports".into());
                    args.push("100".into());
                }
                args.push(host);
                Ok(args)
            }
            "nikto" => {
                let host = super::str_field(input, "host")?;
                // `-Format` selects nikto's *file* writer: with no `-o` it
                // aborts before scanning ("Unable to open '' for write"). The
                // default screen output is what the executor captures, so the
                // flag is left out entirely.
                let mut args = vec!["-h".into(), host, "-nointeractive".into()];
                if let Some(port) = input.get("port").and_then(|v| v.as_u64()) {
                    args.push("-port".into());
                    args.push(port.to_string());
                }
                // nikto's own scan limit, set below the adapter's 300s timeout,
                // so it finishes and reports instead of being killed mid-run.
                args.push("-maxtime".into());
                args.push(NIKTO_MAXTIME_SECS.to_string());
                Ok(args)
            }
            "tcpdump" => {
                let iface = super::str_field(input, "iface")?;
                if !iface
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                {
                    anyhow::bail!("invalid interface name");
                }
                if !std::path::Path::new("/sys/class/net").join(&iface).exists() {
                    anyhow::bail!("interface `{iface}` does not exist on this host");
                }
                let count = super::opt_u64(input, "packets", 200).clamp(1, 5_000);
                let mut args = vec![
                    "-i".into(),
                    iface,
                    "-c".into(),
                    count.to_string(),
                    "-w".into(),
                ];
                let out = super::opt_str_field(input, "output").unwrap_or_else(|| "capture.pcap".into());
                let out = out.trim_matches(|c: char| c == '/' || c == '.').to_string();
                args.push(if out.is_empty() { "capture.pcap".into() } else { out });
                if let Some(f) = super::opt_str_field(input, "filter") {
                    if f.len() > 200
                        || !f
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || " .:<>=!&|()[]+-*/'".contains(c))
                    {
                        anyhow::bail!("invalid bpf filter");
                    }
                    args.push(f);
                }
                Ok(args)
            }
            "sqlmap" => {
                let url = super::str_field(input, "url")?;
                let mut args = vec![
                    "-u".into(),
                    url,
                    "--batch".into(),
                    "--random-agent".into(),
                    "--timeout".into(),
                    "15".into(),
                    "--retries".into(),
                    "1".into(),
                ];
                let level = super::opt_u64(input, "level", 1).clamp(1, 5);
                let risk = super::opt_u64(input, "risk", 1).clamp(1, 3);
                args.push("--level".into());
                args.push(level.to_string());
                args.push("--risk".into());
                args.push(risk.to_string());
                if let Some(data) = super::opt_str_field(input, "data") {
                    if data.len() > 2_000 {
                        anyhow::bail!("data too long");
                    }
                    args.push("--data".into());
                    args.push(data);
                }
                if let Some(cookie) = super::opt_str_field(input, "cookie") {
                    if cookie.len() > 2_000 {
                        anyhow::bail!("cookie too long");
                    }
                    args.push("--cookie".into());
                    args.push(cookie);
                }
                if let Some(t) = super::opt_str_field(input, "technique") {
                    if !t.chars().all(|c| c.is_ascii_uppercase() || c == ',') || t.len() > 16 {
                        anyhow::bail!("invalid technique list");
                    }
                    args.push("--technique".into());
                    args.push(t);
                }
                Ok(args)
            }
            "hydra" => {
                let host = super::str_field(input, "host")?;
                let service = super::str_field(input, "service")?;
                if !service.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c == '_') {
                    anyhow::bail!("invalid service name");
                }
                let mut args = vec![
                    host,
                    service,
                    "-t".into(),
                    "4".into(),
                    "-f".into(), // stop at first valid credential
                    "-V".into(),
                ];
                match (
                    super::opt_str_field(input, "username"),
                    super::opt_str_field(input, "userlist"),
                ) {
                    (Some(u), _) => {
                        if u.len() > 128 {
                            anyhow::bail!("username too long");
                        }
                        args.push("-l".into());
                        args.push(u);
                    }
                    (None, Some(list)) => {
                        let p = std::path::PathBuf::from(&list);
                        crate::ctx::require_input_file(&p)?;
                        args.push("-L".into());
                        args.push(list);
                    }
                    (None, None) => anyhow::bail!("provide `username` or `userlist`"),
                }
                let passlist = super::str_field(input, "passlist")?;
                let p = std::path::PathBuf::from(&passlist);
                crate::ctx::require_input_file(&p)?;
                args.push("-P".into());
                args.push(passlist);
                if let Some(port) = input.get("port").and_then(|v| v.as_u64()) {
                    args.push("-s".into());
                    args.push(port.to_string());
                }
                Ok(args)
            }
            "nuclei" => {
                let url = super::str_field(input, "url")?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    anyhow::bail!("nuclei needs an http(s) url");
                }
                if url.len() > 2_048 {
                    anyhow::bail!("url too long");
                }
                let mut args = vec![
                    "-t".into(),
                    ctx.config.nuclei_templates.display().to_string(),
                    "-u".into(),
                    url,
                    "-jsonl".into(),
                    "-silent".into(),
                    "-nc".into(),
                    // Never hand target callbacks to a third-party service.
                    "-no-interactsh".into(),
                    "-timeout".into(),
                    "10".into(),
                    "-retries".into(),
                    "1".into(),
                ];
                if let Some(sev) = super::opt_str_field(input, "severity") {
                    if !["info", "low", "medium", "high", "critical"].contains(&sev.as_str()) {
                        anyhow::bail!("invalid severity filter");
                    }
                    args.push("-severity".into());
                    args.push(sev);
                }
                if let Some(tags) = super::opt_str_field(input, "tags") {
                    if tags.len() > 120
                        || !tags
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ',' || c == '-')
                    {
                        anyhow::bail!("invalid tags");
                    }
                    args.push("-tags".into());
                    args.push(tags);
                }
                Ok(args)
            }
            "msfconsole" => {
                let module = super::str_field(input, "module")?;
                if module.len() > 96
                    || !module
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "/_-".contains(c))
                {
                    anyhow::bail!("invalid module path");
                }
                let host = super::str_field(input, "host")?;
                if host.len() > 128
                    || !host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || ".-:/_".contains(c))
                {
                    anyhow::bail!("invalid host for msfconsole");
                }
                let action =
                    super::opt_str_field(input, "action").unwrap_or_else(|| "run".into());
                if action != "run" && action != "check" {
                    anyhow::bail!("action must be `run` or `check`");
                }

                // The whole session is one argv element handed to `-x`. Option
                // values are character-filtered so nothing can chain a second
                // console command out of them.
                let mut script = format!("use {module}; ");
                if let Some(opts) = input.get("options").and_then(|v| v.as_object()) {
                    if opts.len() > 24 {
                        anyhow::bail!("too many options (max 24)");
                    }
                    for (k, v) in opts {
                        if k.len() > 32
                            || !k
                                .chars()
                                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                        {
                            anyhow::bail!("invalid option name `{k}`");
                        }
                        if k == "RHOSTS" || k == "RPORT" {
                            anyhow::bail!("set the target with `host`/`port`, not `{k}`");
                        }
                        let val = v
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("option `{k}` must be a string"))?;
                        let banned = [';', '|', '`', '$', '\n', '\r', '"', '\'', '\\', '&'];
                        if val.len() > 200 || val.chars().any(|c| banned.contains(&c)) {
                            anyhow::bail!("option `{k}` contains a rejected character");
                        }
                        script.push_str(&format!("set {k} {val}; "));
                    }
                }
                script.push_str(&format!("set RHOSTS {host}; "));
                if let Some(port) = input.get("port").and_then(|v| v.as_u64()) {
                    if port == 0 || port > 65_535 {
                        anyhow::bail!("invalid port");
                    }
                    script.push_str(&format!("set RPORT {port}; "));
                }
                script.push_str(&format!("{action}; exit"));
                Ok(vec!["-q".into(), "-x".into(), script])
            }
            other => anyhow::bail!("no argument builder for `{other}`"),
        }
    }

    /// john runs in two phases (crack, then `--show`) against a hash file this
    /// call writes, so it gets its own path instead of `build_args`.
    fn john_plan(
        &self,
        input: &serde_json::Value,
        ctx: &ToolCtx,
        hashfile: &std::path::Path,
        max_run_secs: u64,
    ) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        let pot = ctx.workdir.join("lantern.pot");
        let pot_arg = format!("--pot={}", pot.display());
        let mut crack = vec![pot_arg.clone()];
        let mut show = vec!["--show".to_string(), pot_arg];

        if let Some(fmt) = super::opt_str_field(input, "format") {
            if fmt.len() > 64
                || !fmt
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
            {
                anyhow::bail!("invalid john format name");
            }
            crack.push(format!("--format={fmt}"));
            show.push(format!("--format={fmt}"));
        }

        let wordlist = match super::opt_str_field(input, "wordlist") {
            Some(p) => {
                let path = std::path::PathBuf::from(&p);
                crate::ctx::require_input_file(&path)?;
                // Reads stay inside the two directories Lantern owns.
                if !path.starts_with(&ctx.config.tools_dir)
                    && !path.starts_with(&ctx.config.paths.root)
                {
                    anyhow::bail!("wordlist must live under the tools dir or the data root");
                }
                path
            }
            None => {
                let d = ctx.config.tools_dir.join("john").join("password.lst");
                if !d.is_file() {
                    anyhow::bail!("no bundled wordlist: pass `wordlist` or run `lantern setup`");
                }
                d
            }
        };
        crack.push(format!("--wordlist={}", wordlist.display()));
        if input.get("rules").and_then(|v| v.as_bool()).unwrap_or(false) {
            crack.push("--rules".into());
        }
        crack.push(format!("--max-run-time={max_run_secs}"));
        crack.push(hashfile.display().to_string());
        show.push(hashfile.display().to_string());
        Ok((crack, show))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(match self.entry.binary {
            "nmap" => 180,
            "nikto" => 300,
            "sqlmap" => 600,
            "hydra" => 180,
            "tcpdump" => 60,
            "nuclei" => 600,
            "msfconsole" => 300,
            "john" => 360,
            _ => 120,
        })
    }

    /// Best-effort human summary of raw tool output.
    fn summarize(&self, out: &exec::ExecOutcome) -> String {
        let text = out.combined(12_000);
        let lines: Vec<&str> = text.lines().collect();
        match self.entry.binary {
            "nmap" => {
                let ports: Vec<&str> = lines
                    .iter()
                    .filter(|l| {
                        let t = l.trim();
                        t.starts_with(|c: char| c.is_ascii_digit())
                            && t.contains("/tcp")
                            && t.split_whitespace().count() >= 3
                    })
                    .copied()
                    .collect();
                if ports.is_empty() {
                    format!("nmap: no open ports reported (exit {:?})", out.exit_code)
                } else {
                    format!("nmap: {} open port(s): {}", ports.len(), ports.join(" | "))
                }
            }
            "sqlmap" => {
                let hits: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.to_ascii_lowercase().contains("is vulnerable"))
                    .copied()
                    .collect();
                if hits.is_empty() {
                    "sqlmap: finished, no injectable parameter identified".into()
                } else {
                    format!("sqlmap: {} injectable parameter(s)", hits.len())
                }
            }
            "nikto" => {
                let osv: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.starts_with("+ OSVDB"))
                    .copied()
                    .collect();
                let findings: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.starts_with('+') && !l.starts_with("+ OSVDB") && l.len() > 12)
                    .copied()
                    .collect();
                format!(
                    "nikto: {} finding(s), {} known-vulnerability reference(s)",
                    findings.len(),
                    osv.len()
                )
            }
            "hydra" => {
                let found: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.starts_with("[") && l.contains("password:"))
                    .copied()
                    .collect();
                if found.is_empty() {
                    "hydra: completed, no credential found".into()
                } else {
                    format!("hydra: {} credential(s) found", found.len())
                }
            }
            "tcpdump" => {
                format!(
                    "tcpdump: captured {} packet(s)",
                    out.stdout
                        .lines()
                        .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
                        .count()
                )
            }
            "nuclei" => {
                let mut by_sev: Vec<(String, usize)> = Vec::new();
                let mut total = 0usize;
                for line in out.stdout.lines() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        if v.get("name").is_some() {
                            total += 1;
                            let sev = v
                                .pointer("/info/severity")
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            match by_sev.iter_mut().find(|(s, _)| *s == sev) {
                                Some((_, n)) => *n += 1,
                                None => by_sev.push((sev, 1)),
                            }
                        }
                    }
                }
                if total == 0 {
                    "nuclei: finished, no template matched".into()
                } else {
                    let detail: Vec<String> = by_sev
                        .iter()
                        .map(|(s, n)| format!("{s}: {n}"))
                        .collect();
                    format!("nuclei: {total} finding(s) ({})", detail.join(", "))
                }
            }
            "msfconsole" => {
                let sessions = lines
                    .iter()
                    .filter(|l| l.to_ascii_lowercase().contains("session opened"))
                    .count();
                if sessions > 0 {
                    format!("msfconsole: {sessions} session(s) opened")
                } else if text.contains("Completed") || text.to_ascii_lowercase().contains("checked")
                {
                    "msfconsole: module finished without a session".into()
                } else {
                    format!("msfconsole: exit {:?}", out.exit_code)
                }
            }
            "john" => {
                let cracked = john_cracked(&text);
                if cracked == 0 {
                    "john: finished, nothing cracked".into()
                } else {
                    format!("john: {cracked} hash(es) cracked")
                }
            }
            _ => {
                let first = lines.first().unwrap_or(&"").to_string();
                format!("{}: exit {:?} {}", self.entry.binary, out.exit_code, first)
            }
        }
    }

    /// john runs in two phases (crack, then `--show`) against a hash file this
    /// call writes into the flow's own artifact directory.
    async fn execute_john(
        &self,
        input: serde_json::Value,
        ctx: &ToolCtx,
    ) -> anyhow::Result<ToolOutput> {
        let hashes = super::str_field(&input, "hashes")?;
        let blob = validate_hashes(&hashes)?;
        let hash_path = ctx.write_artifact("john-hashes.txt", blob.as_bytes())?;
        let max_run = self.timeout().as_secs().saturating_sub(30).max(30);
        let (crack, show) = self.john_plan(&input, ctx, &hash_path, max_run)?;

        let started = std::time::Instant::now();
        let crack_out = exec::run(
            ExecRequest {
                tool: self.name(),
                binary: "john",
                args: &crack,
                timeout: self.timeout(),
                max_output_bytes: ctx.config.max_output_bytes,
                offensive: self.entry.offensive,
            },
            ctx,
        )
        .await?;

        // Only spend the second invocation when the first one actually ran.
        let show_out = if crack_out.timed_out {
            None
        } else {
            Some(
                exec::run(
                    ExecRequest {
                        tool: self.name(),
                        binary: "john",
                        args: &show,
                        timeout: Duration::from_secs(30),
                        max_output_bytes: ctx.config.max_output_bytes,
                        offensive: self.entry.offensive,
                    },
                    ctx,
                )
                .await?,
            )
        };

        let mut text = crack_out.combined(8_000);
        if let Some(s) = &show_out {
            text.push_str("\n--- john --show ---\n");
            text.push_str(&s.combined(4_000));
        }
        let cracked = john_cracked(&text);
        let total = blob.lines().filter(|l| !l.trim().is_empty()).count();
        let summary = if cracked == 0 {
            format!("john: finished, nothing cracked ({total} hash(es) supplied)")
        } else {
            format!("john: {cracked} of {total} hash(es) cracked")
        };

        let elapsed = started.elapsed().as_millis() as u64;
        let log = format!("$ john {}\n$ john {}\n{}", crack.join(" "), show.join(" "), text);
        let log_artifact = ctx.write_artifact("john.log", log.as_bytes()).ok();

        let out_json = json!({
            "binary": "john",
            "args": crack,
            "exit_code": crack_out.exit_code,
            "timed_out": crack_out.timed_out,
            "duration_ms": elapsed,
            "cracked": cracked,
            "hashes": total,
            "output": lantern_core::text_clip(&text, 6_000),
        });
        let mut o = ToolOutput::new(
            format!("{summary} (john exit {:?} in {elapsed} ms)", crack_out.exit_code),
            out_json,
            crack_out.success(),
        );
        let mut artifacts = vec![hash_path];
        if let Some(a) = log_artifact {
            artifacts.push(a);
        }
        o = o.with_artifacts(artifacts);
        Ok(o)
    }
}

/// Accept a small batch of hash lines: a conservative charset so nothing odd
/// reaches john's own parser.
fn validate_hashes(raw: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut count = 0usize;
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        count += 1;
        if count > 64 {
            anyhow::bail!("too many hashes (max 64 per call)");
        }
        if l.len() > 512 {
            anyhow::bail!("hash line too long (max 512 characters)");
        }
        if !l.chars().all(|c| c.is_ascii_alphanumeric() || "$*/:+.,=@-".contains(c)) {
            anyhow::bail!("hash line contains an unsupported character");
        }
        out.push_str(l);
        out.push('\n');
    }
    if count == 0 {
        anyhow::bail!("no hashes supplied");
    }
    Ok(out)
}

/// Read `N password hash(es) cracked` out of john's own output. The word
/// `cracked` anchors the match, so "Loaded 2 password hashes" is not a count.
fn john_cracked(text: &str) -> usize {
    for line in text.lines() {
        if let Some(cracked_at) = line.find(" cracked") {
            let head = &line[..cracked_at];
            if let Some(hash_at) = head.rfind(" password hash") {
                if let Some(n) = head[..hash_at]
                    .trim_end()
                    .rsplit(' ')
                    .next()
                    .and_then(|t| t.parse::<usize>().ok())
                {
                    return n;
                }
            }
        }
    }
    0
}

impl Tool for HostTool {
    fn name(&self) -> &'static str {
        // Static strings: leak the composed name once (single-digit count).
        match self.entry.binary {
            "nmap" => "host_nmap",
            "nikto" => "host_nikto",
            "tcpdump" => "host_tcpdump",
            "sqlmap" => "host_sqlmap",
            "hydra" => "host_hydra",
            "nuclei" => "host_nuclei",
            "msfconsole" => "host_msfconsole",
            "john" => "host_john",
            _ => "host_unknown",
        }
    }

    fn description(&self) -> &'static str {
        self.entry.description
    }

    fn parameters(&self) -> serde_json::Value {
        match self.entry.binary {
            "nmap" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope host or IP"},
                    "ports": {"type": "string", "description": "e.g. \"1-1024,3306\" (digits, commas, dashes only)"}
                },
                "required": ["host"]
            }),
            "nikto" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope host or IP"},
                    "port": {"type": "integer", "description": "web port, default 80"}
                },
                "required": ["host"]
            }),
            "tcpdump" => json!({
                "type": "object",
                "properties": {
                    "iface": {"type": "string", "description": "interface, e.g. wlan0"},
                    "packets": {"type": "integer", "description": "packet count, default 200, max 5000"},
                    "output": {"type": "string", "description": "pcap filename inside the flow workdir"},
                    "filter": {"type": "string", "description": "optional bpf filter, e.g. \"port 80\""}
                },
                "required": ["iface"]
            }),
            "sqlmap" => json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "full in-scope URL, parameterised"},
                    "data": {"type": "string", "description": "optional POST body"},
                    "cookie": {"type": "string", "description": "optional cookie header"},
                    "level": {"type": "integer", "description": "1-5, default 1"},
                    "risk": {"type": "integer", "description": "1-3, default 1"},
                    "technique": {"type": "string", "description": "e.g. BEUST"}
                },
                "required": ["url"]
            }),
            "hydra" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope host or IP"},
                    "service": {"type": "string", "description": "e.g. ssh, http-get, ftp"},
                    "port": {"type": "integer"},
                    "username": {"type": "string", "description": "single username"},
                    "userlist": {"type": "string", "description": "file with usernames, one per line"},
                    "passlist": {"type": "string", "description": "file with passwords, one per line"}
                },
                "required": ["host", "service", "passlist"]
            }),
            "nuclei" => json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "in-scope http(s) url"},
                    "severity": {"type": "string", "description": "info|low|medium|high|critical"},
                    "tags": {"type": "string", "description": "comma-separated template tags"}
                },
                "required": ["url"]
            }),
            "msfconsole" => json!({
                "type": "object",
                "properties": {
                    "module": {"type": "string", "description": "e.g. auxiliary/scanner/http/title"},
                    "host": {"type": "string", "description": "in-scope host, IP or CIDR (RHOSTS)"},
                    "port": {"type": "integer", "description": "RPORT"},
                    "action": {"type": "string", "description": "run (default) or check"},
                    "options": {
                        "type": "object",
                        "description": "datastore options, e.g. {\"TARGETURI\": \"/wp-login.php\"}"
                    }
                },
                "required": ["module", "host"]
            }),
            "john" => json!({
                "type": "object",
                "properties": {
                    "hashes": {"type": "string", "description": "one hash per line (max 64)"},
                    "format": {"type": "string", "description": "john format, e.g. raw-md5, NT, bcrypt"},
                    "wordlist": {"type": "string", "description": "wordlist path under the tools dir or data root"},
                    "rules": {"type": "boolean", "description": "apply word-mangling rules (slower)"}
                },
                "required": ["hashes"]
            }),
            _ => json!({"type": "object", "properties": {}}),
        }
    }

    fn requires_offensive(&self) -> bool {
        self.entry.offensive
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            // john is an offline tool: no target, so no scope check applies.
            if self.entry.binary == "john" {
                return self.execute_john(input, ctx).await;
            }

            // Scope check on whatever authority the input describes.
            let target = ["host", "url"]
                .iter()
                .find_map(|k| input.get(*k).and_then(|v| v.as_str()))
                .unwrap_or_default();
            let auth = authority_of(target);
            let (host, _port) = split_host_port(&auth);
            if host.is_empty() {
                anyhow::bail!("missing target for {}", self.entry.binary);
            }
            ctx.check_scope(&host)?;
            if !target.is_empty() && target.contains("://") {
                ctx.check_scope(&auth)?;
            }

            if self.entry.binary == "nuclei" && !ctx.config.nuclei_templates.is_dir() {
                anyhow::bail!(
                    "nuclei template set not found at {} - run `lantern setup`",
                    ctx.config.nuclei_templates.display()
                );
            }

            let args = self.build_args(&input, ctx)?;

            let started = std::time::Instant::now();
            let outcome = exec::run(
                ExecRequest {
                    tool: self.name(),
                    binary: self.entry.binary,
                    args: &args,
                    timeout: self.timeout(),
                    max_output_bytes: ctx.config.max_output_bytes,
                    offensive: self.entry.offensive,
                },
                ctx,
            )
            .await?;

            let summary = self.summarize(&outcome);
            let elapsed = started.elapsed().as_millis() as u64;

            // Full raw output becomes a retention-tracked artifact.
            let blob = format!(
                "$ {} {}\n--- stdout ---\n{}\n--- stderr ---\n{}\n(exit {:?}, truncated: {})\n",
                self.entry.binary,
                args.join(" "),
                outcome.stdout,
                outcome.stderr,
                outcome.exit_code,
                outcome.truncated
            );
            let artifact = ctx
                .write_artifact(&format!("{}.log", self.entry.binary), blob.as_bytes())
                .ok();

            let out_json = json!({
                "binary": self.entry.binary,
                "args": args,
                "exit_code": outcome.exit_code,
                "timed_out": outcome.timed_out,
                "truncated": outcome.truncated,
                "bytes_out": outcome.bytes_out,
                "duration_ms": outcome.duration_ms,
                "output": lantern_core::text_clip(&outcome.combined(8_000), 6_000),
            });

            let full = format!(
                "{summary} ({} exit {:?} in {elapsed} ms{})",
                self.entry.binary,
                outcome.exit_code,
                if outcome.timed_out { ", timed out" } else { "" }
            );
            let mut o = ToolOutput::new(full, out_json, outcome.success());
            if let Some(a) = artifact {
                o = o.with_artifacts(vec![a]);
            }
            Ok(o)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(binary: &str) -> HostToolEntry {
        host_tools().into_iter().find(|e| e.binary == binary).unwrap()
    }

    #[test]
    fn nikto_scans_to_the_screen_and_stops_itself() {
        let ctx = super::super::test_ctx();
        let tool = HostTool { entry: entry("nikto") };
        let args = tool
            .build_args(&json!({"host": "10.0.0.1", "port": 443}), &ctx)
            .unwrap();

        assert_eq!(args[0], "-h");
        assert!(args.windows(2).any(|w| w == ["-port", "443"]), "{args:?}");
        // `-Format` selects the file writer; with no `-o` nikto aborts with
        // "Unable to open '' for write" and never scans.
        assert!(!args.contains(&"-Format".to_string()), "{args:?}");
        let at = args
            .iter()
            .position(|a| a == "-maxtime")
            .expect("nikto needs its own scan cap");
        assert_eq!(args[at + 1], NIKTO_MAXTIME_SECS.to_string());
    }

    #[test]
    fn active_tools_are_gated() {
        for b in ["sqlmap", "hydra", "nuclei", "msfconsole", "john"] {
            assert!(entry(b).offensive, "{b} must require --offensive");
        }
        for b in ["nmap", "nikto", "tcpdump"] {
            assert!(!entry(b).offensive, "{b} must stay non-offensive");
        }
        assert_eq!(entry("nuclei").binary, "nuclei");
    }

    #[test]
    fn argument_builders_never_emit_shell_metacharacters() {
        let ctx = super::super::test_ctx();
        let sqlmap = HostTool { entry: entry("sqlmap") };
        let args = sqlmap
            .build_args(&json!({"url": "http://10.0.0.1/a?id=1", "level": 3}), &ctx)
            .unwrap();
        assert!(args.contains(&"--level".to_string()));
        assert!(args.contains(&"3".to_string()));
        assert!(args.iter().all(|a| !a.contains(';') && !a.contains('|') && !a.contains('`')));

        let nmap = HostTool { entry: entry("nmap") };
        let args = nmap
            .build_args(&json!({"host": "10.0.0.1", "ports": "1-100"}), &ctx)
            .unwrap();
        assert_eq!(args[0], "-sT");
        assert!(args.contains(&"1-100".to_string()));
        // Model cannot inject arbitrary flags.
        assert!(nmap
            .build_args(&json!({"host": "10.0.0.1", "ports": "-oN /etc/x"}), &ctx)
            .is_err());
        // Host strings are passed verbatim as a single argv element (no shell), and
        // the scope check rejects them before execution.
        let hostile = nmap
            .build_args(&json!({"host": "10.0.0.1; rm -rf /"}), &ctx)
            .unwrap();
        assert_eq!(hostile.last().unwrap(), "10.0.0.1; rm -rf /");
    }

    #[test]
    fn tcpdump_iface_is_validated() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("tcpdump") };
        assert!(t.build_args(&json!({"iface": "wlan0"}), &ctx).is_ok());
        assert!(t.build_args(&json!({"iface": "not; rm -rf /"}), &ctx).is_err());
        assert!(t.build_args(&json!({"iface": "doesnotexist0"}), &ctx).is_err());
    }

    #[test]
    fn authority_and_port_splitting() {
        assert_eq!(authority_of("https://user:pass@example.com:8443/x"), "example.com:8443");
        assert_eq!(authority_of("http://192.168.0.1/"), "192.168.0.1");
        assert_eq!(split_host_port("example.com:8443"), ("example.com".into(), Some(8443)));
        assert_eq!(split_host_port("example.com"), ("example.com".into(), None));
        assert_eq!(split_host_port("[::1]:443"), ("::1".into(), Some(443)));
    }

    #[test]
    fn hydra_requires_input_files() {
        let ctx = super::super::test_ctx();
        let h = HostTool { entry: entry("hydra") };
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "ssh", "username": "root"}), &ctx)
            .is_err(), "missing passlist");
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "ssh", "username": "root",
                                "passlist": "/nonexistent-list"}), &ctx)
            .is_err(), "file must exist");
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "SSH;rm", "username": "root",
                                "passlist": "/etc/hostname"}), &ctx)
            .is_err(), "service charset");
    }

    #[test]
    fn nuclei_args_are_fixed_flags_plus_validated_filters() {
        let ctx = super::super::test_ctx();
        let n = HostTool { entry: entry("nuclei") };
        let args = n
            .build_args(&json!({"url": "https://example.org/login", "severity": "high"}), &ctx)
            .unwrap();
        assert!(args.contains(&"-no-interactsh".to_string()), "no third-party callbacks");
        assert!(args.contains(&"-jsonl".to_string()));
        assert!(args.contains(&"-severity".to_string()));
        assert!(args.contains(&"high".to_string()));
        // Positional target is the url, one argv element.
        assert!(args.iter().any(|a| a == "https://example.org/login"));

        assert!(n.build_args(&json!({"url": "ftp://x"}), &ctx).is_err(), "scheme");
        assert!(n
            .build_args(&json!({"url": "https://example.org", "severity": "urgent"}), &ctx)
            .is_err(), "severity enum");
        assert!(n
            .build_args(&json!({"url": "https://example.org", "tags": "cve, --headless"}), &ctx)
            .is_err(), "tag charset");
    }

    #[test]
    fn msfconsole_script_is_one_argv_element_and_injection_is_rejected() {
        let ctx = super::super::test_ctx();
        let m = HostTool { entry: entry("msfconsole") };
        let args = m
            .build_args(
                &json!({
                    "module": "auxiliary/scanner/http/title",
                    "host": "10.0.0.5",
                    "port": 8080,
                    "action": "check",
                    "options": {"TARGETURI": "/wp-login.php"}
                }),
                &ctx,
            )
            .unwrap();
        assert_eq!(args, vec![
            "-q".to_string(),
            "-x".to_string(),
            "use auxiliary/scanner/http/title; set TARGETURI /wp-login.php; set RHOSTS 10.0.0.5; \
             set RPORT 8080; check; exit"
                .to_string()
        ]);

        // A value cannot chain a second console command.
        let err = m
            .build_args(
                &json!({"module": "auxiliary/scanner/http/title", "host": "10.0.0.5",
                        "options": {"TARGETURI": "/x; irb"}}),
                &ctx,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("rejected character"), "{err}");
        // Module paths are strict, so no option-string smuggling there either.
        assert!(m
            .build_args(&json!({"module": "auxiliary/x; run", "host": "10.0.0.5"}), &ctx)
            .is_err());
        assert!(m
            .build_args(&json!({"module": "auxiliary/scanner/http/title", "host": "10.0.0.5",
                                "action": "rm -rf"}), &ctx)
            .is_err());
        // RHOSTS is set from the scope-checked `host`, never from free-form options.
        assert!(m
            .build_args(&json!({"module": "auxiliary/scanner/http/title", "host": "10.0.0.5",
                                "options": {"RHOSTS": "8.8.8.8"}}), &ctx)
            .is_err());
    }

    #[test]
    fn john_hashes_are_validated() {
        assert!(validate_hashes("").is_err());
        assert!(validate_hashes("\n  \n").is_err());
        assert_eq!(validate_hashes("5f4dcc3b5aa765d61d8327deb882cf99").unwrap().lines().count(), 1);
        assert!(validate_hashes("$2a$05$abc+/=,.*:123").is_ok(), "bcrypt charset");
        assert!(validate_hashes("deadbeef\n; rm -rf /").is_err(), "shell metachar");
        let many = (0..65).map(|i| format!("hash{i}")).collect::<Vec<_>>().join("\n");
        assert!(validate_hashes(&many).is_err(), "batch cap");
        assert!(validate_hashes(&"x".repeat(600)).is_err(), "line cap");
    }

    #[test]
    fn john_plan_uses_local_files_only() {
        let ctx = super::super::test_ctx();
        let j = HostTool { entry: entry("john") };
        let hashfile = ctx.write_artifact("h.txt", b"5f4dcc3b5aa765d61d8327deb882cf99\n").unwrap();
        let wl = ctx.workdir.join("wl.txt");
        std::fs::write(&wl, b"password\n123456\n").unwrap();

        let (crack, show) = j
            .john_plan(
                &json!({"hashes": "x", "wordlist": wl.display().to_string(), "rules": true,
                        "format": "raw-md5"}),
                &ctx,
                &hashfile,
                330,
            )
            .unwrap();
        assert!(crack.contains(&"--rules".to_string()));
        assert!(crack.contains(&"--format=raw-md5".to_string()));
        assert!(crack.contains(&"--max-run-time=330".to_string()));
        assert!(crack.iter().any(|a| a.starts_with("--pot=")));
        assert_eq!(show[0], "--show");
        assert!(show.iter().any(|a| a == &hashfile.display().to_string()));
        assert!(crack.iter().all(|a| !a.contains(';') && !a.contains('|')));

        // Reads outside the two directories Lantern owns are refused.
        assert!(j
            .john_plan(
                &json!({"hashes": "x", "wordlist": "/etc/shadow"}),
                &ctx,
                &hashfile,
                60
            )
            .is_err());
        // Format names cannot smuggle argv.
        assert!(j
            .john_plan(
                &json!({"hashes": "x", "wordlist": wl.display().to_string(),
                        "format": "raw-md5 --rules"}),
                &ctx,
                &hashfile,
                60
            )
            .is_err());
    }

    #[test]
    fn john_output_parsing_reads_the_cracked_count() {
        assert_eq!(john_cracked("1 password hash cracked, 0 left"), 1);
        assert_eq!(john_cracked("Loaded 2 password hashes\n3 password hashes cracked, 1 left"), 3);
        assert_eq!(john_cracked("Session completed"), 0);
    }
}
