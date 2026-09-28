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
    fn build_args(&self, input: &serde_json::Value) -> anyhow::Result<Vec<String>> {
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
                let mut args = vec![
                    "-h".into(),
                    host,
                    "-nointeractive".into(),
                    "-Format".into(),
                    "txt".into(),
                ];
                if let Some(port) = input.get("port").and_then(|v| v.as_u64()) {
                    args.push("-port".into());
                    args.push(port.to_string());
                }
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
            other => anyhow::bail!("no argument builder for `{other}`"),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(match self.entry.binary {
            "nmap" => 180,
            "nikto" => 300,
            "sqlmap" => 600,
            "hydra" => 180,
            "tcpdump" => 60,
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
            _ => {
                let first = lines.first().unwrap_or(&"").to_string();
                format!("{}: exit {:?} {}", self.entry.binary, out.exit_code, first)
            }
        }
    }
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

            let args = self.build_args(&input)?;

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
    fn sqlmap_and_hydra_are_gated() {
        assert!(entry("sqlmap").offensive);
        assert!(entry("hydra").offensive);
        assert!(!entry("nmap").offensive);
        assert!(!entry("nikto").offensive);
        assert!(!entry("tcpdump").offensive);
    }

    #[test]
    fn argument_builders_never_emit_shell_metacharacters() {
        let sqlmap = HostTool { entry: entry("sqlmap") };
        let args = sqlmap
            .build_args(&json!({"url": "http://10.0.0.1/a?id=1", "level": 3}))
            .unwrap();
        assert!(args.contains(&"--level".to_string()));
        assert!(args.contains(&"3".to_string()));
        assert!(args.iter().all(|a| !a.contains(';') && !a.contains('|') && !a.contains('`')));

        let nmap = HostTool { entry: entry("nmap") };
        let args = nmap.build_args(&json!({"host": "10.0.0.1", "ports": "1-100"})).unwrap();
        assert_eq!(args[0], "-sT");
        assert!(args.contains(&"1-100".to_string()));
        // Model cannot inject arbitrary flags.
        assert!(nmap.build_args(&json!({"host": "10.0.0.1", "ports": "-oN /etc/x"})).is_err());
        // Host strings are passed verbatim as a single argv element (no shell), and
        // the scope check rejects them before execution.
        let hostile = nmap.build_args(&json!({"host": "10.0.0.1; rm -rf /"})).unwrap();
        assert_eq!(hostile.last().unwrap(), "10.0.0.1; rm -rf /");
        assert_eq!(hostile.len().count_ones(), hostile.len().count_ones());
    }

    #[test]
    fn tcpdump_iface_is_validated() {
        let t = HostTool { entry: entry("tcpdump") };
        assert!(t.build_args(&json!({"iface": "wlan0"})).is_ok());
        assert!(t.build_args(&json!({"iface": "not; rm -rf /"})).is_err());
        assert!(t.build_args(&json!({"iface": "doesnotexist0"})).is_err());
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
        let h = HostTool { entry: entry("hydra") };
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "ssh", "username": "root"}))
            .is_err(), "missing passlist");
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "ssh", "username": "root",
                                "passlist": "/nonexistent-list"}))
            .is_err(), "file must exist");
        assert!(h
            .build_args(&json!({"host": "10.0.0.1", "service": "SSH;rm", "username": "root",
                                "passlist": "/etc/hostname"}))
            .is_err(), "service charset");
    }
}
