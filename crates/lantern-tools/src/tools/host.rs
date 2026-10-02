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
            binary: "testssl.sh",
            description: "Deep TLS/SSL inspection of an in-scope host: protocol versions, \
                           cipher strength, known vulnerabilities (Heartbleed-class checks). \
                           Passive protocol negotiation, not exploitation.",
            offensive: false,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "gobuster",
            description: "Faster, multi-threaded directory/file discovery against an \
                           in-scope URL than dir_bruteforce - same risk tier as nikto.",
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
            binary: "amass",
            description: "ACTIVE: amass subdomain enumeration against an in-scope domain - \
                           active DNS resolution and optional brute-forcing, generating real \
                           traffic against the target's and third parties' DNS infrastructure, \
                           unlike the passive subdomain_enum (crt.sh) tool. Requires --offensive.",
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
        HostToolEntry {
            binary: "GetUserSPNs.py",
            description: "ACTIVE: Kerberoasting - dumps crackable TGS hashes for in-scope AD \
                           service accounts (Impacket). Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "GetNPUsers.py",
            description: "ACTIVE: AS-REP Roasting - dumps crackable hashes for in-scope AD \
                           accounts without Kerberos pre-auth (Impacket). Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "crackmapexec",
            description: "ACTIVE: SMB/WinRM/LDAP enumeration and credential check against an \
                           in-scope AD host - never runs code on the target. Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "bloodhound-python",
            description: "ACTIVE: collects in-scope AD relationship data for BloodHound. \
                           Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
        HostToolEntry {
            binary: "kube-hunter",
            description: "ACTIVE: kube-hunter remote active probing of an in-scope Kubernetes \
                           cluster for known attack vectors. Requires --offensive.",
            offensive: true,
            default_args: vec![],
        },
    ]
}

/// AD domain name: dots/dashes/alphanumerics only, no shell metacharacters.
fn valid_ad_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// AD account name: conservative charset, blocks every character that could
/// matter to a downstream parser even though there is no shell in this path.
fn valid_ad_account(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.chars().any(|c| matches!(c, ';' | '|' | '`' | '$' | '\n' | '\r' | '\\' | '"' | '\''))
}

/// A domain controller target: IP, hostname, or `[v6]`, nothing else.
fn valid_dc_target(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
}

/// Free-text secret (password): no control characters, bounded length. Still
/// passed as a single argv element (no shell), so this is defense in depth,
/// not an injection boundary.
fn valid_secret(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(|c| c.is_control())
}

/// NTLM hash, `LM:NT` or a bare `NT` hash - 32 hex characters per half.
fn valid_ntlm_hash_pair(s: &str) -> bool {
    let is_hex32 = |p: &str| p.len() == 32 && p.chars().all(|c| c.is_ascii_hexdigit());
    match s.split_once(':') {
        Some((lm, nt)) => is_hex32(lm) && is_hex32(nt),
        None => is_hex32(s),
    }
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

/// Does `s` look like a bare `ip/prefix` CIDR with nothing else attached?
/// Used to route a target like msfconsole's `RHOSTS` straight into
/// `Scope::allows`'s CIDR-subset check instead of through `authority_of`,
/// which exists for URLs and would otherwise strip the `/prefix` as if it
/// were a path.
fn is_bare_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((addr, prefix)) => {
            !prefix.is_empty()
                && !prefix.contains('/')
                && prefix.chars().all(|c| c.is_ascii_digit())
                && addr.parse::<std::net::IpAddr>().is_ok()
        }
        None => false,
    }
}

/// What should actually be handed to `Scope::allows` for this raw `host`/`url`
/// input. A bare CIDR (e.g. msfconsole's `RHOSTS`) is scope-checked as the
/// whole range it names, so it is kept intact instead of being run through
/// `authority_of`, which exists for URLs and would otherwise strip the
/// `/prefix` the same way it strips a URL path — silently validating only the
/// network's base address and letting a wider range than declared through.
fn scope_target_of(target: &str) -> String {
    if !target.contains("://") && is_bare_cidr(target) {
        return target.to_string();
    }
    let auth = authority_of(target);
    split_host_port(&auth).0
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
            "testssl.sh" => {
                let host = super::str_field(input, "host")?;
                let target = if let Some(port) = input.get("port").and_then(|v| v.as_u64()) {
                    if port == 0 || port > 65_535 {
                        anyhow::bail!("invalid port");
                    }
                    format!("{host}:{port}")
                } else {
                    host
                };
                Ok(vec![
                    "--quiet".into(),
                    "--color".into(),
                    "0".into(),
                    // Non-interactive: a warning (e.g. an old OpenSSL build)
                    // must never block an automated run waiting on a
                    // keypress nobody is there to give.
                    "--warnings".into(),
                    "batch".into(),
                    target,
                ])
            }
            "gobuster" => {
                let url = super::str_field(input, "url")?;
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    anyhow::bail!("gobuster needs an http(s) url");
                }
                if url.len() > 2_048 {
                    anyhow::bail!("url too long");
                }
                let wordlist_path = match super::opt_str_field(input, "wordlist") {
                    Some(p) => {
                        let path = std::path::PathBuf::from(&p);
                        crate::ctx::require_input_file(&path)?;
                        if !path.starts_with(&ctx.config.tools_dir)
                            && !path.starts_with(&ctx.config.paths.root)
                        {
                            anyhow::bail!("wordlist must live under the tools dir or the data root");
                        }
                        path
                    }
                    // No custom wordlist: materialise the same built-in list
                    // dir_bruteforce already ships, so there is always a
                    // working default and no extra file to provision.
                    None => ctx.write_artifact(
                        "gobuster-wordlist.txt",
                        crate::tools::wordlist::RAW.as_bytes(),
                    )?,
                };
                let threads = super::opt_u64(input, "threads", 20).clamp(1, 50);
                let mut args = vec![
                    "dir".into(),
                    "-u".into(),
                    url,
                    "-w".into(),
                    wordlist_path.display().to_string(),
                    "-q".into(),
                    "-k".into(), // don't fail on a self-signed/expired cert
                    "-t".into(),
                    threads.to_string(),
                    "--timeout".into(),
                    "10s".into(),
                ];
                if let Some(ext) = super::opt_str_field(input, "extensions") {
                    if ext.len() > 64 || !ext.chars().all(|c| c.is_ascii_alphanumeric() || c == ',') {
                        anyhow::bail!("invalid extensions list");
                    }
                    args.push("-x".into());
                    args.push(ext);
                }
                Ok(args)
            }
            "amass" => {
                let host = super::str_field(input, "host")?;
                if host.is_empty()
                    || host.len() > 253
                    || !host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    anyhow::bail!("invalid domain for amass");
                }
                let timeout_min = super::opt_u64(input, "timeout_minutes", 5).clamp(1, 30);
                let mut args = vec![
                    "enum".into(),
                    "-d".into(),
                    host,
                    "-timeout".into(),
                    timeout_min.to_string(),
                ];
                if input.get("brute").and_then(|v| v.as_bool()).unwrap_or(false) {
                    // Active wordlist-based brute forcing on top of active
                    // resolution: more traffic against the target's and
                    // resolvers' infrastructure, opt-in beyond the --offensive
                    // gate this whole tool already sits behind.
                    args.push("-brute".into());
                }
                Ok(args)
            }
            "GetUserSPNs.py" => {
                let domain = super::str_field(input, "domain")?;
                if !valid_ad_domain(&domain) {
                    anyhow::bail!("invalid AD domain");
                }
                let username = super::str_field(input, "username")?;
                if !valid_ad_account(&username) {
                    anyhow::bail!("invalid username");
                }
                let dc_ip = super::str_field(input, "dc_ip")?;
                if !valid_dc_target(&dc_ip) {
                    anyhow::bail!("invalid dc_ip");
                }
                let mut args = Vec::new();
                match (
                    super::opt_str_field(input, "password"),
                    super::opt_str_field(input, "hashes"),
                ) {
                    (Some(p), _) => {
                        if !valid_secret(&p) {
                            anyhow::bail!("invalid password");
                        }
                        args.push(format!("{domain}/{username}:{p}"));
                    }
                    (None, Some(h)) => {
                        if !valid_ntlm_hash_pair(&h) {
                            anyhow::bail!("invalid `hashes` (expected LM:NT, 32 hex each)");
                        }
                        args.push(format!("{domain}/{username}"));
                        args.push("-hashes".into());
                        args.push(h);
                    }
                    (None, None) => anyhow::bail!("provide `password` or `hashes`"),
                }
                args.push("-dc-ip".into());
                args.push(dc_ip);
                args.push("-request".into());
                Ok(args)
            }
            "GetNPUsers.py" => {
                let domain = super::str_field(input, "domain")?;
                if !valid_ad_domain(&domain) {
                    anyhow::bail!("invalid AD domain");
                }
                let dc_ip = super::str_field(input, "dc_ip")?;
                if !valid_dc_target(&dc_ip) {
                    anyhow::bail!("invalid dc_ip");
                }
                let mut args = Vec::new();
                match (
                    super::opt_str_field(input, "username"),
                    super::opt_str_field(input, "usersfile"),
                ) {
                    (Some(u), _) => {
                        if !valid_ad_account(&u) {
                            anyhow::bail!("invalid username");
                        }
                        args.push(format!("{domain}/{u}"));
                    }
                    (None, Some(list)) => {
                        let p = std::path::PathBuf::from(&list);
                        crate::ctx::require_input_file(&p)?;
                        args.push(format!("{domain}/"));
                        args.push("-usersfile".into());
                        args.push(list);
                    }
                    (None, None) => anyhow::bail!("provide `username` or `usersfile`"),
                }
                args.push("-no-pass".into());
                args.push("-dc-ip".into());
                args.push(dc_ip);
                args.push("-format".into());
                args.push("hashcat".into());
                Ok(args)
            }
            "crackmapexec" => {
                let protocol = super::str_field(input, "protocol")?;
                if !["smb", "winrm", "ldap"].contains(&protocol.as_str()) {
                    anyhow::bail!("protocol must be smb, winrm, or ldap");
                }
                let target = super::str_field(input, "target")?;
                if !valid_dc_target(&target) && !is_bare_cidr(&target) {
                    anyhow::bail!("invalid target for crackmapexec");
                }
                let mut args = vec![protocol, target];
                if let Some(u) = super::opt_str_field(input, "username") {
                    if !valid_ad_account(&u) {
                        anyhow::bail!("invalid username");
                    }
                    args.push("-u".into());
                    args.push(u);
                }
                match (
                    super::opt_str_field(input, "password"),
                    super::opt_str_field(input, "hashes"),
                ) {
                    (Some(p), _) => {
                        if !valid_secret(&p) {
                            anyhow::bail!("invalid password");
                        }
                        args.push("-p".into());
                        args.push(p);
                    }
                    (None, Some(h)) => {
                        if !valid_ntlm_hash_pair(&h) {
                            anyhow::bail!("invalid `hashes` (expected LM:NT or a bare NT hash)");
                        }
                        args.push("-H".into());
                        args.push(h);
                    }
                    (None, None) => {}
                }
                if let Some(domain) = super::opt_str_field(input, "domain") {
                    if !valid_ad_domain(&domain) {
                        anyhow::bail!("invalid domain");
                    }
                    args.push("-d".into());
                    args.push(domain);
                }
                // Enumeration-only: never a code-execution flag (-x/-X/
                // --exec-method are not in this allowlist and never will be -
                // Lantern carries no exploit/execution code of its own).
                const ALLOWED_MODULES: &[&str] = &[
                    "--shares",
                    "--users",
                    "--groups",
                    "--sessions",
                    "--pass-pol",
                    "--loggedon-users",
                    "--local-groups",
                    "--disks",
                ];
                if let Some(m) = super::opt_str_field(input, "enum_flag") {
                    if !ALLOWED_MODULES.contains(&m.as_str()) {
                        anyhow::bail!(
                            "enum_flag must be one of {ALLOWED_MODULES:?} (no code-execution \
                             flags are ever accepted)"
                        );
                    }
                    args.push(m);
                }
                Ok(args)
            }
            "bloodhound-python" => {
                let domain = super::str_field(input, "domain")?;
                if !valid_ad_domain(&domain) {
                    anyhow::bail!("invalid AD domain");
                }
                let username = super::str_field(input, "username")?;
                if !valid_ad_account(&username) {
                    anyhow::bail!("invalid username");
                }
                let password = super::str_field(input, "password")?;
                if !valid_secret(&password) {
                    anyhow::bail!("invalid password");
                }
                let dc_ip = super::str_field(input, "dc_ip")?;
                if !valid_dc_target(&dc_ip) {
                    anyhow::bail!("invalid dc_ip");
                }
                let method = super::opt_str_field(input, "collection_method")
                    .unwrap_or_else(|| "DCOnly".into());
                const ALLOWED_METHODS: &[&str] = &[
                    "Default",
                    "DCOnly",
                    "All",
                    "Group",
                    "LocalAdmin",
                    "Session",
                    "Trusts",
                    "ACL",
                ];
                if !ALLOWED_METHODS.contains(&method.as_str()) {
                    anyhow::bail!("collection_method must be one of {ALLOWED_METHODS:?}");
                }
                Ok(vec![
                    "-d".into(),
                    domain,
                    "-u".into(),
                    username,
                    "-p".into(),
                    password,
                    "-ns".into(),
                    dc_ip.clone(),
                    "-dc".into(),
                    dc_ip,
                    "-c".into(),
                    method,
                    "--zip".into(),
                ])
            }
            "kube-hunter" => {
                let host = super::str_field(input, "host")?;
                if !valid_dc_target(&host) && !is_bare_cidr(&host) {
                    anyhow::bail!("invalid host for kube-hunter");
                }
                Ok(vec!["--remote".into(), host, "--report".into(), "json".into()])
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
            "testssl.sh" => 300,
            "gobuster" => 300,
            // amass's own -timeout_minutes caps at 30 min (1,800s); this outer
            // bound leaves a 2-minute buffer for it to flush output and exit
            // cleanly, the same pattern nikto's -maxtime uses under its adapter.
            "amass" => 1_920,
            "GetUserSPNs.py" => 120,
            "GetNPUsers.py" => 120,
            "crackmapexec" => 180,
            "bloodhound-python" => 600,
            "kube-hunter" => 300,
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
            "testssl.sh" => {
                let vulnerable: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.contains("VULNERABLE"))
                    .copied()
                    .collect();
                if vulnerable.is_empty() {
                    "testssl.sh: no VULNERABLE findings reported".into()
                } else {
                    format!(
                        "testssl.sh: {} VULNERABLE finding(s): {}",
                        vulnerable.len(),
                        vulnerable
                            .iter()
                            .take(3)
                            .map(|l| l.trim())
                            .collect::<Vec<_>>()
                            .join(" | ")
                    )
                }
            }
            "gobuster" => {
                // gobuster prints one `status: NNN` line per discovered path
                // in `-q` mode: "/admin (Status: 301) [Size: 178]".
                let found: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.to_ascii_lowercase().contains("(status:"))
                    .copied()
                    .collect();
                if found.is_empty() {
                    "gobuster: no paths found".into()
                } else {
                    format!("gobuster: {} path(s) found", found.len())
                }
            }
            "amass" => {
                // Default (non-JSON) output: one discovered FQDN per line.
                let names: Vec<&str> = lines
                    .iter()
                    .filter(|l| l.contains('.') && !l.trim().is_empty() && !l.starts_with(['[', ' ']))
                    .copied()
                    .collect();
                if names.is_empty() {
                    "amass: no additional names resolved".into()
                } else {
                    format!("amass: {} name(s) resolved", names.len())
                }
            }
            "GetUserSPNs.py" => {
                let hits = lines.iter().filter(|l| l.contains("$krb5tgs$")).count();
                if hits == 0 {
                    "GetUserSPNs.py: no roastable service accounts found".into()
                } else {
                    format!("GetUserSPNs.py: {hits} roastable service account hash(es)")
                }
            }
            "GetNPUsers.py" => {
                let hits = lines.iter().filter(|l| l.contains("$krb5asrep$")).count();
                if hits == 0 {
                    "GetNPUsers.py: no AS-REP roastable accounts found".into()
                } else {
                    format!("GetNPUsers.py: {hits} AS-REP roastable account hash(es)")
                }
            }
            "crackmapexec" => {
                let hits = lines.iter().filter(|l| l.contains("[+]")).count();
                format!("crackmapexec: {hits} successful check(s) (exit {:?})", out.exit_code)
            }
            "bloodhound-python" => {
                if text.contains(".zip") || text.to_ascii_lowercase().contains("done") {
                    "bloodhound-python: collection finished".into()
                } else {
                    format!("bloodhound-python: exit {:?}", out.exit_code)
                }
            }
            "kube-hunter" => {
                let hits = text.matches("\"vulnerability\"").count();
                if hits == 0 {
                    "kube-hunter: finished, no vulnerabilities reported".into()
                } else {
                    format!("kube-hunter: {hits} vulnerabilit(y/ies) reported")
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
                resolved_ips: &[],
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
                        resolved_ips: &[],
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
            "testssl.sh" => "host_testssl",
            "gobuster" => "host_gobuster",
            "amass" => "host_amass",
            "GetUserSPNs.py" => "host_getuserspns",
            "GetNPUsers.py" => "host_getnpusers",
            "crackmapexec" => "host_crackmapexec",
            "bloodhound-python" => "host_bloodhound",
            "kube-hunter" => "host_kubehunter",
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
            "testssl.sh" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope host or IP"},
                    "port": {"type": "integer", "description": "TLS port, default 443"}
                },
                "required": ["host"]
            }),
            "gobuster" => json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "in-scope http(s) url"},
                    "wordlist": {"type": "string", "description": "optional wordlist path under the tools dir or data root; defaults to the bundled list"},
                    "threads": {"type": "integer", "description": "1-50, default 20"},
                    "extensions": {"type": "string", "description": "comma-separated extensions, e.g. \"php,bak\""}
                },
                "required": ["url"]
            }),
            "amass" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope domain"},
                    "timeout_minutes": {"type": "integer", "description": "1-30, default 5"},
                    "brute": {"type": "boolean", "description": "also active-brute-force subdomains (more traffic)"}
                },
                "required": ["host"]
            }),
            "GetUserSPNs.py" => json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string", "description": "or `hashes`"},
                    "hashes": {"type": "string", "description": "NTLM LM:NT"},
                    "dc_ip": {"type": "string", "description": "in-scope DC"}
                },
                "required": ["domain", "username", "dc_ip"]
            }),
            "GetNPUsers.py" => json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "usersfile": {"type": "string", "description": "one user per line"},
                    "dc_ip": {"type": "string", "description": "in-scope DC"}
                },
                "required": ["domain", "dc_ip"]
            }),
            "crackmapexec" => json!({
                "type": "object",
                "properties": {
                    "protocol": {"type": "string", "description": "smb|winrm|ldap"},
                    "target": {"type": "string", "description": "in-scope host/IP/CIDR"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "hashes": {"type": "string", "description": "NTLM LM:NT or NT"},
                    "domain": {"type": "string"},
                    "enum_flag": {"type": "string", "description": "read-only only: --shares --users --groups --sessions --pass-pol --loggedon-users --local-groups --disks"}
                },
                "required": ["protocol", "target"]
            }),
            "bloodhound-python" => json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "dc_ip": {"type": "string", "description": "in-scope DC"},
                    "collection_method": {"type": "string", "description": "DCOnly|All|Group|Session|Trusts|ACL"}
                },
                "required": ["domain", "username", "password", "dc_ip"]
            }),
            "kube-hunter" => json!({
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "in-scope Kubernetes API/node host, IP, or CIDR"}
                },
                "required": ["host"]
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
            let target = ["host", "url", "dc_ip", "target"]
                .iter()
                .find_map(|k| input.get(*k).and_then(|v| v.as_str()))
                .unwrap_or_default();
            if target.is_empty() {
                anyhow::bail!("missing target for {}", self.entry.binary);
            }
            let has_scheme = target.contains("://");
            let scope_target = scope_target_of(target);
            if scope_target.is_empty() {
                anyhow::bail!("missing target for {}", self.entry.binary);
            }
            ctx.check_scope(&scope_target)?;
            if has_scheme {
                ctx.check_scope(&authority_of(target))?;
            }

            // Resolve DNS for a bare hostname right before executing, so the
            // audit trail shows the address actually used rather than only
            // the name the operator scoped, and — whenever the scope itself
            // names concrete IP ranges, which is the configuration the README
            // recommends — a hostname that now resolves outside those ranges
            // is refused instead of silently scanned. This narrows, but
            // cannot fully close, the gap between this check and the
            // moment the host tool itself resolves the name: that binary
            // does its own DNS lookup and nothing in user space can pin a
            // third-party tool's connection to one address without breaking
            // vhost-based tools (nikto, sqlmap) that need the name intact.
            let mut resolved_ips: Vec<String> = Vec::new();
            if scope_target.parse::<std::net::IpAddr>().is_err() && !scope_target.contains('/') {
                match crate::tools::dns::resolve_addresses(&scope_target).await {
                    Ok(ips) => {
                        resolved_ips = ips.iter().map(|ip| ip.to_string()).collect();
                        let scope_has_networks = ctx.scope.entries().iter().any(|e| {
                            matches!(e, lantern_core::scope::ScopeEntry::Net { .. })
                        });
                        if scope_has_networks && !ips.is_empty() {
                            let any_in_scope =
                                ips.iter().any(|ip| ctx.scope.allows(&ip.to_string()));
                            if !any_in_scope {
                                anyhow::bail!(
                                    "`{scope_target}` resolves to {} which --scope does not \
                                     cover; DNS may have changed since the scope was declared \
                                     — add the resolved address to --scope or re-check the \
                                     target before running {}",
                                    resolved_ips.join(", "),
                                    self.entry.binary
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            host = %scope_target,
                            error = %e,
                            "DNS resolution before execution failed; proceeding on the \
                             hostname-level scope check alone"
                        );
                    }
                }
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
                    resolved_ips: &resolved_ips,
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
                "resolved_ips": resolved_ips,
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
        for b in [
            "sqlmap",
            "hydra",
            "nuclei",
            "msfconsole",
            "john",
            "amass",
            "GetUserSPNs.py",
            "GetNPUsers.py",
            "crackmapexec",
            "bloodhound-python",
            "kube-hunter",
        ] {
            assert!(entry(b).offensive, "{b} must require --offensive");
        }
        for b in ["nmap", "nikto", "tcpdump", "testssl.sh", "gobuster"] {
            assert!(!entry(b).offensive, "{b} must stay non-offensive");
        }
        assert_eq!(entry("nuclei").binary, "nuclei");
    }

    #[test]
    fn getuserspns_builds_a_single_domain_user_pass_argument() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("GetUserSPNs.py") };
        let args = t
            .build_args(
                &json!({"domain": "corp.local", "username": "svc", "password": "s3cr3t", "dc_ip": "10.0.0.5"}),
                &ctx,
            )
            .unwrap();
        assert_eq!(args[0], "corp.local/svc:s3cr3t");
        assert!(args.windows(2).any(|w| w == ["-dc-ip", "10.0.0.5"]));
        assert!(args.contains(&"-request".to_string()));

        let args = t
            .build_args(
                &json!({"domain": "corp.local", "username": "svc",
                        "hashes": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                        "dc_ip": "10.0.0.5"}),
                &ctx,
            )
            .unwrap();
        assert!(args.contains(&"-hashes".to_string()));

        assert!(t
            .build_args(&json!({"domain": "corp.local; rm -rf /", "username": "svc",
                                "password": "x", "dc_ip": "10.0.0.5"}), &ctx)
            .is_err());
        assert!(t
            .build_args(&json!({"domain": "corp.local", "username": "svc", "dc_ip": "10.0.0.5"}), &ctx)
            .is_err(), "needs password or hashes");
    }

    #[test]
    fn getnpusers_supports_single_user_or_a_usersfile() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("GetNPUsers.py") };
        let args = t
            .build_args(&json!({"domain": "corp.local", "username": "jdoe", "dc_ip": "10.0.0.5"}), &ctx)
            .unwrap();
        assert_eq!(args[0], "corp.local/jdoe");
        assert!(args.contains(&"-no-pass".to_string()));

        let args = t
            .build_args(
                &json!({"domain": "corp.local", "usersfile": "/etc/hostname", "dc_ip": "10.0.0.5"}),
                &ctx,
            )
            .unwrap();
        assert!(args.contains(&"-usersfile".to_string()));

        assert!(t
            .build_args(&json!({"domain": "corp.local", "dc_ip": "10.0.0.5"}), &ctx)
            .is_err(), "needs username or usersfile");
        assert!(t
            .build_args(
                &json!({"domain": "corp.local", "usersfile": "/nonexistent-file", "dc_ip": "10.0.0.5"}),
                &ctx
            )
            .is_err());
    }

    #[test]
    fn crackmapexec_never_accepts_a_code_execution_flag() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("crackmapexec") };
        let args = t
            .build_args(
                &json!({"protocol": "smb", "target": "10.0.0.5", "username": "u", "password": "p",
                        "enum_flag": "--shares"}),
                &ctx,
            )
            .unwrap();
        assert_eq!(args[0], "smb");
        assert!(args.contains(&"--shares".to_string()));

        for bad in ["-x", "-X", "--exec-method", "whoami"] {
            assert!(
                t.build_args(
                    &json!({"protocol": "smb", "target": "10.0.0.5", "enum_flag": bad}),
                    &ctx
                )
                .is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(t.build_args(&json!({"protocol": "ftp", "target": "10.0.0.5"}), &ctx).is_err());
    }

    #[test]
    fn bloodhound_python_requires_credentials_and_validates_collection_method() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("bloodhound-python") };
        let args = t
            .build_args(
                &json!({"domain": "corp.local", "username": "u", "password": "p", "dc_ip": "10.0.0.5"}),
                &ctx,
            )
            .unwrap();
        assert!(args.contains(&"--zip".to_string()));
        assert!(args.contains(&"DCOnly".to_string()));

        assert!(t
            .build_args(
                &json!({"domain": "corp.local", "username": "u", "password": "p", "dc_ip": "10.0.0.5",
                        "collection_method": "Everything"}),
                &ctx
            )
            .is_err());
    }

    #[test]
    fn ntlm_hash_validation() {
        assert!(valid_ntlm_hash_pair(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        ));
        assert!(valid_ntlm_hash_pair("31d6cfe0d16ae931b73c59d7e0c089c0"));
        assert!(!valid_ntlm_hash_pair("not-a-hash"));
        assert!(!valid_ntlm_hash_pair("31d6cfe0d16ae931b73c59d7e0c089c0:short"));
    }

    #[test]
    fn testssl_builds_host_and_port() {
        let ctx = super::super::test_ctx();
        let t = HostTool { entry: entry("testssl.sh") };
        let args = t.build_args(&json!({"host": "example.com"}), &ctx).unwrap();
        assert!(args.contains(&"--warnings".to_string()));
        assert!(args.last().unwrap() == "example.com");

        let args = t
            .build_args(&json!({"host": "example.com", "port": 8443}), &ctx)
            .unwrap();
        assert_eq!(args.last().unwrap(), "example.com:8443");

        assert!(t.build_args(&json!({"host": "example.com", "port": 70_000}), &ctx).is_err());
    }

    #[test]
    fn gobuster_defaults_to_the_bundled_wordlist_and_validates_the_url() {
        let ctx = super::super::test_ctx();
        let g = HostTool { entry: entry("gobuster") };
        let args = g.build_args(&json!({"url": "https://example.com"}), &ctx).unwrap();
        assert_eq!(args[0], "dir");
        assert!(args.contains(&"-w".to_string()));
        let wl_idx = args.iter().position(|a| a == "-w").unwrap() + 1;
        assert!(args[wl_idx].ends_with("gobuster-wordlist.txt"), "{:?}", args[wl_idx]);
        assert!(std::path::Path::new(&args[wl_idx]).exists(), "wordlist must actually be written");

        assert!(g.build_args(&json!({"url": "ftp://example.com"}), &ctx).is_err(), "scheme");
        assert!(g
            .build_args(&json!({"url": "https://example.com", "extensions": "php;rm -rf"}), &ctx)
            .is_err());

        let args = g
            .build_args(&json!({"url": "https://example.com", "threads": 999}), &ctx)
            .unwrap();
        let t_idx = args.iter().position(|a| a == "-t").unwrap() + 1;
        assert_eq!(args[t_idx], "50", "threads must clamp to the max");
    }

    #[test]
    fn amass_validates_domain_and_gates_brute_force_behind_an_explicit_flag() {
        let ctx = super::super::test_ctx();
        let a = HostTool { entry: entry("amass") };
        let args = a.build_args(&json!({"host": "example.com"}), &ctx).unwrap();
        assert_eq!(args, vec!["enum", "-d", "example.com", "-timeout", "5"]);
        assert!(!args.contains(&"-brute".to_string()));

        let args = a
            .build_args(&json!({"host": "example.com", "brute": true, "timeout_minutes": 999}), &ctx)
            .unwrap();
        assert!(args.contains(&"-brute".to_string()));
        let t_idx = args.iter().position(|a| a == "-timeout").unwrap() + 1;
        assert_eq!(args[t_idx], "30", "timeout_minutes must clamp to the max");

        assert!(a.build_args(&json!({"host": "example.com; rm -rf /"}), &ctx).is_err());
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
    fn cidr_targets_are_kept_intact_for_the_scope_check() {
        // A bare CIDR goes to Scope::allows whole, not stripped to its base
        // address the way a URL path would be.
        assert_eq!(scope_target_of("10.0.0.0/24"), "10.0.0.0/24");
        assert_eq!(scope_target_of("10.0.0.5"), "10.0.0.5");
        // A URL's path is still stripped as before.
        assert_eq!(scope_target_of("https://example.com/a/b"), "example.com");
        // Not a CIDR shape (host/path, or a non-digit "prefix"): falls back to
        // authority stripping rather than being misread as a network.
        assert_eq!(scope_target_of("example.com/admin"), "example.com");
    }

    #[test]
    fn is_bare_cidr_rejects_non_cidr_shapes() {
        assert!(is_bare_cidr("10.0.0.0/24"));
        assert!(is_bare_cidr("::1/128"));
        assert!(!is_bare_cidr("example.com/admin"));
        assert!(!is_bare_cidr("10.0.0.0/24/x"));
        assert!(!is_bare_cidr("10.0.0.5"));
        assert!(!is_bare_cidr("not-an-ip/24"));
    }

    #[tokio::test]
    async fn msfconsole_cannot_widen_a_cidr_scope_via_the_base_address() {
        // End-to-end regression for the scope-bypass this patch closes: a
        // scope of 10.0.0.0/24 must not let a model-supplied RHOSTS of
        // 10.0.0.0/8 through just because the network's base address
        // ("10.0.0.0") legitimately sits inside the declared /24.
        let mut ctx = super::super::test_ctx();
        ctx.scope = std::sync::Arc::new(
            lantern_core::scope::Scope::parse("10.0.0.0/24").unwrap(),
        );
        let m = HostTool { entry: entry("msfconsole") };
        let err = m
            .execute(
                json!({"module": "auxiliary/scanner/http/title", "host": "10.0.0.0/8"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("scope") || err.to_string().contains("out of"),
            "expected a scope rejection, got: {err}"
        );

        // The equal /24 — exactly what was declared — must still be allowed
        // through the scope gate (it may still fail later for lack of a real
        // msfconsole binary in the test sandbox; that is a different error).
        let ok_or_sandbox = m
            .execute(
                json!({"module": "auxiliary/scanner/http/title", "host": "10.0.0.0/24"}),
                &ctx,
            )
            .await;
        if let Err(e) = ok_or_sandbox {
            assert!(
                !e.to_string().to_lowercase().contains("scope"),
                "an in-scope /24 must not be rejected as out of scope: {e}"
            );
        }
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
