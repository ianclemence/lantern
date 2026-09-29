//! `lantern setup` - provision every host tool this build expects, so a fresh
//! machine needs one command instead of a package-manager tour.
//!
//! Everything runs through the same sandboxed executor the agent itself uses:
//! argv arrays only (no shell anywhere), cleared environment, rlimits,
//! timeouts and an audit row per command. The limits are widened for
//! provisioning - a package install or a source build writes far more than a
//! scan does - but they are never removed.

use anyhow::{bail, Context as _};
use lantern_core::budget::{dir_size, Budget};
use lantern_core::config::Config;
use lantern_core::scope::Scope;
use lantern_core::storage::Db;
use lantern_tools::ctx::ToolCtx;
use lantern_tools::exec::{self, ExecRequest};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Allowlisted binary -> distribution package, for the tools the distro ships.
const PACKAGES: &[(&str, &str)] = &[
    ("nmap", "nmap"),
    ("sqlmap", "sqlmap"),
    ("nikto", "nikto"),
    ("hydra", "hydra"),
    ("tcpdump", "tcpdump"),
    ("bwrap", "bubblewrap"),
];

/// Toolchain needed to build john and to clone the template set.
const BUILD_PACKAGES: &[&str] = &["build-essential", "libssl-dev", "zlib1g-dev", "git"];

/// Provisioning needs a handful of binaries the agent never runs.
const PROVISION_TOOLS: &[&str] = &["git", "gcc", "make", "configure", "sudo", "apt-get", "gpg", "dpkg"];

const JOHN_REPO: &str = "https://github.com/openwall/john.git";
const TEMPLATES_REPO: &str = "https://github.com/projectdiscovery/nuclei-templates.git";
const MSF_KEY_URL: &str = "https://apt.metasploit.com/metasploit-framework.gpg.key";
const MSF_RING: &str = "/usr/share/keyrings/metasploit-framework.gpg";
const MSF_SOURCES_PATH: &str = "/etc/apt/sources.list.d/metasploit-framework.sources";

pub(crate) fn ok(msg: &str) {
    println!("  [ok]      {msg}");
}
pub(crate) fn installing(msg: &str) {
    println!("  [install] {msg}");
}
pub(crate) fn skipped(msg: &str) {
    println!("  [skip]    {msg}");
}
pub(crate) fn warn(msg: &str) {
    println!("  [warn]    {msg}");
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let tools_dir = config.tools_dir.clone();
    let user_allowlist = config.allowlist.clone();
    let templates = config.nuclei_templates.clone();

    std::fs::create_dir_all(tools_dir.join("bin")).ok();
    std::fs::create_dir_all(tools_dir.join("share")).ok();

    let sudo = have_sudo();
    let apt = has_bin("apt-get");

    println!("lantern setup\n");
    println!("  tools dir : {}", tools_dir.display());
    println!(
        "  sudo      : {}",
        if sudo {
            "available (system packages can be installed)"
        } else {
            "not usable - system packages will be reported, not installed"
        }
    );
    println!(
        "  templates : {}",
        templates.display()
    );
    if config.offline {
        println!("  mode      : offline - network steps are skipped");
    }
    println!();

    // The model half of the setup comes first: three questions and one API
    // call, while the provisioning steps below can take minutes. Without a
    // terminal there is nobody to ask, so it stores the configuration the
    // environment already describes - or says which variable is missing.
    let wizard = crate::wizard::run(&config).await?;

    // Provisioning runs under wider limits than an assessment does: unpacking a
    // package writes gigabytes, a source build needs minutes of CPU.
    let mut config = config;
    config.child_cpu_secs = 1800;
    config.child_as_bytes = 4 << 30;
    config.max_output_bytes = 64 << 20;
    for extra in PROVISION_TOOLS {
        if !config.allowlist.iter().any(|a| a == extra) {
            config.allowlist.push((*extra).to_string());
        }
    }
    // The john build directory joins the restricted PATH up front: the resolver
    // only checks the string now and the directory exists by the time we build.
    let mut path = config.restricted_path.clone();
    for dir in [tools_dir.join("bin"), tools_dir.join("john"), tools_dir.join(".build/john/src")] {
        path.push(':');
        path.push_str(&dir.display().to_string());
    }
    config.restricted_path = path;

    let db = Db::open(&config.paths.db())?;
    let budget = Budget::new(config.data_cap_bytes, dir_size(&config.paths.root));
    let scope = Scope::parse("0.0.0.0/0, ::0/0")?;
    let mut ctx = ToolCtx::new(
        Arc::new(config.clone()),
        Arc::new(db),
        Arc::new(budget),
        Arc::new(scope),
        None,
        true,
    )?;

    // 1. distribution packages ------------------------------------------------
    let wanted: Vec<(&str, &str)> = PACKAGES
        .iter()
        .filter(|(bin, _)| resolve(&config, bin).is_err())
        .copied()
        .collect();
    if wanted.is_empty() {
        ok("system packages: all present");
    } else if !apt {
        for (bin, pkg) in &wanted {
            warn(&format!(
                "{bin}: not found and no apt-get here - install `{pkg}` with your package manager"
            ));
        }
    } else if !sudo {
        for (bin, pkg) in &wanted {
            warn(&format!("{bin}: missing and sudo is not usable - install `{pkg}`"));
        }
    } else {
        let pkgs: Vec<String> = wanted.iter().map(|(_, p)| (*p).to_string()).collect();
        installing(&format!("apt-get install {}", pkgs.join(" ")));
        apt_install(&mut ctx, &pkgs).await?;
    }

    // 2. build toolchain (only when something still has to be built) ---------
    let need_john = resolve(&config, "john").is_err() || !is_john_jumbo(&mut ctx, &config).await;
    // Upstream keeps the CVE templates under `http/cves` (a top-level `cves/`
    // no longer exists), so probe the path that is actually checked out.
    let need_templates = !templates.join("http/cves").is_dir();
    if need_john || need_templates {
        let missing_build: Vec<&str> = BUILD_PACKAGES
            .iter()
            .copied()
            .filter(|p| build_package_missing(*p))
            .collect();
        if !missing_build.is_empty() {
            if apt && sudo {
                installing(&format!(
                    "apt-get install {} (build toolchain)",
                    missing_build.join(" ")
                ));
                apt_install(&mut ctx, &missing_build.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .await?;
            } else {
                for p in &missing_build {
                    warn(&format!("`{p}` is missing and cannot be installed automatically"));
                }
            }
        }
    }

    // 3. john -----------------------------------------------------------------
    if need_john {
        if config.offline {
            skipped("john: offline mode, not built");
        } else {
            installing("john (jumbo, built from source into the tools dir)");
            build_john(&mut ctx, &config).await?;
            ok("john");
        }
    } else {
        ok("john (jumbo formats available)");
    }

    // 4. nuclei ----------------------------------------------------------------
    if resolve(&config, "nuclei").is_ok() {
        ok("nuclei");
    } else if config.offline {
        skipped("nuclei: offline mode, not downloaded");
    } else {
        installing("nuclei (release binary into the tools dir)");
        install_nuclei(&tools_dir).await?;
        ok("nuclei");
    }

    // 5. template set -----------------------------------------------------------
    if !need_templates {
        ok(&format!("templates: {}", templates.display()));
    } else if config.offline {
        skipped("nuclei templates: offline mode, not cloned");
    } else if resolve(&config, "git").is_err() {
        warn("git is unavailable - cannot fetch the nuclei template set");
    } else {
        installing("nuclei templates (cves subset, sparse clone)");
        clone_templates(&mut ctx, &templates).await?;
        ok(&format!(
            "templates: {} yaml file(s)",
            count_yaml(&templates)
        ));
    }

    // 6. exploit framework ---------------------------------------------------------
    if resolve(&config, "msfconsole").is_ok() {
        ok("msfconsole");
    } else if config.offline {
        skipped("msfconsole: offline mode, not installed");
    } else {
        installing("metasploit-framework (signing key, signed repository, ~754 MB)");
        install_metasploit(&mut ctx, &config, sudo, apt).await?;
    }

    // 7. report --------------------------------------------------------------------
    println!("\n  result:");
    let mut missing = Vec::new();
    for bin in &user_allowlist {
        match resolve(&config, bin) {
            Ok(p) => println!("    {bin:<11} ok       {}", p.display()),
            Err(_) => {
                println!("    {bin:<11} MISSING");
                missing.push(bin.clone());
            }
        }
    }
    // Restate the model half once provisioning is over: by now the wizard's
    // own lines have scrolled past several minutes of install output.
    if let Some(out) = &wizard {
        println!(
            "\n  model     : {} / {} @ {}{}",
            out.provider,
            out.model,
            out.base_url,
            if out.key_saved {
                " - key saved (mode 0600)"
            } else {
                ""
            }
        );
    }

    if missing.is_empty() {
        println!("\n  every allowlisted tool is ready - run `lantern doctor` to verify.");
    } else {
        println!(
            "\n  still missing: {} - see the warnings above, then re-run `lantern setup`.",
            missing.join(", ")
        );
    }

    // The binary usually still sits in the build directory. Put it on PATH for
    // real rather than handing over an export line that dies with the shell it
    // was printed in.
    println!();
    install_on_path();
    Ok(())
}

// --- getting the binary onto PATH -------------------------------------------

/// One symlink in `~/.local/bin`: the standard per-user binary directory, it
/// survives every rebuild (cargo rewrites the same path the link points at),
/// and no shell startup file is edited - when the directory is not searched
/// yet, the line to add is printed instead of being applied behind the
/// operator's back.
fn install_on_path() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(name) = exe.file_name() else {
        return;
    };
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    if home.is_empty() {
        return;
    }
    let bin = PathBuf::from(home).join(".local/bin");
    let link = bin.join(name);

    // Running from the installed copy itself: nothing to link, only to report.
    if link == exe {
        report(&bin, &link);
        return;
    }
    // Never take over a real file that happens to be named `lantern`.
    if let Ok(md) = std::fs::symlink_metadata(&link) {
        if !md.file_type().is_symlink() {
            warn(&format!(
                "{} exists and is not a link to this build - leaving it alone; \
                 remove it and re-run `lantern setup` to install {}",
                link.display(),
                exe.display()
            ));
            return;
        }
    }

    match install_link(&bin, &link, &exe) {
        Ok(()) => report(&bin, &link),
        Err(e) => warn(&format!("could not install {}: {e:#}", link.display())),
    }
}

fn report(bin: &Path, link: &Path) {
    // The check is about the directory the link went into - not about the
    // directory the build happens to live in, which is never on PATH and used
    // to make an installed binary report itself as missing.
    if path_searches(std::env::var_os("PATH").as_deref(), bin) {
        ok(&format!("on PATH: {}", link.display()));
    } else {
        warn(&format!(
            "{} is linked but not searched yet - add it once to ~/.bashrc: \
             export PATH=\"$HOME/.local/bin:$PATH\"",
            bin.display()
        ));
    }
}

/// Create the directory and point `link` at `exe` in one step (write a
/// temporary name, rename over the old link) so the command is never missing
/// mid-update and a rerun simply repoints it.
fn install_link(bin: &Path, link: &Path, exe: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(bin).with_context(|| format!("creating {}", bin.display()))?;
    let name = link.file_name().unwrap_or(link.as_os_str());
    let tmp = bin.join(format!(".{}.new", name.to_string_lossy()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(exe, &tmp).with_context(|| format!("linking {}", link.display()))?;
    std::fs::rename(&tmp, link).with_context(|| format!("installing {}", link.display()))?;
    Ok(())
}

/// Whether `dir` is one of the directories the shell searches. Takes the PATH
/// as an argument so the rule is testable without mutating the environment;
/// trailing slashes are ignored, since both spellings name the same directory.
fn path_searches(path: Option<&std::ffi::OsStr>, dir: &Path) -> bool {
    let Some(path) = path else {
        return false;
    };
    let target = dir.to_string_lossy().trim_end_matches('/').to_string();
    std::env::split_paths(path).any(|d| d.to_string_lossy().trim_end_matches('/') == target)
}

// --- detection helpers -------------------------------------------------------

fn resolve(config: &Config, bin: &str) -> anyhow::Result<PathBuf> {
    exec::resolve_binary(bin, &config.restricted_path, &config.allowlist)
}

/// `sudo -n true`: usable without a password prompt (we never prompt).
fn have_sudo() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Look for a plain binary on the system PATH (no allowlist involvement).
fn has_bin(name: &str) -> bool {
    ["/usr/local/bin", "/usr/bin", "/bin"]
        .iter()
        .any(|d| Path::new(d).join(name).is_file())
}

/// Cheap presence test for a distribution package's payload.
fn build_package_missing(pkg: &str) -> bool {
    match pkg {
        "git" | "gcc" | "make" => !has_bin(pkg),
        "libssl-dev" => !Path::new("/usr/include/openssl/ssl.h").exists(),
        "zlib1g-dev" => !Path::new("/usr/include/zlib.h").exists(),
        _ => false,
    }
}

// --- command plumbing ---------------------------------------------------------

async fn run_cmd(
    ctx: &mut ToolCtx,
    tool: &str,
    binary: &str,
    args: &[String],
    timeout: Duration,
    cwd: Option<PathBuf>,
) -> anyhow::Result<exec::ExecOutcome> {
    let out = run_raw(ctx, tool, binary, args, timeout, cwd).await?;
    if !out.success() {
        bail!(
            "{binary} failed (exit {:?}, timed out: {}): {}",
            out.exit_code,
            out.timed_out,
            out.combined(1_500)
        );
    }
    Ok(out)
}

/// Run and report the outcome without failing: used for capability probes.
async fn run_raw(
    ctx: &mut ToolCtx,
    tool: &str,
    binary: &str,
    args: &[String],
    timeout: Duration,
    cwd: Option<PathBuf>,
) -> anyhow::Result<exec::ExecOutcome> {
    if let Some(dir) = cwd {
        ctx.workdir = dir;
    }
    let out = exec::run(
        ExecRequest {
            tool,
            binary,
            args,
            timeout,
            max_output_bytes: ctx.config.max_output_bytes,
            offensive: false,
        },
        ctx,
    )
    .await?;
    tracing::debug!(binary, exit = ?out.exit_code, "setup command");
    Ok(out)
}

async fn apt_install(ctx: &mut ToolCtx, pkgs: &[String]) -> anyhow::Result<()> {
    let mut args = vec![
        "-n".into(),
        "apt-get".into(),
        "install".into(),
        "-y".into(),
        "--no-install-recommends".into(),
        "-o".into(),
        "Dpkg::Options::=--force-confold".into(),
    ];
    args.extend(pkgs.iter().cloned());
    // `sudo` is the binary; its arguments are argv elements, never a command line.
    run_cmd(ctx, "setup", "sudo", &args, Duration::from_secs(1_800), None).await?;
    Ok(())
}

// --- individual provisions -------------------------------------------------------

/// Probe john with a jumbo-only option: vanilla builds reject it outright.
async fn is_john_jumbo(ctx: &mut ToolCtx, config: &Config) -> bool {
    if resolve(config, "john").is_err() {
        return false;
    }
    let args = vec!["--list=formats".to_string()];
    match run_raw(ctx, "setup", "john", &args, Duration::from_secs(30), None).await {
        Ok(out) => out.success() && out.stdout.matches(',').count() > 100,
        Err(_) => false,
    }
}

async fn build_john(ctx: &mut ToolCtx, config: &Config) -> anyhow::Result<()> {
    if resolve(config, "git").is_err() || resolve(config, "make").is_err() {
        bail!("git/make are unavailable: install the build toolchain first");
    }
    let build = config.tools_dir.join(".build/john");
    if build.exists() {
        std::fs::remove_dir_all(&build).ok();
    }
    let build_parent = config.tools_dir.join(".build");
    std::fs::create_dir_all(&build_parent)?;

    run_cmd(
        ctx,
        "setup",
        "git",
        &[
            "clone".into(),
            "--depth".into(),
            "1".into(),
            JOHN_REPO.into(),
            build.display().to_string(),
        ],
        Duration::from_secs(600),
        None,
    )
    .await?;

    let src = build.join("src");
    let configure = src.join("configure");
    run_cmd(
        ctx,
        "setup",
        "configure",
        &["--disable-native-tests".into()],
        Duration::from_secs(600),
        Some(src.clone()),
    )
    .await
    .with_context(|| format!("running {}", configure.display()))?;

    let jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    run_cmd(
        ctx,
        "setup",
        "make",
        &["-s".into(), format!("-j{jobs}")],
        Duration::from_secs(1_800),
        Some(src),
    )
    .await?;

    let run_dir = build.join("run");
    let target = config.tools_dir.join("john");
    if !run_dir.join("john").is_file() {
        bail!("build finished but {} is missing", run_dir.join("john").display());
    }
    if target.exists() {
        std::fs::remove_dir_all(&target).ok();
    }
    std::fs::rename(&run_dir, &target)
        .with_context(|| format!("moving build output to {}", target.display()))?;
    // Source and objects are pure build residue: reclaim them immediately.
    std::fs::remove_dir_all(&build).ok();
    Ok(())
}

async fn install_nuclei(tools_dir: &Path) -> anyhow::Result<()> {
    let arch = zip_arch(std::env::consts::ARCH).with_context(|| {
        format!("no nuclei release build for architecture `{}`", std::env::consts::ARCH)
    })?;
    let releases = fetch("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest").await?;
    let meta: serde_json::Value =
        serde_json::from_slice(&releases).context("parsing the release metadata")?;
    let tag = meta
        .get("tag_name")
        .and_then(|v| v.as_str())
        .context("release metadata has no tag_name")?
        .to_string();
    let version = tag.trim_start_matches('v');
    let url = format!(
        "https://github.com/projectdiscovery/nuclei/releases/download/{tag}/nuclei_{version}_linux_{arch}.zip"
    );
    tracing::info!(%url, "fetching nuclei");
    let zip = fetch(&url).await.with_context(|| format!("downloading {url}"))?;

    let dest = tools_dir.join("bin/nuclei");
    extract_member(&zip, "nuclei", &dest)?;
    ok(&format!(
        "nuclei {} -> {} ({} bytes)",
        tag,
        dest.display(),
        std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0)
    ));
    Ok(())
}

async fn clone_templates(ctx: &mut ToolCtx, templates: &Path) -> anyhow::Result<()> {
    if templates.exists() && templates.read_dir().map(|mut d| d.next().is_some()).unwrap_or(true) {
        // A half-finished clone would only fail again: start clean.
        std::fs::remove_dir_all(templates).ok();
    }
    if let Some(parent) = templates.parent() {
        std::fs::create_dir_all(parent)?;
    }
    run_cmd(
        ctx,
        "setup",
        "git",
        &[
            "clone".into(),
            "--depth".into(),
            "1".into(),
            "--filter=blob:none".into(),
            "--sparse".into(),
            TEMPLATES_REPO.into(),
            templates.display().to_string(),
        ],
        Duration::from_secs(900),
        None,
    )
    .await?;
    run_cmd(
        ctx,
        "setup",
        "git",
        &[
            "-C".into(),
            templates.display().to_string(),
            "sparse-checkout".into(),
            "set".into(),
            "cves".into(),
            "http/cves".into(),
        ],
        Duration::from_secs(300),
        None,
    )
    .await?;
    Ok(())
}

async fn install_metasploit(
    ctx: &mut ToolCtx,
    config: &Config,
    sudo: bool,
    apt: bool,
) -> anyhow::Result<()> {
    if !sudo || !apt {
        warn("msfconsole: needs apt-get plus passwordless sudo - skipped");
        return Ok(());
    }
    if resolve(config, "gpg").is_err() || resolve(config, "dpkg").is_err() {
        warn("msfconsole: gpg/dpkg unavailable - skipped");
        return Ok(());
    }

    // The signing key goes through a file, never a pipe or a shell.
    let build = config.tools_dir.join(".build");
    std::fs::create_dir_all(&build)?;
    let arch_out = run_cmd(
        ctx,
        "setup",
        "dpkg",
        &["--print-architecture".into()],
        Duration::from_secs(30),
        None,
    )
    .await?;
    let deb_arch = arch_out.stdout.trim().to_string();
    if !["amd64", "arm64", "armhf", "i386"].contains(&deb_arch.as_str()) {
        warn(&format!(
            "msfconsole: no packages published for `{deb_arch}` - skipped"
        ));
        return Ok(());
    }

    installing("metasploit-framework (signing key + repository)");
    let key = fetch(MSF_KEY_URL)
        .await
        .context("downloading the repository signing key")?;
    let key_file = build.join("metasploit-framework.key");
    std::fs::write(&key_file, &key)?;
    run_cmd(
        ctx,
        "setup",
        "sudo",
        &[
            "gpg".into(),
            "--dearmor".into(),
            "--yes".into(),
            "--output".into(),
            MSF_RING.into(),
            key_file.display().to_string(),
        ],
        Duration::from_secs(120),
        None,
    )
    .await?;

    let sources = build.join("metasploit-framework.sources");
    std::fs::write(&sources, msf_sources(&deb_arch))?;
    run_cmd(
        ctx,
        "setup",
        "sudo",
        &[
            "install".into(),
            "-m".into(),
            "644".into(),
            sources.display().to_string(),
            MSF_SOURCES_PATH.into(),
        ],
        Duration::from_secs(60),
        None,
    )
    .await?;

    installing("apt-get update (adding the metasploit repository)");
    run_cmd(
        ctx,
        "setup",
        "sudo",
        &["-n".into(), "apt-get".into(), "update".into()],
        Duration::from_secs(600),
        None,
    )
    .await?;
    installing("apt-get install metasploit-framework (~754 MB)");
    apt_install(ctx, &["metasploit-framework".into()]).await?;
    if resolve(config, "msfconsole").is_ok() {
        ok("msfconsole");
    } else {
        warn("msfconsole: package installed but not resolvable yet");
    }
    Ok(())
}

// --- pure helpers (unit tested) -------------------------------------------------

/// DEB822 source stanza for Rapid7's repository (suite is always `lucid`).
pub fn msf_sources(arch: &str) -> String {
    format!(
        "Types: deb\nURIs: https://apt.metasploit.com\nSuites: lucid\nComponents: main\n\
         Architectures: {arch}\nSigned-By: {MSF_RING}\n"
    )
}

/// Release-zip architecture name for a rust target arch.
pub fn zip_arch(rust_arch: &str) -> Option<&'static str> {
    match rust_arch {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("amd64"),
        _ => None,
    }
}

/// Download a URL into memory.
async fn fetch(url: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .connect_timeout(Duration::from_secs(20))
        .user_agent(concat!("lantern-setup/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.get(url).send().await?.error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}

/// Extract a single member of a zip archive (deflate) to `dest`, mode 0755.
fn extract_member(zip_bytes: &[u8], member: &str, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .context("opening the release archive")?;
    let mut file = archive
        .by_name(member)
        .with_context(|| format!("archive member `{member}` not found"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).context("reading the archive member")?;
    drop(file);
    std::fs::write(dest, &buf).with_context(|| format!("writing {}", dest.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn count_yaml(dir: &Path) -> usize {
    fn walk(p: &Path, n: &mut usize) {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(&path, n);
            } else if path.extension().is_some_and(|x| x == "yaml") {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-process temp directory for filesystem-shaped tests.
    fn test_tmp(prefix: &str) -> PathBuf {
        let thread = std::thread::current()
            .name()
            .unwrap_or("main")
            .replace("::", "_");
        std::env::temp_dir().join(format!(
            "lantern-{prefix}-{}-{thread}",
            std::process::id()
        ))
    }

    #[test]
    fn setup_takes_no_optional_tool_switches() {
        use clap::Parser as _;
        // One command provisions everything: there is nothing to opt into and
        // nothing to confirm on the way in.
        assert!(crate::Cli::try_parse_from(["lantern", "setup"]).is_ok());
        for argv in [
            ["setup", "--with-metasploit"].as_slice(),
            ["setup", "--yes"].as_slice(),
        ] {
            let mut full = vec!["lantern"];
            full.extend_from_slice(argv);
            match crate::Cli::try_parse_from(full) {
                Ok(_) => panic!("{} was accepted - optional additions are back", argv[1]),
                Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument),
            }
        }
    }

    #[test]
    fn metasploit_sources_are_deb822_and_signed() {
        for arch in ["amd64", "arm64"] {
            let s = msf_sources(arch);
            assert!(s.starts_with("Types: deb\n"));
            assert!(s.contains("Suites: lucid\n"));
            assert!(s.contains(&format!("Architectures: {arch}\n")));
            assert!(s.contains(&format!("Signed-By: {MSF_RING}\n")));
            assert!(s.ends_with('\n'));
        }
    }

    #[test]
    fn release_arch_mapping() {
        assert_eq!(zip_arch("aarch64"), Some("arm64"));
        assert_eq!(zip_arch("x86_64"), Some("amd64"));
        assert_eq!(zip_arch("riscv64"), None);
    }

    #[test]
    fn package_map_covers_the_distribution_tools_only() {
        // Tools with no distribution package must not appear here: they are
        // provisioned into the tools dir instead (john, nuclei, templates).
        for (bin, pkg) in PACKAGES {
            assert!(!bin.is_empty() && !pkg.is_empty());
            assert!(!pkg.contains(' '), "one package per entry: {pkg}");
        }
        let bins: Vec<&str> = PACKAGES.iter().map(|(b, _)| *b).collect();
        for built in ["john", "nuclei", "msfconsole"] {
            assert!(!bins.contains(&built), "{built} is provisioned, not packaged");
        }
    }

    #[test]
    fn build_deps_map_to_real_headers() {
        assert!(build_package_missing("git") == !has_bin("git"));
        assert!(!build_package_missing("something-unknown"));
    }

    #[test]
    fn zip_extraction_writes_an_executable() {
        // A store-only (no compression) zip built by hand: one member, "nuclei".
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
            w.start_file("nuclei", opts).unwrap();
            use std::io::Write as _;
            w.write_all(b"#!/bin/sh\necho hi\n").unwrap();
            w.finish().unwrap();
        }
        let root = test_tmp("setup-zip");
        let _ = std::fs::remove_dir_all(&root);
        let dest = root.join("bin/nuclei");
        extract_member(&cursor.into_inner(), "nuclei", &dest).unwrap();
        assert!(dest.is_file());
        assert_eq!(std::fs::read(&dest).unwrap(), b"#!/bin/sh\necho hi\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(extract_member(b"not a zip", "nuclei", &root.join("x")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn yaml_counter_walks_subdirectories() {
        let root = test_tmp("setup-yaml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("cves/2024")).unwrap();
        std::fs::write(root.join("cves/a.yaml"), b"x").unwrap();
        std::fs::write(root.join("cves/2024/b.yaml"), b"x").unwrap();
        std::fs::write(root.join("cves/readme.md"), b"x").unwrap();
        assert_eq!(count_yaml(&root), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn provisioning_never_widens_the_agent_allowlist_permanently() {
        // The extra binaries are appended to a *copy* of the config: the
        // assessment allowlist is untouched by setup.
        let mut config = Config::load().unwrap();
        let before = config.allowlist.clone();
        for extra in PROVISION_TOOLS {
            if !config.allowlist.iter().any(|a| a == extra) {
                config.allowlist.push((*extra).to_string());
            }
        }
        assert!(config.allowlist.len() > before.len());
        assert!(config.allowlist.starts_with(&before));
        let fresh = Config::load().unwrap();
        assert_eq!(fresh.allowlist, before, "Config::load is unaffected");
    }

    #[test]
    fn the_binary_is_linked_once_and_repointed_on_a_rebuild() {
        let root = test_tmp("install-link");
        let _ = std::fs::remove_dir_all(&root);
        let bin = root.join(".local/bin");
        let link = bin.join("lantern");
        let build = root.join("lantern/target/release/lantern");
        std::fs::create_dir_all(build.parent().unwrap()).unwrap();
        std::fs::write(&build, b"elf").unwrap();

        install_link(&bin, &link, &build).expect("first install");
        assert_eq!(std::fs::read_link(&link).unwrap(), build);
        assert!(!bin.join(".lantern.new").exists(), "temporary name left behind");

        // rebuilt somewhere else: the link follows in one step, and there is
        // no moment where the name is missing
        let rebuild = root.join("elsewhere/lantern");
        std::fs::create_dir_all(rebuild.parent().unwrap()).unwrap();
        std::fs::write(&rebuild, b"elf-again").unwrap();
        install_link(&bin, &link, &rebuild).expect("reinstall");
        assert_eq!(std::fs::read_link(&link).unwrap(), rebuild);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_binary_directory_is_created_when_it_is_missing() {
        let root = test_tmp("install-dir");
        let _ = std::fs::remove_dir_all(&root);
        let bin = root.join("fresh/bin");
        let exe = root.join("build/lantern");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"elf").unwrap();

        install_link(&bin, &bin.join("lantern"), &exe).expect("install");
        assert!(bin.is_dir(), "the directory was created");
        assert!(std::fs::read_link(bin.join("lantern")).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_path_check_asks_about_the_link_directory_not_the_build_directory() {
        // The old check compared the *build* directory against PATH, so a
        // properly installed symlink kept reporting itself as missing.
        let searched = std::ffi::OsStr::new("/usr/bin:/home/u/.local/bin");
        assert!(path_searches(Some(searched), Path::new("/home/u/.local/bin")));
        assert!(!path_searches(
            Some(searched),
            Path::new("/home/u/lantern/target/release")
        ));
        assert!(!path_searches(None, Path::new("/home/u/.local/bin")));
        assert!(
            path_searches(Some(std::ffi::OsStr::new("/home/u/.local/bin/")), Path::new("/home/u/.local/bin")),
            "a trailing slash names the same directory"
        );
    }
}
