//! `lantern` - native security assessment from the CLI.

mod ask;
mod chat;
mod doctor;
mod misc;
mod prefs;
mod run;
mod setup;
mod wizard;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use lantern_core::config::Config;
use lantern_core::retention;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "lantern",
    version,
    about = "Native security assessment agent for small Linux hosts",
    long_about = "Lantern runs a scoped, fully audited security assessment from the \
command line. Tools run in-process or as allowlisted host binaries with a cleared \
environment, restricted PATH, rlimits, timeouts, output caps and per-flow working \
directories. There is no shell, no background service and no web UI.\n\n\
SAFETY: only assess systems you are authorised to test. Targets outside --scope are \
refused. Active testing (sqlmap, hydra, nuclei, msfconsole, john) additionally \
requires --offensive, and every invocation is written to SQLite and to a trace file."
)]
struct Cli {
    /// More log output: -v debug, -vv trace
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify the device, the storage budget and every integration
    Doctor,
    /// Provision every host tool this build expects (no manual installs)
    Setup,
    /// Run an assessment flow against an in-scope target
    Run {
        /// Target host, IP or URL
        #[arg(long)]
        target: String,
        /// Comma-separated hosts, IPs and CIDRs this flow may touch
        #[arg(long)]
        scope: String,
        /// Roles to run, e.g. "researcher,pentester" (default: full pipeline)
        #[arg(long)]
        roles: Option<String>,
        /// Enable active testing (sqlmap, hydra, nuclei, msfconsole, john).
        /// Audit-logged and scope-gated.
        #[arg(long)]
        offensive: bool,
        /// Scripted run: no model calls, nothing is spent
        #[arg(long)]
        dry_run: bool,
        /// Cap model steps per role (can only lower a role's own cap)
        #[arg(long)]
        steps: Option<usize>,
        /// Let roles stop and ask you a question before deciding. Without a
        /// terminal, set LANTERN_OPERATOR_ANSWER to reply unattended.
        #[arg(long)]
        interactive: bool,
    },
    /// Instruct the assessment in natural language instead of flags
    Ask {
        /// The instruction itself. May be a sentence or a whole framework
        #[arg(long)]
        prompt: Option<String>,
        /// Read the instruction from this file instead
        #[arg(long)]
        file: Option<PathBuf>,
        /// Target host, IP or URL (always the authority, whatever the prompt says)
        #[arg(long)]
        target: String,
        /// Comma-separated hosts, IPs and CIDRs this flow may touch
        #[arg(long)]
        scope: String,
        /// Roles to run, e.g. "researcher,pentester" (default: full pipeline)
        #[arg(long)]
        roles: Option<String>,
        /// Enable active testing. The prompt can restrain this, never grant it
        #[arg(long)]
        offensive: bool,
        /// Scripted run: no model calls, nothing is spent
        #[arg(long)]
        dry_run: bool,
        /// Cap model steps per role (can only lower a role's own cap)
        #[arg(long)]
        steps: Option<usize>,
        /// Let roles stop and ask you a question before deciding. Without a
        /// terminal, set LANTERN_OPERATOR_ANSWER to reply unattended.
        #[arg(long)]
        interactive: bool,
    },
    /// Conversational terminal over the assessment flow
    Chat {
        /// Starting target (change it later with /target)
        #[arg(long)]
        target: Option<String>,
        /// Starting scope (change it later with /scope)
        #[arg(long)]
        scope: Option<String>,
        /// Roles to run, e.g. "researcher,pentester" (default: full pipeline)
        #[arg(long)]
        roles: Option<String>,
        /// Enable active testing for the session. A prompt can still restrain
        /// any single flow, never grant it
        #[arg(long)]
        offensive: bool,
        /// Scripted runs: no model calls, nothing is spent
        #[arg(long)]
        dry_run: bool,
        /// Cap model steps per role (can only lower a role's own cap)
        #[arg(long)]
        steps: Option<usize>,
    },
    /// List recorded flows
    Flows {
        /// How many flows to show
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// Render a stored report (stdout, or a file with --out)
    Report {
        flow_id: String,
        /// Write the markdown to this path instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List every tool this build can use
    Tools,
    /// Enforce retention: compress old artifacts, prune, vacuum
    Gc,
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.verbose {
        0 => {}
        1 => std::env::set_var("RUST_LOG", "lantern=debug,warn"),
        _ => std::env::set_var("RUST_LOG", "trace"),
    }

    let mut config = Config::load().context("loading configuration")?;
    // Layer the wizard's preferences and credentials over the environment.
    prefs::apply(&mut config);
    config.init_dirs().context("creating the data root")?;
    // Keeps the guard alive for the whole run: stderr + size-capped file log.
    let _log = lantern_core::logging::init(&config).context("initialising logging")?;

    match cli.cmd {
        Cmd::Doctor => doctor::run(&config).await?,
        Cmd::Gc => misc::gc(&config)?,
        cmd => {
            match cmd {
                Cmd::Run {
                    target,
                    scope,
                    roles,
                    offensive,
                    dry_run,
                    steps,
                    interactive,
                } => {
                    config.offensive = config.offensive || offensive;
                    run::run(
                        config,
                        run::Args {
                            target,
                            scope,
                            roles,
                            offensive,
                            dry_run,
                            steps,
                            interactive,
                        },
                    )
                    .await?;
                }
                Cmd::Ask {
                    prompt,
                    file,
                    target,
                    scope,
                    roles,
                    offensive,
                    dry_run,
                    steps,
                    interactive,
                } => {
                    config.offensive = config.offensive || offensive;
                    ask::run(
                        config,
                        ask::Args {
                            prompt,
                            file,
                            target,
                            scope,
                            roles,
                            offensive,
                            dry_run,
                            steps,
                            interactive,
                        },
                    )
                    .await?;
                }
                // Setup is the one command that downloads and builds gigabytes
                // (packages, john from source, template clones), so it is the
                // only place the free-space floor refuses. Everything else is
                // bounded by the data-root and log caps, and an already
                // configured machine must not be blocked from working.
                Cmd::Setup => {
                    retention::check_floor(&config)?;
                    setup::run(config).await?
                }
                Cmd::Chat {
                    target,
                    scope,
                    roles,
                    offensive,
                    dry_run,
                    steps,
                } => {
                    config.offensive = config.offensive || offensive;
                    chat::run(
                        config,
                        chat::Args {
                            target,
                            scope,
                            roles,
                            offensive,
                            dry_run,
                            steps,
                        },
                    )
                    .await?;
                }
                Cmd::Flows { limit } => misc::flows(&config, limit)?,
                Cmd::Report { flow_id, out } => misc::report(&config, &flow_id, out)?,
                Cmd::Tools => misc::tools(&config)?,
                Cmd::Doctor | Cmd::Gc => unreachable!("handled above"),
            }
        }
    }
    Ok(())
}
