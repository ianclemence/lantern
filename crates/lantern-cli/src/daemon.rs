//! `lantern queue` and `lantern daemon`: an unattended work queue.
//!
//! This is a polling loop, never an HTTP server or a long-lived listening
//! socket - consistent with the rest of the project ("no shell, no
//! background service, no web UI" becomes "no *network-facing* background
//! service": the daemon only reads its own SQLite queue table and runs
//! flows through the exact same `run::run` path `lantern run` already uses).
//! `lantern queue add` from one invocation and `lantern daemon` running in
//! another talk to each other only through that one database file.

use crate::run;
use lantern_core::config::Config;
use lantern_core::storage::Db;
use lantern_core::timeutil;
use std::time::Duration;

pub fn queue_add(
    config: &Config,
    target: String,
    scope: String,
    roles: Option<String>,
    offensive: bool,
    dry_run: bool,
    steps: Option<usize>,
) -> anyhow::Result<()> {
    // Fail fast on a malformed roles list rather than queuing a job the
    // daemon can only discover is broken once it is claimed.
    run::parse_roles(roles.as_deref())?;
    let db = Db::open(&config.paths.db())?;
    let job = db.enqueue(
        &target,
        &scope,
        roles.as_deref(),
        offensive,
        dry_run,
        steps.map(|s| s as i64),
    )?;
    println!("queued job #{} - {target} (scope: {scope})", job.id);
    Ok(())
}

pub fn queue_list(config: &Config, status: Option<String>) -> anyhow::Result<()> {
    let db = Db::open(&config.paths.db())?;
    let jobs = db.list_queue(status.as_deref())?;
    if jobs.is_empty() {
        println!("queue is empty{}", status.map(|s| format!(" (status={s})")).unwrap_or_default());
        return Ok(());
    }
    println!(
        "{:<6} {:<9} {:<28} {:<21} {:<26} ERROR",
        "ID", "STATUS", "TARGET", "CREATED", "FLOW"
    );
    for j in jobs {
        println!(
            "{:<6} {:<9} {:<28} {:<21} {:<26} {}",
            j.id,
            j.status,
            clip(&j.target, 28),
            timeutil::rfc3339(j.created_at),
            j.flow_id.as_deref().unwrap_or("-"),
            j.error.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

pub fn queue_remove(config: &Config, id: i64) -> anyhow::Result<()> {
    let db = Db::open(&config.paths.db())?;
    if db.remove_queue_job(id)? {
        println!("removed job #{id}");
        Ok(())
    } else {
        anyhow::bail!("no such pending/finished job: #{id}");
    }
}

/// Poll the queue, running one job at a time to completion before claiming
/// the next - the same reasoning `lantern run` already applies to a single
/// invocation's own concurrency cap, just at the level of whole flows
/// instead of tasks inside one flow. Exits cleanly on SIGINT/SIGTERM: the
/// current job is allowed to finish (or fail) and record its own result;
/// nothing is killed mid-flow.
pub async fn run_daemon(config: Config, poll_interval_secs: u64) -> anyhow::Result<()> {
    println!(
        "lantern daemon: polling {} every {poll_interval_secs}s (Ctrl-C to stop after the \
         current job finishes)",
        config.paths.db().display()
    );

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("lantern daemon: stopping (SIGINT)");
                return Ok(());
            }
            _ = sigterm.recv() => {
                println!("lantern daemon: stopping (SIGTERM)");
                return Ok(());
            }
            job = claim_one(&config) => {
                match job? {
                    Some(()) => continue,
                    None => tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await,
                }
            }
        }
    }
}

/// Claim and run exactly one queued job, if one is waiting. `Ok(None)` means
/// the queue was empty - the caller sleeps before polling again.
async fn claim_one(config: &Config) -> anyhow::Result<Option<()>> {
    let db = Db::open(&config.paths.db())?;
    let Some(job) = db.claim_next_queued()? else {
        return Ok(None);
    };
    println!("lantern daemon: running job #{} - {}", job.id, job.target);

    let args = run::Args {
        target: job.target.clone(),
        scope: job.scope.clone(),
        roles: job.roles.clone(),
        offensive: job.offensive,
        dry_run: job.dry_run,
        steps: job.steps.map(|s| s as usize),
        interactive: false, // nobody is watching an unattended daemon job
    };

    match run::run(config.clone(), args).await {
        Ok(()) => {
            // `run::run` creates its own flow id but does not hand it back;
            // the most recent flow for this exact target is close enough
            // for the queue row to point somewhere useful, and is never
            // load-bearing - `lantern flows`/`report` remain the source of
            // truth for the assessment itself.
            let flow_id = db
                .list_flows(50)?
                .into_iter()
                .find(|f| f.target == job.target)
                .map(|f| f.id);
            db.finish_queue_job(job.id, flow_id.as_deref(), None)?;
            println!("lantern daemon: job #{} finished", job.id);
        }
        Err(e) => {
            db.finish_queue_job(job.id, None, Some(&e.to_string()))?;
            println!("lantern daemon: job #{} failed: {e:#}", job.id);
        }
    }
    Ok(Some(()))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max.saturating_sub(1)).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(name: &str) -> Config {
        let root = std::env::temp_dir().join(format!("lantern-daemon-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::load().unwrap();
        config.paths = lantern_core::config::Paths::new(root);
        config.paths.ensure().unwrap();
        config
    }

    #[test]
    fn queue_add_rejects_an_unknown_role_before_touching_the_database() {
        let config = test_config("bad-role");
        let err = queue_add(
            &config,
            "example.com".into(),
            "example.com".into(),
            Some("not-a-role".into()),
            false,
            true,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown role"), "{err}");
        let db = Db::open(&config.paths.db()).unwrap();
        assert!(db.list_queue(None).unwrap().is_empty(), "nothing queued on a rejected add");
    }

    #[test]
    fn queue_add_list_remove_round_trip() {
        let config = test_config("roundtrip");
        queue_add(&config, "a.example.com".into(), "a.example.com".into(), None, false, true, None)
            .unwrap();
        let db = Db::open(&config.paths.db()).unwrap();
        let jobs = db.list_queue(None).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].target, "a.example.com");

        queue_remove(&config, jobs[0].id).unwrap();
        assert!(db.list_queue(None).unwrap().is_empty());

        let err = queue_remove(&config, 999_999).unwrap_err();
        assert!(err.to_string().contains("no such"), "{err}");
    }

    #[tokio::test]
    async fn claim_one_runs_a_dry_run_job_to_completion() {
        let config = test_config("claim-dry-run");
        queue_add(
            &config,
            "example.com".into(),
            "example.com".into(),
            None,
            false,
            true, // dry-run: no model calls, nothing is spent
            Some(1),
        )
        .unwrap();

        let ran = claim_one(&config).await.unwrap();
        assert!(ran.is_some(), "a pending job was claimed and run");

        let db = Db::open(&config.paths.db()).unwrap();
        let jobs = db.list_queue(None).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].status, "done", "{:?}", jobs[0].error);

        assert!(claim_one(&config).await.unwrap().is_none(), "nothing left to claim");
    }
}
