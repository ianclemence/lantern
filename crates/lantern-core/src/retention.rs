//! Retention: the policy that keeps a 32 GB SD card from filling up.
//!
//! Order of operations:
//!   1. raw scan artifacts age out (7 d) -> gzip -> delete
//!   2. trace JSONL ages out (14 d)      -> delete
//!   3. logs are capped by size and age  -> gzip + delete
//!   4. SQLite free pages are reclaimed  -> incremental, then full if critical
//!   5. the data-root budget is re-measured from disk

use crate::budget::{dir_size, Budget, FsStat};
use crate::config::Config;
use crate::error::Result;
use crate::logging;
use crate::storage::Db;
use crate::timeutil;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub artifacts_compressed: u64,
    pub artifacts_deleted: u64,
    pub traces_deleted: u64,
    pub bytes_reclaimed: u64,
    pub data_root_bytes: u64,
    pub data_cap_bytes: u64,
    pub fs_free_bytes: u64,
    pub fs_floor_bytes: u64,
    pub vacuum: String,
}

impl Report {
    pub fn summary(&self) -> String {
        format!(
            "data root {:.1}/{:.1} MB | fs free {:.1} GB (floor {:.1} GB) | reclaimed {:.1} MB | +{} compressed, -{} artifacts, -{} traces | vacuum: {}",
            self.data_root_bytes as f64 / 1_048_576.0,
            self.data_cap_bytes as f64 / 1_048_576.0,
            self.fs_free_bytes as f64 / 1e9,
            self.fs_floor_bytes as f64 / 1e9,
            self.bytes_reclaimed as f64 / 1_048_576.0,
            self.artifacts_compressed,
            self.artifacts_deleted,
            self.traces_deleted,
            self.vacuum
        )
    }
}

/// Run the full retention pass.
pub fn run(config: &Config, db: &Db, budget: &Budget) -> Result<Report> {
    let mut rep = Report::default();
    let now = timeutil::now();

    // 1. artifacts: compress first, delete once already compressed
    let expired = db.artifacts_expired(now)?;
    for a in expired {
        let path = Path::new(&a.path);
        if !a.compressed {
            if path.exists() && logging::compress_file(path) {
                let new_len = std::fs::metadata(logging::gz_path_of(path)).map(|m| m.len()).unwrap_or(a.bytes as u64);
                rep.bytes_reclaimed += (a.bytes as u64).saturating_sub(new_len);
                db.update_artifact(a.id, &logging::gz_path_of(path).display().to_string(), new_len, true)?;
                rep.artifacts_compressed += 1;
                continue;
            }
        }
        // Already gzipped (or uncompressible): drop it.
        if path.exists() {
            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            if std::fs::remove_file(path).is_ok() {
                rep.bytes_reclaimed += len;
            }
        }
        db.delete_artifact(a.id)?;
        rep.artifacts_deleted += 1;
    }

    // 2. trace JSONL
    rep.traces_deleted = prune_dir(
        &config.paths.traces(),
        config.trace_retention_days,
    );

    // 3. logs
    let logs = config.paths.logs();
    let before = dir_size(&logs);
    logging::enforce_log_cap(&logs, config.log_cap_bytes, config.log_retention_days);
    rep.bytes_reclaimed += before.saturating_sub(dir_size(&logs));

    // 4. database space
    let fs = FsStat::for_path(&config.paths.root)?;
    let free_pct = if fs.total_bytes > 0 {
        (fs.free_bytes * 100 / fs.total_bytes) as u8
    } else {
        100
    };
    if free_pct < config.vacuum_free_percent {
        // Full VACUUM needs ~1x the DB free; only attempt if the floor allows it.
        let db_bytes = db.file_size();
        if fs.free_bytes > db_bytes + fs.floor_bytes(config.floor_percent) {
            db.full_vacuum()?;
            rep.vacuum = "full".into();
        } else {
            db.incremental_vacuum()?;
            rep.vacuum = "incremental (low free space)".into();
        }
    } else {
        db.incremental_vacuum()?;
        rep.vacuum = "incremental".into();
    }

    // 5. budget re-measure
    budget.resync(&config.paths.root);
    rep.data_root_bytes = budget.used_bytes();
    rep.data_cap_bytes = budget.cap_bytes();
    rep.fs_free_bytes = fs.free_bytes;
    rep.fs_floor_bytes = fs.floor_bytes(config.floor_percent);

    Ok(rep)
}

/// Delete files in `dir` older than `days`. Returns how many were removed.
fn prune_dir(dir: &Path, days: u64) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(days * 86_400));
    let Some(cutoff) = cutoff else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        if md.modified().map(|m| m < cutoff).unwrap_or(false) {
            if std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// One-line status shown on every startup: how much of the budget is used and
/// what is left before the hard cap.
pub fn startup_line(config: &Config, budget: &Budget) -> String {
    let fs = FsStat::for_path(&config.paths.root).unwrap_or(FsStat {
        total_bytes: 0,
        free_bytes: 0,
    });
    format!(
        "data root {:.1}/{:.1} MB ({}%) | fs free {:.1} GB of {:.1} GB | floor keeps {:.1} GB free",
        budget.used_bytes() as f64 / 1_048_576.0,
        budget.cap_bytes() as f64 / 1_048_576.0,
        if budget.cap_bytes() > 0 {
            budget.used_bytes() * 100 / budget.cap_bytes()
        } else {
            0
        },
        fs.free_bytes as f64 / 1e9,
        fs.total_bytes as f64 / 1e9,
        fs.floor_bytes(config.floor_percent) as f64 / 1e9,
    )
}

/// Refuse to start when the filesystem is already under the floor.
///
/// Only `lantern setup` calls this: provisioning downloads packages and builds
/// from source, so it is the step that can actually consume gigabytes. The
/// assessment commands are bounded by the data-root and log caps and must not
/// be blocked on a machine that is already configured.
pub fn check_floor(config: &Config) -> Result<FsStat> {
    let fs = FsStat::for_path(&config.paths.root)?;
    check_floor_against(fs, config.floor_percent)?;
    Ok(fs)
}

/// The pure comparison `check_floor` makes, split out so it can be tested
/// against a constructed `FsStat` instead of this machine's real free space.
/// A hermetic sandbox or CI runner can legitimately have less than the
/// device's 20% floor free regardless of what `lantern` itself is doing, so a
/// test that calls real `statvfs` and asserts the result is an environment
/// fact, not a property of this code — see `floor_check_logic` below.
fn check_floor_against(fs: FsStat, floor_percent: u8) -> Result<()> {
    let floor = fs.floor_bytes(floor_percent);
    if fs.free_bytes < floor {
        return Err(crate::CoreError::BudgetExceeded(format!(
            "filesystem has {:.2} GB free but the {:.1}% floor requires {:.2} GB — \
             free space before running `lantern setup`",
            fs.free_bytes as f64 / 1e9,
            floor_percent,
            floor as f64 / 1e9
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};

    fn test_config() -> Config {
        let root = std::env::temp_dir().join(format!(
            "lantern-ret-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("t")
        ));
        let mut c = Config::load().unwrap();
        c.paths = Paths::new(root.clone());
        c.data_cap_bytes = 10 * 1024 * 1024;
        c
    }

    #[test]
    fn compress_then_delete_artifacts() {
        let config = test_config();
        let _ = std::fs::remove_dir_all(&config.paths.root);
        config.paths.ensure().unwrap();
        let db = Db::open(&config.paths.db()).unwrap();

        let art = config.paths.artifacts().join("scan1.txt");
        std::fs::write(&art, vec![b'A'; 200_000]).unwrap();
        db.add_artifact(Some("f"), "scan", &art.display().to_string(), 200_000, 1)
            .unwrap();

        let budget = Budget::new(config.data_cap_bytes, dir_size(&config.paths.root));
        let r = run(&config, &db, &budget).unwrap();
        assert_eq!(r.artifacts_compressed, 1, "expired artifact should gzip: {:?}", r);
        assert!(logging::gz_path_of(&art).exists());

        // Next pass: already compressed -> deleted.
        {
            let mut st = db.all_artifacts().unwrap();
            st.clear();
        }
        // Expire it again (still `1`, which is in the past).
        let r2 = run(&config, &db, &budget).unwrap();
        assert_eq!(r2.artifacts_deleted, 1, "compressed artifact should be removed: {r2:?}");
        assert!(!logging::gz_path_of(&art).exists());

        assert!(r.data_root_bytes > 0);
        assert!(r.fs_free_bytes > 0);
        let _ = std::fs::remove_dir_all(&config.paths.root);
    }

    #[test]
    fn startup_line_mentions_budget() {
        let config = test_config();
        let budget = Budget::new(config.data_cap_bytes, 12345);
        let line = startup_line(&config, &budget);
        assert!(line.contains("data root"));
        assert!(line.contains("floor"));
    }

    /// Pure logic, independent of this machine's actual free space: a sandbox
    /// or CI runner can legitimately sit under the 20% floor without that
    /// being a defect in `lantern`. (A previous version of this test called
    /// the real `check_floor` and asserted it passed on whatever host ran the
    /// suite, which is exactly the kind of environment-dependent assertion
    /// this split exists to avoid.)
    #[test]
    fn floor_check_logic() {
        let comfortable = FsStat { total_bytes: 100_000_000_000, free_bytes: 50_000_000_000 };
        assert!(check_floor_against(comfortable, 20).is_ok());

        let under_floor = FsStat { total_bytes: 100_000_000_000, free_bytes: 10_000_000_000 };
        let err = check_floor_against(under_floor, 20).unwrap_err();
        assert!(err.to_string().contains("floor"), "{err}");

        // Exactly at the floor is not below it.
        let exact = FsStat { total_bytes: 100_000_000_000, free_bytes: 20_000_000_000 };
        assert!(check_floor_against(exact, 20).is_ok());
    }

    /// `check_floor` itself still works end to end against the real
    /// filesystem; it just must not assert a specific pass/fail outcome that
    /// depends on how much space happens to be free wherever tests run.
    #[test]
    fn floor_check_runs_against_the_real_filesystem() {
        let config = test_config();
        let _ = check_floor(&config);
    }
}
