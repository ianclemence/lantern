//! Structured logging: stderr for the operator, a size-capped rotating file on
//! disk for post-hoc review. Replaces any external monitoring stack.

use crate::config::Config;
use crate::error::{CoreError, Result};
use std::io;
use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Keeps the background log writer alive for the process lifetime.
pub struct LogGuard {
    _guard: WorkerGuard,
}

/// Install the global tracing subscriber. Safe to call once; subsequent calls
/// are ignored by `tracing`.
pub fn init(config: &Config) -> Result<LogGuard> {
    let dir = config.paths.logs();
    std::fs::create_dir_all(&dir).map_err(|e| CoreError::io(dir.display().to_string(), e))?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lantern=info,warn"));

    let file_appender = tracing_appender::rolling::daily(&dir, "lantern.log");
    let (nb, guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(nb)
        .with_ansi(false)
        .with_target(true);

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_ansi(true);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .try_init();

    enforce_log_cap(&dir, config.log_cap_bytes, config.log_retention_days);

    // The guard must outlive every log record: the caller keeps it in scope.
    Ok(LogGuard { _guard: guard })
}

/// Enforce `max_bytes` / `max_age_days` on a directory of log files.
///
/// Order: drop anything past the age limit, gzip yesterday's files, then delete
/// the oldest files until the directory fits under the byte cap.
pub fn enforce_log_cap(dir: &Path, max_bytes: u64, max_age_days: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    for e in entries.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        files.push((
            e.path(),
            md.len(),
            md.modified().unwrap_or(std::time::UNIX_EPOCH),
        ));
    }
    if files.is_empty() {
        return;
    }
    files.sort_by_key(|f| f.2);

    let now = std::time::SystemTime::now();
    let max_age = std::time::Duration::from_secs(max_age_days.saturating_mul(86_400));

    // 1. age-based deletion
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    for (path, size, mtime) in files.clone() {
        if total <= max_bytes {
            break;
        }
        if now.duration_since(mtime).map(|d| d > max_age).unwrap_or(false) {
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
    }

    // 2. compress anything older than a day that is not yet compressed
    for (path, _size, mtime) in files.clone() {
        if path.extension().map(|e| e == "gz").unwrap_or(false) {
            continue;
        }
        if now.duration_since(mtime).map(|d| d.as_secs() > 86_400).unwrap_or(false) {
            compress(&path);
        }
    }

    // 3. recompute and delete oldest until under the cap
    let mut files = list_files(dir);
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    for (path, size, _) in files.drain(..) {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn list_files(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                if md.is_file() {
                    out.push((
                        e.path(),
                        md.len(),
                        md.modified().unwrap_or(std::time::UNIX_EPOCH),
                    ));
                }
            }
        }
    }
    out.sort_by_key(|f| f.2);
    out
}

/// Gzip a file in place (`x.log` -> `x.log.gz`) and remove the original.
/// Best effort: on failure the original is left alone.
fn compress(path: &Path) {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Read, Write};

    let mut src = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut buf = Vec::new();
    if src.read_to_end(&mut buf).is_err() {
        return;
    }
    let gz_path = gz_path_of(path);
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    if enc.write_all(&buf).is_err() {
        return;
    }
    let Ok(compressed) = enc.finish() else { return };
    if compressed.len() >= buf.len() {
        return; // no gain, keep the original
    }
    if std::fs::write(&gz_path, &compressed).is_ok() {
        let _ = std::fs::remove_file(path);
    }
}

/// `x.log` -> `x.log.gz` (keeps every dot of the original name).
pub fn gz_path_of(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".gz");
    PathBuf::from(p)
}

/// Public helper used by retention: compress an artifact file in place.
pub fn compress_file(path: &Path) -> bool {
    let before = path.exists();
    compress(path);
    before && gz_path_of(path).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn enforce_cap_deletes_oldest() {
        let dir = std::env::temp_dir().join(format!("lantern-logtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..5 {
            let p = dir.join(format!("lantern.log.{i}"));
            fs::write(&p, vec![b'x'; 10_000]).unwrap();
            // Space files out in time so ordering is deterministic.
            let f = fs::File::options().write(true).open(&p).unwrap();
            f.set_times(fs::FileTimes::new().set_modified(
                std::time::SystemTime::now()
                    - std::time::Duration::from_secs(60 * (i as u64) + 120),
            ))
            .unwrap();
        }
        let before = list_files(&dir).len();
        assert_eq!(before, 5);
        enforce_log_cap(&dir, 25_000, 3650);
        let after: u64 = list_files(&dir).iter().map(|f| f.1).sum();
        assert!(after <= 25_000, "cap violated: {after}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn age_limit_removes_old() {
        let dir = std::env::temp_dir().join(format!("lantern-logage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("old.log");
        fs::write(&p, vec![b'x'; 100]).unwrap();
        let f = fs::File::options().write(true).open(&p).unwrap();
        f.set_times(fs::FileTimes::new().set_modified(
            std::time::SystemTime::now() - std::time::Duration::from_secs(90 * 86_400),
        ))
        .unwrap();
        enforce_log_cap(&dir, 1_000_000, 30);
        assert!(!p.exists(), "old log should be deleted by age");
        let _ = fs::remove_dir_all(&dir);
    }
}
