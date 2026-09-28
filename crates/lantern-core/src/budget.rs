//! Disk budgeting: statvfs-backed free space, data-root usage accounting and
//! the hard cap that refuses work which would push the filesystem under its floor.

use crate::error::{CoreError, Result};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Filesystem statistics for the volume holding `path`.
#[derive(Debug, Clone, Copy)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

impl FsStat {
    /// Filesystem stats for the volume holding `path`.
    ///
    /// If `path` does not exist yet (fresh data root), the nearest existing
    /// ancestor is measured instead — it is on the same volume.
    pub fn for_path(path: &Path) -> Result<Self> {
        let mut probe = Some(path);
        while let Some(p) = probe {
            match Self::statvfs(p) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    let is_missing = matches!(&e, CoreError::Io { source, .. }
                        if source.kind() == std::io::ErrorKind::NotFound);
                    if !is_missing {
                        return Err(e);
                    }
                    probe = p.parent();
                }
            }
        }
        Err(CoreError::Config(format!(
            "no existing ancestor for {}",
            path.display()
        )))
    }

    fn statvfs(path: &Path) -> Result<Self> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| CoreError::Config(format!("bad path {path:?}: {e}")))?;
        unsafe {
            let mut st: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c.as_ptr(), &mut st) != 0 {
                return Err(CoreError::io(
                    path.display().to_string(),
                    std::io::Error::last_os_error(),
                ));
            }
            let frsize = if st.f_frsize != 0 { st.f_frsize } else { st.f_bsize } as u64;
            Ok(FsStat {
                total_bytes: st.f_blocks as u64 * frsize,
                free_bytes: st.f_bavail as u64 * frsize,
            })
        }
    }

    /// Fraction of the filesystem that must never be touched (default 20%).
    pub fn floor_bytes(&self, percent: u8) -> u64 {
        self.total_bytes * u64::from(percent) / 100
    }

    /// Bytes we are allowed to consume before hitting the floor.
    pub fn usable_bytes(&self, percent: u8) -> u64 {
        self.free_bytes.saturating_sub(self.floor_bytes(percent))
    }
}

/// Recursive size of a directory (follows no symlinks; ignores failures so a
/// concurrently-removed file never aborts accounting).
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

/// Tracks bytes written to the data root during this process and refuses work
/// that would breach the configured cap.
pub struct Budget {
    cap_bytes: u64,
    used_baseline: AtomicU64,
    reserved: AtomicU64,
}

impl Budget {
    /// `existing` is the on-disk size of the data root at startup.
    pub fn new(cap_bytes: u64, existing_bytes: u64) -> Self {
        Self {
            cap_bytes,
            used_baseline: AtomicU64::new(existing_bytes),
            reserved: AtomicU64::new(0),
        }
    }

    pub fn cap_bytes(&self) -> u64 {
        self.cap_bytes
    }

    pub fn used_bytes(&self) -> u64 {
        self.used_baseline.load(Ordering::Relaxed)
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.cap_bytes.saturating_sub(self.used_bytes())
    }

    /// Check whether `additional` bytes may be written. Fails loudly instead of
    /// letting a scan fill the disk. Reservations count against the cap too, so
    /// two concurrent tasks cannot both claim the last free bytes.
    pub fn can_write(&self, additional: u64) -> Result<()> {
        let committed = self.used_bytes();
        let held = self.reserved.load(Ordering::Relaxed);
        if committed + held + additional > self.cap_bytes {
            return Err(CoreError::BudgetExceeded(format!(
                "need {} B but only {} B of {} B data budget remains ({} B committed, {} B reserved)",
                additional,
                self.cap_bytes.saturating_sub(committed + held),
                self.cap_bytes,
                committed,
                held
            )));
        }
        Ok(())
    }

    /// Reserve `bytes` up-front (call before starting a task), returns a guard
    /// that releases on drop after committing actual usage.
    pub fn reserve(&self, bytes: u64) -> Result<Reservation<'_>> {
        self.can_write(bytes)?;
        self.reserved.fetch_add(bytes, Ordering::Relaxed);
        Ok(Reservation { budget: self, bytes })
    }

    pub fn commit(&self, bytes: u64) {
        self.used_baseline.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Re-scan the data root (after gc / external changes).
    pub fn resync(&self, path: &Path) {
        self.used_baseline.store(dir_size(path), Ordering::Relaxed);
    }
}

pub struct Reservation<'a> {
    budget: &'a Budget,
    bytes: u64,
}

impl Reservation<'_> {
    /// Commit `actual` bytes and release the remainder of the reservation.
    pub fn commit(self, actual: u64) {
        let actual = actual.min(self.bytes);
        self.budget.commit(actual);
        self.budget
            .reserved
            .fetch_sub(self.bytes, Ordering::Relaxed);
        std::mem::forget(self);
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.budget.reserved.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn statvfs_reports_this_volume() {
        let st = FsStat::for_path(Path::new("/")).expect("statvfs /");
        assert!(st.total_bytes > 1_000_000_000, "29 GB volume expected");
        let floor = st.floor_bytes(20);
        assert!(floor > 0);
        // The host must always keep >=20% free, so usable() is free minus floor.
        assert_eq!(st.usable_bytes(20), st.free_bytes.saturating_sub(floor));
    }

    #[test]
    fn cap_refuses_over_budget_writes() {
        let b = Budget::new(1000, 900);
        assert!(b.can_write(50).is_ok());
        assert!(b.can_write(200).is_err());
        assert_eq!(b.remaining_bytes(), 100);
    }

    #[test]
    fn reservation_releases_on_drop() {
        let b = Budget::new(1000, 0);
        {
            let _r = b.reserve(400).unwrap();
            assert!(b.reserve(700).is_err());
        }
        assert!(b.reserve(700).is_ok());
    }

    #[test]
    fn dir_size_walks_nested() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert!(dir_size(&dir) > 0);
        assert_eq!(dir_size(Path::new("/nonexistent/lantern")), 0);
    }
}
