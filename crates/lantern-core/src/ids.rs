//! Identifier generation. Deliberately dependency-free: ids only need to be
//! sortable and unique across every `lantern` process that can touch one
//! data root at once - which, since the database is a single SQLite file in
//! WAL mode, is more than one process. See `format_id`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tick() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pure core: millisecond timestamp, OS pid, and this process's own counter.
/// Split out from `new` so the one property that actually matters - two
/// different processes cannot produce the same id - is a test against fixed
/// inputs, not something inferred from calling `new()` twice in the same
/// process (which only ever exercises one pid and a counter that was never
/// reset, and so could never have caught the bug this replaced).
fn format_id(prefix: &str, millis: u64, pid: u32, tick: u64) -> String {
    format!("{prefix}_{millis:x}{pid:x}{:04x}", tick & 0xffff)
}

/// Short, sortable id with a type prefix, unique across concurrent
/// `lantern` processes on this host.
///
/// `lantern run`/`ask`/`chat` are ordinary short-lived processes, not a
/// daemon with one in-memory sequence to hand out - and the data root they
/// share is a single SQLite file in WAL mode, which is explicitly built to
/// let more than one writer touch it. Two operators (or one operator and a
/// scheduled job) starting a flow within the same millisecond is a normal
/// thing to happen, not an edge case: each process's own counter starts
/// fresh at 0, so the millisecond timestamp and counter alone used to be
/// exactly the same string for both - an outright flow-id collision, with
/// both flows' commands, tasks and findings landing under one id in the
/// shared database. Mixing in the OS pid closes that: two processes cannot
/// share a pid, so they cannot collide on their very first id regardless of
/// timing, and within one process the counter still disambiguates every
/// call after that.
pub fn new(prefix: &str) -> String {
    format_id(prefix, millis(), std::process::id(), tick())
}

pub fn new_flow() -> String {
    new("flw")
}

pub fn new_task() -> String {
    new("tsk")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_and_prefixed() {
        let a = new_flow();
        let b = new_flow();
        assert_ne!(a, b);
        assert!(a.starts_with("flw_"));
        assert!(new_task().starts_with("tsk_"));
    }

    #[test]
    fn different_processes_at_the_same_instant_cannot_collide() {
        // The bug this replaced: two processes, each with a counter that
        // starts fresh at 0, beginning in the same millisecond produced an
        // identical id outright - timestamp and counter said nothing about
        // *which process* made the call. Same millisecond, same fresh
        // counter value, different pid must still mean different ids.
        let a = format_id("flw", 123_456_789, 1_111, 0);
        let b = format_id("flw", 123_456_789, 2_222, 0);
        assert_ne!(a, b, "two processes must never collide on their first id");
    }

    #[test]
    fn same_process_still_disambiguates_by_counter() {
        let a = format_id("flw", 123_456_789, 1_111, 0);
        let b = format_id("flw", 123_456_789, 1_111, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn ids_sort_lexically_by_time_within_one_process() {
        // Sortable is a stated property: within a process, later calls at a
        // later or equal millisecond must not sort before earlier ones.
        let a = new_flow();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = new_flow();
        assert!(a < b, "{a} should sort before {b}");
    }
}
