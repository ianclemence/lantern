//! Identifier generation. Deliberately dependency-free: ids only need to be
//! sortable and unique on a single host.

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

/// Short, sortable, collision-resistant-enough id with a type prefix.
pub fn new(prefix: &str) -> String {
    format!("{}_{:x}{:04x}", prefix, millis(), tick() & 0xffff)
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
}
