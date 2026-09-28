//! Built-in wordlist for directory discovery (~2.4k entries, 28 KB).
//! Compiled into the binary so the host needs no data files on disk.

pub const RAW: &str = include_str!("../../assets/dirb.txt");

/// Parsed once per process (lazily) as needed.
pub fn entries() -> Vec<&'static str> {
    RAW.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect()
}

pub fn count() -> usize {
    RAW.lines().filter(|l| !l.trim().is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_usable() {
        let e = entries();
        assert!(e.len() >= 1_000, "expected a real wordlist, got {}", e.len());
        assert!(e.contains(&"admin"));
        assert!(e.contains(&".git/HEAD"));
        assert!(count() == e.len());
        // No blank lines, no CRLF, no paths escaping a relative URL.
        assert!(RAW.lines().all(|l| l == l.trim() && !l.contains('\r')));
    }
}
