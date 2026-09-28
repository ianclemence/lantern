//! Lantern core: configuration, device profiling, storage, budgeting, logging and retention.
//!
//! This crate contains no agent logic and no network tooling. Everything here is
//! infrastructure that the rest of the workspace depends on.

pub mod budget;
pub mod config;
pub mod device;
pub mod error;
pub mod ids;
pub mod logging;
pub mod retention;
pub mod scope;
pub mod storage;
pub mod timeutil;

pub use config::Config;
pub use error::CoreError;

/// Truncate `text` to roughly `max_tokens` tokens, keeping the tail where
/// actionable detail usually lives (tool output). Shared by every crate that
/// hands text back to the model.
pub fn text_clip(text: &str, max_tokens: usize) -> String {
    let max_bytes = max_tokens.saturating_mul(4);
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut idx = text.len() - max_bytes;
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    format!("[...truncated...]\n{}", &text[idx..])
}

#[cfg(test)]
mod clip_tests {
    #[test]
    fn clips_on_token_boundary() {
        let s = "hello world ".repeat(100);
        let c = crate::text_clip(&s, 10);
        assert!(c.len() <= 40 + 20);
        assert!(c.starts_with("[...truncated...]"));
        assert_eq!(crate::text_clip("short", 100), "short");
    }

    #[test]
    fn never_splits_utf8() {
        let s = "héllo wörld ünïcode ".repeat(50);
        let c = crate::text_clip(&s, 8);
        assert!(c.is_char_boundary(0));
        assert!(std::str::from_utf8(c.as_bytes()).is_ok());
    }
}
