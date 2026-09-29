//! Working-context management: chain summarization sized to the device.
//!
//! A small host cannot afford a large conversation, and an expensive API cannot
//! afford resending one. When the working set passes `summarize_at` tokens the
//! runtime asks the model to compress the older portion, keeps the newest
//! `keep_recent` tokens verbatim, and pins the summary as a system message.

use crate::provider::{Message, Role};

#[derive(Debug, Clone)]
pub struct ContextWindow {
    budget: usize,
    summarize_at: usize,
    keep_recent: usize,
    messages: Vec<Message>,
    summary: Option<String>,
}

/// Drop leading tool replies after a trim.
///
/// Providers reject a `tool` message whose requesting assistant message has
/// been cut away (DeepSeek: "Messages with role 'tool' must be a response to a
/// preceding message with 'tool_calls'"), which is exactly what token-based
/// trimming produces when the boundary lands between a call and its reply.
/// Only the front is ever cut, so dropping the replies at the front restores
/// the pairing for the whole remaining slice.
fn drop_orphan_replies(messages: &mut Vec<Message>) {
    let cut = messages
        .iter()
        .take_while(|m| m.role == Role::Tool)
        .count();
    if cut > 0 {
        messages.drain(..cut);
    }
}

impl ContextWindow {
    pub fn new(budget: usize, summarize_at: usize, keep_recent: usize) -> Self {
        Self {
            budget,
            summarize_at: summarize_at.max(keep_recent + 512),
            keep_recent,
            messages: Vec::new(),
            summary: None,
        }
    }

    pub fn push(&mut self, message: Message) {
        self.messages.push(message);
    }

    pub fn extend(&mut self, messages: impl IntoIterator<Item = Message>) {
        self.messages.extend(messages);
    }

    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn tokens(&self) -> usize {
        self.messages.iter().map(|m| m.estimate_tokens()).sum::<usize>()
            + self
                .summary
                .as_deref()
                .map(|s| (s.len() + 3) / 4)
                .unwrap_or(0)
    }

    pub fn needs_summary(&self) -> bool {
        self.tokens() > self.summarize_at
    }

    /// Messages to hand to the summarizer (everything so far).
    pub fn material_for_summary(&self) -> Vec<Message> {
        self.messages.clone()
    }

    /// Replace the transcript with the summary plus the newest messages that fit
    /// inside `keep_recent` tokens.
    pub fn apply_summary(&mut self, summary: String) {
        self.summary = Some(summary);

        let mut kept: Vec<Message> = Vec::new();
        let mut used = 0usize;
        for m in self.messages.iter().rev() {
            let t = m.estimate_tokens();
            if used + t > self.keep_recent && !kept.is_empty() {
                break;
            }
            used += t;
            kept.push(m.clone());
        }
        kept.reverse();
        drop_orphan_replies(&mut kept);
        self.messages = kept;
    }

    /// Message list to send: system prompt, optional summary, then the live
    /// transcript. Stays inside `budget` by dropping the oldest live messages.
    pub fn render(&self, system: &str) -> Vec<Message> {
        let mut out = Vec::with_capacity(self.messages.len() + 2);
        out.push(Message::system(system));
        if let Some(s) = &self.summary {
            out.push(Message::system(format!(
                "Summary of earlier work in this flow:\n{s}"
            )));
        }

        let mut used: usize = out.iter().map(|m| m.estimate_tokens()).sum();
        let start = self
            .messages
            .iter()
            .rposition(|m| {
                let t = m.estimate_tokens();
                if used + t > self.budget {
                    true
                } else {
                    used += t;
                    false
                }
            })
            .map(|i| i + 1)
            .unwrap_or(0);
        let mut kept: Vec<Message> = self.messages[start..].to_vec();
        drop_orphan_replies(&mut kept);
        out.extend(kept);
        out
    }

    /// Truncate `text` to roughly `max_tokens` tokens, keeping the tail where
    /// actionable detail usually lives (tool output).
    pub fn clip(text: &str, max_tokens: usize) -> String {
        lantern_core::text_clip(text, max_tokens)
    }
}

/// Prompt used to compress history.
pub fn summarization_prompt(transcript: &[Message]) -> Vec<Message> {
    let mut msgs = vec![Message::system(
        "You compress penetration-testing transcripts. Produce a dense factual summary: \
         hosts and ports already discovered, tools already run and their results, hypotheses \
         tested and ruled out, and open questions. Keep exact hostnames, IPs, ports and \
         version strings. No preamble, no markdown headings, max 200 words.",
    )];
    let body = transcript
        .iter()
        .map(|m| format!("[{}]\n{}", m.role.as_str(), m.content))
        .collect::<Vec<_>>()
        .join("\n\n");
    msgs.push(Message::user(ContextWindow::clip(&body, 4_000)));
    msgs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(id: &str) -> crate::provider::ToolCall {
        crate::provider::ToolCall {
            id: id.into(),
            name: "port_scan".into(),
            arguments: "{}".into(),
        }
    }

    /// What providers insist on: every reply follows the assistant message
    /// that asked for it.
    fn assert_pairs_are_intact(transcript: &[Message]) {
        let mut expect_reply_for: Option<usize> = None;
        for (i, m) in transcript.iter().enumerate() {
            match m.role {
                Role::Tool => {
                    assert_eq!(
                        expect_reply_for,
                        Some(i - 1),
                        "reply at {i} has no request before it"
                    );
                }
                Role::Assistant if !m.tool_calls.is_empty() => {
                    expect_reply_for = Some(i);
                }
                _ => expect_reply_for = None,
            }
        }
    }

    #[test]
    fn budget_trimming_never_leaves_a_reply_without_its_request() {
        let mut cw = ContextWindow::new(400, 400, 80);
        cw.push(Message::user("objective"));
        // The oversized request is the one the budget has to drop, which
        // lands the cut exactly between it and its reply.
        cw.push(Message::assistant_with_calls("call", vec![call("c1")]));
        cw.messages[1].content = "x".repeat(1_800);
        cw.push(Message::tool("c1", "result one"));
        cw.push(Message::assistant_with_calls("call", vec![call("c2")]));
        cw.push(Message::tool("c2", "result two"));

        let out = cw.render("system");
        let transcript = &out[1..]; // past the system prompt
        assert!(
            !matches!(transcript.first().map(|m| m.role), Some(Role::Tool)),
            "window opens on an orphan reply"
        );
        assert_pairs_are_intact(transcript);
    }

    #[test]
    fn summarizing_drops_replies_whose_request_was_summarized_away() {
        let mut cw = ContextWindow::new(6_000, 1_000, 50);
        cw.push(Message::user("objective"));
        cw.push(Message::assistant_with_calls("call", vec![call("c1")]));
        cw.push(Message::tool("c1", &"r".repeat(400)));

        cw.apply_summary("earlier work, condensed".into());

        assert!(
            !matches!(cw.messages.first().map(|m| m.role), Some(Role::Tool)),
            "summary kept an orphan reply"
        );
        assert_pairs_are_intact(&cw.messages);
    }

    #[test]
    fn triggers_summary_only_when_over_threshold() {
        let mut cw = ContextWindow::new(6_000, 1_000, 300);
        assert!(!cw.needs_summary());
        for i in 0..60 {
            cw.push(Message::user(format!("{} {}", "x".repeat(60), i)));
        }
        assert!(cw.needs_summary(), "tokens={}", cw.tokens());
    }

    #[test]
    fn summary_shrinks_the_window() {
        let mut cw = ContextWindow::new(6_000, 500, 200);
        for i in 0..40 {
            cw.push(Message::user(format!("{} {}", "y".repeat(80), i)));
        }
        let before = cw.tokens();
        cw.apply_summary("discovered port 22 and 80 on 10.0.0.5".into());
        assert!(cw.tokens() < before);
        assert!(cw.summary().is_some());
        // summary is surfaced as a system message
        let rendered = cw.render("system prompt");
        assert!(rendered[0].content.contains("system prompt"));
        assert!(rendered.iter().any(|m| m.content.contains("Summary of earlier work")));
    }

    #[test]
    fn render_respects_budget() {
        let mut cw = ContextWindow::new(400, 10_000, 10_000);
        for i in 0..30 {
            cw.push(Message::user(format!("{} {}", "z".repeat(120), i)));
        }
        let rendered = cw.render("sys");
        let tokens: usize = rendered.iter().map(|m| m.estimate_tokens()).sum();
        assert!(tokens <= 400 + 50, "rendered {tokens} tokens, budget 400");
        assert!(rendered.len() >= 2, "system prompt must survive truncation");
    }

    #[test]
    fn clip_keeps_utf8_boundaries() {
        let s = "héllo wörld ".repeat(50);
        let clipped = ContextWindow::clip(&s, 20);
        assert!(clipped.len() <= 20 * 4 + 20);
        assert!(clipped.starts_with("[...truncated...]"));
        assert!(clipped.is_char_boundary(0));
    }

    #[test]
    fn summarization_prompt_contains_transcript() {
        let msgs = summarization_prompt(&[Message::user("found 10.0.0.5:22")]);
        assert_eq!(msgs.len(), 2);
        assert!(msgs[1].content.contains("10.0.0.5:22"));
    }
}
