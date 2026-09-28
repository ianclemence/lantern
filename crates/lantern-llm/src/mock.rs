//! Scripted provider for tests and `--dry-run`.
//!
//! The agent loop must be verifiable without spending API credits: this provider
//! replays a fixed sequence of replies (text, tool calls, or failures).

use crate::provider::{
    BoxFuture, ChatProvider, ChatReply, Message, Role, ToolCall, Usage,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub enum Scripted {
    /// Plain assistant text.
    Text(String),
    /// Assistant requests one tool call.
    ToolCall { name: String, arguments: String },
    /// Assistant requests several tool calls at once.
    ToolCalls(Vec<(String, String)>),
    /// Provider failure (exercises retry/abort paths).
    Fail(String),
}

pub struct MockProvider {
    script: Mutex<VecDeque<Scripted>>,
    fallback: Scripted,
    pub calls: AtomicUsize,
    name: String,
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            script: Mutex::new(VecDeque::new()),
            fallback: Scripted::Text("{}".into()),
            calls: AtomicUsize::new(0),
            name: "mock".into(),
        }
    }

    pub fn with_script(script: Vec<Scripted>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            fallback: Scripted::Text("{}".into()),
            calls: AtomicUsize::new(0),
            name: "mock".into(),
        }
    }

    /// Ends with a JSON object reply, useful for structured steps.
    pub fn ending_with_json(json: &str) -> Self {
        Self::with_script(vec![Scripted::Text(json.to_string())])
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatProvider for MockProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat<'a>(&'a self, request: crate::provider::ChatRequest) -> BoxFuture<'a, anyhow::Result<ChatReply>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let next = {
                let mut s = self.script.lock().expect("script lock");
                s.pop_front().unwrap_or_else(|| self.fallback.clone())
            };
            match next {
                Scripted::Fail(msg) => Err(anyhow::anyhow!(msg)),
                Scripted::Text(t) => Ok(ChatReply {
                    message: Message {
                        role: Role::Assistant,
                        content: t,
                        tool_call_id: None,
                        tool_calls: Vec::new(),
                    },
                    finish_reason: "stop".into(),
                    usage: Some(Usage {
                        input_tokens: request.estimate_tokens() as u64,
                        output_tokens: 8,
                    }),
                    model: "mock".into(),
                }),
                Scripted::ToolCall { name, arguments } => Ok(ChatReply {
                    message: Message::assistant_with_calls(
                        "",
                        vec![ToolCall {
                            id: format!("call_{}", self.calls.load(Ordering::Relaxed)),
                            name,
                            arguments,
                        }],
                    ),
                    finish_reason: "tool_calls".into(),
                    usage: None,
                    model: "mock".into(),
                }),
                Scripted::ToolCalls(calls) => Ok(ChatReply {
                    message: Message::assistant_with_calls(
                        "",
                        calls
                            .into_iter()
                            .enumerate()
                            .map(|(i, (name, arguments))| ToolCall {
                                id: format!("call_{i}"),
                                name,
                                arguments,
                            })
                            .collect(),
                    ),
                    finish_reason: "tool_calls".into(),
                    usage: None,
                    model: "mock".into(),
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ChatRequest;

    #[tokio::test]
    async fn replays_script_then_falls_back() {
        let p = MockProvider::with_script(vec![
            Scripted::ToolCall { name: "dns".into(), arguments: "{\"host\":\"x\"}".into() },
            Scripted::Text("done".into()),
        ]);
        let r1 = p.chat(ChatRequest::new(vec![Message::user("go")])).await.unwrap();
        assert!(r1.has_tool_calls());
        assert_eq!(r1.message.tool_calls[0].name, "dns");

        let r2 = p.chat(ChatRequest::new(vec![Message::user("go")])).await.unwrap();
        assert_eq!(r2.text(), "done");

        let r3 = p.chat(ChatRequest::new(vec![Message::user("go")])).await.unwrap();
        assert_eq!(r3.text(), "{}");
        assert_eq!(p.call_count(), 3);
    }

    #[tokio::test]
    async fn failure_is_reported() {
        let p = MockProvider::with_script(vec![Scripted::Fail("quota".into())]);
        let err = p.chat(ChatRequest::new(vec![])).await.unwrap_err();
        assert!(err.to_string().contains("quota"));
    }
}
