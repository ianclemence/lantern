//! Chat types and the provider trait.
//!
//! The trait returns boxed futures rather than using `async fn` in the trait so
//! that every provider future is `Send` and can be spawned onto the tokio
//! runtime without extra bounds.

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

/// A structured tool the model may request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    /// JSON-schema-ish object: `{"type":"object","properties":{...},"required":[...]}`
    pub parameters: serde_json::Value,
}

impl ToolDef {
    pub fn new(name: &str, description: &str, parameters: serde_json::Value) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            parameters,
        }
    }

    /// Wire form expected by OpenAI-compatible endpoints.
    pub fn wire(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

impl ToolCall {
    /// Parse the argument blob; a model that emits trailing prose still yields
    /// the JSON object it meant.
    pub fn args(&self) -> serde_json::Value {
        crate::util::extract_json(&self.arguments).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }
    }
    pub fn assistant_with_calls(content: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_call_id: None,
            tool_calls: calls,
        }
    }
    pub fn tool(call_id: &str, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            tool_call_id: Some(call_id.to_string()),
            tool_calls: Vec::new(),
        }
    }

    /// Rough token estimate. Deliberately conservative (bytes/4 is optimistic
    /// for code and tool output), so we over-reserve rather than overflow.
    pub fn estimate_tokens(&self) -> usize {
        let mut n = (self.content.len() + 3) / 4;
        for c in &self.tool_calls {
            n += (c.arguments.len() + 3) / 4 + 8;
        }
        n + 4
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: u32,
    pub temperature: f32,
    /// Ask for a JSON object body (sets `response_format` where supported).
    pub json_mode: bool,
}

impl ChatRequest {
    pub fn new(messages: Vec<Message>) -> Self {
        Self {
            messages,
            tools: Vec::new(),
            max_tokens: 2_000,
            temperature: 0.2,
            json_mode: false,
        }
    }

    pub fn with_tools(mut self, tools: Vec<ToolDef>) -> Self {
        self.tools = tools;
        self
    }

    pub fn json(mut self) -> Self {
        self.json_mode = true;
        self
    }

    pub fn max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = n;
        self
    }

    pub fn temperature(mut self, t: f32) -> Self {
        self.temperature = t;
        self
    }

    /// Rough size of the whole call: the messages *and* the tool schemas.
    /// Every endpoint bills the schemas on each request even though they never
    /// appear in the conversation, so leaving them out would understate a run
    /// by a few thousand tokens.
    pub fn estimate_tokens(&self) -> usize {
        let messages: usize = self.messages.iter().map(|m| m.estimate_tokens()).sum();
        let schemas: usize = self
            .tools
            .iter()
            .map(|t| (t.wire().to_string().len() + 3) / 4)
            .sum();
        messages + schemas
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatReply {
    pub message: Message,
    pub finish_reason: String,
    pub usage: Option<Usage>,
    pub model: String,
}

impl ChatReply {
    pub fn text(&self) -> &str {
        &self.message.content
    }
    pub fn has_tool_calls(&self) -> bool {
        !self.message.tool_calls.is_empty()
    }
}

/// Implemented by every generation backend.
pub trait ChatProvider: Send + Sync {
    fn name(&self) -> &str;
    fn chat<'a>(&'a self, request: ChatRequest) -> BoxFuture<'a, anyhow::Result<ChatReply>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_args_are_resilient() {
        let call = ToolCall {
            id: "1".into(),
            name: "port_scan".into(),
            arguments: "```json\n{\"host\":\"10.0.0.1\",\"ports\":\"1-100\"}\n```".into(),
        };
        assert_eq!(call.args()["host"], "10.0.0.1");
    }

    #[test]
    fn message_token_estimate_is_positive() {
        let m = Message::user("hello world");
        assert!(m.estimate_tokens() >= 4);
        let req = ChatRequest::new(vec![Message::system("abc"), m]);
        assert!(req.estimate_tokens() > 0);
    }

    #[test]
    fn the_estimate_counts_the_tool_schemas_too() {
        // Every endpoint bills the schemas on every request even though they
        // never appear in the conversation - on this build they are the
        // largest single part of a call, so leaving them out would understate
        // a run by a few thousand tokens.
        let messages = || vec![Message::system("abc"), Message::user("hello world")];
        let bare = ChatRequest::new(messages()).estimate_tokens();
        let with_tools = ChatRequest::new(messages())
            .with_tools(vec![
                ToolDef::new("port_scan", "scan a host", serde_json::json!({"type":"object"})),
                ToolDef::new("dns_lookup", "resolve names", serde_json::json!({"type":"object"})),
            ])
            .estimate_tokens();
        assert!(
            with_tools > bare,
            "schemas must count: {bare} tokens bare, {with_tools} with two tools"
        );
    }

    #[test]
    fn wire_form_of_tools() {
        let t = ToolDef::new("dns", "resolve", serde_json::json!({"type":"object"}));
        let w = t.wire();
        assert_eq!(w["type"], "function");
        assert_eq!(w["function"]["name"], "dns");
    }
}
