//! Anthropic Messages client.
//!
//! Same trait as `openai_compat`, different wire shape: system messages move to
//! a top-level `system` field, tool results become `tool_result` blocks inside a
//! user turn, tool calls come back as `tool_use` blocks whose `input` is a JSON
//! object rather than a string. Consecutive turns of the same role are merged
//! because the endpoint requires strict alternation.

use crate::provider::{BoxFuture, ChatProvider, ChatReply, Message, Role, ToolCall, Usage};
use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct Anthropic {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
    name: String,
    retries: u32,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    system: Vec<String>,
    messages: Vec<WireTurn>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<serde_json::Value>,
    stream: bool,
}

/// One role turn. `blocks` holds the content pieces that turn carries.
#[derive(Serialize)]
struct WireTurn {
    role: String,
    content: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct WireResponse {
    model: Option<String>,
    #[serde(default)]
    content: Vec<WireBlock>,
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct WireBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    id: Option<String>,
    name: Option<String>,
    input: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

/// The argument blob a `tool_use` block expects as an object: parsed JSON when
/// it parses, otherwise the raw text kept under a key so nothing is lost.
fn input_object(raw: &str) -> serde_json::Value {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(_)) => serde_json::from_str(raw).unwrap_or(json_empty()),
        Ok(serde_json::Value::Null) => json_empty(),
        Ok(other) => serde_json::json!({ "value": other }),
        Err(_) => serde_json::json!({ "_raw": raw }),
    }
}

fn json_empty() -> serde_json::Value {
    serde_json::json!({})
}

/// Build the request body. Pure so the shape is testable without a network.
/// Only the model name is borrowed; everything else is copied in.
fn build_body<'a>(
    model: &'a str,
    messages: &[Message],
    tools: &[crate::provider::ToolDef],
    max_tokens: u32,
    temperature: f32,
    json_mode: bool,
) -> WireRequest<'a> {
    let mut system: Vec<String> = Vec::new();
    let mut turns: Vec<WireTurn> = Vec::new();

    // Consecutive turns of one role must arrive as a single turn here.
    let mut push = |role: &str, blocks: Vec<serde_json::Value>| {
        if blocks.is_empty() {
            return;
        }
        match turns.last_mut() {
            Some(last) if last.role == role => last.content.extend(blocks),
            _ => turns.push(WireTurn {
                role: role.to_string(),
                content: blocks,
            }),
        }
    };

    for m in messages {
        match m.role {
            Role::System => {
                if !m.content.trim().is_empty() {
                    system.push(m.content.clone());
                }
            }
            Role::User => push(
                "user",
                (!m.content.is_empty())
                    .then(|| serde_json::json!({ "type": "text", "text": m.content }))
                    .into_iter()
                    .collect(),
            ),
            Role::Tool => {
                let id = m.tool_call_id.clone().unwrap_or_default();
                push(
                    "user",
                    vec![serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": m.content,
                    })],
                );
            }
            Role::Assistant => {
                let mut blocks = Vec::new();
                if !m.content.is_empty() {
                    blocks.push(serde_json::json!({ "type": "text", "text": m.content }));
                }
                for c in &m.tool_calls {
                    blocks.push(serde_json::json!({
                        "type": "tool_use",
                        "id": c.id,
                        "name": c.name,
                        "input": input_object(&c.arguments),
                    }));
                }
                push("assistant", blocks);
            }
        }
    }

    // The endpoint opens on a user turn; a transcript that starts with an
    // assistant line gets a short one so the request is well formed.
    if turns.first().map(|t| t.role.as_str()) == Some("assistant") {
        turns.insert(
            0,
            WireTurn {
                role: "user".into(),
                content: vec![serde_json::json!({ "type": "text", "text": "Continue." })],
            },
        );
    }

    if json_mode {
        system.push(
            "Respond with a single JSON object and nothing else: no prose, no code fence."
                .to_string(),
        );
    }

    WireRequest {
        model,
        max_tokens,
        temperature,
        system,
        messages: turns,
        tools: tools.iter().map(|t| t.wire()).collect(),
        stream: false,
    }
}

impl Anthropic {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let base = base_url.into().trim_end_matches('/').to_string();
        let model = model.into();
        let name = format!("anthropic:{base}");
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("lantern/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building http client")?;
        Ok(Self {
            client,
            base_url: base,
            model,
            api_key: api_key.into(),
            name,
            retries: 2,
        })
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// `{base}/v1/messages`, tolerating a base that already ends in `/v1`.
    fn url(&self) -> String {
        if self.base_url.ends_with("/v1") {
            format!("{}/messages", self.base_url)
        } else {
            format!("{}/v1/messages", self.base_url)
        }
    }

    async fn post(&self, body: &WireRequest<'_>) -> anyhow::Result<WireResponse> {
        let url = self.url();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let resp = self
                .client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                return serde_json::from_str(&text)
                    .with_context(|| format!("decoding message from {}", self.base_url));
            }

            let retryable = status.as_u16() == 429
                || status.is_server_error()
                || status.as_u16() == 402 /* quota blip */;
            if retryable && attempt <= self.retries {
                let delay = Duration::from_millis(400 * u64::from(attempt) * u64::from(attempt));
                tracing::warn!(
                    attempt,
                    status = %status,
                    delay_ms = delay.as_millis() as u64,
                    "anthropic request failed, retrying"
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            // Never echo the key; the body may quote request metadata only.
            let snippet: String = text.chars().take(400).collect();
            bail!("anthropic http {status}: {snippet}");
        }
    }
}

impl ChatProvider for Anthropic {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat<'a>(
        &'a self,
        request: crate::provider::ChatRequest,
    ) -> BoxFuture<'a, anyhow::Result<ChatReply>> {
        Box::pin(async move {
            let body = build_body(
                &self.model,
                &request.messages,
                &request.tools,
                request.max_tokens,
                request.temperature,
                request.json_mode,
            );

            let resp: WireResponse = self.post(&body).await?;

            let mut text = String::new();
            let mut calls = Vec::new();
            for block in resp.content {
                match block.kind.as_str() {
                    "text" => text.push_str(block.text.as_deref().unwrap_or_default()),
                    "tool_use" => {
                        calls.push(ToolCall {
                            id: block.id.unwrap_or_default(),
                            name: block.name.unwrap_or_default(),
                            arguments: block
                                .input
                                .unwrap_or(serde_json::json!({}))
                                .to_string(),
                        });
                    }
                    _ => {}
                }
            }
            if text.is_empty() && calls.is_empty() {
                return Err(anyhow!("anthropic returned no content"));
            }

            let finish_reason = match resp.stop_reason.as_deref() {
                Some("tool_use") => "tool_calls".to_string(),
                Some("max_tokens") => "length".to_string(),
                Some(other) => other.to_string(),
                None if !calls.is_empty() => "tool_calls".to_string(),
                None => "stop".to_string(),
            };

            Ok(ChatReply {
                message: Message {
                    role: Role::Assistant,
                    content: text,
                    tool_call_id: None,
                    tool_calls: calls,
                },
                finish_reason,
                usage: resp.usage.map(|u| Usage {
                    input_tokens: u.input_tokens.unwrap_or_default(),
                    output_tokens: u.output_tokens.unwrap_or_default(),
                }),
                model: resp.model.unwrap_or_else(|| self.model.clone()),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ChatRequest, ToolDef};

    fn req(messages: Vec<Message>) -> WireRequest<'static> {
        build_body("claude-test", &messages, &[], 1_000, 0.2, false)
    }

    #[test]
    fn system_turns_move_to_the_top_level_system_field() {
        let body = req(vec![
            Message::system("be brief"),
            Message::user("hello"),
            Message::assistant("hi"),
        ]);
        assert_eq!(body.system, vec!["be brief".to_string()]);
        let roles: Vec<&str> = body.messages.iter().map(|t| t.role.as_str()).collect();
        assert_eq!(roles, ["user", "assistant"], "system is not a message turn");
    }

    #[test]
    fn tool_results_become_one_user_turn_and_alternation_holds() {
        let body = req(vec![
            Message::system("s"),
            Message::user("scan"),
            Message::assistant_with_calls(
                "scanning",
                vec![
                    ToolCall {
                        id: "c1".into(),
                        name: "dns".into(),
                        arguments: "{\"host\":\"x\"}".into(),
                    },
                    ToolCall {
                        id: "c2".into(),
                        name: "tcp".into(),
                        arguments: "{\"port\":80}".into(),
                    },
                ],
            ),
            Message::tool("c1", "10.0.0.5"),
            Message::tool("c2", "80/tcp open"),
            Message::user("what now?"),
        ]);
        let roles: Vec<&str> = body.messages.iter().map(|t| t.role.as_str()).collect();
        // consecutive user turns arrive as one: results first, then the question
        assert_eq!(roles, ["user", "assistant", "user"]);
        let blocks = &body.messages[2].content;
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["type"], "tool_result");
        assert_eq!(blocks[0]["tool_use_id"], "c1");
        assert_eq!(blocks[0]["content"], "10.0.0.5");
        assert_eq!(blocks[1]["tool_use_id"], "c2");
        assert_eq!(blocks[1]["content"], "80/tcp open");
        assert_eq!(blocks[2]["type"], "text");
        assert_eq!(blocks[2]["text"], "what now?");
    }

    #[test]
    fn assistant_tool_calls_carry_a_json_object_input() {
        let body = req(vec![
            Message::user("scan"),
            Message::assistant_with_calls(
                "on it",
                vec![
                    ToolCall {
                        id: "c1".into(),
                        name: "dns".into(),
                        arguments: "{\"host\":\"x\"}".into(),
                    },
                    ToolCall {
                        id: "c2".into(),
                        name: "odd".into(),
                        arguments: "not json at all".into(),
                    },
                ],
            ),
        ]);
        let blocks = &body.messages[1].content;
        assert_eq!(blocks[1]["type"], "tool_use");
        assert_eq!(blocks[1]["input"]["host"], "x");
        assert_eq!(blocks[1]["id"], "c1");
        // unparseable arguments are preserved rather than dropped
        assert_eq!(blocks[2]["input"]["_raw"], "not json at all");
    }

    #[test]
    fn a_transcript_that_opens_with_the_assistant_gets_a_user_turn_first() {
        let body = req(vec![Message::assistant("already talking")]);
        assert_eq!(body.messages[0].role, "user");
        assert_eq!(body.messages[1].role, "assistant");
        assert_eq!(body.messages[1].content[0]["text"], "already talking");
    }

    #[test]
    fn empty_turns_are_dropped_not_sent() {
        let body = req(vec![
            Message::user(""),
            Message::assistant(""),
            Message::user("real question"),
        ]);
        assert_eq!(body.messages.len(), 1);
        assert_eq!(body.messages[0].content[0]["text"], "real question");
    }

    #[test]
    fn json_mode_adds_the_instruction_to_the_system_field() {
        let msgs = vec![Message::system("s"), Message::user("q")];
        let tools = vec![ToolDef::new("t", "d", serde_json::json!({}))];
        let body = build_body("claude-test", &msgs, &tools, 500, 0.1, true);
        assert_eq!(body.system.len(), 2);
        assert!(body.system[1].contains("JSON object"));
        assert_eq!(body.tools.len(), 1);
        assert_eq!(body.tools[0]["type"], "function");
    }

    #[test]
    fn url_ends_in_v1_messages() {
        let a = Anthropic::new("https://api.anthropic.com", "m", "k", Duration::from_secs(1))
            .unwrap();
        assert_eq!(a.url(), "https://api.anthropic.com/v1/messages");
        let b = Anthropic::new("https://proxy.local/v1/", "m", "k", Duration::from_secs(1)).unwrap();
        assert_eq!(b.url(), "https://proxy.local/v1/messages");
    }

    #[test]
    fn a_reply_decodes_text_tool_use_and_usage() {
        let raw = r#"{
            "model": "claude-test",
            "content": [
                {"type": "text", "text": "running scan\n"},
                {"type": "tool_use", "id": "toolu_1", "name": "nmap", "input": {"target": "10.0.0.5"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 120, "output_tokens": 34}
        }"#;
        let parsed: WireResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.content.len(), 2);
        let replies = Anthropic::new("https://api.anthropic.com", "m", "k", Duration::from_secs(1))
            .unwrap();
        assert_eq!(replies.url(), "https://api.anthropic.com/v1/messages");

        // decode exactly what `chat` does
        let mut text = String::new();
        let mut calls = Vec::new();
        for block in parsed.content {
            match block.kind.as_str() {
                "text" => text.push_str(block.text.as_deref().unwrap_or_default()),
                "tool_use" => calls.push(ToolCall {
                    id: block.id.unwrap_or_default(),
                    name: block.name.unwrap_or_default(),
                    arguments: block.input.unwrap_or_default().to_string(),
                }),
                _ => {}
            }
        }
        assert_eq!(text, "running scan\n");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args()["target"], "10.0.0.5");
        assert_eq!(
            parsed.usage.unwrap().input_tokens,
            Some(120),
            "usage arrives as input/output tokens"
        );
        assert_eq!(parsed.stop_reason.as_deref(), Some("tool_use"));
    }

    #[test]
    fn builds_without_network() {
        let c = Anthropic::new(
            "https://example.invalid",
            "claude-test",
            "sk-test",
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(c.name(), "anthropic:https://example.invalid");
        let req = ChatRequest::new(vec![Message::user("hi")]).max_tokens(16);
        assert!(req.estimate_tokens() > 0);
    }
}
