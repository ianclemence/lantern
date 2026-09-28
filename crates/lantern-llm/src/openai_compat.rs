//! OpenAI-compatible chat client (DeepSeek is the default endpoint; any
//! compatible base URL works). Reads the key from memory only.

use crate::provider::{
    BoxFuture, ChatProvider, ChatReply, Message, Role, ToolCall, Usage,
};
use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OpenAiCompat {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
    name: String,
    retries: u32,
}

#[derive(Serialize)]
struct WireMessage<'a> {
    role: &'a str,
    content: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<WireToolCall<'a>>,
}

#[derive(Serialize)]
struct WireToolCall<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    function: WireFunction<'a>,
}

#[derive(Serialize)]
struct WireFunction<'a> {
    name: &'a str,
    arguments: &'a str,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: Vec<WireMessage<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<serde_json::Value>,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<serde_json::Value>,
    stream: bool,
}

#[derive(Deserialize)]
struct WireResponse {
    model: Option<String>,
    choices: Vec<WireChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct WireChoice {
    finish_reason: Option<String>,
    message: WireAssistant,
}

#[derive(Deserialize)]
struct WireAssistant {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<WireCallOut>>,
}

#[derive(Deserialize)]
struct WireCallOut {
    id: String,
    function: WireFunctionOut,
}

#[derive(Deserialize)]
struct WireFunctionOut {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

impl OpenAiCompat {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let base = base_url.into().trim_end_matches('/').to_string();
        let model = model.into();
        let name = format!("openai-compat:{base}");
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

    fn wire_messages(messages: &[Message]) -> Vec<WireMessage<'_>> {
        messages
            .iter()
            .map(|m| WireMessage {
                role: m.role.as_str(),
                content: &m.content,
                tool_call_id: m.tool_call_id.as_deref(),
                tool_calls: m
                    .tool_calls
                    .iter()
                    .map(|c| WireToolCall {
                        id: &c.id,
                        kind: "function",
                        function: WireFunction {
                            name: &c.name,
                            arguments: &c.arguments,
                        },
                    })
                    .collect(),
            })
            .collect()
    }

    async fn post(&self, body: &WireRequest<'_>) -> anyhow::Result<WireResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&self.api_key)
                .json(body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                return serde_json::from_str(&text)
                    .with_context(|| format!("decoding chat completion from {}", self.base_url));
            }

            let retryable = status.as_u16() == 429
                || status.is_server_error()
                || status.as_u16() == 402 /* provider-specific quota blip */;
            if retryable && attempt <= self.retries {
                let delay = Duration::from_millis(400 * u64::from(attempt) * u64::from(attempt));
                tracing::warn!(
                    attempt,
                    status = %status,
                    delay_ms = delay.as_millis() as u64,
                    "llm request failed, retrying"
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            // Never echo the key; the body may quote request metadata only.
            let snippet: String = text.chars().take(400).collect();
            bail!("llm http {status}: {snippet}");
        }
    }
}

impl ChatProvider for OpenAiCompat {
    fn name(&self) -> &str {
        &self.name
    }

    fn chat<'a>(&'a self, request: crate::provider::ChatRequest) -> BoxFuture<'a, anyhow::Result<ChatReply>> {
        Box::pin(async move {
            let tools: Vec<serde_json::Value> = request.tools.iter().map(|t| t.wire()).collect();
            let body = WireRequest {
                model: &self.model,
                messages: Self::wire_messages(&request.messages),
                tools,
                max_tokens: request.max_tokens,
                temperature: request.temperature,
                response_format: request
                    .json_mode
                    .then(|| serde_json::json!({"type": "json_object"})),
                stream: false,
            };

            let resp: WireResponse = self.post(&body).await?;
            let Some(choice) = resp.choices.into_iter().next() else {
                return Err(anyhow!("llm returned no choices"));
            };

            let calls = choice
                .message
                .tool_calls
                .unwrap_or_default()
                .into_iter()
                .map(|c| ToolCall {
                    id: c.id,
                    name: c.function.name,
                    arguments: c.function.arguments,
                })
                .collect();

            let message = Message {
                role: Role::Assistant,
                content: choice.message.content.unwrap_or_default(),
                tool_call_id: None,
                tool_calls: calls,
            };

            Ok(ChatReply {
                message,
                finish_reason: choice.finish_reason.unwrap_or_else(|| "stop".into()),
                usage: resp.usage.map(|u| Usage {
                    input_tokens: u.prompt_tokens,
                    output_tokens: u.completion_tokens,
                }),
                model: resp.model.unwrap_or_else(|| self.model.clone()),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_carries_tool_calls() {
        let msgs = vec![
            Message::system("s"),
            Message::assistant_with_calls(
                "calling",
                vec![ToolCall {
                    id: "c1".into(),
                    name: "dns".into(),
                    arguments: "{\"host\":\"x\"}".into(),
                }],
            ),
            Message::tool("c1", "93.184.216.34"),
        ];
        let wire = OpenAiCompat::wire_messages(&msgs);
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"tool_calls\""));
        assert!(json.contains("tool_call_id"));
        assert!(json.contains("93.184.216.34"));
        assert!(!json.contains("null"));
    }

    #[test]
    fn builds_without_network() {
        let c = OpenAiCompat::new(
            "https://example.invalid",
            "deepseek-flash",
            "key",
            Duration::from_secs(5),
        );
        assert!(c.is_ok());
        assert_eq!(c.unwrap().name, "openai-compat:https://example.invalid");
    }
}
