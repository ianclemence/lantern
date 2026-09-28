//! Model clients: an OpenAI-compatible chat provider, a typed structured
//! judgement client, and an embedding client with an explicit disabled state.
//!
//! Credentials come from the environment and are never written to disk.

pub mod context;
pub mod embed;
pub mod jev;
pub mod mock;
pub mod openai_compat;
pub mod provider;
pub mod util;

pub use context::ContextWindow;
pub use embed::{Embedder, OllamaEmbedder};
pub use jev::{Answer, JevClient, JevResponse, Question};
pub use mock::MockProvider;
pub use openai_compat::OpenAiCompat;
pub use provider::{
    BoxFuture, ChatProvider, ChatReply, Message, Role, ToolCall, ToolDef, Usage,
};
