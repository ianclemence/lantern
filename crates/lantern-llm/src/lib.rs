//! Model clients: the chat providers and an embedding client with an
//! explicit disabled state.
//!
//! Credentials reach these clients in memory only: nothing here writes a key
//! anywhere.

pub mod anthropic;
pub mod context;
pub mod embed;
pub mod mock;
pub mod openai_compat;
pub mod provider;
pub mod util;

pub use anthropic::Anthropic;
pub use context::ContextWindow;
pub use embed::{Embedder, OllamaEmbedder};
pub use mock::MockProvider;
pub use openai_compat::OpenAiCompat;
pub use provider::{
    BoxFuture, ChatProvider, ChatReply, Message, Role, ToolCall, ToolDef, Usage,
};
