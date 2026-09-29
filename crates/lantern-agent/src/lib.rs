//! Lantern agent runtime: roles, prompts, the tool-calling loop, review and
//! deterministic reporting. Cross-role memory lives in `lantern-tools` so
//! prompts and the memory tools read one store.
//!
//! The crate has no HTTP server and no threads of its own - everything runs on
//! the caller's tokio runtime so the device stays responsive.

pub mod ctx;
pub mod findings;
pub mod prompts;
pub mod provider;
pub mod report;
pub mod roles;
pub mod runtime;

pub use ctx::AgentCtx;
pub use provider::provider_for;
pub use roles::RoleId;
pub use runtime::{run_flow, FlowOptions, FlowOutcome, RoleOutcome};
