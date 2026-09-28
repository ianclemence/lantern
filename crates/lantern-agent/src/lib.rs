//! Lantern agent runtime: roles, prompts, cross-role memory, the tool-calling
//! loop, structured judgement and deterministic reporting.
//!
//! The crate has no HTTP server and no threads of its own - everything runs on
//! the caller's tokio runtime so the device stays responsive.

pub mod ctx;
pub mod findings;
pub mod memory;
pub mod prompts;
pub mod report;
pub mod roles;
pub mod runtime;

pub use ctx::AgentCtx;
pub use roles::RoleId;
pub use runtime::{run_flow, FlowOptions, FlowOutcome, RoleOutcome};
