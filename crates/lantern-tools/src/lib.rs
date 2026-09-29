//! Native tool implementations plus a sandboxed host-exec layer.
//!
//! Everything runs directly on the host, so isolation comes from:
//! an executable allowlist, a cleared environment, a restricted PATH, a new
//! session per child, rlimits (CPU/AS/FSIZE/NOFILE/NPROC/CORE), wall-clock
//! timeouts, output caps, per-flow working directories and full audit logging.

pub mod ctx;
pub mod exec;
pub mod memory;
pub mod registry;
pub mod tools;

pub use ctx::ToolCtx;
pub use exec::{ExecOutcome, ExecRequest};
pub use memory::Memory;
pub use registry::{Registry, Tool, ToolOutput};
