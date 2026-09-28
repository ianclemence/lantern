//! Native tool implementations plus a sandboxed host-exec layer.
//!
//! There is no container runtime on this host, so isolation comes from:
//! an executable allowlist, a cleared environment, a restricted PATH, a new
//! session per child, rlimits (CPU/AS/FSIZE/NOFILE/NPROC/CORE), wall-clock
//! timeouts, output caps, per-flow working directories and full audit logging.

pub mod ctx;
pub mod exec;
pub mod registry;
pub mod tools;

pub use ctx::ToolCtx;
pub use exec::{ExecOutcome, ExecRequest};
pub use registry::{Registry, Tool, ToolOutput};
