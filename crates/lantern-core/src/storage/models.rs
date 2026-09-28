//! Row types. Serde derives double as API/CLI output formatting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    pub target: String,
    pub scope: String,
    pub status: String,
    pub options: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRow {
    pub id: i64,
    pub flow_id: String,
    pub role: String,
    pub kind: String,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub status: String,
    pub error: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRow {
    pub id: i64,
    pub flow_id: Option<String>,
    pub ts: i64,
    pub tool: String,
    pub binary: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub bytes_out: i64,
    pub duration_ms: i64,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub flow_id: String,
    pub ts: i64,
    pub title: String,
    /// info | low | medium | high | critical
    pub severity: String,
    pub asset: String,
    pub port: Option<i64>,
    pub proto: Option<String>,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub confidence: Option<f64>,
    pub judge: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFinding {
    pub title: String,
    pub severity: String,
    pub asset: String,
    pub port: Option<i64>,
    pub proto: Option<String>,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub confidence: Option<f64>,
    pub judge: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRow {
    pub id: i64,
    pub flow_id: Option<String>,
    pub kind: String,
    pub path: String,
    pub bytes: i64,
    pub created_at: i64,
    pub expires_at: i64,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRow {
    pub id: i64,
    pub scope: String,
    pub kind: String,
    pub text: String,
    pub hits: i64,
    pub created_at: i64,
    /// cosine score when returned by vector search
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub id: i64,
    pub flow_id: Option<String>,
    pub ts: i64,
    pub level: String,
    pub kind: String,
    pub message: String,
}
