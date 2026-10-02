//! SQLite schema. Versioned with `PRAGMA user_version`.
//!
//! Design notes for this device:
//! - WAL + `synchronous=NORMAL` + `temp_store=MEMORY`: fewer SD-card writes.
//! - `auto_vacuum=INCREMENTAL` so we can reclaim space without a full rewrite.
//! - Embeddings live as little-endian f32 BLOBs; similarity is computed in Rust.
//! - FTS5 gives keyword search; it degrades to `LIKE` if unavailable.

pub const SCHEMA_VERSION: i64 = 3;

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id         TEXT PRIMARY KEY,
    target     TEXT NOT NULL,
    scope      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'created',
    options    TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    parent_id   INTEGER,
    role        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    input       TEXT NOT NULL DEFAULT '{}',
    output      TEXT,
    status      TEXT NOT NULL DEFAULT 'queued',
    attempts    INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tasks_flow ON tasks(flow_id, status);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT,
    task_id INTEGER,
    ts      INTEGER NOT NULL,
    level   TEXT NOT NULL,
    kind    TEXT NOT NULL,
    message TEXT NOT NULL,
    data    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_flow ON events(flow_id, ts);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     TEXT,
    ts          INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    binary      TEXT NOT NULL,
    args        TEXT NOT NULL,
    cwd         TEXT NOT NULL,
    exit_code   INTEGER,
    timed_out   INTEGER NOT NULL DEFAULT 0,
    truncated   INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    stdout_path TEXT,
    stderr_path TEXT,
    -- DNS A/AAAA records resolved for the target immediately before this
    -- command ran, as a JSON string array. Lets a post-hoc review catch a
    -- hostname that resolved to something other than what the operator
    -- scoped (DNS drift / rebinding) between scope declaration and execution.
    -- NULL for targets that were already IP literals or CIDR ranges, which
    -- need no resolution.
    resolved_ips TEXT
);
CREATE INDEX IF NOT EXISTS idx_commands_flow ON commands(flow_id, ts);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    asset       TEXT NOT NULL,
    port        INTEGER,
    proto       TEXT,
    description TEXT NOT NULL DEFAULT '',
    evidence    TEXT,
    remediation TEXT,
    confidence  REAL,
    judge       TEXT,
    status      TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_findings_flow ON findings(flow_id, severity);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     TEXT,
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    bytes       INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    compressed  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_artifacts_expiry ON artifacts(expires_at);

CREATE TABLE IF NOT EXISTS memory (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scope     TEXT NOT NULL DEFAULT 'global',
    kind      TEXT NOT NULL,
    text      TEXT NOT NULL,
    embedding BLOB,
    hits      INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_scope ON memory(scope);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    text,
    tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS knowledge (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    rel TEXT NOT NULL,
    ts  INTEGER NOT NULL,
    PRIMARY KEY (src, dst, rel)
);

-- `lantern daemon`'s work queue: one row per flow the operator scheduled to
-- run unattended. The daemon polls for 'pending' rows, claims one at a time
-- (never concurrently - the same single-connection-behind-a-mutex reasoning
-- as the rest of this database), and runs it through the exact same
-- `run_flow` path `lantern run` uses.
CREATE TABLE IF NOT EXISTS queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    scope       TEXT NOT NULL,
    roles       TEXT,
    offensive   INTEGER NOT NULL DEFAULT 0,
    dry_run     INTEGER NOT NULL DEFAULT 0,
    steps       INTEGER,
    status      TEXT NOT NULL DEFAULT 'pending',
    flow_id     TEXT,
    error       TEXT,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(status, created_at);
"#;

pub const PRAGMAS: &[(&str, &str)] = &[
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("auto_vacuum", "INCREMENTAL"),
    ("foreign_keys", "ON"),
    ("temp_store", "MEMORY"),
    ("busy_timeout", "5000"),
];
