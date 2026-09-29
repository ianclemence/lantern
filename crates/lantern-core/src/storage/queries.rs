//! Data access. Every statement is parameterised; no string interpolation of
//! user or model supplied values ever reaches SQL.

use super::models::*;
use super::{cosine, decode_embedding, encode_embedding, Db};
use crate::error::Result;
use crate::timeutil;
use rusqlite::{params, OptionalExtension, Row};

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Stats {
    pub flows: i64,
    pub running_flows: i64,
    pub tasks: i64,
    pub commands: i64,
    pub findings: i64,
    pub open_findings: i64,
    pub memory_rows: i64,
    pub events: i64,
    pub artifacts: i64,
    pub artifact_bytes: i64,
}

impl Db {
    fn one<T>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        map: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>> {
        self.with(|c| Ok(c.query_row(sql, params, map).optional()?))
    }

    // ---------------------------------------------------------------- flows

    pub fn create_flow(
        &self,
        id: &str,
        target: &str,
        scope: &str,
        options: &serde_json::Value,
    ) -> Result<Flow> {
        let now = timeutil::now();
        self.with(|c| {
            c.execute(
                "INSERT INTO flows (id, target, scope, status, options, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'created', ?4, ?5, ?5)",
                params![id, target, scope, options.to_string(), now],
            )?;
            Ok(())
        })?;
        self.get_flow(id)?.ok_or_else(|| crate::CoreError::Other("flow disappeared".into()))
    }

    fn flow_from_row(r: &Row<'_>) -> rusqlite::Result<Flow> {
        let opts: String = r.get(4)?;
        Ok(Flow {
            id: r.get(0)?,
            target: r.get(1)?,
            scope: r.get(2)?,
            status: r.get(3)?,
            options: serde_json::from_str(&opts).unwrap_or(serde_json::Value::Null),
            created_at: r.get(5)?,
            updated_at: r.get(6)?,
        })
    }

    pub fn get_flow(&self, id: &str) -> Result<Option<Flow>> {
        self.one(
            "SELECT id, target, scope, status, options, created_at, updated_at
             FROM flows WHERE id = ?1",
            params![id],
            Self::flow_from_row,
        )
    }

    pub fn list_flows(&self, limit: i64) -> Result<Vec<Flow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, target, scope, status, options, created_at, updated_at
                 FROM flows ORDER BY created_at DESC LIMIT ?1",
            )?;
            let rows = st.query_map(params![limit], Self::flow_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn set_flow_status(&self, id: &str, status: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE flows SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status, timeutil::now(), id],
            )?;
            Ok(())
        })
    }

    /// Record the counters the report quotes: model steps and tool
    /// invocations. They are merged into the flow's options, so whatever is
    /// already there (offensive, roles, dry_run) survives.
    pub fn set_flow_stats(&self, id: &str, steps: usize, tool_calls: usize) -> Result<()> {
        let mut options = self
            .get_flow(id)?
            .ok_or_else(|| crate::CoreError::Other(format!("no such flow: {id}")))?
            .options;
        if !options.is_object() {
            options = serde_json::json!({});
        }
        options["steps"] = serde_json::json!(steps);
        options["tool_calls"] = serde_json::json!(tool_calls);
        self.with(|c| {
            c.execute(
                "UPDATE flows SET options = ?1, updated_at = ?2 WHERE id = ?3",
                params![options.to_string(), timeutil::now(), id],
            )?;
            Ok(())
        })
    }

    // ---------------------------------------------------------------- tasks

    pub fn insert_task(
        &self,
        flow_id: &str,
        role: &str,
        kind: &str,
        input: &serde_json::Value,
    ) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO tasks (flow_id, role, kind, input, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'queued', ?5)",
                params![flow_id, role, kind, input.to_string(), timeutil::now()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn task_started(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE tasks SET status='running', started_at=?1, attempts=attempts+1 WHERE id=?2",
                params![timeutil::now(), id],
            )?;
            Ok(())
        })
    }

    pub fn task_finished(
        &self,
        id: i64,
        status: &str,
        output: Option<&serde_json::Value>,
        error: Option<&str>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE tasks SET status=?1, output=?2, error=?3, finished_at=?4 WHERE id=?5",
                params![
                    status,
                    output.map(|v| v.to_string()),
                    error,
                    timeutil::now(),
                    id
                ],
            )?;
            Ok(())
        })
    }

    fn task_from_row(r: &Row<'_>) -> rusqlite::Result<TaskRow> {
        let input: String = r.get(4)?;
        let output: Option<String> = r.get(5)?;
        Ok(TaskRow {
            id: r.get(0)?,
            flow_id: r.get(1)?,
            role: r.get(2)?,
            kind: r.get(3)?,
            input: serde_json::from_str(&input).unwrap_or(serde_json::Value::Null),
            output: output
                .and_then(|s| serde_json::from_str(&s).ok()),
            status: r.get(6)?,
            error: r.get(7)?,
            created_at: r.get(8)?,
            started_at: r.get(9)?,
            finished_at: r.get(10)?,
        })
    }

    pub fn tasks_for_flow(&self, flow_id: &str) -> Result<Vec<TaskRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, role, kind, input, output, status, error,
                        created_at, started_at, finished_at
                 FROM tasks WHERE flow_id = ?1 ORDER BY id",
            )?;
            let rows = st.query_map(params![flow_id], Self::task_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    // --------------------------------------------------------------- events

    pub fn add_event(
        &self,
        flow_id: Option<&str>,
        task_id: Option<i64>,
        level: &str,
        kind: &str,
        message: &str,
        data: Option<&serde_json::Value>,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO events (flow_id, task_id, ts, level, kind, message, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    flow_id,
                    task_id,
                    timeutil::now(),
                    level,
                    kind,
                    message,
                    data.map(|v| v.to_string())
                ],
            )?;
            Ok(())
        })
    }

    pub fn events_for_flow(&self, flow_id: &str) -> Result<Vec<EventRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, ts, level, kind, message FROM events
                 WHERE flow_id = ?1 ORDER BY id",
            )?;
            let rows = st.query_map(params![flow_id], |r| {
                Ok(EventRow {
                    id: r.get(0)?,
                    flow_id: r.get(1)?,
                    ts: r.get(2)?,
                    level: r.get(3)?,
                    kind: r.get(4)?,
                    message: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    // ------------------------------------------------------------- commands

    pub fn add_command(&self, c: &CommandRow) -> Result<i64> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO commands
                 (flow_id, ts, tool, binary, args, cwd, exit_code, timed_out, truncated,
                  bytes_out, duration_ms, stdout_path, stderr_path)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    c.flow_id,
                    c.ts,
                    c.tool,
                    c.binary,
                    serde_json::to_string(&c.args).unwrap_or_else(|_| "[]".into()),
                    c.cwd,
                    c.exit_code,
                    c.timed_out as i64,
                    c.truncated as i64,
                    c.bytes_out,
                    c.duration_ms,
                    c.stdout_path,
                    c.stderr_path
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    fn command_from_row(r: &Row<'_>) -> rusqlite::Result<CommandRow> {
        let args: String = r.get(5)?;
        Ok(CommandRow {
            id: r.get(0)?,
            flow_id: r.get(1)?,
            ts: r.get(2)?,
            tool: r.get(3)?,
            binary: r.get(4)?,
            args: serde_json::from_str(&args).unwrap_or_default(),
            cwd: r.get(6)?,
            exit_code: r.get(7)?,
            timed_out: r.get(8)?,
            truncated: r.get(9)?,
            bytes_out: r.get(10)?,
            duration_ms: r.get(11)?,
            stdout_path: r.get(12)?,
            stderr_path: r.get(13)?,
        })
    }

    pub fn commands_for_flow(&self, flow_id: &str) -> Result<Vec<CommandRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, ts, tool, binary, args, cwd, exit_code, timed_out,
                        truncated, bytes_out, duration_ms, stdout_path, stderr_path
                 FROM commands WHERE flow_id = ?1 ORDER BY id",
            )?;
            let rows = st.query_map(params![flow_id], Self::command_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    // ------------------------------------------------------------ findings

    pub fn add_finding(&self, flow_id: &str, f: &NewFinding) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO findings
                 (flow_id, ts, title, severity, asset, port, proto, description, evidence,
                  remediation, confidence, judge, status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'open')",
                params![
                    flow_id,
                    timeutil::now(),
                    f.title,
                    f.severity,
                    f.asset,
                    f.port,
                    f.proto,
                    f.description,
                    f.evidence,
                    f.remediation,
                    f.confidence,
                    f.judge
                ],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    fn finding_from_row(r: &Row<'_>) -> rusqlite::Result<Finding> {
        Ok(Finding {
            id: r.get(0)?,
            flow_id: r.get(1)?,
            ts: r.get(2)?,
            title: r.get(3)?,
            severity: r.get(4)?,
            asset: r.get(5)?,
            port: r.get(6)?,
            proto: r.get(7)?,
            description: r.get(8)?,
            evidence: r.get(9)?,
            remediation: r.get(10)?,
            confidence: r.get(11)?,
            judge: r.get(12)?,
            status: r.get(13)?,
        })
    }

    pub fn findings_for_flow(&self, flow_id: &str) -> Result<Vec<Finding>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, ts, title, severity, asset, port, proto, description,
                        evidence, remediation, confidence, judge, status
                 FROM findings WHERE flow_id = ?1
                 ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END, id",
            )?;
            let rows = st.query_map(params![flow_id], Self::finding_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn set_finding_status(&self, id: i64, status: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE findings SET status=?1 WHERE id=?2",
                params![status, id],
            )?;
            Ok(())
        })
    }

    /// Record the reflector's judgement (confidence 0..1 and judge label).
    pub fn judge_finding(&self, id: i64, judge: &str, confidence: f64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE findings SET judge=?1, confidence=?2 WHERE id=?3",
                params![judge, confidence.clamp(0.0, 1.0), id],
            )?;
            Ok(())
        })
    }

    // ----------------------------------------------------------- artifacts

    pub fn add_artifact(
        &self,
        flow_id: Option<&str>,
        kind: &str,
        path: &str,
        bytes: u64,
        expires_at: i64,
    ) -> Result<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO artifacts (flow_id, kind, path, bytes, created_at, expires_at, compressed)
                 VALUES (?1,?2,?3,?4,?5,?6,0)",
                params![flow_id, kind, path, bytes as i64, timeutil::now(), expires_at],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    fn artifact_from_row(r: &Row<'_>) -> rusqlite::Result<ArtifactRow> {
        Ok(ArtifactRow {
            id: r.get(0)?,
            flow_id: r.get(1)?,
            kind: r.get(2)?,
            path: r.get(3)?,
            bytes: r.get(4)?,
            created_at: r.get(5)?,
            expires_at: r.get(6)?,
            compressed: r.get::<_, i64>(7)? != 0,
        })
    }

    pub fn artifacts_expired(&self, before: i64) -> Result<Vec<ArtifactRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, kind, path, bytes, created_at, expires_at, compressed
                 FROM artifacts WHERE expires_at <= ?1 ORDER BY expires_at",
            )?;
            let rows = st.query_map(params![before], Self::artifact_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn all_artifacts(&self) -> Result<Vec<ArtifactRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, flow_id, kind, path, bytes, created_at, expires_at, compressed
                 FROM artifacts ORDER BY created_at",
            )?;
            let rows = st.query_map([], Self::artifact_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn update_artifact(&self, id: i64, path: &str, bytes: u64, compressed: bool) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE artifacts SET path=?1, bytes=?2, compressed=?3 WHERE id=?4",
                params![path, bytes as i64, compressed as i64, id],
            )?;
            Ok(())
        })
    }

    pub fn delete_artifact(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM artifacts WHERE id=?1", params![id])?;
            Ok(())
        })
    }

    // -------------------------------------------------------------- memory

    #[allow(clippy::too_many_arguments)]
    pub fn memory_add(
        &self,
        scope: &str,
        kind: &str,
        text: &str,
        embedding: Option<&[f32]>,
    ) -> Result<i64> {
        let blob = embedding.map(encode_embedding);
        self.with(|c| {
            c.execute(
                "INSERT INTO memory (scope, kind, text, embedding, hits, created_at)
                 VALUES (?1,?2,?3,?4,0,?5)",
                params![scope, kind, text, blob, timeutil::now()],
            )?;
            let id = c.last_insert_rowid();
            c.execute(
                "INSERT INTO memory_fts (rowid, text) VALUES (?1, ?2)",
                params![id, text],
            )?;
            Ok(id)
        })
    }

    fn memory_from_row(r: &Row<'_>) -> rusqlite::Result<MemoryRow> {
        Ok(MemoryRow {
            id: r.get(0)?,
            scope: r.get(1)?,
            kind: r.get(2)?,
            text: r.get(3)?,
            hits: r.get(4)?,
            created_at: r.get(5)?,
            score: None,
        })
    }

    /// Keyword (FTS5, `LIKE` fallback) search over memory.
    pub fn memory_keyword(&self, scope: &str, query: &str, limit: i64) -> Result<Vec<MemoryRow>> {
        let tokens: Vec<String> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 1)
            .map(|t| format!("\"{}\"", t.replace('"', "")))
            .collect();

        if !tokens.is_empty() {
            let match_expr = tokens.join(" OR ");
            let rows = self.with(|c| {
                let mut st = c.prepare(
                    "SELECT m.id, m.scope, m.kind, m.text, m.hits, m.created_at
                     FROM memory_fts f
                     JOIN memory m ON m.id = f.rowid
                     WHERE memory_fts MATCH ?1 AND (m.scope = ?2 OR m.scope = 'global')
                     ORDER BY rank LIMIT ?3",
                )?;
                let rows = st.query_map(params![match_expr, scope, limit], Self::memory_from_row)?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            });
            if let Ok(rows) = rows {
                if !rows.is_empty() {
                    return Ok(rows);
                }
            }
        }

        // FTS5 unavailable or no match: plain substring search (still bounded).
        let like = format!("%{}%", query.replace('%', "").replace('_', ""));
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, scope, kind, text, hits, created_at FROM memory
                 WHERE (scope = ?1 OR scope = 'global') AND text LIKE ?2
                 ORDER BY created_at DESC LIMIT ?3",
            )?;
            let rows = st.query_map(params![scope, like, limit], Self::memory_from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// Vector search over the same rows; returns cosine scores.
    pub fn memory_vector(
        &self,
        scope: &str,
        query_vec: &[f32],
        limit: i64,
    ) -> Result<Vec<MemoryRow>> {
        let mut rows = self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, scope, kind, text, hits, created_at, embedding
                 FROM memory WHERE scope = ?1 OR scope = 'global'",
            )?;
            let mut cur = st.query(params![scope])?;
            let mut out: Vec<(MemoryRow, Option<Vec<u8>>)> = Vec::new();
            while let Some(r) = cur.next()? {
                out.push((Self::memory_from_row(r)?, r.get::<_, Option<Vec<u8>>>(6)?));
            }
            Ok(out)
        })?;

        let mut scored: Vec<MemoryRow> = Vec::new();
        for (mut row, blob) in rows.drain(..) {
            if let Some(blob) = blob {
                if let Some(vec) = decode_embedding(&blob) {
                    let s = cosine(query_vec, &vec);
                    if s > 0.0 {
                        row.score = Some(f64::from(s));
                        scored.push(row);
                    }
                }
            }
        }
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(limit as usize);
        Ok(scored)
    }

    pub fn memory_touch(&self, id: i64) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE memory SET hits = hits + 1 WHERE id=?1", params![id])?;
            Ok(())
        })
    }

    pub fn memory_count(&self) -> Result<i64> {
        self.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM memory", [], |r| r.get(0))?))
    }

    pub fn memory_with_embeddings(&self) -> Result<i64> {
        self.with(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM memory WHERE embedding IS NOT NULL",
                [],
                |r| r.get(0),
            )?)
        })
    }

    // ------------------------------------------------------------ knowledge

    pub fn link(&self, src: &str, dst: &str, rel: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO knowledge (src, dst, rel, ts) VALUES (?1,?2,?3,?4)",
                params![src, dst, rel, timeutil::now()],
            )?;
            Ok(())
        })
    }

    pub fn links_from(&self, src: &str) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT dst, rel FROM knowledge WHERE src = ?1")?;
            let rows = st.query_map(params![src], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    // --------------------------------------------------------------- stats

    pub fn stats(&self) -> Result<Stats> {
        self.with(|c| {
            let mut s = Stats::default();
            s.flows = c.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))?;
            s.running_flows = c.query_row(
                "SELECT COUNT(*) FROM flows WHERE status IN ('created','running')",
                [],
                |r| r.get(0),
            )?;
            s.tasks = c.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0))?;
            s.commands = c.query_row("SELECT COUNT(*) FROM commands", [], |r| r.get(0))?;
            s.findings = c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
            s.open_findings = c.query_row(
                "SELECT COUNT(*) FROM findings WHERE status='open'",
                [],
                |r| r.get(0),
            )?;
            s.memory_rows = c.query_row("SELECT COUNT(*) FROM memory", [], |r| r.get(0))?;
            s.events = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            s.artifacts = c.query_row("SELECT COUNT(*) FROM artifacts", [], |r| r.get(0))?;
            s.artifact_bytes =
                c.query_row("SELECT COALESCE(SUM(bytes),0) FROM artifacts", [], |r| r.get(0))?;
            Ok(s)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Db;

    fn db(name: &str) -> Db {
        let dir = std::env::temp_dir().join(format!(
            "lantern-q-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("t.db")).expect("open")
    }

    #[test]
    fn flow_stats_merge_into_options() {
        let db = db("stats");
        db.create_flow(
            "flw_s",
            "example.com",
            "example.com",
            &serde_json::json!({"offensive": true}),
        )
        .unwrap();
        db.set_flow_stats("flw_s", 11, 15).unwrap();

        let f = db.get_flow("flw_s").unwrap().expect("flow");
        assert_eq!(f.options["steps"], 11);
        assert_eq!(f.options["tool_calls"], 15);
        assert_eq!(f.options["offensive"], true, "existing options survive");

        assert!(db.set_flow_stats("flw_missing", 1, 1).is_err());
    }

    #[test]
    fn flow_task_finding_lifecycle() {
        let db = db("lifecycle");
        let f = db
            .create_flow("flw_1", "192.168.0.107", "192.168.0.0/24", &serde_json::json!({}))
            .unwrap();
        assert_eq!(f.status, "created");

        let t = db.insert_task(&f.id, "planner", "recon", &serde_json::json!({"k": 1})).unwrap();
        db.task_started(t).unwrap();
        db.task_finished(t, "done", Some(&serde_json::json!({"ok": true})), None).unwrap();
        let tasks = db.tasks_for_flow(&f.id).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].status, "done");
        assert_eq!(tasks[0].output, Some(serde_json::json!({"ok": true})));

        let fid = db
            .add_finding(
                &f.id,
                &NewFinding {
                    title: "OpenSSH exposed".into(),
                    severity: "medium".into(),
                    asset: "192.168.0.107".into(),
                    port: Some(22),
                    proto: Some("tcp".into()),
                    description: "ssh on 22".into(),
                    evidence: Some("SSH-2.0-OpenSSH_8.9".into()),
                    remediation: None,
                    confidence: Some(0.8),
                    judge: Some("manual review".into()),
                },
            )
            .unwrap();
        assert!(fid > 0);
        let mut fs = db.findings_for_flow(&f.id).unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, "medium");

        // severity ordering
        db.add_finding(
            &f.id,
            &NewFinding {
                title: "critical".into(),
                severity: "critical".into(),
                asset: "x".into(),
                port: None,
                proto: None,
                description: String::new(),
                evidence: None,
                remediation: None,
                confidence: None,
                judge: None,
            },
        )
        .unwrap();
        fs = db.findings_for_flow(&f.id).unwrap();
        assert_eq!(fs[0].severity, "critical");

        db.set_flow_status(&f.id, "done").unwrap();
        assert_eq!(db.get_flow(&f.id).unwrap().unwrap().status, "done");
    }

    #[test]
    fn command_audit_is_recorded() {
        let db = db("audit");
        let f = db
            .create_flow("flw_2", "h", "h", &serde_json::json!({}))
            .unwrap();
        let id = db
            .add_command(&CommandRow {
                id: 0,
                flow_id: Some(f.id.clone()),
                ts: 0,
                tool: "port_scan".into(),
                binary: "lantern".into(),
                args: vec!["--help".into()],
                cwd: "/tmp".into(),
                exit_code: Some(0),
                timed_out: false,
                truncated: false,
                bytes_out: 12,
                duration_ms: 3,
                stdout_path: None,
                stderr_path: None,
            })
            .unwrap();
        assert!(id > 0);
        let rows = db.commands_for_flow(&f.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].args, vec!["--help"]);
        assert_eq!(rows[0].exit_code, Some(0));
    }

    #[test]
    fn memory_keyword_and_vector() {
        let db = db("memory");
        db.memory_add("global", "note", "nmap found port 22 open on host", None)
            .unwrap();
        let v = [1.0f32, 0.0, 0.0];
        db.memory_add("flow:1", "result", "http 404 on /admin", Some(&v)).unwrap();

        let hits = db.memory_keyword("flow:1", "port nmap", 10).unwrap();
        assert!(!hits.is_empty(), "FTS/LIKE fallback should match");

        let near = db.memory_vector("flow:1", &[1.0, 0.0, 0.0], 10).unwrap();
        assert_eq!(near.len(), 1);
        assert!(near[0].score.unwrap() > 0.99);

        let far = db.memory_vector("flow:1", &[0.0, 1.0, 0.0], 10).unwrap();
        assert!(far.is_empty());

        assert_eq!(db.memory_count().unwrap(), 2);
        assert_eq!(db.memory_with_embeddings().unwrap(), 1);
    }

    #[test]
    fn artifacts_expiry_query() {
        let db = db("artifacts");
        db.add_artifact(Some("flw_1"), "scan", "/tmp/a.txt", 10, 100).unwrap();
        db.add_artifact(Some("flw_1"), "scan", "/tmp/b.txt", 20, 1_000_000).unwrap();
        assert_eq!(db.artifacts_expired(500).unwrap().len(), 1);
        assert_eq!(db.all_artifacts().unwrap().len(), 2);
    }
}
