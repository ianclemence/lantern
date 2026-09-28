//! Storage: a single SQLite database in WAL mode behind a mutex.
//!
//! One connection is deliberate: it keeps the resident set small on an 8 GB
//! host and WAL still lets readers proceed while a writer holds the lock.

pub mod models;
pub mod queries;
pub mod schema;

use crate::error::{CoreError, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CoreError::io(parent.display().to_string(), e))?;
        }
        let conn = Connection::open(path)?;

        // PRAGMA journal_mode and busy_timeout return a row, so they cannot go
        // through execute_batch (which rejects statements that produce results).
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.query_row("PRAGMA busy_timeout=5000", [], |_| Ok(()))?;
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL;
             PRAGMA auto_vacuum=INCREMENTAL;
             PRAGMA foreign_keys=ON;
             PRAGMA temp_store=MEMORY;",
        )?;

        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < schema::SCHEMA_VERSION {
            conn.execute_batch(schema::DDL)?;
            conn.execute_batch(&format!("PRAGMA user_version={}", schema::SCHEMA_VERSION))?;
            tracing::info!(version = schema::SCHEMA_VERSION, "database schema initialized");
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run a closure with exclusive access to the connection.
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| CoreError::Other("database lock poisoned".into()))?;
        f(&guard)
    }

    /// Convenience for infallible closures.
    pub fn with_ok<T>(&self, f: impl FnOnce(&Connection) -> T) -> Result<T> {
        self.with(|c| Ok(f(c)))
    }

    pub fn file_size(&self) -> u64 {
        self.with_ok(|_| 0).unwrap_or(0);
        std::fs::metadata(self.path())
            .map(|m| m.len())
            .unwrap_or(0)
    }

    pub fn path(&self) -> std::path::PathBuf {
        self.with_ok(|c| {
            c.path()
                .map(std::path::PathBuf::from)
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    /// Reclaim free pages in place (cheap) rather than rewriting the file.
    pub fn incremental_vacuum(&self) -> Result<()> {
        self.with(|c| {
            // Returns no rows; `execute` is the correct rusqlite entry point.
            c.execute("PRAGMA incremental_vacuum", [])?;
            Ok(())
        })
    }

    /// Full rewrite; only invoked when free disk is critically low.
    pub fn full_vacuum(&self) -> Result<()> {
        self.with(|c| {
            c.execute_batch("VACUUM;")?;
            Ok(())
        })
    }

    pub fn integrity_ok(&self) -> Result<bool> {
        self.with(|c| {
            let v: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            Ok(v == "ok")
        })
    }
}

/// Little-endian f32 blob encoding for embeddings.
pub fn encode_embedding(values: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 4);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

pub fn decode_embedding(blob: &[u8]) -> Option<Vec<f32>> {
    if blob.len() % 4 != 0 || blob.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(blob.len() / 4);
    for chunk in blob.chunks_exact(4) {
        out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Some(out)
}

/// Cosine similarity in [-1, 1]. Returns 0.0 for zero vectors or a length mismatch.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_roundtrip() {
        let v = vec![0.1f32, -2.5, 3.75, 0.0];
        let blob = encode_embedding(&v);
        assert_eq!(blob.len(), 16);
        let back = decode_embedding(&blob).unwrap();
        for (x, y) in v.iter().zip(back.iter()) {
            assert!((x - y).abs() < 1e-6);
        }
        assert!(decode_embedding(&[0, 1, 2]).is_none());
    }

    #[test]
    fn cosine_behaves() {
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        assert_eq!(cosine(&[1.0, 0.0], &[1.0, 0.0, 0.0]), 0.0);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn opens_and_migrates() {
        let dir = std::env::temp_dir().join(format!(
            "lantern-db-{}-migrate",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Db::open(&dir.join("t.db")).unwrap();
        assert!(db.integrity_ok().unwrap());
        // second open is a no-op migration
        drop(db);
        let db2 = Db::open(&dir.join("t.db")).unwrap();
        assert!(db2.integrity_ok().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
