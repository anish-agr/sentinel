use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use sentinel_events::Event;
use serde::Serialize;
use std::path::Path;
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
  seq             INTEGER PRIMARY KEY,
  run_id          TEXT NOT NULL,
  step            INTEGER NOT NULL,
  ts              TEXT NOT NULL,
  kind            TEXT NOT NULL,
  tool            TEXT,
  args_summary    TEXT,
  exit_code       INTEGER,
  duration_ms     INTEGER,
  tokens_in       INTEGER NOT NULL DEFAULT 0,
  tokens_out      INTEGER NOT NULL DEFAULT 0,
  cost_usd        REAL    NOT NULL DEFAULT 0,
  repo_state_hash TEXT,
  checkpoint_id   TEXT,
  stderr_norm_hash TEXT,
  files_touched   TEXT NOT NULL DEFAULT '[]',
  raw             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_run  ON events(run_id, step);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS events_state ON events(repo_state_hash);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"#;

#[derive(Debug, Clone, Serialize)]
pub struct RunRow {
    pub run_id: String,
    pub started: String,
    pub ended: String,
    pub events: u64,
    pub steps: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd: f64,
    pub checkpoints: u64,
    pub blocks: u64,
}

/// SQLite index over the event log. Purely derived — `rebuild` drops and
/// replays every line, which is the recovery path if it is ever corrupted.
pub struct Index {
    conn: Connection,
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        // The CLI opens this database while the daemon is writing to it. Without
        // a busy timeout, a command blocks forever the moment they overlap.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        // Switching journal mode needs an exclusive lock, so only do it when the
        // database is not already in WAL.
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Index { conn })
    }

    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn insert(&self, ev: &Event) -> Result<i64> {
        let tokens = ev.tokens.unwrap_or_default();
        self.conn.execute(
            "INSERT INTO events (run_id, step, ts, kind, tool, args_summary, exit_code, duration_ms,
                                 tokens_in, tokens_out, cost_usd, repo_state_hash, checkpoint_id,
                                 stderr_norm_hash, files_touched, raw)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                ev.run_id.to_string(),
                ev.step as i64,
                ev.ts.to_rfc3339(),
                ev.kind.as_str(),
                ev.tool,
                ev.args_summary,
                ev.exit_code,
                ev.duration_ms.map(|d| d as i64),
                tokens.input as i64,
                tokens.output as i64,
                tokens.cost_usd,
                ev.repo_state_hash,
                ev.checkpoint_id,
                ev.stderr_norm_hash,
                serde_json::to_string(&ev.files_touched)?,
                serde_json::to_string(ev)?,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn clear(&self) -> Result<()> {
        self.conn.execute("DELETE FROM events", [])?;
        self.conn
            .execute("DELETE FROM sqlite_sequence WHERE name='events'", [])
            .ok();
        Ok(())
    }

    pub fn next_step(&self, run: Uuid) -> Result<u64> {
        let s: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(step), 0) FROM events WHERE run_id = ?1",
            params![run.to_string()],
            |r| r.get(0),
        )?;
        Ok(s as u64 + 1)
    }

    pub fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn runs(&self) -> Result<Vec<RunRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id, MIN(ts), MAX(ts), COUNT(*), COALESCE(MAX(step),0),
                    SUM(tokens_in), SUM(tokens_out), SUM(cost_usd),
                    SUM(kind = 'checkpoint'), SUM(kind = 'guard_decision')
             FROM events GROUP BY run_id ORDER BY MIN(ts) DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RunRow {
                run_id: r.get(0)?,
                started: r.get(1)?,
                ended: r.get(2)?,
                events: r.get::<_, i64>(3)? as u64,
                steps: r.get::<_, i64>(4)? as u64,
                tokens_in: r.get::<_, i64>(5)? as u64,
                tokens_out: r.get::<_, i64>(6)? as u64,
                cost_usd: r.get(7)?,
                checkpoints: r.get::<_, i64>(8)? as u64,
                blocks: r.get::<_, i64>(9)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Raw event JSON with its sequence number, ready to hand to the UI.
    pub fn events_json(&self, run: Option<Uuid>, limit: u32) -> Result<Vec<serde_json::Value>> {
        let (sql, args): (&str, Vec<String>) = match run {
            Some(r) => (
                "SELECT seq, raw FROM events WHERE run_id = ?1 ORDER BY seq LIMIT ?2",
                vec![r.to_string(), limit.to_string()],
            ),
            None => (
                "SELECT seq, raw FROM events ORDER BY seq DESC LIMIT ?1",
                vec![limit.to_string()],
            ),
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, raw) = row?;
            let mut v: serde_json::Value = serde_json::from_str(&raw)?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("seq".into(), seq.into());
            }
            out.push(v);
        }
        // The unfiltered query takes the newest rows first so that a limit
        // returns the latest activity; callers always want them in order.
        if run.is_none() {
            out.reverse();
        }
        Ok(out)
    }

    pub fn load(&self, run: Uuid) -> Result<Vec<Event>> {
        let mut stmt = self
            .conn
            .prepare("SELECT raw FROM events WHERE run_id = ?1 ORDER BY seq")?;
        let rows = stmt.query_map(params![run.to_string()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(serde_json::from_str(&raw?)?);
        }
        Ok(out)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
