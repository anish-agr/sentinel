use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable namespace so a run id can be derived from (repo, session) without
/// keeping state anywhere.
const RUN_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x1c, 0x4a, 0x2e, 0x9b, 0x74, 0x4d, 0x3a, 0xb6, 0x05, 0x1e, 0xd8, 0x7c, 0x33, 0x90, 0x21,
]);

pub fn run_id(repo: &str, session: &str) -> Uuid {
    Uuid::new_v5(&RUN_NAMESPACE, format!("{repo}\u{0}{session}").as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ToolCall,
    ToolResult,
    FileMutation,
    TestResult,
    Process,
    Checkpoint,
    AgentMessage,
    Detection,
    GuardDecision,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::ToolCall => "tool_call",
            EventKind::ToolResult => "tool_result",
            EventKind::FileMutation => "file_mutation",
            EventKind::TestResult => "test_result",
            EventKind::Process => "process",
            EventKind::Checkpoint => "checkpoint",
            EventKind::AgentMessage => "agent_message",
            EventKind::Detection => "detection",
            EventKind::GuardDecision => "guard_decision",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Tokens {
    #[serde(rename = "in")]
    pub input: u64,
    #[serde(rename = "out")]
    pub output: u64,
    #[serde(default)]
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffStats {
    pub added: u64,
    pub removed: u64,
}

/// One line of the append-only log. Full payloads (diffs, stderr, raw args) live
/// in the blob store; only their hashes appear here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub run_id: Uuid,
    pub step: u64,
    pub ts: DateTime<Utc>,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_norm_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Tokens>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_touched: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_stats: Option<DiffStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_state_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_vector_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    /// Kind-specific detail (guard verdicts, detector findings). Additive slot so
    /// the fields above stay exactly as specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl Event {
    pub fn new(run_id: Uuid, step: u64, kind: EventKind) -> Self {
        Event {
            run_id,
            step,
            ts: Utc::now(),
            kind,
            tool: None,
            args_hash: None,
            args_summary: None,
            exit_code: None,
            stderr_norm_hash: None,
            duration_ms: None,
            tokens: None,
            files_touched: Vec::new(),
            diff_stats: None,
            repo_state_hash: None,
            test_vector_hash: None,
            checkpoint_id: None,
            meta: None,
        }
    }

    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    pub fn args(mut self, hash: impl Into<String>, summary: impl Into<String>) -> Self {
        self.args_hash = Some(hash.into());
        self.args_summary = Some(summary.into());
        self
    }

    pub fn meta(mut self, meta: serde_json::Value) -> Self {
        self.meta = Some(meta);
        self
    }

    pub fn files(mut self, files: Vec<String>) -> Self {
        self.files_touched = files;
        self
    }
}

/// Payload carried on `guard_decision` events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDecisionMeta {
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// Payload carried on `detection` events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMeta {
    pub detector: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_steps: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Event {
        Event::new(run_id("/repo", "sess-1"), 42, EventKind::ToolCall)
            .tool("bash")
            .args("a".repeat(64), "cargo test")
            .files(vec!["src/lib.rs".into()])
            .meta(serde_json::json!({"k": 1}))
    }

    #[test]
    fn round_trips_through_json() {
        let ev = sample();
        let line = serde_json::to_string(&ev).unwrap();
        assert!(!line.contains('\n'));
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn omits_empty_optionals() {
        let ev = Event::new(Uuid::nil(), 0, EventKind::Checkpoint);
        let line = serde_json::to_string(&ev).unwrap();
        assert!(!line.contains("args_hash"));
        assert!(!line.contains("files_touched"));
        assert!(line.contains("\"kind\":\"checkpoint\""));
    }

    #[test]
    fn accepts_minimal_line() {
        let line = r#"{"run_id":"00000000-0000-0000-0000-000000000000","step":1,"ts":"2026-01-01T00:00:00Z","kind":"tool_result"}"#;
        let ev: Event = serde_json::from_str(line).unwrap();
        assert_eq!(ev.kind, EventKind::ToolResult);
        assert!(ev.tool.is_none());
    }

    #[test]
    fn tokens_use_spec_field_names() {
        let t = Tokens {
            input: 10,
            output: 20,
            cost_usd: 0.5,
        };
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(s, r#"{"in":10,"out":20,"cost_usd":0.5}"#);
    }

    #[test]
    fn run_id_is_stable_and_scoped_to_repo() {
        assert_eq!(run_id("/a", "s"), run_id("/a", "s"));
        assert_ne!(run_id("/a", "s"), run_id("/b", "s"));
        assert_ne!(run_id("/a", "s"), run_id("/a", "t"));
    }
}
