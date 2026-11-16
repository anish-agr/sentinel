use crate::state::{lock, Daemon, RepoState};
use anyhow::Result;
use sentinel_events::{run_id, Event, EventKind, GuardDecisionMeta};
use sentinel_guard::{evaluate, Action, Ctx, Shell, Verdict};
use sentinel_store::cas::sha256_hex;
use sentinel_store::{checkpoint, scrub, Store};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const MUTATING_TOOLS: &[&str] = &[
    "bash",
    "powershell",
    "write",
    "edit",
    "notebookedit",
    "multiedit",
];

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

pub fn tool_action<'a>(tool: &str, input: &'a Value) -> Action<'a> {
    match tool.to_ascii_lowercase().as_str() {
        "bash" => Action::Shell {
            command: field(input, "command").unwrap_or_default(),
            shell: Shell::Posix,
        },
        "powershell" => Action::Shell {
            command: field(input, "command").unwrap_or_default(),
            shell: Shell::PowerShell,
        },
        "write" | "edit" | "multiedit" | "notebookedit" => Action::Write {
            path: field(input, "file_path")
                .or_else(|| field(input, "notebook_path"))
                .unwrap_or_default(),
        },
        _ => Action::Other,
    }
}

/// A one-line description of what the tool was asked to do.
fn describe(tool: &str, input: &Value) -> String {
    let text = match tool.to_ascii_lowercase().as_str() {
        "bash" | "powershell" => field(input, "command").unwrap_or("").to_string(),
        "write" | "edit" | "multiedit" => field(input, "file_path").unwrap_or("").to_string(),
        "read" => field(input, "file_path").unwrap_or("").to_string(),
        "glob" | "grep" => format!(
            "{} {}",
            field(input, "pattern").unwrap_or(""),
            field(input, "path").unwrap_or("")
        ),
        "webfetch" => field(input, "url").unwrap_or("").to_string(),
        _ => input.to_string(),
    };
    scrub::summary(text.trim())
}

fn touched_files(input: &Value, repo: &Path) -> Vec<String> {
    ["file_path", "notebook_path", "path"]
        .iter()
        .filter_map(|k| field(input, k))
        .map(|p| relative(repo, p))
        .collect()
}

fn relative(repo: &Path, path: &str) -> String {
    let p = PathBuf::from(path);
    p.strip_prefix(repo)
        .unwrap_or(&p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn guard_ctx(repo: &Arc<RepoState>, cwd: &Path) -> Ctx {
    let git = repo.git();
    let mut ctx = Ctx::new(repo.root.clone());
    ctx.cwd = cwd.to_path_buf();
    ctx.branch = git.branch;
    ctx.dirty = git.dirty;
    ctx.untracked = git.untracked;
    ctx.config = repo.guard_config();
    ctx
}

fn allow() -> Value {
    json!({"decision": "allow"})
}

/// Handles one PreToolUse/PostToolUse payload. Any error here degrades to
/// "allow": Sentinel failing must never stop the user's session.
pub fn handle(daemon: &Daemon, phase: &str, payload: &Value) -> Value {
    match try_handle(daemon, phase, payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sentinel: hook handling failed, allowing: {e:#}");
            allow()
        }
    }
}

fn try_handle(daemon: &Daemon, phase: &str, payload: &Value) -> Result<Value> {
    let cwd = field(payload, "cwd")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    let Some(root) = checkpoint::find_repo_root(&cwd) else {
        return Ok(allow());
    };
    if !Store::is_enrolled(&root) {
        return Ok(allow());
    }

    let repo = daemon.repo(&root)?;
    repo.mark_hook();
    let session = field(payload, "session_id").unwrap_or("unknown-session");
    let run = run_id(&root.to_string_lossy(), session);
    let tool = field(payload, "tool_name").unwrap_or("unknown").to_string();
    let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);

    let summary = describe(&tool, &input);
    let args_hash = sha256_hex(input.to_string().as_bytes());
    let files = touched_files(&input, &root);

    // The session ended: capture the last of the transcript and report on the
    // run as a whole.
    if phase == "stop" {
        let mut store = lock(&repo.store);
        if let Some(path) = field(payload, "transcript_path") {
            record_agent_turns(daemon, run, path, &mut store).ok();
        }
        drop(store);
        crate::state::run_detectors(&repo, run).ok();

        let mut store = lock(&repo.store);
        let events = store.load_run(run)?;
        for detection in sentinel_detect::session_end(&events) {
            let step = store.next_step(run)?;
            let ev = Event::new(run, step, EventKind::Detection)
                .tool(detection.meta.detector.clone())
                .meta(serde_json::to_value(&detection.meta)?);
            store.append(&ev)?;
        }
        return Ok(allow());
    }

    if phase == "pre" {
        let ctx = guard_ctx(&repo, &cwd);
        let decision = evaluate(&tool_action(&tool, &input), &ctx);

        let mut store = lock(&repo.store);
        store.cas.put(input.to_string().as_bytes()).ok();
        let step = store.next_step(run)?;
        let mut ev = Event::new(run, step, EventKind::ToolCall)
            .tool(tool.clone())
            .args(args_hash, summary.clone())
            .files(files);
        if let Some(mode) = field(payload, "permission_mode") {
            ev.meta = Some(json!({"permission_mode": mode}));
        }
        store.append(&ev)?;

        let overridden = decision.is_blocking()
            && decision
                .fingerprint
                .as_deref()
                .is_some_and(|fp| crate::oneshot::consume(&root, fp));

        if decision.verdict != Verdict::Allow || decision.allowlisted {
            let meta = GuardDecisionMeta {
                verdict: if decision.allowlisted {
                    "allowlisted".into()
                } else if overridden {
                    "overridden".into()
                } else {
                    format!("{:?}", decision.verdict).to_lowercase()
                },
                rule: decision.rule.map(String::from),
                reason: decision.reason.clone(),
                command: Some(summary.clone()),
            };
            let step = store.next_step(run)?;
            let ev = Event::new(run, step, EventKind::GuardDecision)
                .tool(tool)
                .args(decision.fingerprint.clone().unwrap_or_default(), summary)
                .meta(serde_json::to_value(&meta)?);
            store.append(&ev)?;
        }
        drop(store);

        repo.mark_call_start(run);

        if decision.is_blocking() && !overridden {
            return Ok(json!({
                "decision": "deny",
                "rule": decision.rule,
                "reason": decision.reason,
                "fingerprint": decision.fingerprint,
            }));
        }
        return Ok(allow());
    }

    // PostToolUse
    let response = payload.get("tool_response").cloned().unwrap_or(Value::Null);
    let (exit_code, stderr) = response_outcome(&response);
    let response_hash = (!response.is_null()).then(|| sha256_hex(response.to_string().as_bytes()));

    let mut store = lock(&repo.store);
    let step = store.next_step(run)?;
    let mut ev = Event::new(run, step, EventKind::ToolResult)
        .tool(tool.clone())
        .args(args_hash, summary)
        .files(files);
    ev.exit_code = exit_code;
    ev.duration_ms = repo.take_call_duration(run);
    if let Some(hash) = response_hash {
        store.cas.put(response.to_string().as_bytes()).ok();
        ev.meta = Some(json!({ "response_hash": hash }));
    }
    if let Some(err) = stderr.filter(|s| !s.trim().is_empty()) {
        let normalized = sentinel_detect::normalize_stderr(&err);
        ev.stderr_norm_hash = Some(sha256_hex(normalized.as_bytes()));
        store.cas.put(err.as_bytes()).ok();
    }
    store.append(&ev)?;

    if let Some(command) = command_text(&input) {
        if sentinel_detect::is_test_command(command) {
            if let Some(hash) = response_text(&response)
                .as_deref()
                .and_then(sentinel_detect::test_vector_hash)
            {
                let step = store.next_step(run)?;
                let mut test_ev = Event::new(run, step, EventKind::TestResult).tool(tool.clone());
                test_ev.test_vector_hash = Some(hash);
                test_ev.exit_code = exit_code;
                store.append(&test_ev)?;
            }
        }
    }

    if let Some(path) = field(payload, "transcript_path") {
        record_agent_turns(daemon, run, path, &mut store).ok();
    }
    drop(store);

    if MUTATING_TOOLS.contains(&tool.to_ascii_lowercase().as_str()) {
        daemon.queue_checkpoint(Arc::clone(&repo), run);
    }

    // Detections are fed back to the agent as context rather than only drawn on
    // the timeline. Telling it that it has hit the same error three times is the
    // one intervention that can end a loop without blocking anything.
    let findings = crate::state::run_detectors(&repo, run).unwrap_or_default();
    if findings.is_empty() {
        return Ok(allow());
    }
    Ok(json!({
        "decision": "allow",
        "context": format!("Sentinel observed:\n- {}", findings.join("\n- ")),
    }))
}

/// Appends any agent turns written since we last looked. This is where token
/// counts come from: hook payloads carry none.
fn record_agent_turns(
    daemon: &Daemon,
    run: uuid::Uuid,
    path: &str,
    store: &mut sentinel_store::Store,
) -> Result<()> {
    // Persisted, not held in memory: an in-memory offset resets when the daemon
    // restarts, and the whole transcript is then re-read and re-emitted.
    let key = format!("transcript:{path}");
    let offset = store
        .index()
        .get_meta(&key)?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (turns, new_offset) = crate::transcript::read_since(Path::new(path), offset)?;
    store.index().set_meta(&key, &new_offset.to_string())?;

    for turn in turns {
        let step = store.next_step(run)?;
        let mut ev = Event::new(run, step, EventKind::AgentMessage)
            .args(sha256_hex(turn.text.as_bytes()), scrub::summary(&turn.text));
        ev.tool = turn.model.clone();
        ev.tokens = Some(sentinel_events::Tokens {
            input: turn.usage.total_input(),
            output: turn.usage.output_tokens,
            cost_usd: daemon.pricing.cost(turn.model.as_deref(), &turn.usage),
        });
        if !turn.text.trim().is_empty() {
            store.cas.put(turn.text.as_bytes()).ok();
        }
        store.append(&ev)?;
    }
    Ok(())
}

/// Claude Code's shell result is `{stdout, stderr, interrupted, isImage}` and
/// carries no exit code at all, so a null one is expected rather than a parse
/// failure. Other tiers may supply one, so we still read it where it exists.
fn command_text(input: &Value) -> Option<&str> {
    field(input, "command")
}

fn response_text(response: &Value) -> Option<String> {
    if let Some(s) = response.as_str() {
        return Some(s.to_string());
    }
    let pick = |key: &str| response.get(key).and_then(Value::as_str).unwrap_or("");
    let joined = ["stdout", "stderr", "output", "content", "result"]
        .iter()
        .map(|k| pick(k))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    (!joined.is_empty()).then_some(joined)
}

fn response_outcome(response: &Value) -> (Option<i64>, Option<String>) {
    let code = response
        .get("exit_code")
        .or_else(|| response.get("exitCode"))
        .and_then(Value::as_i64)
        .or_else(|| {
            response
                .get("is_error")
                .or_else(|| response.get("isError"))
                .and_then(Value::as_bool)
                .map(i64::from)
        })
        .or_else(|| {
            response
                .get("interrupted")
                .and_then(Value::as_bool)
                .filter(|i| *i)
                .map(|_| 130)
        });
    let stderr = response
        .get("stderr")
        .and_then(Value::as_str)
        .map(str::to_string);
    (code, stderr)
}

pub fn timing_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_and_powershell_map_to_their_own_shells() {
        let input = json!({"command": "rm -rf /"});
        assert!(matches!(
            tool_action("Bash", &input),
            Action::Shell {
                shell: Shell::Posix,
                ..
            }
        ));
        assert!(matches!(
            tool_action("PowerShell", &input),
            Action::Shell {
                shell: Shell::PowerShell,
                ..
            }
        ));
    }

    #[test]
    fn edit_tools_are_treated_as_writes() {
        let input = json!({"file_path": "/repo/.env"});
        assert!(
            matches!(tool_action("Edit", &input), Action::Write { path } if path == "/repo/.env")
        );
        assert!(matches!(tool_action("Write", &input), Action::Write { .. }));
        assert!(matches!(tool_action("Read", &input), Action::Other));
    }

    #[test]
    fn summaries_are_scrubbed_and_bounded() {
        let input = json!({"command": "deploy --token=ghp_abcdefghijklmnopqrstuvwxyz012345"});
        let s = describe("Bash", &input);
        assert!(s.contains("<redacted>"), "{s}");
        assert!(!s.contains("ghp_abcdefghij"));
        assert!(s.chars().count() <= 200);
    }

    #[test]
    fn outcomes_are_read_from_several_response_shapes() {
        assert_eq!(response_outcome(&json!({"exit_code": 2})).0, Some(2));
        assert_eq!(response_outcome(&json!({"exitCode": 3})).0, Some(3));
        assert_eq!(response_outcome(&json!({"is_error": true})).0, Some(1));
        assert_eq!(response_outcome(&Value::Null).0, None);
        // The real Claude Code shell result shape: no exit code, but stderr.
        let real =
            json!({"stdout": "ok", "stderr": "warn", "interrupted": false, "isImage": false});
        assert_eq!(response_outcome(&real), (None, Some("warn".into())));
        assert_eq!(response_outcome(&json!({"interrupted": true})).0, Some(130));
        assert_eq!(
            response_outcome(&json!({"stderr": "boom"})).1.as_deref(),
            Some("boom")
        );
    }

    #[test]
    fn paths_are_recorded_relative_to_the_repo() {
        let repo = PathBuf::from("/repo");
        assert_eq!(relative(&repo, "/repo/src/main.rs"), "src/main.rs");
        assert_eq!(relative(&repo, "src/main.rs"), "src/main.rs");
    }
}
