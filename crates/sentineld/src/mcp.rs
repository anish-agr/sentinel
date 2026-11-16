use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONSULT_TIMEOUT: Duration = Duration::from_millis(400);

/// Maps an arbitrary MCP tool call onto the normalized vocabulary the daemon
/// understands. Unknown tools pass through under their own name and are simply
/// recorded.
pub fn classify(name: &str, args: &Value) -> (String, Value) {
    for key in ["command", "cmd", "script", "shell_command"] {
        if let Some(cmd) = args.get(key).and_then(Value::as_str) {
            return ("Bash".into(), json!({ "command": cmd }));
        }
    }
    let lower = name.to_ascii_lowercase();
    if ["write", "edit", "create", "delete", "remove", "move"]
        .iter()
        .any(|v| lower.contains(v))
    {
        for key in ["file_path", "path", "filename", "target_file"] {
            if let Some(path) = args.get(key).and_then(Value::as_str) {
                return ("Write".into(), json!({ "file_path": path }));
            }
        }
    }
    (name.to_string(), args.clone())
}

/// The result text of a tools/call response, for the post-event record.
fn response_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// What to do with one request line headed for the server.
pub enum Verdict {
    Forward,
    /// Reply on the runtime's behalf instead of forwarding: the JSON-RPC
    /// response carrying the refusal.
    Refuse(Value),
}

pub struct Proxy<F: Fn(&str, &Value) -> Value> {
    session: String,
    cwd: String,
    /// Sends a phase + payload to the daemon and returns its decision.
    /// Injected so the pure logic is testable without a daemon.
    consult: F,
    pending: Mutex<HashMap<String, (String, Value)>>,
}

impl<F: Fn(&str, &Value) -> Value> Proxy<F> {
    pub fn new(session: String, cwd: String, consult: F) -> Self {
        Proxy {
            session,
            cwd,
            consult,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn payload(&self, tool: &str, input: &Value, response: Option<Value>) -> Value {
        let mut p = json!({
            "session_id": self.session,
            "cwd": self.cwd,
            "tool_name": tool,
            "tool_input": input,
        });
        if let Some(r) = response {
            p["tool_response"] = r;
        }
        p
    }

    pub fn on_request(&self, line: &str) -> Verdict {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return Verdict::Forward;
        };
        if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
            return Verdict::Forward;
        }
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let (tool, input) = classify(name, &args);

        let decision = (self.consult)("pre", &self.payload(&tool, &input, None));
        if decision.get("decision").and_then(Value::as_str) == Some("deny") {
            let reason = decision
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("blocked");
            let rule = decision
                .get("rule")
                .and_then(Value::as_str)
                .unwrap_or("guard");
            return Verdict::Refuse(json!({
                "jsonrpc": "2.0",
                "id": msg.get("id").cloned().unwrap_or(Value::Null),
                "result": {
                    "content": [{
                        "type": "text",
                        "text": format!("Sentinel blocked this: {reason} [rule: {rule}]. If this was intended, the user can run `sentinel allow --last` and you may retry.")
                    }],
                    "isError": true
                }
            }));
        }
        if let Some(id) = msg.get("id") {
            lock(&self.pending).insert(id.to_string(), (tool, input));
        }
        Verdict::Forward
    }

    pub fn on_response(&self, line: &str) {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let Some(id) = msg.get("id") else { return };
        let Some((tool, input)) = lock(&self.pending).remove(&id.to_string()) else {
            return;
        };
        let result = msg.get("result").cloned().unwrap_or(Value::Null);
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || msg.get("error").is_some();
        let response = json!({
            "stdout": response_text(&result),
            "stderr": if is_error { response_text(&result) } else { String::new() },
            "is_error": is_error,
        });
        (self.consult)("post", &self.payload(&tool, &input, Some(response)));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Consults the daemon; any failure at all is "allow" — the proxy must never
/// break a session the daemon cannot see.
fn consult_daemon(phase: &str, payload: &Value) -> Value {
    let allow = json!({"decision": "allow"});
    let Some(info) = crate::read_info() else {
        return allow;
    };
    let body = json!({"phase": phase, "payload": payload}).to_string();
    match crate::request(
        info.port,
        &info.token,
        "POST",
        "/hook",
        Some(&body),
        CONSULT_TIMEOUT,
    ) {
        Ok(text) => serde_json::from_str(&text).unwrap_or(allow),
        Err(_) => allow,
    }
}

/// Runs the proxy until the wrapped server exits; returns its exit code.
pub fn run(target: &[String]) -> Result<i32> {
    if target.is_empty() {
        bail!("usage: sentinel mcp -- <real MCP server command>");
    }
    let mut child = Command::new(&target[0])
        .args(&target[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", target[0]))?;

    let cwd = std::env::current_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let proxy = Arc::new(Proxy::new(
        format!("mcp-{}", child.id()),
        cwd,
        consult_daemon,
    ));
    let out = Arc::new(Mutex::new(std::io::stdout()));

    let mut child_in = child.stdin.take().context("child stdin")?;
    let child_out = child.stdout.take().context("child stdout")?;

    let reader = {
        let proxy = Arc::clone(&proxy);
        let out = Arc::clone(&out);
        std::thread::spawn(move || {
            for line in BufReader::new(child_out).lines().map_while(Result::ok) {
                proxy.on_response(&line);
                let mut o = lock(&out);
                let _ = writeln!(o, "{line}");
                let _ = o.flush();
            }
        })
    };

    let stdin = std::io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        match proxy.on_request(&line) {
            Verdict::Forward => {
                if writeln!(child_in, "{line}")
                    .and_then(|()| child_in.flush())
                    .is_err()
                {
                    break;
                }
            }
            Verdict::Refuse(reply) => {
                let mut o = lock(&out);
                let _ = writeln!(o, "{reply}");
                let _ = o.flush();
            }
        }
    }
    drop(child_in);
    let status = child.wait()?;
    let _ = reader.join();
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_rm(phase: &str, payload: &Value) -> Value {
        assert!(matches!(phase, "pre" | "post"));
        let cmd = payload["tool_input"]["command"].as_str().unwrap_or("");
        if phase == "pre" && cmd.contains("rm -rf") {
            json!({"decision": "deny", "rule": "fs.remove_protected", "reason": "protected path"})
        } else {
            json!({"decision": "allow"})
        }
    }

    #[test]
    fn shell_like_tools_normalize_to_bash() {
        for (name, args) in [
            ("bash", json!({"command": "ls"})),
            ("run_shell", json!({"cmd": "ls"})),
            ("execute", json!({"script": "ls"})),
        ] {
            let (tool, input) = classify(name, &args);
            assert_eq!(tool, "Bash");
            assert_eq!(input["command"], "ls");
        }
        let (tool, input) = classify("write_file", &json!({"path": "/x/.env", "content": "s"}));
        assert_eq!(tool, "Write");
        assert_eq!(input["file_path"], "/x/.env");
        // Unknown tools keep their identity.
        assert_eq!(
            classify("search_docs", &json!({"query": "q"})).0,
            "search_docs"
        );
    }

    #[test]
    fn a_denied_call_is_answered_not_forwarded() {
        let proxy = Proxy::new("s".into(), "/repo".into(), deny_rm);
        let req = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"bash","arguments":{"command":"rm -rf ~/.ssh"}}});
        match proxy.on_request(&req.to_string()) {
            Verdict::Refuse(reply) => {
                assert_eq!(reply["id"], 7);
                assert_eq!(reply["result"]["isError"], true);
                let text = reply["result"]["content"][0]["text"].as_str().unwrap();
                assert!(text.contains("protected path"));
                assert!(
                    text.contains("sentinel allow"),
                    "must name the override path"
                );
            }
            Verdict::Forward => panic!("a blocked call must not reach the server"),
        }
    }

    #[test]
    fn allowed_calls_forward_and_pair_with_their_response() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static POSTS: AtomicUsize = AtomicUsize::new(0);
        let counting = |phase: &str, payload: &Value| {
            if phase == "post" {
                POSTS.fetch_add(1, Ordering::SeqCst);
                assert_eq!(payload["tool_response"]["stdout"], "done");
            }
            json!({"decision": "allow"})
        };
        let proxy = Proxy::new("s".into(), "/repo".into(), counting);
        let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"ls"}}});
        assert!(matches!(
            proxy.on_request(&req.to_string()),
            Verdict::Forward
        ));

        let resp =
            json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}});
        proxy.on_response(&resp.to_string());
        assert_eq!(POSTS.load(Ordering::SeqCst), 1);

        // Unrelated traffic passes through without recording.
        proxy.on_response(&json!({"jsonrpc":"2.0","id":99,"result":{}}).to_string());
        assert_eq!(POSTS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_tool_traffic_is_never_touched() {
        let proxy = Proxy::new("s".into(), "/".into(), |_, _| panic!("must not consult"));
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#,
            "not json at all",
        ] {
            assert!(matches!(proxy.on_request(line), Verdict::Forward));
        }
    }
}
