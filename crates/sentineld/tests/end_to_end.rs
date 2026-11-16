//! A full tier A session driven through the same entry point Claude Code's
//! hooks use, in process: record, guard, checkpoint, detect, restore.

use sentinel_store::Store;
use sentineld::state::{lock, Daemon};
use sentineld::{hooks, server};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn payload(cwd: &Path, tool: &str, input: Value, response: Option<Value>) -> Value {
    let mut p = json!({
        "session_id": "test-session",
        "cwd": cwd.to_string_lossy(),
        "tool_name": tool,
        "tool_input": input,
    });
    if let Some(r) = response {
        p["tool_response"] = r;
    }
    p
}

fn events(daemon: &Arc<Daemon>, repo: &Path) -> Vec<Value> {
    let state = daemon.repo(repo).unwrap();
    let store = lock(&state.store);
    store.events_json(None, 500).unwrap()
}

fn wait_for(daemon: &Arc<Daemon>, repo: &Path, pred: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(found) = events(daemon, repo).into_iter().find(&pred) {
            return found;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for an event");
}

#[test]
fn a_session_is_recorded_guarded_and_checkpointed() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    fs::write(repo.join("app.py"), "def add(a, b):\n    return a + b\n").unwrap();
    Store::init(repo).unwrap();

    let daemon = Daemon::new(0, "test-token".into());

    // A safe command passes through.
    let allowed = hooks::handle(
        &daemon,
        "pre",
        &payload(repo, "Bash", json!({"command": "cargo test"}), None),
    );
    assert_eq!(allowed["decision"], "allow");
    hooks::handle(
        &daemon,
        "post",
        &payload(
            repo,
            "Bash",
            json!({"command": "cargo test"}),
            Some(json!({"exit_code": 0})),
        ),
    );

    // A force-push to a protected branch does not.
    let blocked = hooks::handle(
        &daemon,
        "pre",
        &payload(
            repo,
            "Bash",
            json!({"command": "git push --force origin main"}),
            None,
        ),
    );
    assert_eq!(blocked["decision"], "deny", "force-push should be blocked");
    assert_eq!(blocked["rule"], "git.force_push");
    assert!(blocked["reason"].as_str().unwrap().contains("main"));

    // So does a write into a credential path.
    let blocked = hooks::handle(
        &daemon,
        "pre",
        &payload(
            repo,
            "Write",
            json!({"file_path": "~/.ssh/authorized_keys"}),
            None,
        ),
    );
    assert_eq!(
        blocked["decision"], "deny",
        "credential write should be blocked"
    );

    // Settle the pre-edit checkpoint before changing anything, so the state we
    // later rewind to is unambiguous.
    let before_edit = wait_for(&daemon, repo, |e| e["kind"] == "checkpoint");
    let checkpoint_id = before_edit["checkpoint_id"].as_str().unwrap().to_string();

    // A real edit is recorded and produces its own checkpoint.
    hooks::handle(
        &daemon,
        "pre",
        &payload(repo, "Edit", json!({"file_path": "app.py"}), None),
    );
    fs::write(repo.join("app.py"), "def add(a, b):\n    return a - b\n").unwrap();
    hooks::handle(
        &daemon,
        "post",
        &payload(
            repo,
            "Edit",
            json!({"file_path": "app.py"}),
            Some(json!({"exit_code": 0})),
        ),
    );
    wait_for(&daemon, repo, |e| {
        e["kind"] == "checkpoint" && e["checkpoint_id"] != json!(checkpoint_id.clone())
    });

    let log = events(&daemon, repo);
    let kinds: Vec<&str> = log.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"tool_call"));
    assert!(kinds.contains(&"tool_result"));
    assert!(kinds.contains(&"guard_decision"));
    assert!(kinds.contains(&"checkpoint"));

    // Steps are dense and strictly increasing, so the timeline has no holes.
    let steps: Vec<u64> = log.iter().map(|e| e["step"].as_u64().unwrap()).collect();
    assert!(
        steps.windows(2).all(|w| w[1] > w[0]),
        "steps must increase: {steps:?}"
    );

    // Rewinding to the pre-edit checkpoint undoes the edit exactly.
    let state = daemon.repo(repo).unwrap();
    let mut store = lock(&state.store);
    let (plan, safety) = store.restore(&checkpoint_id).unwrap();
    assert_eq!(plan.modified, vec!["app.py"]);
    assert!(
        !safety.is_empty(),
        "a safety snapshot must be taken before restoring"
    );
    assert_eq!(
        fs::read_to_string(repo.join("app.py")).unwrap(),
        "def add(a, b):\n    return a + b\n",
        "restore must put the original content back"
    );

    // And the safety snapshot can roll that decision forward again.
    store.restore(&safety).unwrap();
    assert_eq!(
        fs::read_to_string(repo.join("app.py")).unwrap(),
        "def add(a, b):\n    return a - b\n"
    );
}

#[test]
fn secrets_never_reach_the_event_log() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "test-token".into());

    let secret = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    hooks::handle(
        &daemon,
        "pre",
        &payload(
            repo,
            "Bash",
            json!({"command": format!("deploy --token={secret}")}),
            None,
        ),
    );

    let raw = fs::read_to_string(repo.join(".sentinel/events.jsonl")).unwrap();
    assert!(!raw.contains(secret), "the raw token appeared in the log");
    assert!(
        raw.contains("<redacted>"),
        "the summary should show a redaction"
    );
}

#[test]
fn repeated_identical_errors_raise_a_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "test-token".into());

    for pid in 0..3 {
        let input = json!({"command": "pytest -q"});
        hooks::handle(&daemon, "pre", &payload(repo, "Bash", input.clone(), None));
        hooks::handle(
            &daemon,
            "post",
            &payload(
                repo,
                "Bash",
                input,
                Some(json!({
                    "exit_code": 1,
                    // Only the volatile parts differ between runs.
                    "stderr": format!("AssertionError at /home/u{pid}/app.py:2 pid 1234{pid}")
                })),
            ),
        );
    }

    let detection = wait_for(&daemon, repo, |e| e["meta"]["detector"] == "error_identity");
    assert_eq!(
        detection["meta"]["evidence_steps"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn a_detected_loop_is_reported_back_to_the_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "test-token".into());

    let input = json!({"command": "pytest -q"});
    let mut context = None;
    for _ in 0..3 {
        hooks::handle(&daemon, "pre", &payload(repo, "Bash", input.clone(), None));
        let reply = hooks::handle(
            &daemon,
            "post",
            &payload(
                repo,
                "Bash",
                input.clone(),
                Some(json!({"stderr": "AssertionError: nope"})),
            ),
        );
        assert_eq!(reply["decision"], "allow", "detectors must never block");
        if let Some(text) = reply["context"].as_str() {
            context = Some(text.to_string());
        }
    }

    let context = context.expect("three identical failures should be reported back");
    assert!(context.contains("same error"), "got: {context}");

    // Reported once, not on every subsequent call.
    let repeat = hooks::handle(
        &daemon,
        "post",
        &payload(
            repo,
            "Bash",
            input,
            Some(json!({"stderr": "AssertionError: nope"})),
        ),
    );
    assert!(
        repeat["context"].is_null(),
        "a finding must not be repeated every step"
    );
}

#[test]
fn the_pre_hook_stays_inside_its_latency_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "test-token".into());
    let call = payload(
        repo,
        "Bash",
        json!({"command": "git push --force origin main"}),
        None,
    );

    // Warm the caches the way a real session would.
    for _ in 0..5 {
        hooks::handle(&daemon, "pre", &call);
    }
    let started = Instant::now();
    let runs = 50;
    for _ in 0..runs {
        hooks::handle(&daemon, "pre", &call);
    }
    let mean = started.elapsed() / runs;
    println!("pre-hook mean: {:?}", mean);
    assert!(
        mean < Duration::from_millis(30),
        "guard decision took {mean:?}, over the 30ms budget"
    );
}

#[test]
fn tier_c_records_observed_mutations_and_defers_to_tier_a() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    fs::write(repo.join(".gitignore"), "target/\n").unwrap();
    fs::write(repo.join("src.rs"), "x").unwrap();
    fs::create_dir_all(repo.join("target")).unwrap();
    fs::write(repo.join("target/junk.o"), "o").unwrap();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "t".into());

    // Ignored and internal paths produce nothing.
    let n = sentineld::watcher::record_mutations(
        &daemon,
        repo,
        &[
            repo.join("target/junk.o"),
            repo.join(".sentinel/x"),
            repo.join(".git/HEAD"),
        ],
    )
    .unwrap();
    assert_eq!(n, 0, "gitignored and internal paths are not mutations");

    // A real edit is recorded and checkpointed.
    let n = sentineld::watcher::record_mutations(&daemon, repo, &[repo.join("src.rs")]).unwrap();
    assert_eq!(n, 1);
    let ev = wait_for(&daemon, repo, |e| e["kind"] == "file_mutation");
    assert_eq!(ev["files_touched"][0], "src.rs");
    wait_for(&daemon, repo, |e| e["kind"] == "checkpoint");

    // While tier A hooks are live on this repo, observation stands down.
    hooks::handle(
        &daemon,
        "pre",
        &payload(repo, "Bash", json!({"command": "ls"}), None),
    );
    let n = sentineld::watcher::record_mutations(&daemon, repo, &[repo.join("src.rs")]).unwrap();
    assert_eq!(n, 0, "tier C must not double-record a hook-covered repo");
}

#[test]
fn unenrolled_repositories_are_ignored_entirely() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = Daemon::new(0, "test-token".into());
    let decision = hooks::handle(
        &daemon,
        "pre",
        &payload(
            tmp.path(),
            "Bash",
            json!({"command": "git push --force origin main"}),
            None,
        ),
    );
    assert_eq!(
        decision["decision"], "allow",
        "an unenrolled repo must not be guarded"
    );
    assert!(
        !tmp.path().join(".sentinel").exists(),
        "nothing may be written there"
    );
}

#[test]
fn malformed_payloads_fail_open() {
    let tmp = tempfile::tempdir().unwrap();
    Store::init(tmp.path()).unwrap();
    let daemon = Daemon::new(0, "test-token".into());

    for bad in [
        json!({}),
        json!({"cwd": ""}),
        json!({"tool_name": "Bash"}),
        Value::Null,
    ] {
        assert_eq!(hooks::handle(&daemon, "pre", &bad)["decision"], "allow");
    }
}

#[test]
fn the_http_surface_answers_over_loopback() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().to_path_buf();
    Store::init(&repo).unwrap();

    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = http.server_addr().to_ip().unwrap().port();
    let daemon = Daemon::new(port, "secret-token".into());
    daemon.repo(&repo).unwrap();
    {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || server::serve(daemon, http));
    }

    let timeout = Duration::from_secs(5);
    let health =
        sentineld::request(port, "secret-token", "GET", "/api/health", None, timeout).unwrap();
    assert!(health.contains("\"ok\":true"));

    // The timeline page is served, with the token substituted in.
    let page = sentineld::request(port, "secret-token", "GET", "/", None, timeout).unwrap();
    assert!(page.contains("<title>Sentinel"));
    assert!(page.contains("secret-token") && !page.contains("__SENTINEL_TOKEN__"));

    // A guard verdict round-trips over the wire.
    let body = json!({
        "phase": "pre",
        "payload": payload(&repo, "Bash", json!({"command": "git push --force origin main"}), None)
    })
    .to_string();
    let denied =
        sentineld::request(port, "secret-token", "POST", "/hook", Some(&body), timeout).unwrap();
    assert!(denied.contains("\"deny\""), "got {denied}");

    // Data endpoints require the token.
    let unauthorized =
        sentineld::request(port, "wrong-token", "GET", "/api/repos", None, timeout).unwrap();
    assert!(
        unauthorized.contains("401") || unauthorized.contains("invalid"),
        "got {unauthorized}"
    );
}

#[test]
fn a_malformed_blob_hash_cannot_kill_the_http_workers() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().to_path_buf();
    Store::init(&repo).unwrap();

    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = http.server_addr().to_ip().unwrap().port();
    let daemon = Daemon::new(port, "secret-token".into());
    daemon.repo(&repo).unwrap();
    {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || server::serve(daemon, http));
    }

    let timeout = Duration::from_secs(5);
    let repo_q = repo
        .to_string_lossy()
        .replace('/', "%2F")
        .replace(':', "%3A");

    // The token is free: an unauthenticated GET / embeds it in the page.
    let page = sentineld::request(port, "", "GET", "/", None, timeout).unwrap();
    assert!(
        page.contains("secret-token"),
        "GET / hands out the API token without authentication"
    );

    for (i, bad) in [
        "",
        "a",
        "ab",
        "%C3%A9",
        "0123",
        "..%2F..%2Fetc%2Fpasswd",
        "",
    ]
    .iter()
    .enumerate()
    {
        let url = format!("/api/blob?repo={repo_q}&hash={bad}");
        let reply = sentineld::request(port, "secret-token", "GET", &url, None, timeout).unwrap();
        assert!(
            reply.contains("error"),
            "request {i} for hash {bad:?} should be a clean error, got {reply:?}"
        );
        assert!(
            !reply.is_empty(),
            "request {i} for hash {bad:?} got no response at all — the worker died"
        );
    }

    // The whole point: the guard is still answering afterwards.
    let health = sentineld::request(port, "secret-token", "GET", "/api/health", None, timeout)
        .expect("health request");
    assert!(
        health.contains("\"ok\":true"),
        "the daemon stopped serving after malformed blob requests: {health:?}"
    );

    // And it still refuses what it refused before, rather than merely being up.
    let body = json!({
        "phase": "pre",
        "payload": payload(&repo, "Bash", json!({"command": "rm -rf /etc"}), None)
    })
    .to_string();
    let denied =
        sentineld::request(port, "secret-token", "POST", "/hook", Some(&body), timeout).unwrap();
    assert!(
        denied.contains("\"deny\""),
        "the guard stopped denying after the attack: {denied}"
    );
}

#[test]
fn an_allowlisted_command_still_leaves_a_row_in_the_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();

    let command = "git push --force origin main";
    let fingerprint = sentinel_guard::fingerprint("git.force_push", command);
    fs::create_dir_all(repo.join(".sentinel")).unwrap();
    fs::write(
        repo.join(".sentinel/guard.toml"),
        format!(
            "enabled = true\nallow = [\"{fingerprint}\"]\n\n\
             [rules]\n\"git.force_push\" = \"deny\"\n"
        ),
    )
    .unwrap();

    let daemon = Daemon::new(0, "test-token".into());
    let state = daemon.repo(repo).unwrap();
    state.refresh();

    let out = hooks::handle(
        &daemon,
        "pre",
        &payload(repo, "Bash", json!({"command": command}), None),
    );
    assert_eq!(
        out["decision"], "allow",
        "the allowlist must still permit the command; got {out}"
    );

    let row = events(&daemon, repo)
        .into_iter()
        .find(|e| e["kind"] == "guard_decision")
        .expect("an allowlisted override wrote no event at all");
    assert_eq!(
        row["meta"]["verdict"], "allowlisted",
        "the override must be distinguishable from an ordinary allow: {row}"
    );
    assert_eq!(row["meta"]["rule"], "git.force_push");
    assert!(
        row["meta"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("allowlist")),
        "the row must say why the rule did not block: {row}"
    );
}

/// The same short-circuit reached through `POST /api/allow`, which is the
/// second of the three routes. It also used to call `allow_always`
/// unconditionally, so one click in the web UI bought a permanent grant.
#[test]
fn the_api_allow_route_grants_one_retry_and_records_the_override() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().to_path_buf();
    Store::init(&repo).unwrap();
    fs::create_dir_all(repo.join(".sentinel")).unwrap();
    fs::write(
        repo.join(".sentinel/guard.toml"),
        "enabled = true\n\n[rules]\n\"git.force_push\" = \"deny\"\n",
    )
    .unwrap();

    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = http.server_addr().to_ip().unwrap().port();
    let daemon = Daemon::new(port, "secret-token".into());
    daemon.repo(&repo).unwrap();
    {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || server::serve(daemon, http));
    }
    let timeout = Duration::from_secs(5);

    let command = "git push --force origin main";
    let denied = hooks::handle(
        &daemon,
        "pre",
        &payload(&repo, "Bash", json!({"command": command}), None),
    );
    assert_eq!(denied["decision"], "deny", "got {denied}");
    let fingerprint = denied["fingerprint"].as_str().unwrap().to_string();

    // The default is one retry, and the reply says so.
    let body = json!({"repo": repo.to_string_lossy(), "fingerprint": fingerprint}).to_string();
    let reply = sentineld::request(
        port,
        "secret-token",
        "POST",
        "/api/allow",
        Some(&body),
        timeout,
    )
    .unwrap();
    assert!(reply.contains("\"scope\":\"once\""), "got {reply}");
    assert!(
        !fs::read_to_string(repo.join(".sentinel/guard.toml"))
            .unwrap()
            .contains("allow ="),
        "the API wrote a permanent allowlist entry for a single click"
    );

    // Spent after one attempt, and recorded as an override rather than a plain
    // allow — the distinction the ledger has to carry.
    let first = hooks::handle(
        &daemon,
        "pre",
        &payload(&repo, "Bash", json!({"command": command}), None),
    );
    assert_eq!(first["decision"], "allow", "got {first}");
    let again = hooks::handle(
        &daemon,
        "pre",
        &payload(&repo, "Bash", json!({"command": command}), None),
    );
    assert_eq!(
        again["decision"], "deny",
        "the API grant outlived its one attempt; got {again}"
    );
    assert!(
        events(&daemon, &repo)
            .iter()
            .any(|e| e["kind"] == "guard_decision" && e["meta"]["verdict"] == "overridden"),
        "the API override left no row"
    );

    // And `always: true` is still available, by name.
    let body = json!({
        "repo": repo.to_string_lossy(),
        "fingerprint": fingerprint,
        "always": true
    })
    .to_string();
    let reply = sentineld::request(
        port,
        "secret-token",
        "POST",
        "/api/allow",
        Some(&body),
        timeout,
    )
    .unwrap();
    assert!(reply.contains("\"scope\":\"always\""), "got {reply}");
}

#[test]
fn writing_the_guards_own_config_is_refused_and_recorded() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    Store::init(repo).unwrap();
    let daemon = Daemon::new(0, "test-token".into());

    for path in [".sentinel/guard.toml", ".claude/settings.json"] {
        let target = repo.join(path).to_string_lossy().to_string();
        let out = hooks::handle(
            &daemon,
            "pre",
            &payload(repo, "Write", json!({"file_path": target}), None),
        );
        assert_eq!(
            out["decision"], "deny",
            "an unmediated write to {path}; got {out}"
        );
        assert_eq!(out["rule"], "guard.control_plane", "got {out}");
    }

    // …and the same through a shell, which is the other half of the surface.
    let out = hooks::handle(
        &daemon,
        "pre",
        &payload(
            repo,
            "Bash",
            json!({"command": format!("echo 'enabled = false' > {}/.sentinel/guard.toml", repo.display())}),
            None,
        ),
    );
    assert_eq!(out["decision"], "deny", "got {out}");

    let rows: Vec<Value> = events(&daemon, repo)
        .into_iter()
        .filter(|e| e["kind"] == "guard_decision")
        .collect();
    assert_eq!(
        rows.len(),
        3,
        "every control-plane change must leave a row, got {rows:#?}"
    );
    assert!(rows.iter().all(|r| r["meta"]["verdict"] == "deny"));
}
