use std::io::Write;
use std::process::{Command, Stdio};

const HOOK: &str = env!("CARGO_BIN_EXE_sentinel-hook");

/// A port nothing is listening on, so `connect` is refused immediately.
fn dead_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

fn run_hook(home: &std::path::Path, phase: &str, stdin: &str) -> String {
    run_hook_styled(home, phase, stdin, None)
}

fn run_hook_styled(
    home: &std::path::Path,
    phase: &str,
    stdin: &str,
    style: Option<&str>,
) -> String {
    let mut child = Command::new(HOOK)
        .arg(phase)
        .env("SENTINEL_HOME", home)
        .env_remove("SENTINEL_HARNESS")
        .env("SENTINEL_DENIAL_STYLE", style.unwrap_or(""))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sentinel-hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("hook should terminate");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn bash(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "audit",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

/// A daemon.json pointing at a port that refuses the connection: the daemon was
/// installed and started, and is now dead. Exactly the state the audit left the
/// machine in.
#[test]
fn a_refused_connection_denies_rather_than_allowing() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("daemon.json"),
        serde_json::json!({
            "port": dead_port(),
            "token": "t",
            "pid": 1,
            "version": "0",
            "started": "now",
        })
        .to_string(),
    )
    .unwrap();

    let out = run_hook(tmp.path(), "pre", &bash("rm -rf /etc"));
    assert!(
        out.contains("\"deny\""),
        "a dead daemon must deny, not wave the command through; got {out:?}"
    );
}

#[test]
fn a_missing_daemon_record_denies_too() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_hook(tmp.path(), "pre", &bash("rm -rf /etc"));
    assert!(
        out.contains("\"deny\""),
        "an absent daemon must deny; got {out:?}"
    );
}

/// A refusal the agent cannot act on is nearly as bad as no refusal. The
/// unreachable-daemon denial has to say what happened and how to fix it.
#[test]
fn the_refusal_says_the_daemon_is_unreachable() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_hook(tmp.path(), "pre", &bash("rm -rf /etc"));
    let lower = out.to_lowercase();
    assert!(
        lower.contains("daemon"),
        "the refusal must name the cause; got {out:?}"
    );
    assert!(
        lower.contains("sentinel start") || lower.contains("not running"),
        "the refusal must say how to recover; got {out:?}"
    );
}

/// Post-tool hooks fire after the command has already run, so denying there
/// buys nothing and would spray refusals over every completed call. Fail-closed
/// belongs on the pre-execution path only.
#[test]
fn the_post_phase_does_not_deny_after_the_fact() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_hook(tmp.path(), "post", &bash("rm -rf /etc"));
    assert!(
        !out.contains("\"deny\""),
        "post-hook must not deny a command that already ran; got {out:?}"
    );
}

#[test]
fn the_unreachable_refusal_is_not_ablated_by_the_denial_style() {
    let tmp = tempfile::tempdir().unwrap();
    for style in ["terse", "explain", "padded", "defer", "full"] {
        let out = run_hook_styled(tmp.path(), "pre", &bash("rm -rf /etc"), Some(style));
        assert!(out.contains("\"deny\""), "style {style}: {out:?}");
        assert!(
            out.to_lowercase().contains("daemon"),
            "style {style} hid the cause: {out:?}"
        );
    }
}

/// The override is adjudicated by the daemon. Offering it while the daemon is
/// unreachable points the agent at a loop it cannot get out of.
#[test]
fn the_unreachable_refusal_does_not_offer_an_override_it_cannot_honour() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_hook(tmp.path(), "pre", &bash("rm -rf /etc"));
    assert!(
        !out.contains("sentinel allow"),
        "the override needs the daemon that is down; got {out:?}"
    );
    assert!(
        out.contains("sentinel start"),
        "it must point at the thing that actually fixes this; got {out:?}"
    );
}

/// Fail-closed must not mean "closed on everything". A request the hook cannot
/// even parse is a malformed *request*, not a missing guard, and the daemon
/// itself is documented to fail open on those.
#[test]
fn an_unparseable_request_is_not_treated_as_a_dead_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_hook(tmp.path(), "pre", "this is not json");
    assert!(
        !out.contains("\"deny\""),
        "a malformed payload is not evidence the daemon is down; got {out:?}"
    );
}
