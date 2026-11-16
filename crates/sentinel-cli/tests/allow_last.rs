use sentinel_store::Store;
use sentineld::hooks;
use sentineld::state::Daemon;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

const SENTINEL: &str = env!("CARGO_BIN_EXE_sentinel");

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git must be on PATH for this test");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with an uncommitted change, because `git.discard_changes` only
/// fires when there is something to discard.
fn dirty_repo(repo: &Path) {
    git(repo, &["init", "--quiet"]);
    git(repo, &["config", "user.email", "test@example.invalid"]);
    git(repo, &["config", "user.name", "Test"]);
    std::fs::write(repo.join("app.py"), "print(1)\n").unwrap();
    git(repo, &["add", "app.py"]);
    git(repo, &["commit", "--quiet", "-m", "first"]);
    std::fs::write(repo.join("app.py"), "print(2)\n").unwrap();

    // Pin the two rules this test relies on, so a guard.toml in the developer's
    // XDG config directory cannot turn either of them off underneath it.
    std::fs::create_dir_all(repo.join(".sentinel")).unwrap();
    std::fs::write(
        repo.join(".sentinel/guard.toml"),
        "enabled = true\n\n[rules]\n\
         \"git.discard_changes\" = \"deny\"\n\
         \"perm.chmod_world_writable\" = \"deny\"\n",
    )
    .unwrap();
}

fn bash(repo: &Path, command: &str) -> Value {
    json!({
        "session_id": "allow-last",
        "cwd": repo.to_string_lossy(),
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
}

/// Runs the real CLI in the repository, with its state directories redirected
/// into the sandbox so it neither reads nor writes the developer's own.
fn sentinel(repo: &Path, home: &Path, args: &[&str]) -> String {
    let (ok, stdout, stderr) = sentinel_try(repo, home, args);
    assert!(ok, "sentinel {args:?} failed: {stderr}");
    stdout
}

/// As above, but for the calls that are supposed to be refused.
fn sentinel_try(repo: &Path, home: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(SENTINEL)
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("SENTINEL_HOME", home.join("sentinel"))
        .output()
        .expect("the sentinel binary should run");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn allow_last_targets_the_newest_block_after_an_override() {
    let work = tempfile::tempdir().unwrap();
    let repo = work.path().join("project");
    let home = work.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    dirty_repo(&repo);
    Store::init(&repo).unwrap();

    let daemon = Daemon::new(0, "test-token".into());
    let state = daemon.repo(&repo).unwrap();

    // 1. The guard refuses to discard the worktree.
    let denied = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        denied["decision"], "deny",
        "git restore . should be blocked in a dirty worktree; got {denied}"
    );
    assert_eq!(denied["rule"], "git.discard_changes");

    // 2. The operator releases exactly that block with a one-shot grant, chosen
    //    by `--last` from the real CLI.
    let granted = sentinel(&repo, &home, &["allow", "--last", "--once"]);
    assert!(
        granted.contains("git restore ."),
        "--last should have picked the only block there is; got {granted:?}"
    );

    // 3. The retry goes through and is recorded as an override.
    let allowed = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        allowed["decision"], "allow",
        "the one-shot grant should let the retry through; got {allowed}"
    );

    let settled = sentinel(&repo, &home, &["blocks"]);
    assert!(
        !settled.contains("git restore ."),
        "the released block is still listed:\n{settled}"
    );
    let (ok, out, err) = sentinel_try(&repo, &home, &["allow", "--last", "--once"]);
    assert!(
        !ok,
        "a spent grant must not be re-issuable; the CLI handed out another:\n{out}"
    );
    assert!(
        err.contains("nothing has been blocked"),
        "expected `--last` to find no outstanding block, got: {err}"
    );

    // 4. An unrelated command is refused.
    let chmod = hooks::handle(&daemon, "pre", &bash(&repo, "chmod -R 777 ."));
    assert_eq!(chmod["decision"], "deny", "got {chmod}");
    assert_eq!(chmod["rule"], "perm.chmod_world_writable");

    let denied_again = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        denied_again["decision"], "deny",
        "the spent grant must not still be releasing this; got {denied_again}"
    );

    // The newest block is visible again. Under the defect it was not: `blocks`
    // showed only the chmod, because `git restore .`'s fingerprint had appeared
    // on an override earlier in the window.
    let listed = sentinel(&repo, &home, &["blocks"]);
    assert!(
        listed.contains("git restore ."),
        "the newest block is missing from `sentinel blocks`:\n{listed}"
    );

    // 6. `--last` now names it. This is the assertion the bug failed: it used
    //    to name `chmod -R 777 .`. `--always` is spelled out because one retry
    //    is the default now; this step is about the permanent grant.
    let permanent = sentinel(&repo, &home, &["allow", "--last", "--always"]);
    assert!(
        permanent.contains("git restore ."),
        "--last targeted the wrong command:\n{permanent}"
    );
    assert!(
        !permanent.contains("chmod"),
        "--last whitelisted an unrelated command:\n{permanent}"
    );

    // 7. The whitelist landed where the operator pointed it, and nowhere else.
    //    Re-read the config the CLI just wrote before asking the guard again.
    state.refresh();
    let restore_now = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        restore_now["decision"], "allow",
        "the command the operator chose should now be allowed; got {restore_now}"
    );
    let chmod_now = hooks::handle(&daemon, "pre", &bash(&repo, "chmod -R 777 ."));
    assert_eq!(
        chmod_now["decision"], "deny",
        "chmod -R 777 . was never chosen and must still be blocked; got {chmod_now}"
    );
}

#[test]
fn a_bare_allow_grants_one_retry_rather_than_a_permanent_pass() {
    let work = tempfile::tempdir().unwrap();
    let repo = work.path().join("project");
    let home = work.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    dirty_repo(&repo);
    Store::init(&repo).unwrap();

    let daemon = Daemon::new(0, "test-token".into());
    let state = daemon.repo(&repo).unwrap();

    let denied = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(denied["decision"], "deny", "got {denied}");

    // No --once, no --always: the default.
    let out = sentinel(&repo, &home, &["allow", "--last"]);
    assert!(
        out.contains("once"),
        "the default grant must announce itself as one retry:\n{out}"
    );
    state.refresh();

    // Nothing was written into the repository's policy…
    let cfg = std::fs::read_to_string(repo.join(".sentinel/guard.toml")).unwrap();
    assert!(
        !cfg.contains("allow"),
        "a bare `allow` wrote a permanent entry into guard.toml:\n{cfg}"
    );

    // …the one retry is honoured…
    let first = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        first["decision"], "allow",
        "the single retry must be permitted; got {first}"
    );

    // …and it is spent.
    state.refresh();
    let second = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
    assert_eq!(
        second["decision"], "deny",
        "a bare `allow` handed out a permanent pass; got {second}"
    );
}

/// `--always` still does what it says, or the change above is just a removed
/// feature.
#[test]
fn always_still_writes_a_permanent_entry() {
    let work = tempfile::tempdir().unwrap();
    let repo = work.path().join("project");
    let home = work.path().join("home");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    dirty_repo(&repo);
    Store::init(&repo).unwrap();

    let daemon = Daemon::new(0, "test-token".into());
    let state = daemon.repo(&repo).unwrap();

    assert_eq!(
        hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."))["decision"],
        "deny"
    );
    sentinel(&repo, &home, &["allow", "--last", "--always"]);
    state.refresh();

    for attempt in 0..2 {
        let d = hooks::handle(&daemon, "pre", &bash(&repo, "git restore ."));
        assert_eq!(
            d["decision"], "allow",
            "attempt {attempt} of a permanent grant was refused; got {d}"
        );
    }
}
