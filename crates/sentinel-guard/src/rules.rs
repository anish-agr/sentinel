//! The ruleset. Every rule is a pure function of a normalized command plus
//! repository context, which is what makes bypass testing tractable.

use crate::config::{home_dir, GuardConfig};
use crate::normalize::{Cmd, Pipeline};
use std::path::{Path, PathBuf};

pub struct Ctx {
    pub repo: PathBuf,
    pub cwd: PathBuf,
    pub branch: Option<String>,
    pub dirty: bool,
    pub untracked: bool,
    pub home: Option<PathBuf>,
    pub config: GuardConfig,
}

impl Ctx {
    pub fn new(repo: impl Into<PathBuf>) -> Ctx {
        let repo = repo.into();
        Ctx {
            cwd: repo.clone(),
            repo,
            branch: None,
            dirty: false,
            untracked: false,
            home: home_dir(),
            config: GuardConfig::default(),
        }
    }

    fn home_str(&self) -> Option<String> {
        self.home.as_deref().map(norm_path)
    }

    /// `~`, `$HOME`, `${HOME}` and `%USERPROFILE%` all mean the same directory.
    fn expand(&self, raw: &str) -> String {
        let mut s = raw.replace('\\', "/");
        if let Some(home) = self.home_str() {
            for var in [
                "$HOME",
                "${HOME}",
                "%USERPROFILE%",
                "$env:USERPROFILE",
                "$HOMEPATH",
            ] {
                s = s.replace(var, &home);
            }
            if s == "~" {
                s = home;
            } else if let Some(rest) = s.strip_prefix("~/") {
                s = format!("{home}/{rest}");
            }
        }
        s
    }

    pub fn resolve(&self, raw: &str) -> String {
        let expanded = self.expand(raw);
        let joined = if is_absolute(&expanded) {
            expanded
        } else {
            format!("{}/{}", norm_path(&self.cwd), expanded)
        };
        lexical_normalize(&joined)
    }

    pub fn protected_path(&self, target: &str) -> Option<String> {
        let resolved = casefold(&self.resolve(target));
        for pat in &self.config.protected_paths {
            let expanded = casefold(&self.expand(pat));
            if glob_match(&expanded, &resolved) || glob_match(&format!("{expanded}/**"), &resolved)
            {
                return Some(pat.clone());
            }
        }
        None
    }

    /// A path the operating system owns. Kept apart from `protected_path` so
    /// the rule that fires reads true: deleting `/etc` is system destruction,
    /// not credential theft.
    pub fn system_path(&self, target: &str) -> Option<String> {
        let resolved = casefold(&self.resolve(target));
        for pat in &self.config.system_paths {
            let expanded = casefold(&self.expand(pat));
            if glob_match(&expanded, &resolved) || glob_match(&format!("{expanded}/**"), &resolved)
            {
                return Some(pat.clone());
            }
        }
        None
    }

    /// Either kind of path that must not be destroyed.
    pub fn sensitive_path(&self, target: &str) -> Option<String> {
        self.protected_path(target)
            .or_else(|| self.system_path(target))
    }

    pub fn control_path(&self, target: &str) -> Option<String> {
        let resolved = casefold(&self.resolve(target));
        let global = crate::config::global_path()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .into_iter()
            .collect::<Vec<_>>();
        for pat in crate::config::CONTROL_PLANE_PATHS
            .iter()
            .map(|s| (*s).to_string())
            .chain(global)
        {
            let expanded = casefold(&self.expand(&pat));
            if glob_match(&expanded, &resolved) || glob_match(&format!("{expanded}/**"), &resolved)
            {
                return Some(pat);
            }
        }
        None
    }

    /// A directory that merely CONTAINS a control-plane file. Matched exactly,
    /// with no `/**` fallback: deleting `.claude` unregisters the hooks, while
    /// writing a scratch file inside it is ordinary agent work.
    pub fn control_container(&self, target: &str) -> Option<String> {
        let resolved = casefold(&self.resolve(target));
        crate::config::CONTROL_PLANE_DIRS
            .iter()
            .find(|pat| glob_match(&casefold(&self.expand(pat)), &resolved))
            .map(|pat| (*pat).to_string())
    }

    pub fn outside_repo(&self, target: &str) -> bool {
        let resolved = casefold(&self.resolve(target));
        let repo = casefold(&norm_path(&self.repo));
        resolved != repo && !resolved.starts_with(&format!("{repo}/"))
    }

    pub fn is_root_like(&self, target: &str) -> bool {
        let r = casefold(&self.resolve(target));
        let trimmed = r.trim_end_matches('/');
        trimmed.is_empty()
            || (trimmed.len() == 2 && trimmed.ends_with(':'))
            || self.home_str().is_some_and(|h| casefold(&h) == trimmed)
    }

    pub fn is_protected_branch(&self, branch: &str) -> bool {
        let b = branch.trim().trim_start_matches("refs/heads/");
        self.config
            .protected_branches
            .iter()
            .any(|p| glob_match(&casefold(p), &casefold(b)))
    }
}

fn is_absolute(p: &str) -> bool {
    p.starts_with('/') || (p.len() >= 2 && p.as_bytes()[1] == b':')
}

fn norm_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn casefold(s: &str) -> String {
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s.to_string()
    }
}

fn lexical_normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.len() > 1 || (out.len() == 1 && !out[0].ends_with(':')) {
                    out.pop();
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Glob with `**` spanning path segments and `*`/`?` inside one.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let t: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    segments_match(&p, &t)
}

fn segments_match(p: &[&str], t: &[&str]) -> bool {
    match p.split_first() {
        None => t.is_empty(),
        Some((&"**", rest)) => (0..=t.len()).any(|i| segments_match(rest, &t[i..])),
        Some((seg, rest)) => !t.is_empty() && wildcard(seg, t[0]) && segments_match(rest, &t[1..]),
    }
}

fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            mark += 1;
            ti = mark;
            pi = star + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn is_recursive(cmd: &Cmd) -> bool {
    cmd.short_flags.contains(&'r')
        || cmd.short_flags.contains(&'R')
        || cmd.long_flags.contains("recursive")
        || cmd.long_flags.contains("recurse")
        || cmd.long_flags.contains("s")
}

fn is_forced(cmd: &Cmd) -> bool {
    cmd.short_flags.contains(&'f')
        || cmd.long_flags.contains("force")
        || cmd.long_flags.contains("q")
}

pub struct Rule {
    pub id: &'static str,
    pub summary: &'static str,
    pub check: fn(&Cmd, &Pipeline, &Ctx) -> Option<String>,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "git.force_push",
        summary: "force-push to a protected branch",
        check: git_force_push,
    },
    Rule {
        id: "git.delete_branch",
        summary: "delete a protected remote branch",
        check: git_delete_branch,
    },
    Rule {
        id: "git.reset_hard",
        summary: "git reset --hard with uncommitted work",
        check: git_reset_hard,
    },
    Rule {
        id: "git.clean_force",
        summary: "git clean -fd with untracked work",
        check: git_clean_force,
    },
    Rule {
        id: "git.history_rewrite",
        summary: "history rewrite on a protected branch",
        check: git_history_rewrite,
    },
    Rule {
        id: "fs.remove_protected",
        summary: "recursive delete of a protected or out-of-repo path",
        check: fs_remove,
    },
    Rule {
        id: "fs.disk_destroy",
        summary: "whole-device or filesystem destruction",
        check: fs_disk_destroy,
    },
    Rule {
        id: "fs.credential_write",
        summary: "write into a credential-shaped path",
        check: fs_credential_write,
    },
    Rule {
        id: "sql.destructive",
        summary: "DROP or TRUNCATE against a non-test database",
        check: sql_destructive,
    },
    Rule {
        id: "perm.chmod_world_writable",
        summary: "chmod 777",
        check: perm_chmod,
    },
    Rule {
        id: "net.pipe_to_shell",
        summary: "piping a download straight into a shell",
        check: net_pipe_to_shell,
    },
    Rule {
        id: "cloud.destroy",
        summary: "destroys remote infrastructure",
        check: cloud_destroy,
    },
    Rule {
        id: "publish.irreversible",
        summary: "publishes a release that cannot be withdrawn",
        check: publish_irreversible,
    },
    Rule {
        id: "fs.destructive_command",
        summary: "an irreversible command, or one that destroys a recovery mechanism",
        check: destructive_table,
    },
    Rule {
        id: "git.discard_changes",
        summary: "discards every uncommitted change",
        check: git_discard_changes,
    },
    Rule {
        id: "git.branch_delete",
        summary: "force-deletes a protected local branch",
        check: git_branch_delete,
    },
    Rule {
        id: "secret.exposure",
        summary: "prints or copies a credential out of the environment",
        check: secret_exposure,
    },
    Rule {
        id: "fs.system_write",
        summary: "writes into a path the operating system owns",
        check: fs_system_write,
    },
    Rule {
        id: "proc.unbounded",
        summary: "starts work with no bound on how long it runs",
        check: proc_unbounded,
    },
    Rule {
        id: "net.exfiltrate",
        summary: "sends local data to a remote host",
        check: net_exfiltrate,
    },
    Rule {
        id: "persist.autostart",
        summary: "installs something that survives the session",
        check: persist_autostart,
    },
    Rule {
        id: "guard.control_plane",
        summary: "changes the guard's own configuration or hook registration",
        check: guard_control_plane,
    },
];

/// Environment variables whose value is a credential. Matched on the name, so
/// the secret itself never has to be read to decide.
const SECRET_NAMES: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "credential",
    "auth",
];

fn looks_like_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|n| lower.contains(n))
}

fn secret_exposure(cmd: &Cmd, pipeline: &Pipeline, ctx: &Ctx) -> Option<String> {
    // `printenv` and bare `env` with no command dump everything at once.
    if cmd.program == "printenv" && cmd.operands.is_empty() {
        return Some("dumps the entire environment, including any credentials in it".into());
    }
    if cmd.program == "env" && cmd.operands.is_empty() && !cmd.raw.contains('=') {
        return Some("dumps the entire environment, including any credentials in it".into());
    }
    if matches!(cmd.program.as_str(), "echo" | "print" | "printf") {
        if let Some(var) = cmd
            .operands
            .iter()
            .find(|o| o.starts_with('$') && looks_like_secret(o))
        {
            return Some(format!(
                "prints `{var}`, putting a credential into the transcript where it persists"
            ));
        }
    }
    if matches!(cmd.program.as_str(), "cat" | "type" | "more" | "less") {
        let moving = cmd.raw.contains('>') || pipeline.piped;
        for target in &cmd.operands {
            if is_secret_material(target) {
                return Some(format!(
                    "prints `{target}`, putting key material into the transcript where it persists"
                ));
            }
            if moving {
                if let Some(pattern) = ctx.protected_path(target) {
                    return Some(format!(
                        "sends the contents of `{target}` onward, and it matches `{pattern}`"
                    ));
                }
            }
        }
    }
    None
}

/// Files that are secret by their nature rather than by where they sit.
/// Templates are excluded deliberately: `.env.example` exists to be read.
fn is_secret_material(path: &str) -> bool {
    let name = path
        .trim_matches(['"', '\''])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    if ["example", "sample", "template", "dist", "default"]
        .iter()
        .any(|suffix| name.contains(suffix))
    {
        return false;
    }
    name.starts_with("id_rsa")
        || name.starts_with("id_ed25519")
        || name.starts_with("id_ecdsa")
        || name.ends_with(".pem")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name.ends_with(".key")
        || name == ".env"
        || name.starts_with(".env.")
        || name == "credentials"
        || name == "secrets.json"
        || name.starts_with("serviceaccount")
}

fn glued_path(arg: &str) -> Option<&str> {
    arg.split_once('=')
        .map(|(_, value)| value)
        .filter(|v| !v.is_empty())
}

/// Programs that destroy or relax whatever they name, in any argument
/// position. `mv a b` destroys `a` as surely as `rm a` does.
const MUTATES_EVERY_OPERAND: &[&str] = &[
    "mv",
    "move-item",
    "mi",
    "rename-item",
    "chmod",
    "chown",
    "chgrp",
    "truncate",
    "tee",
    "set-content",
    "add-content",
    "out-file",
    "dd",
];

/// Programs whose destination is the LAST operand; naming a file anywhere else
/// is reading it. `cp .sentinel/guard.toml /tmp/backup` is a backup, and a
/// guard that refuses backups is a guard somebody turns off.
const MUTATES_LAST_OPERAND: &[&str] = &["cp", "copy-item", "install", "ln"];

fn guard_control_plane(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    let program = cmd.program.as_str();
    let redirects = redirects_to_file(&cmd.raw);
    // `sed FILE` prints; only `sed -i FILE` rewrites it in place.
    let edits_in_place =
        matches!(program, "sed" | "perl" | "ruby") && cmd.has_flag('i', "in-place");

    // Destroying or moving the directory a control-plane file lives in
    // destroys the file. `rm -rf .claude` unregisters every hook.
    let destroys = REMOVERS.contains(&program) || matches!(program, "mv" | "move-item" | "mi");
    if destroys {
        if let Some(dir) = cmd.operands.iter().find_map(|o| ctx.control_container(o)) {
            return Some(format!(
                "removes `{dir}`, which holds the hook registration that causes Sentinel to run at all — the guard would be off afterwards, with nothing in the log to say so"
            ));
        }
    }

    let candidates: Vec<&str> =
        if destroys || MUTATES_EVERY_OPERAND.contains(&program) || edits_in_place {
            cmd.operands.iter().map(String::as_str).collect()
        } else if MUTATES_LAST_OPERAND.contains(&program) {
            cmd.operands
                .last()
                .map(String::as_str)
                .into_iter()
                .collect()
        } else if redirects {
            // The lexer emits `>` as its own word, so a redirect's target is an
            // ordinary operand by the time it reaches here.
            cmd.operands.iter().map(String::as_str).collect()
        } else {
            return None;
        };

    let target = candidates
        .into_iter()
        // `dd of=/repo/.sentinel/guard.toml` names its destination in a glued
        // argument rather than a position.
        .chain(cmd.argv.iter().filter_map(|a| glued_path(a)))
        .find_map(|o| ctx.control_path(o))?;

    Some(format!(
        "changes `{target}`, which is Sentinel's own control plane — the guard reloads it within two seconds, so this is a live policy change rather than an ordinary file edit"
    ))
}

/// Deleting or relaxing permissions on a system path is already covered. This
/// is the remaining case: writing one, which is how a change outlives the
/// session without ever deleting anything.
fn fs_system_write(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    let writes = cmd.raw.contains('>')
        || matches!(
            cmd.program.as_str(),
            "tee" | "cp" | "mv" | "install" | "set-content" | "out-file" | "copy-item"
        )
        // `dd` names its destination in an argument rather than a position.
        || (cmd.program == "dd" && cmd.argv.iter().any(|a| a.starts_with("of=")));
    if !writes {
        return None;
    }
    let target = cmd
        .operands
        .iter()
        .chain(cmd.argv.iter())
        .flat_map(|o| [Some(o.as_str()), glued_path(o)])
        .flatten()
        .find_map(|o| ctx.system_path(o))?;
    Some(format!(
        "writes into `{target}`, which the operating system owns — the change outlives this session"
    ))
}

const MINERS: &[&str] = &["xmrig", "minerd", "cgminer", "ethminer", "cpuminer"];

/// Work with no termination condition. Reversible in principle — you can always
/// kill it — but an agent that starts one has stopped making progress, and on a
/// shared or metered machine the cost is real before anyone notices.
fn proc_unbounded(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    if MINERS.contains(&cmd.program.as_str()) {
        return Some(format!(
            "`{}` is a cryptocurrency miner; nothing in a build needs one",
            cmd.program
        ));
    }
    let raw = cmd.raw.to_ascii_lowercase();
    // A fork bomb, in the forms that survive shell quoting.
    if raw.contains(":(){") || raw.contains(":(){:|:&};:") {
        return Some("a fork bomb: it replicates until the machine stops responding".into());
    }
    let unbounded_loop = raw.contains("while true")
        || raw.contains("while(true")
        || raw.contains("while (true")
        || raw.contains("for(;;)")
        || raw.contains("for (;;)");
    if unbounded_loop && !raw.contains("break") && !raw.contains("timeout") {
        return Some(
            "loops with no exit condition, no break, and no timeout — it will not stop on its own"
                .into(),
        );
    }
    if raw.contains("setrecursionlimit") {
        return Some(
            "raises the recursion limit, which converts a bug into a crash or a hang".into(),
        );
    }
    None
}

/// Data leaving the machine. A checkpoint cannot reach anything past this
/// point, which is what separates it from a local mistake.
fn net_exfiltrate(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program == "scp"
        || (cmd.program == "rsync" && cmd.operands.iter().any(|o| o.contains(':')))
    {
        let target = cmd.operands.last()?;
        return Some(format!(
            "copies local files to `{target}`, which no local checkpoint can undo"
        ));
    }
    if cmd.program == "nc" && (cmd.short_flags.contains(&'e') || cmd.short_flags.contains(&'l')) {
        return Some("opens a raw network channel out of this machine".into());
    }
    if DOWNLOADERS.contains(&cmd.program.as_str()) {
        let uploads = cmd.has_flag('d', "data")
            || cmd
                .long_flags
                .iter()
                .any(|f| f.starts_with("data") || f == "upload-file")
            || cmd
                .argv
                .iter()
                .any(|a| a.eq_ignore_ascii_case("post") || a.eq_ignore_ascii_case("put"));
        if !uploads {
            return None;
        }
        // Sending data to a host the user already trusts is ordinary API work.
        let host = cmd.argv.iter().find_map(|a| host_of(a))?;
        if host_allowed(&host, ctx) {
            return None;
        }
        return Some(format!(
            "uploads local data to `{host}`, which this repository does not trust"
        ));
    }
    None
}

fn redirects_to_file(raw: &str) -> bool {
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '>' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] == '>' {
                j += 1;
            }
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            // `&` is descriptor duplication; end of input is a redirect whose
            // target the lexer has already split away.
            if j < chars.len() && chars[j] != '&' {
                return true;
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    false
}

fn persist_autostart(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    if cmd.program == "crontab" && !cmd.short_flags.contains(&'l') {
        return Some("edits the crontab, scheduling work that outlives this session".into());
    }
    if cmd.program == "launchctl" || cmd.program == "schtasks" {
        return Some(format!("`{}` registers a persistent job", cmd.program));
    }
    if cmd.program == "systemctl" && cmd.subcommand() == Some("enable") {
        return Some("enables a service to start on every boot".into());
    }
    let writes = redirects_to_file(&cmd.raw)
        || matches!(cmd.program.as_str(), "tee" | "cp" | "mv" | "install");
    if !writes {
        return None;
    }
    // Against the operands, not the whole command line: the marker has to be
    // something the command writes to, not a word that happens to appear in it.
    const MARKERS: &[&str] = &[
        "/.bashrc",
        "/.zshrc",
        "/.profile",
        "authorized_keys",
        "autostart",
        "rc.local",
    ];
    for operand in &cmd.operands {
        let target = operand.to_ascii_lowercase();
        if let Some(marker) = MARKERS.iter().find(|m| target.contains(*m)) {
            return Some(format!(
                "writes to `{marker}`, which runs again every session"
            ));
        }
    }
    None
}

/// Irreversible commands expressed as data: program, fragments that must all
/// appear in its arguments, and why it matters. Adding a case is one line, and
/// no case can accidentally depend on repository context.
const DESTRUCTIVE: &[(&str, &[&str], &str)] = &[
    (
        "git",
        &["reflog", "expire"],
        "expires the reflog, which is the only way back after a bad reset",
    ),
    (
        "git",
        &["gc", "prune=now"],
        "prunes unreachable objects immediately, discarding what the reflog could still recover",
    ),
    (
        "git",
        &["stash", "clear"],
        "drops every stash entry, with no undo",
    ),
    (
        "git",
        &["stash", "drop"],
        "drops a stash entry, with no undo",
    ),
    (
        "git",
        &["update-ref", "-d"],
        "deletes a ref directly, bypassing the reflog",
    ),
    (
        "git",
        &["submodule", "deinit"],
        "wipes submodule working trees",
    ),
    (
        "git",
        &["filter-repo", "force"],
        "rewrites the whole repository in place",
    ),
    (
        "crontab",
        &["-r"],
        "removes every scheduled job for this user, with no confirmation and no backup",
    ),
    (
        "terraform",
        &["state", "rm"],
        "drops a resource from state, orphaning the real infrastructure",
    ),
    (
        "docker",
        &["volume", "rm"],
        "deletes a Docker volume and everything stored in it",
    ),
    (
        "docker",
        &["volume", "prune"],
        "deletes every unused Docker volume",
    ),
    (
        "redis-cli",
        &["flushall"],
        "erases every key in the Redis instance",
    ),
    (
        "redis-cli",
        &["flushdb"],
        "erases every key in the selected Redis database",
    ),
    (
        "vssadmin",
        &["delete", "shadows"],
        "deletes Windows shadow copies, removing the system's own restore points",
    ),
    (
        "wevtutil",
        &["cl"],
        "clears a Windows event log, destroying an audit trail",
    ),
    (
        "bcdedit",
        &["/delete"],
        "edits the Windows boot configuration",
    ),
    (
        "csrutil",
        &["disable"],
        "disables macOS System Integrity Protection",
    ),
    ("spctl", &["master-disable"], "disables macOS Gatekeeper"),
    ("iptables", &["-f"], "flushes every firewall rule"),
    ("ufw", &["disable"], "disables the firewall"),
    (
        "set-mppreference",
        &["disablerealtimemonitoring"],
        "disables Windows Defender real-time protection",
    ),
    ("shutdown", &[], "shuts down or restarts the machine"),
    ("reboot", &[], "restarts the machine"),
    ("truncate", &["-s", "0"], "empties a file in place"),
];

fn destructive_table(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    // Whole arguments only, with leading dashes ignored so `--force` matches
    // `force`. Substring matching would fire on `terraform state list`, whose
    // program name happens to contain "rm".
    let args: Vec<String> = cmd
        .argv
        .iter()
        .skip(1)
        .map(|a| a.trim_start_matches('-').to_ascii_lowercase())
        .collect();
    DESTRUCTIVE
        .iter()
        .find(|(program, needles, _)| {
            *program == cmd.program
                && needles
                    .iter()
                    .all(|n| args.iter().any(|a| a == n.trim_start_matches('-')))
        })
        .map(|(program, _, why)| format!("`{program}` {why}"))
}

/// Discarding the worktree is the single most common way an agent loses work
/// that was never committed anywhere.
fn git_discard_changes(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || !ctx.dirty {
        return None;
    }
    let wholesale = match cmd.subcommand()? {
        "checkout" => cmd.targets().iter().any(|t| t == "." || t == "--"),
        "restore" => cmd.targets().iter().any(|t| t == "."),
        _ => return None,
    };
    wholesale.then(|| {
        "discards every uncommitted change in the worktree — git has no record of them afterwards".to_string()
    })
}

fn git_branch_delete(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || cmd.subcommand()? != "branch" {
        return None;
    }
    if !cmd.short_flags.contains(&'D') && !cmd.long_flags.contains("delete") {
        return None;
    }
    let branch = cmd.targets().iter().find(|b| ctx.is_protected_branch(b))?;
    Some(format!("force-deletes protected local branch `{branch}`"))
}

/// Remote resources are outside the worktree, so no checkpoint can bring them
/// back. That makes these strictly less recoverable than anything on disk.
fn cloud_destroy(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    let args = cmd.command_words().join(" ").to_ascii_lowercase();
    let starts = |v: &str| args.starts_with(v);
    let destroys = match cmd.program.as_str() {
        "terraform" | "tofu" => {
            starts("destroy") || (starts("apply") && cmd.long_flags.contains("destroy"))
        }
        "kubectl" => starts("delete"),
        "helm" => starts("uninstall") || starts("delete"),
        "aws" => [
            "s3 rb",
            "delete-bucket",
            "delete-cluster",
            "delete-db-instance",
            "delete-stack",
        ]
        .iter()
        .any(|v| args.contains(v)),
        "gcloud" => args.contains("projects delete") || args.contains("clusters delete"),
        "az" => args.contains("group delete"),
        "heroku" => args.contains("apps:destroy") || args.contains("pg:reset"),
        "fly" | "flyctl" => args.contains("apps destroy"),
        "supabase" => args.contains("db reset"),
        "docker" => starts("system prune") && (is_forced(cmd) || cmd.short_flags.contains(&'a')),
        _ => false,
    };
    destroys.then(|| {
        format!(
            "`{} {args}` destroys remote resources. Sentinel checkpoints the worktree, not infrastructure, so this cannot be undone.",
            cmd.program
        )
    })
}

fn publish_irreversible(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    if cmd.long_flags.contains("dry-run") {
        return None;
    }
    let sub = cmd.subcommand().unwrap_or("");
    let publishes = match cmd.program.as_str() {
        "npm" | "pnpm" | "yarn" | "cargo" => sub == "publish",
        "twine" => sub == "upload",
        "gem" => sub == "push",
        _ => false,
    };
    publishes.then(|| {
        format!(
            "`{} {sub}` releases a version that registries do not let you withdraw.",
            cmd.program
        )
    })
}

fn push_branches(cmd: &Cmd, ctx: &Ctx) -> Vec<String> {
    let operands = cmd.targets();
    let refspecs: Vec<&String> = if operands.len() > 1 {
        operands[1..].iter().collect()
    } else {
        Vec::new()
    };
    if refspecs.is_empty() {
        return ctx.branch.clone().into_iter().collect();
    }
    refspecs
        .iter()
        .map(|r| {
            let r = r.trim_start_matches('+');
            // A refspec's destination is the half after the colon.
            r.split_once(':')
                .map(|(_, dst)| dst)
                .unwrap_or(r)
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn git_force_push(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || cmd.subcommand() != Some("push") {
        return None;
    }
    let plus_refspec = cmd.targets().iter().any(|o| o.starts_with('+'));
    let lease = cmd.long_flags.contains("force-with-lease");
    if !(cmd.has_flag('f', "force") || lease || plus_refspec) {
        return None;
    }
    let branch = push_branches(cmd, ctx)
        .into_iter()
        .find(|b| ctx.is_protected_branch(b))?;
    let qualifier = if lease {
        " (--force-with-lease still rewrites it)"
    } else {
        ""
    };
    Some(format!(
        "force-pushes to protected branch `{branch}`{qualifier} — commits on the remote can be lost permanently"
    ))
}

fn git_delete_branch(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || cmd.subcommand() != Some("push") {
        return None;
    }
    let colon_deletes: Vec<String> = cmd
        .targets()
        .iter()
        .filter_map(|o| o.strip_prefix(':').map(String::from))
        .collect();
    let deleting = cmd.long_flags.contains("delete") || cmd.short_flags.contains(&'d');
    let candidates: Vec<String> = if deleting {
        push_branches(cmd, ctx)
    } else {
        colon_deletes
    };
    let branch = candidates
        .into_iter()
        .find(|b| ctx.is_protected_branch(b))?;
    Some(format!("deletes protected remote branch `{branch}`"))
}

fn git_reset_hard(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || cmd.subcommand() != Some("reset") {
        return None;
    }
    if !cmd.long_flags.contains("hard") || !ctx.dirty {
        return None;
    }
    Some(
        "`git reset --hard` with uncommitted changes in the worktree — git cannot recover them"
            .into(),
    )
}

fn git_clean_force(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" || cmd.subcommand() != Some("clean") {
        return None;
    }
    let removes_dirs = cmd.short_flags.contains(&'d') || cmd.short_flags.contains(&'x');
    if !(is_forced(cmd) && removes_dirs && ctx.untracked) {
        return None;
    }
    Some("`git clean` would delete untracked files that exist in this worktree, and they are in no commit".into())
}

fn git_history_rewrite(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "git" {
        return None;
    }
    let sub = cmd.subcommand()?;
    if !matches!(sub, "rebase" | "filter-branch" | "filter-repo") {
        return None;
    }
    // Finishing an in-progress rebase rewrites nothing new.
    if ["continue", "abort", "skip", "quit"]
        .iter()
        .any(|f| cmd.long_flags.contains(*f))
    {
        return None;
    }
    let branch = ctx.branch.as_deref()?;
    if !ctx.is_protected_branch(branch) {
        return None;
    }
    Some(format!(
        "`git {sub}` rewrites history on protected branch `{branch}`"
    ))
}

const REMOVERS: &[&str] = &[
    "rm",
    "remove-item",
    "ri",
    "rmdir",
    "rd",
    "del",
    "erase",
    "unlink",
    "shred",
    "srm",
];

fn fs_remove(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if !REMOVERS.contains(&cmd.program.as_str()) {
        return None;
    }
    let recursive = is_recursive(cmd);
    for target in &cmd.operands {
        if target == ">" || target.starts_with('-') {
            continue;
        }
        if ctx.is_root_like(target) {
            return Some(format!(
                "deletes `{target}`, which resolves to a filesystem or home root"
            ));
        }
        if let Some(pattern) = ctx.protected_path(target) {
            return Some(format!(
                "deletes `{target}`, which matches the protected path `{pattern}`"
            ));
        }
        if let Some(pattern) = ctx.system_path(target) {
            return Some(format!(
                "deletes `{target}`, which the operating system owns (`{pattern}`)"
            ));
        }
        if recursive && ctx.outside_repo(target) {
            return Some(format!(
                "recursive delete of `{target}`, which is outside this repository ({})",
                ctx.repo.display()
            ));
        }
    }
    if recursive && is_forced(cmd) && cmd.has_substitution {
        return Some(
            "recursive force-delete whose target comes from a command substitution, so it cannot be checked before it runs".into(),
        );
    }
    None
}

fn fs_disk_destroy(cmd: &Cmd, _: &Pipeline, _: &Ctx) -> Option<String> {
    let destroyer = matches!(
        cmd.program.as_str(),
        "mkfs" | "diskpart" | "format" | "format-volume" | "clear-disk" | "initialize-disk"
    ) || cmd.program.starts_with("mkfs.");
    if destroyer {
        return Some(format!(
            "`{}` reformats or repartitions a device",
            cmd.program
        ));
    }
    if cmd.program == "dd" && cmd.argv.iter().any(|a| a.starts_with("of=/dev/")) {
        return Some("`dd` writing directly to a block device".into());
    }
    None
}

fn fs_credential_write(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    let redirects = redirects_to_file(&cmd.raw)
        || matches!(
            cmd.program.as_str(),
            "tee" | "set-content" | "out-file" | "add-content"
        );
    if !redirects {
        return None;
    }
    for target in &cmd.operands {
        if target == ">" || target == ">>" {
            continue;
        }
        if ctx.control_path(target).is_some() {
            continue;
        }
        if let Some(pattern) = ctx.protected_path(target) {
            return Some(format!(
                "writes to `{target}`, which matches the protected path `{pattern}`"
            ));
        }
    }
    None
}

const SQL_CLIENTS: &[&str] = &[
    "psql",
    "mysql",
    "mariadb",
    "mongo",
    "mongosh",
    "clickhouse-client",
    "cockroach",
    "snowsql",
];

fn sql_destructive(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    // Collapse runs of whitespace before matching. SQL treats `DROP  TABLE` and
    // `DROP TABLE` identically, and a keyword search over the raw text does
    // not — two spaces was enough to walk straight past this rule.
    let upper = cmd
        .raw
        .to_uppercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // An unqualified DELETE empties the table just as surely as TRUNCATE does.
    let unbounded_delete = upper.contains("DELETE FROM") && !upper.contains("WHERE");
    let statement = ["DROP TABLE", "DROP DATABASE", "DROP SCHEMA", "TRUNCATE "]
        .into_iter()
        .find(|kw| upper.contains(kw))
        .or(unbounded_delete.then_some("DELETE FROM without WHERE"))?;
    if !SQL_CLIENTS.contains(&cmd.program.as_str()) {
        return None;
    }
    let markers = &ctx.config.test_dsn_markers;
    let looks_local = cmd.argv.iter().any(|a| {
        markers
            .iter()
            .any(|m| a.to_ascii_lowercase().contains(m.as_str()))
    });
    if looks_local {
        return None;
    }
    Some(format!(
        "`{statement}` via {} with no test/local marker in the connection arguments",
        cmd.program
    ))
}

fn perm_chmod(cmd: &Cmd, _: &Pipeline, ctx: &Ctx) -> Option<String> {
    if cmd.program != "chmod" {
        return None;
    }
    let world_writable = cmd
        .operands
        .iter()
        .any(|o| matches!(o.as_str(), "777" | "0777" | "a+rwx" | "ugo+rwx"));
    if !world_writable {
        return None;
    }
    if is_recursive(cmd) {
        return Some("`chmod -R 777` makes an entire tree world-writable".into());
    }
    let target = cmd.operands.iter().find_map(|o| ctx.sensitive_path(o))?;
    Some(format!("`chmod 777` on a path matching `{target}`"))
}

const DOWNLOADERS: &[&str] = &["curl", "wget", "iwr", "invoke-webrequest", "fetch"];

const DECODERS: &[&str] = &["base64", "base32", "xxd", "uudecode", "openssl"];
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "powershell",
    "pwsh",
    "iex",
    "invoke-expression",
];

/// The host part of a URL-ish argument, lowercased and with any userinfo
/// stripped, so `https://user@evil.test/x` and `evil.test` compare equal.
fn host_of(candidate: &str) -> Option<String> {
    if !candidate.contains("://") && !candidate.contains('.') {
        return None;
    }
    let host = candidate
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(candidate)
        .split('/')
        .next()?
        .to_ascii_lowercase();
    let host = host.split('@').next_back().unwrap_or(&host);
    (!host.is_empty()).then(|| host.to_string())
}

fn host_allowed(host: &str, ctx: &Ctx) -> bool {
    ctx.config
        .allowed_hosts
        .iter()
        .any(|h| glob_match(&h.to_ascii_lowercase(), host))
}

fn net_pipe_to_shell(cmd: &Cmd, pipeline: &Pipeline, ctx: &Ctx) -> Option<String> {
    let downloader = DOWNLOADERS.contains(&cmd.program.as_str());
    let decoder = DECODERS.contains(&cmd.program.as_str());
    if !downloader && !decoder {
        return None;
    }
    let position = pipeline.cmds.iter().position(|c| std::ptr::eq(c, cmd))?;
    let shell = pipeline.cmds[position + 1..]
        .iter()
        .find(|c| SHELLS.contains(&c.program.as_str()))?;

    // A decoder feeding an interpreter has no host to clear, and no allowlist
    // entry can make reconstituted bytes reviewed. There is nothing to check
    // against, so there is nothing that can permit it.
    if decoder {
        return Some(format!(
            "decodes a literal with `{}` and executes the result with `{}` \
             without review; the executed text does not appear in the command",
            cmd.program, shell.program
        ));
    }

    let Some(host) = cmd.operands.iter().find_map(|o| host_of(o)) else {
        return Some(format!(
            "pipes `{}` output into `{}` with a destination this gate cannot \
             resolve, so the host it fetches from is unknown here",
            cmd.program, shell.program
        ));
    };
    if host_allowed(&host, ctx) {
        return None;
    }
    Some(format!(
        "downloads from `{host}`, which this repository does not trust, and executes it with `{}` without review",
        shell.program
    ))
}
