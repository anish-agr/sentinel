use anyhow::{bail, Context, Result};
use sentinel_guard::normalize::{parse, Shell};
use sentinel_store::Store;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// How a tool call could be undone, which is really a question about who can
/// see that it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reversibility {
    /// Changed nothing.
    ReadOnly,
    /// An editor tool wrote a file. The vendor's own checkpointing sees these.
    EditorMutation,
    /// A shell command changed the worktree. Vendor checkpointing does not
    /// track these, so this is the class that is unrecoverable without an
    /// external recorder.
    ShellMutation,
    /// A shell command whose targets are only known at execution time, so
    /// nothing can classify it in advance — including a guard.
    OpaqueShell,
    Unknown,
}

impl Reversibility {
    pub fn label(&self) -> &'static str {
        match self {
            Reversibility::ReadOnly => "read-only",
            Reversibility::EditorMutation => "editor mutation (vendor sees it)",
            Reversibility::ShellMutation => "shell mutation (vendor blind)",
            Reversibility::OpaqueShell => "opaque shell (unknowable in advance)",
            Reversibility::Unknown => "unknown",
        }
    }

    /// Stable machine-readable name, used when a classification has to survive
    /// export into a corpus that no longer carries the payload it came from.
    pub fn key(&self) -> &'static str {
        match self {
            Reversibility::ReadOnly => "read_only",
            Reversibility::EditorMutation => "editor_mutation",
            Reversibility::ShellMutation => "shell_mutation",
            Reversibility::OpaqueShell => "opaque_shell",
            Reversibility::Unknown => "unknown",
        }
    }

    pub fn from_key(key: &str) -> Option<Reversibility> {
        Some(match key {
            "read_only" => Reversibility::ReadOnly,
            "editor_mutation" => Reversibility::EditorMutation,
            "shell_mutation" => Reversibility::ShellMutation,
            "opaque_shell" => Reversibility::OpaqueShell,
            "unknown" => Reversibility::Unknown,
            _ => return None,
        })
    }

    pub fn mutates(&self) -> bool {
        matches!(
            self,
            Reversibility::EditorMutation
                | Reversibility::ShellMutation
                | Reversibility::OpaqueShell
        )
    }
}

/// Programs that change the filesystem. Deliberately broad: for a claim about
/// what vendor checkpointing misses, counting a `chmod` as a mutation is a much
/// smaller error than missing an `rm`.
const MUTATING: &[&str] = &[
    // POSIX
    "rm",
    "rmdir",
    "mv",
    "cp",
    "dd",
    "truncate",
    "shred",
    "ln",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "chgrp",
    "install",
    "tee",
    "patch",
    "unzip",
    "tar",
    "gunzip",
    "rsync",
    "sync",
    // PowerShell
    "remove-item",
    "move-item",
    "copy-item",
    "rename-item",
    "new-item",
    "set-content",
    "add-content",
    "clear-content",
    "out-file",
    "set-itemproperty",
    "expand-archive",
    "compress-archive",
    // Windows shell
    "del",
    "erase",
    "move",
    "copy",
    "rd",
    "md",
    "mklink",
    "xcopy",
    "robocopy",
];

/// Programs whose effect depends entirely on a subcommand, so the program name
/// alone says nothing.
fn subcommand_mutates(program: &str, sub: Option<&str>) -> Option<bool> {
    let sub = sub.unwrap_or("");
    match program {
        "git" => Some(matches!(
            sub,
            "checkout"
                | "reset"
                | "clean"
                | "restore"
                | "rm"
                | "mv"
                | "stash"
                | "apply"
                | "revert"
                | "merge"
                | "rebase"
                | "pull"
                | "switch"
                | "cherry-pick"
        )),
        "npm" | "yarn" | "pnpm" | "bun" => Some(matches!(
            sub,
            "install" | "i" | "ci" | "add" | "remove" | "uninstall" | "link"
        )),
        "pip" | "pip3" => Some(matches!(sub, "install" | "uninstall")),
        "cargo" => Some(matches!(
            sub,
            "clean" | "install" | "add" | "remove" | "fix" | "fmt"
        )),
        "make" | "gradle" | "mvn" => Some(true),
        "sed" | "perl" => None, // decided by flags, handled by the caller
        _ => None,
    }
}

const EDITOR_TOOLS: &[&str] = &["write", "edit", "multiedit", "notebookedit"];

/// Classifies one recorded call. `input` is the full argument payload from the
/// blob store, not the truncated summary — a `rm -rf` past the 200-character
/// cut would otherwise read as harmless.
pub fn classify(tool: &str, input: &Value) -> Reversibility {
    let lower = tool.to_ascii_lowercase();
    if EDITOR_TOOLS.contains(&lower.as_str()) {
        return Reversibility::EditorMutation;
    }
    let shell = match lower.as_str() {
        "bash" => Shell::Posix,
        "powershell" => Shell::PowerShell,
        _ => return Reversibility::ReadOnly,
    };
    let Some(command) = input.get("command").and_then(Value::as_str) else {
        return Reversibility::Unknown;
    };

    let mut opaque = false;
    for pipeline in parse(command, shell) {
        for cmd in &pipeline.cmds {
            let program = cmd.program.to_ascii_lowercase();

            // A redirect writes a file whatever the program is.
            if cmd.raw.contains('>') {
                return Reversibility::ShellMutation;
            }
            if MUTATING.contains(&program.as_str()) {
                return Reversibility::ShellMutation;
            }
            match subcommand_mutates(&program, cmd.subcommand()) {
                Some(true) => return Reversibility::ShellMutation,
                Some(false) => continue,
                None => {}
            }
            // In-place edit flags turn a filter into a mutation.
            if matches!(program.as_str(), "sed" | "perl" | "ruby") && cmd.has_flag('i', "in-place")
            {
                return Reversibility::ShellMutation;
            }
            // `find -delete`, `xargs rm`, and friends.
            if program == "find" && cmd.long_flags.iter().any(|f| f == "delete") {
                return Reversibility::ShellMutation;
            }
            if cmd.has_substitution || cmd.has_variable {
                opaque = true;
            }
        }
    }
    if opaque {
        return Reversibility::OpaqueShell;
    }
    Reversibility::ReadOnly
}

/// What the agent did next after the guard stopped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Response {
    /// Cleared the block and the command went through.
    Overrode,
    /// Ran the identical command again without changing anything.
    RetriedIdentical,
    /// Same tool, different arguments — the denial redirected the work.
    Rewrote,
    /// Tripped a rule again on the next attempt.
    BlockedAgain,
    /// Moved on to something unrelated.
    Abandoned,
    /// The session ended before it did anything else.
    EndOfRun,
}

impl Response {
    pub fn label(&self) -> &'static str {
        match self {
            Response::Overrode => "overrode the block",
            Response::RetriedIdentical => "retried the identical command",
            Response::Rewrote => "rewrote the command",
            Response::BlockedAgain => "was blocked again",
            Response::Abandoned => "abandoned the attempt",
            Response::EndOfRun => "run ended",
        }
    }
}

pub struct Denial {
    pub rule: String,
    pub summary: String,
    pub response: Response,
}

pub struct DetectorOutcome {
    pub detector: String,
    /// Whether the behaviour the detector complained about stopped afterwards.
    pub behaviour_changed: Option<bool>,
}

#[derive(Default)]
pub struct Analysis {
    pub reversibility: BTreeMap<Reversibility, usize>,
    pub unrecoverable_payloads: usize,
    pub denials: Vec<Denial>,
    pub detectors: Vec<DetectorOutcome>,
    pub runs: usize,
}

impl Analysis {
    pub fn mutating(&self) -> usize {
        self.reversibility
            .iter()
            .filter(|(k, _)| k.mutates())
            .map(|(_, n)| n)
            .sum()
    }

    /// The motivation number: of everything that changed the worktree, how much
    /// did an editor tool do — and therefore how much can the vendor undo.
    pub fn vendor_blind_share(&self) -> Option<f64> {
        let mutating = self.mutating();
        if mutating == 0 {
            return None;
        }
        let blind = self
            .reversibility
            .iter()
            .filter(|(k, _)| matches!(k, Reversibility::ShellMutation | Reversibility::OpaqueShell))
            .map(|(_, n)| n)
            .sum::<usize>();
        Some(blind as f64 / mutating as f64)
    }

    pub fn responses(&self) -> BTreeMap<Response, usize> {
        let mut counts = BTreeMap::new();
        for d in &self.denials {
            *counts.entry(d.response).or_insert(0) += 1;
        }
        counts
    }

    pub fn detector_summary(&self) -> BTreeMap<String, (usize, usize)> {
        let mut out: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for d in &self.detectors {
            let entry = out.entry(d.detector.clone()).or_default();
            entry.0 += 1;
            if d.behaviour_changed == Some(true) {
                entry.1 += 1;
            }
        }
        out
    }
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn step(v: &Value) -> u64 {
    v["step"].as_u64().unwrap_or(0)
}

/// How many calls after a denial to look before calling it abandoned. Short on
/// purpose: an agent that comes back to the same command twenty steps later is
/// doing something different from one that immediately retries.
const RESPONSE_WINDOW: usize = 6;

/// Analyses every `events.jsonl` under `dir`, so corpora exported from several
/// machines can be concatenated and studied together. One developer is a case
/// study; the questions worth asking need more than one.
pub fn from_corpus(dir: &Path) -> Result<Analysis> {
    let mut events = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            let nested = path.join("events.jsonl");
            if nested.is_file() {
                files.push(nested);
            }
        } else if path.file_name().is_some_and(|n| n == "events.jsonl") {
            files.push(path);
        }
    }
    if files.is_empty() {
        bail!("no events.jsonl found in {}", dir.display());
    }
    for file in &files {
        for line in fs::read_to_string(file)?.lines() {
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                events.push(value);
            }
        }
    }
    analyse(events, None)
}

pub fn run(store: &Store, limit: u32) -> Result<Analysis> {
    let events = store.events_json(None, limit)?;
    analyse(events, Some(store))
}

fn analyse(events: Vec<Value>, store: Option<&Store>) -> Result<Analysis> {
    let mut analysis = Analysis::default();

    // Group by run so ordering questions ("what happened next") stay inside the
    // session they belong to.
    let mut by_run: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for e in &events {
        by_run
            .entry(text(&e["run_id"]).to_string())
            .or_default()
            .push(e);
    }
    analysis.runs = by_run.len();

    for (_, mut run_events) in by_run {
        run_events.sort_by_key(|e| step(e));

        let mut command_at: BTreeMap<u64, String> = BTreeMap::new();
        for event in &run_events {
            if text(&event["kind"]) != "tool_call" {
                continue;
            }
            let tool = text(&event["tool"]);
            let payload = store.and_then(|s| {
                event["args_hash"]
                    .as_str()
                    .and_then(|h| s.cas.get(h).ok())
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            });
            let class = match (&payload, event["reversibility"].as_str()) {
                (Some(input), _) => {
                    if let Some(c) = input.get("command").and_then(Value::as_str) {
                        command_at.insert(step(event), c.to_string());
                    }
                    classify(tool, input)
                }
                // Exported corpus: trust the label computed where the payload
                // still existed, and fall back to the summary for comparisons.
                (None, Some(key)) => {
                    let summary = text(&event["args_summary"]);
                    if !summary.is_empty() {
                        command_at.insert(step(event), summary.to_string());
                    }
                    Reversibility::from_key(key).unwrap_or(Reversibility::Unknown)
                }
                (None, None) => {
                    analysis.unrecoverable_payloads += 1;
                    Reversibility::Unknown
                }
            };
            *analysis.reversibility.entry(class).or_insert(0) += 1;
        }

        for (i, event) in run_events.iter().enumerate() {
            match text(&event["kind"]) {
                "guard_decision" if text(&event["meta"]["verdict"]) != "overridden" => {
                    let denied_command = run_events[..i]
                        .iter()
                        .rev()
                        .find(|e| text(&e["kind"]) == "tool_call")
                        .and_then(|e| command_at.get(&step(e)))
                        .cloned()
                        .unwrap_or_default();
                    analysis.denials.push(Denial {
                        rule: text(&event["meta"]["rule"]).to_string(),
                        summary: text(&event["args_summary"]).to_string(),
                        response: classify_response(
                            &run_events[i + 1..],
                            &denied_command,
                            text(&event["tool"]),
                            &command_at,
                        ),
                    });
                }
                "detection" => {
                    let detector = text(&event["meta"]["detector"]).to_string();
                    // The state hash rides on checkpoints, not on the finding
                    // itself, so "the state when this fired" is the most recent
                    // checkpoint before it.
                    let state_before = run_events[..i]
                        .iter()
                        .rev()
                        .find_map(|e| e["repo_state_hash"].as_str())
                        .map(str::to_string);
                    analysis.detectors.push(DetectorOutcome {
                        behaviour_changed: behaviour_changed(
                            &detector,
                            event,
                            state_before.as_deref(),
                            &run_events[i + 1..],
                        ),
                        detector,
                    });
                }
                _ => {}
            }
        }
    }

    Ok(analysis)
}

fn classify_response(
    after: &[&Value],
    denied_command: &str,
    denied_tool: &str,
    command_at: &BTreeMap<u64, String>,
) -> Response {
    let mut seen = 0;
    for (i, event) in after.iter().enumerate() {
        match text(&event["kind"]) {
            "guard_decision" if text(&event["meta"]["verdict"]) == "overridden" => {
                return Response::Overrode
            }
            "guard_decision" => return Response::BlockedAgain,
            "tool_call" => {
                let command = command_at
                    .get(&step(event))
                    .map(String::as_str)
                    .unwrap_or("");
                if !denied_command.is_empty() && command == denied_command {
                    let overridden = after.get(i + 1).is_some_and(|next| {
                        text(&next["kind"]) == "guard_decision"
                            && text(&next["meta"]["verdict"]) == "overridden"
                    });
                    return if overridden {
                        Response::Overrode
                    } else {
                        Response::RetriedIdentical
                    };
                }
                // Clearing the block is part of overriding, not a new attempt;
                // counting it as unrelated work would hide the override that
                // follows one step later.
                if command.contains("sentinel") && command.contains("allow") {
                    continue;
                }
                if text(&event["tool"]) == denied_tool {
                    return Response::Rewrote;
                }
                seen += 1;
                if seen >= RESPONSE_WINDOW {
                    return Response::Abandoned;
                }
            }
            _ => {}
        }
    }
    if seen == 0 {
        Response::EndOfRun
    } else {
        Response::Abandoned
    }
}

const EFFECT_WINDOW: usize = 8;

fn behaviour_changed(
    detector: &str,
    event: &Value,
    state_before: Option<&str>,
    after: &[&Value],
) -> Option<bool> {
    if after.is_empty() {
        return None;
    }
    // The window is counted in tool calls but keeps every event inside it:
    // repo state hashes ride on checkpoints, so filtering to calls alone would
    // discard the very evidence the state-based detectors are judged on.
    let mut calls = 0;
    let mut window: Vec<&Value> = Vec::new();
    for event in after {
        if text(&event["kind"]) == "tool_call" {
            calls += 1;
            if calls > EFFECT_WINDOW {
                break;
            }
        }
        window.push(event);
    }
    if window.is_empty() {
        return None;
    }
    let after = &window[..];
    match detector {
        // These two complain that the repository is not changing, so the
        // question is whether it changed afterwards.
        "no_progress" | "repeat_state" => {
            let mut saw_state = false;
            let changed = after
                .iter()
                .filter_map(|e| e["repo_state_hash"].as_str())
                .inspect(|_| saw_state = true)
                .any(|h| Some(h) != state_before);
            // No checkpoint inside the window means the repository was never
            // re-measured, so the log genuinely cannot say whether it changed.
            saw_state.then_some(changed)
        }
        // Complains that one file is being re-read. Did reading it continue?
        "redundant_reads" => {
            let files: Vec<&str> = event["meta"]["evidence_steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_u64())
                .filter_map(|target| {
                    after
                        .iter()
                        .chain(std::iter::once(&event))
                        .find(|e| step(e) == target)
                        .and_then(|e| e["files_touched"].as_array())
                        .and_then(|f| f.first())
                        .and_then(Value::as_str)
                })
                .collect();
            let file = files.first()?;
            let reread = after.iter().any(|e| {
                text(&e["kind"]) == "tool_call"
                    && text(&e["tool"]).eq_ignore_ascii_case("read")
                    && e["files_touched"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|f| text(f) == *file))
            });
            Some(!reread)
        }
        "error_identity" => {
            let hash = event["stderr_norm_hash"].as_str();
            let recurred = after
                .iter()
                .filter_map(|e| e["stderr_norm_hash"].as_str())
                .any(|h| Some(h) == hash);
            Some(!recurred)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn shell(command: &str) -> Reversibility {
        classify("Bash", &json!({ "command": command }))
    }

    #[test]
    fn editor_writes_are_visible_to_the_vendor() {
        assert_eq!(
            classify("Edit", &json!({"file_path": "a.rs"})),
            Reversibility::EditorMutation
        );
        assert_eq!(
            classify("Write", &json!({"file_path": "a.rs"})),
            Reversibility::EditorMutation
        );
    }

    #[test]
    fn shell_mutations_are_not() {
        assert_eq!(shell("rm -rf build/"), Reversibility::ShellMutation);
        assert_eq!(shell("mv a.txt b.txt"), Reversibility::ShellMutation);
        assert_eq!(shell("echo hi > out.txt"), Reversibility::ShellMutation);
        assert_eq!(shell("sed -i 's/a/b/' f.txt"), Reversibility::ShellMutation);
        assert_eq!(shell("git checkout -- ."), Reversibility::ShellMutation);
    }

    #[test]
    fn reading_and_inspecting_is_not_a_mutation() {
        assert_eq!(shell("ls -la"), Reversibility::ReadOnly);
        assert_eq!(shell("git status"), Reversibility::ReadOnly);
        assert_eq!(shell("grep -r foo src/"), Reversibility::ReadOnly);
        assert_eq!(shell("sed 's/a/b/' f.txt"), Reversibility::ReadOnly);
        assert_eq!(
            classify("Read", &json!({"file_path": "a.rs"})),
            Reversibility::ReadOnly
        );
    }

    #[test]
    fn a_command_built_at_runtime_is_opaque_not_safe() {
        // The distinction matters: calling this read-only would understate what
        // an external recorder is for, and calling it a mutation would
        // overstate the case.
        assert_eq!(shell("rm $(cat targets.txt)"), Reversibility::ShellMutation);
        assert_eq!(shell("ls $(cat dirs.txt)"), Reversibility::OpaqueShell);
    }

    #[test]
    fn mutations_hide_behind_pipes_and_chains() {
        assert_eq!(shell("cat f | tee out.txt"), Reversibility::ShellMutation);
        assert_eq!(shell("cd src && rm old.rs"), Reversibility::ShellMutation);
    }

    fn ev(kind: &str, step: u64, tool: &str, hash: &str) -> Value {
        json!({"kind": kind, "step": step, "tool": tool, "args_hash": hash, "args_summary": ""})
    }

    fn commands(pairs: &[(u64, &str)]) -> BTreeMap<u64, String> {
        pairs.iter().map(|(s, c)| (*s, c.to_string())).collect()
    }

    #[test]
    fn an_identical_retry_is_distinguished_from_a_rewrite() {
        let seq = [ev("tool_call", 2, "Bash", "aaa")];
        let refs: Vec<&Value> = seq.iter().collect();
        let map = commands(&[(2, "rm -rf x")]);
        assert_eq!(
            classify_response(&refs, "rm -rf x", "Bash", &map),
            Response::RetriedIdentical
        );

        let map = commands(&[(2, "rm -rf y")]);
        assert_eq!(
            classify_response(&refs, "rm -rf x", "Bash", &map),
            Response::Rewrote
        );
    }

    #[test]
    fn the_same_command_with_a_new_description_is_still_a_retry() {
        // args_hash covers the whole tool input, so this case is exactly what
        // comparing command text rather than payload hash exists to catch.
        let seq = [ev("tool_call", 2, "Bash", "different-hash-entirely")];
        let refs: Vec<&Value> = seq.iter().collect();
        let map = commands(&[(2, "git push --force")]);
        assert_eq!(
            classify_response(&refs, "git push --force", "Bash", &map),
            Response::RetriedIdentical
        );
    }

    #[test]
    fn clearing_the_block_is_not_counted_as_unrelated_work() {
        let seq = [
            ev("tool_call", 2, "Bash", "h1"),
            json!({"kind": "guard_decision", "step": 3, "meta": {"verdict": "overridden"}}),
        ];
        let refs: Vec<&Value> = seq.iter().collect();
        let map = commands(&[(2, "sentinel allow --last --once")]);
        assert_eq!(
            classify_response(&refs, "rm -rf x", "Bash", &map),
            Response::Overrode
        );
    }

    #[test]
    fn an_override_outranks_whatever_follows_it() {
        let seq = [
            json!({"kind": "guard_decision", "step": 2, "meta": {"verdict": "overridden"}}),
            ev("tool_call", 3, "Bash", "aaa"),
        ];
        let refs: Vec<&Value> = seq.iter().collect();
        assert_eq!(
            classify_response(&refs, "x", "Bash", &BTreeMap::new()),
            Response::Overrode
        );
    }

    #[test]
    fn nothing_after_a_denial_is_end_of_run_not_abandonment() {
        assert_eq!(
            classify_response(&[], "aaa", "Bash", &BTreeMap::new()),
            Response::EndOfRun
        );
    }

    #[test]
    fn effect_is_measured_in_a_window_not_to_the_end_of_the_run() {
        let state =
            |s: u64, hash: &str| json!({"kind": "tool_call", "step": s, "repo_state_hash": hash});
        let finding = json!({"kind": "detection", "step": 1});

        // A change far beyond the window must not count as an effect, or every
        // detector scores well simply because sessions eventually move on.
        let mut late: Vec<Value> = (2..14).map(|s| state(s, "same")).collect();
        late.push(state(20, "different"));
        let refs: Vec<&Value> = late.iter().collect();
        assert_eq!(
            behaviour_changed("no_progress", &finding, Some("same"), &refs),
            Some(false)
        );

        let prompt = [state(2, "different")];
        let refs: Vec<&Value> = prompt.iter().collect();
        assert_eq!(
            behaviour_changed("no_progress", &finding, Some("same"), &refs),
            Some(true)
        );
    }

    #[test]
    fn no_checkpoint_in_the_window_means_unknown_not_unchanged() {
        // Scoring this as "behaviour did not change" would blame the detector
        // for the recorder not having measured anything yet.
        let finding = json!({"kind": "detection", "step": 1});
        let quiet = [json!({"kind": "tool_call", "step": 2})];
        let refs: Vec<&Value> = quiet.iter().collect();
        assert_eq!(
            behaviour_changed("no_progress", &finding, Some("same"), &refs),
            None
        );
    }
}
