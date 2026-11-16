//! Deterministic detectors. No ML, no thresholds that need tuning, and they
//! never block — they annotate the timeline and say why.

use sentinel_events::{DetectionMeta, Event, EventKind};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Strips the parts of an error message that change between otherwise
/// identical failures, so "the same error again" can be recognised by hash.
pub fn normalize_stderr(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.lines() {
        let mut token = String::new();
        for word in line.split_whitespace() {
            let w = strip_volatile(word);
            if !token.is_empty() {
                token.push(' ');
            }
            token.push_str(&w);
        }
        out.push_str(token.trim());
        out.push('\n');
    }
    out.trim().to_string()
}

fn strip_volatile(word: &str) -> String {
    let looks_hex = word.len() >= 6
        && word.starts_with("0x")
        && word[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if looks_hex {
        return "<addr>".into();
    }
    if word.bytes().all(|b| b.is_ascii_digit()) && word.len() >= 4 {
        return "<num>".into();
    }
    // Absolute paths differ per machine and per checkout; keep the file name.
    if word.contains('/') || word.contains('\\') {
        let tail = word.rsplit(['/', '\\']).next().unwrap_or(word);
        if word.starts_with('/') || word.contains(":\\") || word.contains(":/") {
            return format!("<path>/{tail}");
        }
    }
    // Timestamps like 12:34:56 or 2026-08-07
    let digits = word.bytes().filter(|b| b.is_ascii_digit()).count();
    if digits >= 4 && word.bytes().any(|b| b == b':' || b == b'-') && digits * 2 >= word.len() {
        return "<time>".into();
    }
    word.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectionKey {
    pub detector: &'static str,
    pub subject: String,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub key: DetectionKey,
    pub meta: DetectionMeta,
}

pub fn detector_ids() -> &'static [&'static str] {
    &[
        "repeat_state",
        "error_identity",
        "redundant_reads",
        "repeated_command",
        "test_oscillation",
        "no_progress",
        "no_tests_run",
    ]
}

/// Runs every detector over one run's events. Pure and cheap, so the daemon can
/// call it after each append.
pub fn detect(events: &[Event]) -> Vec<Detection> {
    let mut out = Vec::new();
    out.extend(repeat_state(events));
    out.extend(error_identity(events));
    out.extend(redundant_reads(events));
    out.extend(repeated_command(events));
    out.extend(test_oscillation(events));
    out.extend(no_progress(events));
    out
}

const STALL_THRESHOLD: usize = 12;

/// Work without change. State-hash equality only catches an agent that retypes
/// the same thing; this catches one that keeps trying different things and gets
/// nowhere, which no amount of similarity matching would reveal.
fn no_progress(events: &[Event]) -> Vec<Detection> {
    let mut changed_at = 0;
    let mut current: Option<&str> = None;
    for ev in events {
        if let Some(hash) = ev.repo_state_hash.as_deref() {
            if current != Some(hash) {
                current = Some(hash);
                changed_at = ev.step;
            }
        }
    }
    let since: Vec<u64> = events
        .iter()
        .filter(|e| e.kind == EventKind::ToolCall && e.step > changed_at)
        .map(|e| e.step)
        .collect();
    if since.len() < STALL_THRESHOLD {
        return Vec::new();
    }
    vec![Detection {
        key: DetectionKey {
            detector: "no_progress",
            subject: changed_at.to_string(),
        },
        meta: DetectionMeta {
            detector: "no_progress".into(),
            message: format!(
                "{} tool calls since step {changed_at} and the repository is byte-for-byte unchanged. Whatever is being attempted is not landing.",
                since.len()
            ),
            evidence_steps: since,
        },
    }]
}

const TEST_RUNNERS: &[&str] = &[
    "pytest",
    "cargo test",
    "npm test",
    "npm run test",
    "yarn test",
    "pnpm test",
    "jest",
    "vitest",
    "go test",
    "mvn test",
    "gradle test",
    "rspec",
    "phpunit",
    "dotnet test",
    "ctest",
    "tox",
    "unittest",
    "bun test",
    "swift test",
];

pub fn is_test_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    TEST_RUNNERS.iter().any(|r| lower.contains(r))
}

pub fn failing_tests(output: &str) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut recognised = false;

    for line in output.lines() {
        let line = line.trim();

        // cargo test / go test: "test foo::bar ... FAILED", "--- FAIL: TestFoo"
        if let Some(rest) = line.strip_prefix("--- FAIL:") {
            recognised = true;
            if let Some(name) = rest.split_whitespace().next() {
                names.push(name.to_string());
            }
        } else if line.starts_with("test ") && line.contains("... FAILED") {
            recognised = true;
            if let Some(name) = line
                .strip_prefix("test ")
                .and_then(|r| r.split_whitespace().next())
            {
                names.push(name.to_string());
            }
        }
        // pytest: "FAILED tests/test_x.py::test_name - AssertionError"
        else if let Some(rest) = line.strip_prefix("FAILED ") {
            recognised = true;
            if let Some(name) = rest.split_whitespace().next() {
                names.push(name.to_string());
            }
        }
        // jest / vitest: "✕ renders the header", "● Suite > case"
        else if let Some(rest) = line.strip_prefix('✕').or_else(|| line.strip_prefix('×')) {
            recognised = true;
            let name = rest.trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
        // Summary lines prove this was a test run even when every test passed.
        else if line.starts_with("test result:")
            || line.contains(" passed")
            || line.starts_with("OK ")
            || line == "PASS"
        {
            recognised = true;
        }
    }

    if !recognised {
        return None;
    }
    names.sort();
    names.dedup();
    Some(names)
}

/// A stable identity for one test run's failure set.
pub fn test_vector_hash(output: &str) -> Option<String> {
    let failing = failing_tests(output)?;
    let mut h = Sha256::new();
    for name in &failing {
        h.update(name.as_bytes());
        h.update(b"\n");
    }
    Some(format!("{:x}", h.finalize()))
}

/// Checks that hold only once a session is over. Purely factual: whether a test
/// command ran at all is a matter of record, not of interpretation.
pub fn session_end(events: &[Event]) -> Vec<Detection> {
    let edited: Vec<u64> = events
        .iter()
        .filter(|e| e.kind == EventKind::ToolResult && !e.files_touched.is_empty())
        .map(|e| e.step)
        .collect();
    let tested = events
        .iter()
        .any(|e| e.args_summary.as_deref().is_some_and(is_test_command));
    if edited.is_empty() || tested {
        return Vec::new();
    }
    vec![Detection {
        key: DetectionKey {
            detector: "no_tests_run",
            subject: "session".into(),
        },
        meta: DetectionMeta {
            detector: "no_tests_run".into(),
            message: format!(
                "This session changed files at {} step(s) but never ran a test command. Nothing here has been executed.",
                edited.len()
            ),
            evidence_steps: edited,
        },
    }]
}

/// The same command run over and over. Unlike a repeated read this usually means
/// the agent is waiting for a different answer from an identical question.
fn repeated_command(events: &[Event]) -> Vec<Detection> {
    let mut seen: HashMap<&str, (Vec<u64>, &str)> = HashMap::new();
    for ev in events {
        if ev.kind != EventKind::ToolCall {
            continue;
        }
        if !matches!(
            ev.tool.as_deref().map(str::to_ascii_lowercase).as_deref(),
            Some("bash") | Some("powershell")
        ) {
            continue;
        }
        if let Some(hash) = ev.args_hash.as_deref() {
            let entry = seen
                .entry(hash)
                .or_insert_with(|| (Vec::new(), ev.args_summary.as_deref().unwrap_or("")));
            entry.0.push(ev.step);
        }
    }
    seen.into_values()
        .filter(|(steps, _)| steps.len() >= 3)
        .map(|(steps, summary)| Detection {
            key: DetectionKey {
                detector: "repeated_command",
                subject: summary.to_string(),
            },
            meta: DetectionMeta {
                detector: "repeated_command".into(),
                message: format!(
                    "`{summary}` has been run {} times unchanged (steps {}). If the answer has not changed, neither will it this time.",
                    steps.len(),
                    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
                ),
                evidence_steps: steps,
            },
        })
        .collect()
}

/// The repo returned to a state it has already been in — the agent is going in
/// circles rather than converging.
fn repeat_state(events: &[Event]) -> Vec<Detection> {
    // Consecutive identical states are collapsed first: a run of read-only
    // commands leaves the repo unchanged, which is normal and not a loop. What
    // matters is coming *back* to a state after leaving it.
    let mut sequence: Vec<(u64, &str)> = Vec::new();
    for ev in events {
        if let Some(hash) = ev.repo_state_hash.as_deref() {
            if sequence.last().map(|(_, h)| *h) != Some(hash) {
                sequence.push((ev.step, hash));
            }
        }
    }
    let mut seen: HashMap<&str, Vec<u64>> = HashMap::new();
    for (step, hash) in sequence {
        seen.entry(hash).or_default().push(step);
    }
    seen.into_iter()
        .filter(|(_, steps)| steps.len() >= 2)
        .map(|(hash, steps)| Detection {
            key: DetectionKey { detector: "repeat_state", subject: hash.to_string() },
            meta: DetectionMeta {
                detector: "repeat_state".into(),
                message: format!(
                    "The repository returned to an identical state {} times (steps {}). Work since the first visit produced no net change.",
                    steps.len(),
                    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
                ),
                evidence_steps: steps,
            },
        })
        .collect()
}

fn error_identity(events: &[Event]) -> Vec<Detection> {
    let mut seen: HashMap<&str, Vec<u64>> = HashMap::new();
    for ev in events {
        if let Some(hash) = ev.stderr_norm_hash.as_deref() {
            seen.entry(hash).or_default().push(ev.step);
        }
    }
    seen.into_iter()
        .filter(|(_, steps)| steps.len() >= 3)
        .map(|(hash, steps)| Detection {
            key: DetectionKey { detector: "error_identity", subject: hash.to_string() },
            meta: DetectionMeta {
                detector: "error_identity".into(),
                message: format!(
                    "The same error has now occurred {} times (steps {}). The attempts after the first produced no new information.",
                    steps.len(),
                    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
                ),
                evidence_steps: steps,
            },
        })
        .collect()
}

/// Tokens spent re-reading files already read in this session.
fn redundant_reads(events: &[Event]) -> Vec<Detection> {
    let mut reads: HashMap<&str, Vec<u64>> = HashMap::new();
    for ev in events {
        if ev.kind != EventKind::ToolCall {
            continue;
        }
        if !matches!(ev.tool.as_deref(), Some("Read") | Some("read")) {
            continue;
        }
        for file in &ev.files_touched {
            reads.entry(file).or_default().push(ev.step);
        }
    }
    reads
        .into_iter()
        .filter(|(_, steps)| steps.len() >= 3)
        .map(|(file, steps)| Detection {
            key: DetectionKey { detector: "redundant_reads", subject: file.to_string() },
            meta: DetectionMeta {
                detector: "redundant_reads".into(),
                message: format!(
                    "`{file}` has been read {} times in this run (steps {}). Every read after the first costs tokens for content already in context.",
                    steps.len(),
                    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
                ),
                evidence_steps: steps,
            },
        })
        .collect()
}

/// The failing-test set flipping back and forth: fixing A breaks B, fixing B
/// breaks A.
fn test_oscillation(events: &[Event]) -> Vec<Detection> {
    let vectors: Vec<(u64, &str)> = events
        .iter()
        .filter(|e| e.kind == EventKind::TestResult)
        .filter_map(|e| e.test_vector_hash.as_deref().map(|h| (e.step, h)))
        .collect();
    if vectors.len() < 4 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for window in vectors.windows(4) {
        let [a, b, c, d] = window else { continue };
        if a.1 == c.1 && b.1 == d.1 && a.1 != b.1 {
            out.push(Detection {
                key: DetectionKey {
                    detector: "test_oscillation",
                    subject: format!("{}:{}", a.1, b.1),
                },
                meta: DetectionMeta {
                    detector: "test_oscillation".into(),
                    message: "The set of failing tests is alternating between two states — a fix for one group appears to be breaking another.".into(),
                    evidence_steps: vec![a.0, b.0, c.0, d.0],
                },
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_events::run_id;
    use uuid::Uuid;

    #[test]
    fn reads_cargo_test_failures() {
        let out = "\
running 3 tests
test guard::allows_safe ... ok
test guard::blocks_rm ... FAILED
test store::round_trips ... FAILED

test result: FAILED. 1 passed; 2 failed";
        assert_eq!(
            failing_tests(out).unwrap(),
            vec!["guard::blocks_rm", "store::round_trips"]
        );
    }

    #[test]
    fn reads_pytest_and_go_failures() {
        let pytest = "FAILED tests/test_api.py::test_login - AssertionError\n1 failed, 4 passed";
        assert_eq!(
            failing_tests(pytest).unwrap(),
            vec!["tests/test_api.py::test_login"]
        );

        let go = "--- FAIL: TestParse (0.00s)\n--- FAIL: TestEncode (0.01s)\nFAIL";
        assert_eq!(failing_tests(go).unwrap(), vec!["TestEncode", "TestParse"]);
    }

    #[test]
    fn a_green_run_is_an_empty_set_not_a_missing_one() {
        // The distinction is the whole point: an unreadable run must never
        // compare equal to a passing one, or oscillation would be invented
        // out of output the parser simply did not understand.
        let green = "test result: ok. 12 passed; 0 failed";
        assert_eq!(failing_tests(green), Some(Vec::new()));
        assert_eq!(failing_tests("could not find `Cargo.toml`"), None);
    }

    #[test]
    fn the_hash_tracks_which_tests_failed_not_how_many() {
        let a = "test alpha ... FAILED\ntest result: FAILED";
        let b = "test beta ... FAILED\ntest result: FAILED";
        // Same count, different tests — the common case a naive counter misses.
        assert_ne!(test_vector_hash(a), test_vector_hash(b));

        // Order within one run must not change the identity.
        let unordered = "test beta ... FAILED\ntest alpha ... FAILED\ntest result: FAILED";
        let ordered = "test alpha ... FAILED\ntest beta ... FAILED\ntest result: FAILED";
        assert_eq!(test_vector_hash(unordered), test_vector_hash(ordered));
        assert!(test_vector_hash("no test output here").is_none());
    }

    #[test]
    fn oscillation_needs_a_real_alternation() {
        let vector = |step: u64, hash: &str| {
            let mut e = Event::new(Uuid::nil(), step, EventKind::TestResult);
            e.test_vector_hash = Some(hash.into());
            e
        };
        // A -> B -> A -> B is the pattern worth reporting.
        let flapping = vec![
            vector(1, "a"),
            vector(2, "b"),
            vector(3, "a"),
            vector(4, "b"),
        ];
        assert!(!test_oscillation(&flapping).is_empty());

        // Steady progress through different states is not oscillation.
        let converging = vec![
            vector(1, "a"),
            vector(2, "b"),
            vector(3, "c"),
            vector(4, "d"),
        ];
        assert!(test_oscillation(&converging).is_empty());
    }

    fn ev(step: u64, kind: EventKind) -> Event {
        Event::new(run_id("/r", "s"), step, kind)
    }

    #[test]
    fn stderr_normalization_collapses_volatile_parts() {
        let a =
            normalize_stderr("error at /home/author/proj/src/main.rs:12 pid 48213 0x7ffe1234ab");
        let b = normalize_stderr("error at /Users/dev/proj/src/main.rs:12 pid 91827 0x7ffe9999cd");
        assert_eq!(a, b);
    }

    #[test]
    fn different_errors_stay_different() {
        assert_ne!(
            normalize_stderr("cannot find value `foo`"),
            normalize_stderr("cannot find value `bar`")
        );
    }

    #[test]
    fn revisiting_a_repo_state_is_flagged_once_per_state() {
        let mut events = Vec::new();
        for (step, hash) in [(1, "aaa"), (2, "bbb"), (3, "aaa"), (4, "ccc")] {
            let mut e = ev(step, EventKind::Checkpoint);
            e.repo_state_hash = Some(hash.into());
            events.push(e);
        }
        let found = detect(&events);
        let repeats: Vec<_> = found
            .iter()
            .filter(|d| d.key.detector == "repeat_state")
            .collect();
        assert_eq!(repeats.len(), 1);
        assert_eq!(repeats[0].meta.evidence_steps, vec![1, 3]);
    }

    #[test]
    fn the_same_error_three_times_is_flagged_but_twice_is_not() {
        let build = |n: u64| {
            (1..=n)
                .map(|step| {
                    let mut e = ev(step, EventKind::ToolResult);
                    e.exit_code = Some(1);
                    e.stderr_norm_hash = Some("same".into());
                    e
                })
                .collect::<Vec<_>>()
        };
        assert!(detect(&build(2))
            .iter()
            .all(|d| d.key.detector != "error_identity"));
        assert!(detect(&build(3))
            .iter()
            .any(|d| d.key.detector == "error_identity"));
    }

    #[test]
    fn identical_stderr_is_evidence_even_without_an_exit_code() {
        // Tier A gives us no exit code, so repetition is the only signal.
        let events: Vec<Event> = (1..=4)
            .map(|step| {
                let mut e = ev(step, EventKind::ToolResult);
                e.stderr_norm_hash = Some("same".into());
                e
            })
            .collect();
        assert!(detect(&events)
            .iter()
            .any(|d| d.key.detector == "error_identity"));
    }

    #[test]
    fn rerunning_one_command_unchanged_is_flagged() {
        let events: Vec<Event> = (1..=3)
            .map(|step| {
                Event::new(Uuid::nil(), step, EventKind::ToolCall)
                    .tool("Bash")
                    .args("hash-a", "cargo test")
            })
            .collect();
        let found = detect(&events);
        let hit = found
            .iter()
            .find(|d| d.key.detector == "repeated_command")
            .expect("three identical commands should be flagged");
        assert!(hit.meta.message.contains("cargo test"));

        // Different commands are not a loop.
        let varied: Vec<Event> = (1..=3)
            .map(|step| {
                Event::new(Uuid::nil(), step, EventKind::ToolCall)
                    .tool("Bash")
                    .args(format!("hash-{step}"), "cargo test")
            })
            .collect();
        assert!(detect(&varied)
            .iter()
            .all(|d| d.key.detector != "repeated_command"));
    }

    #[test]
    fn repeated_reads_of_one_file_are_attributed() {
        let events: Vec<Event> = (1..=4)
            .map(|step| {
                ev(step, EventKind::ToolCall)
                    .tool("Read")
                    .files(vec!["src/api.rs".into()])
            })
            .collect();
        let d = detect(&events);
        let read = d
            .iter()
            .find(|d| d.key.detector == "redundant_reads")
            .unwrap();
        assert!(read.meta.message.contains("src/api.rs"));
        assert_eq!(read.meta.evidence_steps.len(), 4);
    }

    #[test]
    fn alternating_test_failures_are_flagged() {
        let events: Vec<Event> = [(1, "a"), (2, "b"), (3, "a"), (4, "b")]
            .into_iter()
            .map(|(step, h)| {
                let mut e = Event::new(Uuid::nil(), step, EventKind::TestResult);
                e.test_vector_hash = Some(h.into());
                e
            })
            .collect();
        assert!(detect(&events)
            .iter()
            .any(|d| d.key.detector == "test_oscillation"));
    }

    #[test]
    fn an_unchanged_repo_across_read_only_steps_is_not_a_loop() {
        let events: Vec<Event> = (1..=6)
            .map(|step| {
                let mut e = ev(step, EventKind::Checkpoint);
                e.repo_state_hash = Some("unchanged".into());
                e
            })
            .collect();
        assert!(
            detect(&events)
                .iter()
                .all(|d| d.key.detector != "repeat_state"),
            "consecutive identical states are not a revisit"
        );
    }

    #[test]
    fn effort_without_any_change_is_flagged() {
        let mut events = vec![{
            let mut e = ev(1, EventKind::Checkpoint);
            e.repo_state_hash = Some("stuck".into());
            e
        }];
        events.extend((2..=15).map(|step| ev(step, EventKind::ToolCall).tool("Bash")));
        assert!(detect(&events)
            .iter()
            .any(|d| d.key.detector == "no_progress"));

        // A few calls after a change is just ordinary work.
        assert!(detect(&events[..5])
            .iter()
            .all(|d| d.key.detector != "no_progress"));
    }

    #[test]
    fn editing_without_ever_running_tests_is_reported_at_session_end() {
        let edit = ev(1, EventKind::ToolResult).files(vec!["src/lib.rs".into()]);
        assert!(session_end(std::slice::from_ref(&edit))
            .iter()
            .any(|d| d.key.detector == "no_tests_run"));

        let tested = ev(2, EventKind::ToolCall)
            .tool("Bash")
            .args("h", "cargo test --workspace");
        assert!(session_end(&[edit, tested]).is_empty());
        // A session that changed nothing has nothing to answer for.
        assert!(session_end(&[ev(1, EventKind::ToolCall)]).is_empty());
    }

    #[test]
    fn a_quiet_run_produces_no_detections() {
        let events: Vec<Event> = (1..=10)
            .map(|step| {
                let mut e = ev(step, EventKind::ToolCall).tool("Read");
                e.repo_state_hash = Some(format!("state{step}"));
                e.files_touched = vec![format!("file{step}.rs")];
                e
            })
            .collect();
        assert!(detect(&events).is_empty());
    }
}
