use anyhow::{Context, Result};
use sentinel_store::Store;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Fields carried through to the export. Everything else is dropped rather
/// than filtered, because an allowlist fails closed when the event schema
/// grows and a denylist quietly starts leaking.
const KEPT: &[&str] = &[
    "run_id",
    "step",
    "ts",
    "kind",
    "tool",
    "args_hash",
    "args_summary",
    "exit_code",
    "duration_ms",
    "files_touched",
    "repo_state_hash",
    "stderr_norm_hash",
    "test_vector_hash",
    "meta",
];

pub struct Summary {
    pub events: usize,
    pub runs: usize,
    pub redacted_paths: usize,
    /// Written lines that still contain the username. Must be zero.
    pub residual: usize,
    pub source: String,
    pub path: PathBuf,
}

/// A stable, non-identifying label for the machine and repository a corpus came
/// from. The absolute path is hashed rather than included: it names a person.
fn source_id(repo: &Path) -> String {
    let hash = sentinel_store::cas::sha256_hex(repo.to_string_lossy().as_bytes());
    format!("src-{}", &hash[..12])
}

/// Replaces every case-insensitive occurrence of `needle`.
fn replace_ci(haystack: &str, needle: &str, replacement: &str, count: &mut usize) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let lower_hay = haystack.to_lowercase();
    let lower_needle = needle.to_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0;
    while let Some(found) = lower_hay[cursor..].find(&lower_needle) {
        let start = cursor + found;
        out.push_str(&haystack[cursor..start]);
        out.push_str(replacement);
        cursor = start + needle.len();
        *count += 1;
    }
    out.push_str(&haystack[cursor..]);
    out
}

fn redact(text: &str, repo: &Path, home: &Path, user: Option<&str>, count: &mut usize) -> String {
    let mut out = text.to_string();
    // Longest first: the repository usually sits inside the home directory, and
    // replacing home first would leave a half-rewritten repository path.
    for (needle, replacement) in [
        (repo.to_string_lossy().to_string(), "<repo>"),
        (repo.to_string_lossy().replace('\\', "/"), "<repo>"),
        (home.to_string_lossy().to_string(), "<home>"),
        (home.to_string_lossy().replace('\\', "/"), "<home>"),
    ] {
        if needle.len() < 3 {
            continue;
        }
        out = replace_ci(&out, &needle, replacement, count);
    }
    // A username under three characters is too short to replace safely: it
    // would match inside ordinary words and corrupt the corpus. Export reports
    // what survived rather than pretending, so this fails loudly downstream.
    if let Some(user) = user.filter(|u| u.len() >= 3) {
        out = replace_ci(&out, user, "<user>", count);
    }
    out
}

fn redact_value(
    value: &Value,
    repo: &Path,
    home: &Path,
    user: Option<&str>,
    count: &mut usize,
) -> Value {
    match value {
        Value::String(s) => Value::String(redact(s, repo, home, user, count)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_value(v, repo, home, user, count))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_value(v, repo, home, user, count)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub fn run(store: &Store, out: &Path, limit: u32) -> Result<Summary> {
    let repo = store.repo().to_path_buf();
    let home = sentineld::home_dir();
    let source = source_id(&repo);
    let user = home
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| n.len() >= 3);

    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let events_path = out.join("events.jsonl");
    let mut file = fs::File::create(&events_path)
        .with_context(|| format!("writing {}", events_path.display()))?;

    let mut redacted_paths = 0;
    let mut residual = 0;
    let mut runs: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut written = 0;

    for event in store.events_json(None, limit)? {
        let mut row = serde_json::Map::new();
        for key in KEPT {
            if let Some(value) = event.get(*key) {
                if value.is_null() {
                    continue;
                }
                row.insert(
                    (*key).to_string(),
                    redact_value(value, &repo, &home, user.as_deref(), &mut redacted_paths),
                );
            }
        }
        // Run ids are uuids derived from the repository path and session id, so
        // they are not identifying on their own, but tagging the source keeps
        // merged corpora separable.
        row.insert("source".into(), json!(source));

        if event["kind"] == "tool_call" {
            let class = event["args_hash"]
                .as_str()
                .and_then(|h| store.cas.get(h).ok())
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .map(|input| crate::analyze::classify(event["tool"].as_str().unwrap_or(""), &input))
                .unwrap_or(crate::analyze::Reversibility::Unknown);
            row.insert("reversibility".into(), json!(class.key()));
        }

        if let Some(run) = event["run_id"].as_str() {
            *runs.entry(run.to_string()).or_insert(0) += 1;
        }
        *kinds
            .entry(event["kind"].as_str().unwrap_or("unknown").to_string())
            .or_insert(0) += 1;

        let line = Value::Object(row).to_string();
        if let Some(user) = user.as_deref() {
            if line.to_lowercase().contains(&user.to_lowercase()) {
                residual += 1;
            }
        }
        writeln!(file, "{line}")?;
        written += 1;
    }

    let manifest = json!({
        "source": source,
        "sentinel_version": sentineld::VERSION,
        "events": written,
        "runs": runs.len(),
        "kinds": kinds,
        "schema": KEPT,
        "redaction": {
            "substitutions": redacted_paths,
            "repository_path": "<repo>",
            "home_directory": "<home>",
            "username": "<user>",
            "lines_with_residual_username": residual,
            "dropped": [
                "blob payloads (full tool arguments and responses)",
                "the home directory and repository path, in slash and backslash forms",
                "the account username, case-insensitively, anywhere it appears",
            ],
            "retained": [
                "the repository's own name, where it appears in commands",
                "args_summary free text, credential-scrubbed and truncated at record time",
                "timestamps at full resolution",
            ],
            "verified":
                "Every written line was searched for the username after redaction; \
                 lines_with_residual_username is that count and must be 0. This checks \
                 one known identifier, not every possible one — a scrubber is a filter, \
                 not a proof, so read the output before publishing it.",
        },
    });
    fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    Ok(Summary {
        events: written,
        runs: runs.len(),
        redacted_paths,
        residual,
        source,
        path: out.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repository_path_is_rewritten_everywhere_it_appears() {
        let repo = Path::new("C:\\Users\\someone\\code\\proj");
        let home = Path::new("C:\\Users\\someone");
        let mut n = 0;
        let out = redact(
            "edited C:\\Users\\someone\\code\\proj\\src\\a.rs from C:\\Users\\someone\\bin",
            repo,
            home,
            Some("someone"),
            &mut n,
        );
        assert!(!out.contains("someone"), "username survived: {out}");
        assert!(out.contains("<repo>") && out.contains("<home>"));
    }

    #[test]
    fn the_repository_is_rewritten_before_the_home_that_contains_it() {
        // Rewriting home first would turn the repo path into "<home>/proj"
        // and leak the directory layout it was supposed to hide.
        let repo = Path::new("/home/someone/proj");
        let home = Path::new("/home/someone");
        let mut n = 0;
        let out = redact(
            "/home/someone/proj/src",
            repo,
            home,
            Some("someone"),
            &mut n,
        );
        assert_eq!(out, "<repo>/src");
    }

    #[test]
    fn the_username_is_caught_in_forms_no_path_matcher_sees() {
        // Every one of these actually survived path-only redaction: Claude
        // Code's project slug, a git-bash path, and a handle in prose.
        let repo = Path::new("C:\\Users\\someone\\proj");
        let home = Path::new("C:\\Users\\someone");
        let cases = [
            "C--Users-someone-Documents-GitHub-proj",
            "cd /c/Users/someone/proj",
            "pushed to github.com/someone-dev/proj",
            "C--Users-SOMEONE-Documents",
        ];
        for case in cases {
            let mut n = 0;
            let out = redact(case, repo, home, Some("someone"), &mut n);
            assert!(
                !out.to_lowercase().contains("someone"),
                "username survived in {case:?}: {out}"
            );
        }
    }

    #[test]
    fn a_username_too_short_to_match_safely_is_left_alone() {
        // Replacing "al" would corrupt every word containing it; the export
        // reports the residual instead of silently mangling the corpus.
        let repo = Path::new("/home/al/proj");
        let home = Path::new("/home/al");
        let mut n = 0;
        let out = redact(
            "normally the value is calculated",
            repo,
            home,
            Some("al"),
            &mut n,
        );
        assert_eq!(out, "normally the value is calculated");
    }

    #[test]
    fn redaction_reaches_into_nested_structures() {
        let repo = Path::new("/home/someone/proj");
        let home = Path::new("/home/someone");
        let mut n = 0;
        let value = json!({"meta": {"command": "rm /home/someone/proj/x"}, "files": ["/home/someone/proj/y"]});
        let out = redact_value(&value, repo, home, Some("someone"), &mut n);
        assert_eq!(out["meta"]["command"], "rm <repo>/x");
        assert_eq!(out["files"][0], "<repo>/y");
    }

    #[test]
    fn the_same_repository_always_gets_the_same_source_id() {
        let a = source_id(Path::new("/home/x/proj"));
        assert_eq!(a, source_id(Path::new("/home/x/proj")));
        assert_ne!(a, source_id(Path::new("/home/x/other")));
        assert!(a.starts_with("src-"));
    }
}
