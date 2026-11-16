use std::path::Path;

/// Every file in this crate that CONSTRUCTS a reason string. Enforced against
/// the filesystem by `every_source_that_can_build_a_reason_is_read_by_this_gate`.
const REASON_SOURCES: &[(&str, &str)] = &[
    ("src/rules.rs", include_str!("../src/rules.rs")),
    ("src/lib.rs", include_str!("../src/lib.rs")),
];

/// Read for its field names only: the `guard.toml` keys the gate forbids a
/// reason from naming are whatever `GuardConfig` declares.
const CONFIG_SRC: &str = include_str!("../src/config.rs");

/// Evidence that a file builds a refusal reason rather than merely handling
/// one. Matched against code with comments and string bodies removed.
const REASON_MARKERS: &[&str] = &["-> Option<String>", "Decision {", "decide(", "reason:"];

/// The override, still forbidden by name. This is no longer the detector — it
/// is the floor under it.
const OVERRIDE_SURFACE: &[&str] = &[
    "sentinel allow",
    "allow --last",
    "allow --once",
    "guard.toml",
];

#[rustfmt::skip]
const OPENERS: &[&str] = &[
    // determiners, pronouns, quantifiers
    "the", "a", "an", "this", "that", "these", "those", "it", "its", "they",
    "them", "their", "there", "here", "no", "none", "nothing", "nobody", "any",
    "every", "each", "both", "either", "neither", "what", "whatever",
    // relatives, conjunctions, connectives
    "which", "who", "whose", "whom", "when", "where", "while", "and", "or",
    "but", "so", "because", "since", "although", "though", "if", "unless",
    "then", "also", "yet", "as", "than",
    // prepositions
    "of", "in", "on", "at", "to", "from", "into", "onto", "with", "without",
    "within", "after", "before", "by", "for", "over", "under", "against",
    "via", "per", "about", "across", "between", "through", "during", "past",
    // copulas and modals
    "is", "are", "was", "were", "be", "been", "being", "has", "have", "had",
    "can", "cannot", "could", "will", "would", "may", "might", "must", "shall",
    "should",
];

/// Clause openers that are not verbs and not function words. Each is vetted
/// individually and each is the NAME OF A THING, so a clause opening with it
/// is describing rather than directing.
const VETTED_OPENERS: &[(&str, &str)] = &[
    ("sentinel", "the product as a sentence subject: \"Sentinel checkpoints the worktree, not infrastructure\""),
    ("git", "the tool as a sentence subject: \"git cannot recover them\""),
    ("recursive", "an adjective: \"recursive delete of `{target}`, which is outside this repository\""),
];

/// Whole reason strings admitted with a written justification. Compared with
/// whitespace collapsed. Keep this list at the size you are willing to defend
/// one entry at a time.
const VETTED_REASONS: &[(&str, &str)] = &[(
    "{reason}\n\nPermitted by an allowlist entry for this fingerprint in guard.toml. The rule fired and was overridden; this is recorded as `allowlisted`.",
    "lib.rs `decide()`. Produced only on the `Verdict::Allow` branch, and \
     `sentineld/src/hooks.rs` puts a reason on the wire only when the decision \
     `is_blocking()`, so this text cannot reach `denial_text` in any arm. It \
     names `guard.toml` because an audit row has to say which grant applied. \
     The Allow-path premise is itself pinned, by \
     `the_vetted_allowlist_reason_is_still_on_the_allow_path`.",
)];

const SHIPPED_WITH_RECOURSE: &[(&str, &str)] = &[
    (
        "git.force_push",
        "force-push to protected branch `{branch}`{qualifier} — commits on the remote can be lost permanently. Push to a feature branch and open a pull request instead.",
    ),
    (
        "net.pipe_to_shell",
        "downloads from `{host}` and executes it with `{}` without review; add the host to allowed_hosts if this is expected",
    ),
    (
        "cloud.destroy",
        "`{} {args}` destroys remote resources. Sentinel checkpoints the worktree, not infrastructure, so this cannot be undone — run it yourself if you mean it.",
    ),
    (
        "publish.irreversible",
        "`{} {sub}` releases a version that registries do not let you withdraw. Try `--dry-run` first, and publish by hand when the output looks right.",
    ),
    (
        "git.reset_hard",
        "`git reset --hard` with uncommitted changes in the worktree — git cannot recover them. Use `git stash` to set them aside, or restore a Sentinel checkpoint afterwards.",
    ),
    (
        "git.clean_force",
        "`git clean` would delete untracked files that exist in this worktree. Run it with -n first to see what goes, or restore a Sentinel checkpoint if you need them back.",
    ),
    (
        "git.discard_changes",
        "discards every uncommitted change in the worktree. `git stash` keeps them, and a Sentinel checkpoint can bring them back afterwards.",
    ),
    (
        "net.pipe_to_shell",
        "pipes `{}` output into `{}` with a destination this gate cannot resolve, so it cannot be checked against allowed_hosts; spell the URL literally if this is expected",
    ),
    (
        "net.exfiltrate",
        "uploads local data to `{host}`, which is not in allowed_hosts",
    ),
    (
        "guard.control_plane",
        "changes `{target}`, which is Sentinel's own control plane — the guard reloads it within two seconds, so this is a live policy change rather than an ordinary file edit. Change it deliberately and outside an agent session.",
    ),
    (
        "guard.control_plane (the 2026-08-22 precedent)",
        "writes to `{path}`, which is Sentinel's own control plane — the guard reloads it within two seconds, so this is a live policy change. Revert it, or use `sentinel allow --once`.",
    ),
];

/// A literal must be prose before it is judged as prose.
const MIN_WORDS_TO_SCAN: usize = 4;
/// The imperative layer needs a sentence, not an argv fragment. `system prune`
/// and `DELETE FROM without WHERE` are match patterns, not reasons; L2 and L3
/// still apply to them.
const MIN_WORDS_FOR_MOOD: usize = 5;

const CLAUSE_SEPS: &[char] = &['.', ';', ':', '\u{2014}', '\n', '!', '?'];
/// Separators that also occur inside a word (`guard.toml`, `3.5`), where they
/// do not end a clause.
const INWORD_SEPS: &[char] = &['.', ';', ':'];
/// A conjoined second imperative: "Try `--dry-run` first, and publish by hand".
const CONJ_SPLITS: &[&str] = &[", and ", ", or ", ", then ", ", but "];

struct Literal {
    line: usize,
    text: String,
    /// What precedes the literal on its own line, so `summary:` fields — which
    /// `sentinel doctor` prints and no refusal renders — can be skipped.
    prefix: String,
}

fn scan(src: &str) -> (Vec<Literal>, String) {
    let src = match src.find("#[cfg(test)]") {
        Some(at) => &src[..at],
        None => src,
    };
    let chars: Vec<char> = src.chars().collect();
    let mut literals: Vec<Literal> = Vec::new();
    let mut code = String::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            code.push('\n');
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    line += 1;
                }
                i += 1;
            }
            i = std::cmp::min(i + 2, chars.len());
            continue;
        }
        if c == '\'' {
            if i + 3 < chars.len() && chars[i + 1] == '\\' && chars[i + 3] == '\'' {
                i += 4;
                continue;
            }
            if i + 2 < chars.len() && chars[i + 2] == '\'' {
                i += 3;
                continue;
            }
            code.push(c);
            i += 1;
            continue;
        }
        if c == '"' {
            let start_line = line;
            let prefix = line_prefix(&chars, i);
            i += 1;
            let mut buf = String::new();
            while i < chars.len() {
                let ch = chars[i];
                if ch == '\\' {
                    let next = if i + 1 < chars.len() {
                        chars[i + 1]
                    } else {
                        ' '
                    };
                    if next == '\n' {
                        line += 1;
                        i += 2;
                        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                            i += 1;
                        }
                        continue;
                    }
                    buf.push(match next {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    });
                    i += 2;
                    continue;
                }
                if ch == '"' {
                    i += 1;
                    break;
                }
                if ch == '\n' {
                    line += 1;
                }
                buf.push(ch);
                i += 1;
            }
            literals.push(Literal {
                line: start_line,
                text: buf,
                prefix,
            });
            continue;
        }
        code.push(c);
        i += 1;
    }
    (literals, code)
}

fn line_prefix(chars: &[char], idx: usize) -> String {
    let mut start = idx;
    while start > 0 && chars[start - 1] != '\n' {
        start -= 1;
    }
    chars[start..idx]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}

/// `scan` reads ordinary string literals only. A raw string would be read
/// wrongly and could hide a reason, so its presence fails the gate rather than
/// being skipped quietly.
fn has_raw_string(src: &str) -> bool {
    let chars: Vec<char> = src.chars().collect();
    for i in 0..chars.len() {
        if chars[i] != 'r' {
            continue;
        }
        let opens = i + 1 < chars.len() && (chars[i + 1] == '"' || chars[i + 1] == '#');
        if !opens {
            continue;
        }
        let before = if i > 0 { chars[i - 1] } else { ' ' };
        if " \t\n(,=[&{:!".contains(before) {
            return true;
        }
    }
    false
}

fn squeeze(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn trunc(text: &str) -> String {
    squeeze(text).chars().take(96).collect()
}

/// The `guard.toml` keys, read from `GuardConfig` rather than hardcoded.
fn config_keys() -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut inside = false;
    for line in CONFIG_SRC.lines() {
        let text = line.trim();
        if text.starts_with("pub struct GuardConfig") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if text == "}" {
            break;
        }
        let Some(rest) = text.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            keys.push(name.to_string());
        }
    }
    keys
}

fn has_word(text: &str, word: &str) -> bool {
    let low = text.to_lowercase();
    let needle = word.to_lowercase();
    if needle.is_empty() {
        return false;
    }
    for (idx, _) in low.match_indices(needle.as_str()) {
        let before = low[..idx].chars().next_back().unwrap_or(' ');
        let after = low[idx + needle.len()..].chars().next().unwrap_or(' ');
        let wordish = |c: char| c.is_alphanumeric() || c == '_';
        if !wordish(before) && !wordish(after) {
            return true;
        }
    }
    false
}

/// Backticked spans, in order of appearance.
fn spans(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '`' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '`' {
                j += 1;
            }
            if j >= chars.len() {
                break;
            }
            out.push(chars[i + 1..j].iter().collect::<String>());
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn split_keep(part: &str, sep: char) -> Vec<String> {
    let chars: Vec<char> = part.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut buf = String::new();
    for k in 0..chars.len() {
        let ch = chars[k];
        if ch == sep {
            let before = if k > 0 { chars[k - 1] } else { ' ' };
            let after = if k + 1 < chars.len() {
                chars[k + 1]
            } else {
                ' '
            };
            if INWORD_SEPS.contains(&sep) && before.is_alphanumeric() && after.is_alphanumeric() {
                buf.push(ch);
                continue;
            }
            out.push(std::mem::take(&mut buf));
            continue;
        }
        buf.push(ch);
    }
    out.push(buf);
    out
}

fn clauses(text: &str) -> Vec<String> {
    let mut parts: Vec<String> = vec![text.to_string()];
    for sep in CLAUSE_SEPS {
        let mut next: Vec<String> = Vec::new();
        for part in &parts {
            next.extend(split_keep(part, *sep));
        }
        parts = next;
    }
    for conj in CONJ_SPLITS {
        let mut next: Vec<String> = Vec::new();
        for part in &parts {
            next.extend(part.split(conj).map(|s| s.to_string()));
        }
        parts = next;
    }
    parts
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// The word whose mood decides the clause. A leading backticked span or
/// `{interpolation}` is the subject under judgement, so the word after it is
/// the one that matters: "`{}` registers a persistent job" is a description.
fn first_word(clause: &str) -> String {
    let mut rest = clause.trim().to_string();
    for _ in 0..8 {
        let Some(first) = rest.chars().next() else {
            return String::new();
        };
        let close = match first {
            '`' => '`',
            '{' => '}',
            _ => break,
        };
        let tail = &rest[first.len_utf8()..];
        let Some(at) = tail.find(close) else {
            return String::new();
        };
        let next = tail[at + close.len_utf8()..].trim().to_string();
        rest = next;
    }
    let trimmed = rest.trim_start_matches(|c: char| "(\"'*- \u{2014}".contains(c));
    match trimmed.split_whitespace().next() {
        Some(word) => word
            .trim_matches(|c: char| "`,.;:!?()\"'".contains(c))
            .to_lowercase(),
        None => String::new(),
    }
}

/// Everything wrong with one reason string, in the words the failure message
/// will use. Empty means the reason describes without directing.
fn findings(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let lower = text.to_lowercase();

    // L2 - the config surface. Naming the knob is an override instruction in
    // substance, however politely it is phrased.
    for key in config_keys() {
        if has_word(text, &key) {
            out.push(format!(
                "names `{key}`, a guard.toml key that relaxes the rule"
            ));
        }
    }
    for token in OVERRIDE_SURFACE {
        if lower.contains(token) {
            out.push(format!("names the override surface `{token}`"));
        }
    }

    // L3 - a command or a flag other than the subject of the refusal.
    for span in spans(text) {
        let inner = span.trim().to_string();
        if inner.contains('{') {
            continue; // an interpolation of the subject
        }
        if inner.starts_with('-') {
            out.push(format!("offers the flag `{inner}`"));
            continue;
        }
        if inner.to_lowercase().starts_with("sentinel ") {
            out.push(format!("names the sentinel CLI `{inner}`"));
            continue;
        }
        let is_subject = text.trim_start().starts_with(&format!("`{span}`"));
        if inner.contains(' ') && !is_subject {
            out.push(format!("names another command `{inner}`"));
        }
    }

    // L1 - imperative mood, which is the layer that fails closed.
    if text.split_whitespace().count() >= MIN_WORDS_FOR_MOOD {
        for clause in clauses(text) {
            let word = first_word(&clause);
            if word.is_empty() || !word.starts_with(|c: char| c.is_alphabetic()) {
                continue;
            }
            if OPENERS.contains(&word.as_str()) {
                continue;
            }
            if VETTED_OPENERS.iter().any(|(w, _)| *w == word) {
                continue;
            }
            // Third person or participle: `deletes`, `discarding`, `permitted`.
            if word.ends_with('s') || word.ends_with("ing") || word.ends_with("ed") {
                continue;
            }
            out.push(format!(
                "clause opens with the bare verb `{word}`, so it reads as an instruction: {:?}",
                trunc(&clause)
            ));
        }
    }
    out
}

fn vetted(text: &str) -> Option<&'static str> {
    let want = squeeze(text);
    VETTED_REASONS
        .iter()
        .find(|(candidate, _)| squeeze(candidate) == want)
        .map(|(_, why)| *why)
}

fn names_override_surface(text: &str) -> bool {
    let flat = squeeze(text).to_lowercase();
    OVERRIDE_SURFACE
        .iter()
        .any(|token| flat.contains(&token.to_lowercase()))
}

fn is_candidate(literal: &Literal) -> bool {
    if literal.prefix.ends_with("summary:") {
        // `Rule.summary` reaches `sentinel doctor` and the settings UI, never
        // a refusal. It is a noun phrase by convention and would read as an
        // imperative to L1.
        return false;
    }
    names_override_surface(&literal.text)
        || literal.text.split_whitespace().count() >= MIN_WORDS_TO_SCAN
}

#[test]
fn no_rule_reason_tells_the_agent_how_to_proceed() {
    let mut offenders: Vec<String> = Vec::new();
    let mut examined = 0usize;
    for (name, src) in REASON_SOURCES {
        assert!(
            !has_raw_string(src),
            "{name} contains a raw string literal, which this gate's extractor \
             does not read. Teach `scan` about raw strings before shipping one \
             in a file that builds reasons."
        );
        let (literals, _) = scan(src);
        for literal in literals {
            if !is_candidate(&literal) {
                continue;
            }
            examined += 1;
            if vetted(&literal.text).is_some() {
                continue;
            }
            let found = findings(&literal.text);
            if found.is_empty() {
                continue;
            }
            let detail = found
                .iter()
                .map(|f| format!("      - {f}"))
                .collect::<Vec<String>>()
                .join("\n");
            offenders.push(format!(
                "  {name}:{}  {:?}\n{detail}",
                literal.line,
                trunc(&literal.text)
            ));
        }
    }

    // A gate that reads nothing passes everything. This is the shape that let
    // the padded arm-check ship as an advisory: assert the instrument works
    // before trusting its silence.
    assert!(
        examined >= 40,
        "the extractor found only {examined} candidate reason strings across \
         {} sources; it is broken, and its silence means nothing",
        REASON_SOURCES.len()
    );

    assert!(
        offenders.is_empty(),
        "A rule reason tells the agent how to proceed.\n{}\n\n\
         The reason is interpolated into `explain` and `defer`, so this hands \
         a way forward to the two arms whose definition is that they have \
         none, and the corpus cannot show that it happened. State what is \
         wrong and stop. Recourse belongs in `denial_text`'s Full arm in \
         sentinel-hook, where the arm assignment decides whether it appears.",
        offenders.join("\n")
    );
}

/// F2: the previous gate read `rules.rs` alone while `guard.control_plane`'s
/// reason lived in `lib.rs`. Coverage is now checked against the filesystem
/// instead of asserted in a comment.
#[test]
fn every_source_that_can_build_a_reason_is_read_by_this_gate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut unread: Vec<String> = Vec::new();
    let mut files = 0usize;
    for entry in std::fs::read_dir(&dir).expect("the guard's src/ must be readable") {
        let path = entry.expect("a readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Some(file) = path.file_name() else {
            continue;
        };
        let name = format!("src/{}", file.to_string_lossy());
        files += 1;
        let body = std::fs::read_to_string(&path).expect("a readable source file");
        let (_, code) = scan(&body);
        let hits: Vec<&str> = REASON_MARKERS
            .iter()
            .copied()
            .filter(|marker| code.contains(marker))
            .collect();
        if hits.is_empty() {
            continue;
        }
        if !REASON_SOURCES.iter().any(|(known, _)| *known == name) {
            unread.push(format!(
                "  {name} builds reasons ({}) and this gate does not read it",
                hits.join(", ")
            ));
        }
    }
    assert!(
        files >= REASON_SOURCES.len(),
        "found {files} source files, fewer than the {} this gate claims to \
         read; the directory walk is wrong",
        REASON_SOURCES.len()
    );
    assert!(
        unread.is_empty(),
        "A reason is built in a file this gate does not read.\n{}\n\n\
         Add it to REASON_SOURCES. This is exactly how `guard.control_plane` \
         moved out from under the first version of this test.",
        unread.join("\n")
    );
}

/// Every reason that shipped with recourse must make the detector fire. The
/// previous gate was green with nine of these in the tree, and four of them
/// reached collected sessions.
#[test]
fn the_gate_flags_every_reason_that_shipped_with_recourse() {
    let mut missed: Vec<String> = Vec::new();
    for (rule, text) in SHIPPED_WITH_RECOURSE {
        if findings(text).is_empty() {
            missed.push(format!("  {rule}: {:?}", trunc(text)));
        }
    }
    assert!(
        missed.is_empty(),
        "the detector does not flag a reason that is known to carry \
         recourse:\n{}",
        missed.join("\n")
    );
}

#[test]
fn a_short_literal_naming_the_override_surface_is_still_caught() {
    for bare in [
        "sentinel allow --once",
        "sentinel allow",
        "allow --last --once",
        "use `sentinel allow`",
    ] {
        assert!(
            !findings(bare).is_empty(),
            "the detector does not flag {bare:?}, which names the override \
             surface directly. A word floor must never apply to the surface \
             check - that is exactly how the 2026-08-22 literal became \
             invisible."
        );
        let literal = Literal {
            text: bare.to_string(),
            line: 0,
            prefix: "reason:".to_string(),
        };
        assert!(
            is_candidate(&literal),
            "{bare:?} is filtered out before the detector ever sees it"
        );
    }
}

/// The pre-fix strings must also be gone from the tree, not merely detectable.
#[test]
fn none_of_the_recourse_bearing_reasons_are_still_in_the_tree() {
    let mut alive: Vec<String> = Vec::new();
    for (name, src) in REASON_SOURCES {
        let (literals, _) = scan(src);
        for literal in &literals {
            let text = squeeze(&literal.text);
            for (rule, shipped) in SHIPPED_WITH_RECOURSE {
                if text == squeeze(shipped) {
                    alive.push(format!("  {name}:{} still carries {rule}", literal.line));
                }
            }
        }
    }
    assert!(alive.is_empty(), "{}", alive.join("\n"));
}

/// The other half of a gate that means something: it must PASS the reasons the
/// ruleset needs. A detector that fires on every string would satisfy the test
/// above and make the ruleset unmaintainable.
#[test]
fn the_detector_accepts_a_purely_descriptive_reason() {
    for text in [
        "force-pushes to protected branch `{branch}`{qualifier} — commits on the remote can be lost permanently",
        "`git reset --hard` with uncommitted changes in the worktree — git cannot recover them",
        "deletes `{target}`, which matches the protected path `{pattern}`",
        "`{} {args}` destroys remote resources. Sentinel checkpoints the worktree, not infrastructure, so this cannot be undone.",
        "recursive delete of `{target}`, which is outside this repository ({})",
        "prunes unreachable objects immediately, discarding what the reflog could still recover",
        "writes to `{path}`, which is Sentinel's own control plane (`{pattern}`) — the guard reloads it within two seconds, so this is a live policy change",
    ] {
        let found = findings(text);
        assert!(
            found.is_empty(),
            "the detector fires on a purely descriptive reason: {text:?}\n{found:?}"
        );
    }
}

/// L2 is only as good as its key list, and the key list is parsed. If the
/// parse breaks, the layer goes quiet.
#[test]
fn the_config_surface_is_read_from_config_rs() {
    let keys = config_keys();
    assert!(
        keys.len() >= 5,
        "parsed only {} GuardConfig keys, so the config-surface layer is \
         nearly inert: {keys:?}",
        keys.len()
    );
    for expected in ["allowed_hosts", "protected_paths", "allow"] {
        assert!(
            keys.iter().any(|k| k == expected),
            "GuardConfig key {expected:?} is not in the parsed set {keys:?}"
        );
    }
}

/// The one vetted reason is vetted on a premise: it is produced only where the
/// verdict is `Allow`, so it never reaches `denial_text`. Pin the premise.
#[test]
fn the_vetted_allowlist_reason_is_still_on_the_allow_path() {
    let src = include_str!("../src/lib.rs");
    let lines: Vec<&str> = src.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("Permitted by an allowlist entry"))
        .expect("the vetted allowlist reason must still exist in lib.rs");
    let start = at.saturating_sub(12);
    let window = lines[start..at].join("\n");
    assert!(
        window.contains("verdict: Verdict::Allow"),
        "the allowlist reason is vetted only because it cannot reach a \
         refusal. It is no longer on the Allow path, so either move it back or \
         remove `guard.toml` from its text:\n{window}"
    );
}

/// The companion invariant: `full` is the only style that names the override.
#[test]
fn only_the_full_style_names_the_override() {
    let hook = include_str!("../../sentinel-hook/src/main.rs").to_lowercase();
    let start = hook
        .find("fn denial_text")
        .expect("denial_text must exist in sentinel-hook");
    let body = &hook[start..];
    let end = body.find("\nfn ").unwrap_or(body.len());
    let body = &body[..end];

    let mentions: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains("sentinel allow"))
        .collect();

    assert_eq!(
        mentions.len(),
        1,
        "Exactly one style may name the override, and it must be Full. Found \
         {} mention(s):\n{}",
        mentions.len(),
        mentions.join("\n")
    );
}
