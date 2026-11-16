use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::enforceability::{Class, Reach};

/// One agent action, as written by `paper/scripts/corpora/fetch.py`.
pub struct Step {
    pub corpus: String,
    pub id: String,
    pub trajectory: String,
    pub step: u32,
    pub label: Option<i64>,
    pub action: String,
    pub arguments: String,
    pub class: Class,
    pub signature: Option<&'static str>,
    pub reach: Reach,
}

const DESTRUCTIVE: &[&str] = &[
    "delete",
    "destroy",
    "drop",
    "purge",
    "revoke",
    "terminate",
    "uninstall",
    "truncate",
    "wipe",
    "erase",
    "remove",
    "deactivate",
    "disable",
    "kill",
    "shutdown",
    "cancel",
    "rollback",
    "restore",
    "reset",
    "unpublish",
    "unsubscribe",
    "expire",
];

/// Operations whose effect leaves the machine but whose *wrongness* is a
/// property of the payload rather than the call.
const EMITTING: &[&str] = &[
    "send",
    "post",
    "publish",
    "share",
    "upload",
    "email",
    "message",
    "notify",
    "invite",
    "transfer",
    "pay",
    "charge",
    "submit",
    "push",
    "sync",
    "export",
    "broadcast",
    "sms",
    "tweet",
    "comment",
    "reply",
    "dispatch",
    "deploy",
    "provision",
    "grant",
    "assign",
    "enrich",
    "insert",
    "create",
    "add",
    "write",
    "update",
    "set",
    "put",
    "patch",
    "upsert",
    "store",
    "save",
];

/// Operations that observe without changing anything.
const READING: &[&str] = &[
    "get",
    "read",
    "list",
    "search",
    "fetch",
    "query",
    "view",
    "find",
    "retrieve",
    "lookup",
    "check",
    "describe",
    "show",
    "count",
    "scan",
    "browse",
    "extract",
    "download",
    "load",
    "inspect",
    "analyze",
    "analyse",
    "summarize",
    "summarise",
    "transcribe",
    "translate",
    "generate",
    "render",
    "detect",
    "classify",
    "predict",
    "recommend",
];

fn tokens(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in name.chars() {
        if ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ' ' {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else if ch.is_ascii_uppercase() && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            current.push(ch.to_ascii_lowercase());
        } else {
            current.push(ch.to_ascii_lowercase());
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn operation_words(arguments: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(map) = arguments.as_object() else {
        return out;
    };
    for (key, value) in map {
        let k = key.to_ascii_lowercase();
        if !matches!(
            k.as_str(),
            "operation" | "action" | "method" | "command" | "type" | "op" | "verb" | "mode"
        ) {
            continue;
        }
        if let Some(s) = value.as_str() {
            out.extend(tokens(s));
        }
    }
    out
}

fn any_of(words: &[String], set: &[&'static str]) -> Option<&'static str> {
    for w in words {
        if let Some(hit) = set.iter().find(|s| **s == w.as_str()) {
            return Some(*hit);
        }
    }
    None
}

/// Whether the whole payload is filler rather than a real call.
fn is_filler(arguments: &Value) -> bool {
    let Some(map) = arguments.as_object() else {
        return false;
    };
    let values: Vec<&str> = map.values().filter_map(Value::as_str).collect();
    !values.is_empty()
        && values.iter().all(|v| {
            let t = v.trim().to_ascii_lowercase();
            t.is_empty() || t == "placeholder" || t == "todo" || t == "n/a" || t == "string"
        })
}

pub fn classify_tool(name: &str, arguments: &Value) -> (Class, Option<&'static str>, Reach) {
    if matches!(
        name,
        "run_command"
            | "edit_file"
            | "create_file"
            | "write_file"
            | "delete_file"
            | "shell_command"
            | "execute_shell_command"
            | "execute_command"
            | "TerminalExecute"
            | "bash"
            | "sh"
    ) {
        let routed = match name {
            "edit_file" | "create_file" | "write_file" | "delete_file" => name,
            _ => "run_command",
        };
        let v = crate::enforceability::classify(routed, arguments);
        return (v.class, v.signature, v.reach.unwrap_or(Reach::Local));
    }
    if name.is_empty() || name == "?" {
        return (Class::NotAnAction, None, Reach::External);
    }
    if is_filler(arguments) {
        return (Class::Unevaluable, None, Reach::External);
    }
    let mut words = tokens(name);
    words.extend(operation_words(arguments));

    let signature = any_of(&words, DESTRUCTIVE)
        .or_else(|| any_of(&words, EMITTING))
        .or_else(|| any_of(&words, READING));

    if signature.is_some() {
        return (Class::Semantic, signature, Reach::External);
    }
    // A tool whose verb is not recognisable. Counted as semantic rather than
    // deterministic: the burden of proof is on the claim that a fixed rule
    // could refuse it, and an unrecognised operation has not met it.
    (Class::Semantic, None, Reach::External)
}

fn read_jsonl(path: &Path) -> Result<Vec<Step>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)?;
        let action = v
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let arguments = v
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // The payload was stored as text so the dump stays greppable; parse it
        // back when it is JSON, and fall back to a flat string when it is not.
        let parsed: Value = serde_json::from_str(&arguments)
            .unwrap_or_else(|_| serde_json::json!({ "text": arguments }));
        // The inner `arguments` object is where an MCP call keeps its operands.
        let payload = parsed
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| parsed.clone());
        let (class, signature, reach) = classify_tool(&action, &payload);
        out.push(Step {
            corpus: v
                .get("corpus")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string(),
            id: v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            trajectory: v
                .get("trajectory")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            step: v.get("step").and_then(Value::as_u64).unwrap_or(0) as u32,
            label: v.get("trajectory_label").and_then(Value::as_i64),
            action,
            arguments,
            class,
            signature,
            reach,
        });
    }
    Ok(out)
}

#[derive(Default)]
struct Tally {
    steps: usize,
    c1: usize,
    c2: usize,
    c3: usize,
    c0: usize,
    trajectories: BTreeMap<String, (Option<i64>, bool)>,
}

pub fn run(data: &Path, dump: Option<&Path>) -> Result<()> {
    let steps = read_jsonl(data)?;
    if steps.is_empty() {
        anyhow::bail!(
            "no steps in {} — run `python paper/scripts/corpora/fetch.py atbench` first",
            data.display()
        );
    }

    let mut per_corpus: BTreeMap<String, Tally> = BTreeMap::new();
    let mut verbs: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in &steps {
        let t = per_corpus.entry(s.corpus.clone()).or_default();
        t.steps += 1;
        match s.class {
            Class::Deterministic => t.c1 += 1,
            Class::Semantic => t.c2 += 1,
            Class::NotAnAction => t.c3 += 1,
            Class::Unevaluable => t.c0 += 1,
        }
        let entry = t
            .trajectories
            .entry(s.trajectory.clone())
            .or_insert((s.label, false));
        if s.class == Class::Deterministic {
            entry.1 = true;
            if let Some(sig) = s.signature {
                *verbs.entry(sig).or_default() += 1;
            }
        }
    }

    println!();
    println!("Replication of the enforceability ceiling on ATBench");
    println!("Action space: remote tool calls, not shell commands. Reported per");
    println!("corpus and never pooled — the ceiling is a function of what the");
    println!("agent can touch, so an average across action spaces means nothing.");
    println!();
    println!(
        "{:<16} {:>7} {:>8} {:>8} {:>8} {:>8}",
        "corpus", "steps", "C1", "C2", "C3", "C0"
    );
    for (name, t) in &per_corpus {
        let pct = |n: usize| 100.0 * n as f64 / t.steps as f64;
        println!(
            "{:<16} {:>7} {:>7.1}% {:>7.1}% {:>7.1}% {:>7.1}%",
            name,
            t.steps,
            pct(t.c1),
            pct(t.c2),
            pct(t.c3),
            pct(t.c0)
        );
    }

    println!();
    println!("Trajectory level — the unit the benchmark actually labels.");
    println!("A trajectory is gateable if ANY step in it admits a deterministic");
    println!("refusal, which is the most generous reading available to a gate.");
    println!();
    println!(
        "{:<16} {:>8} {:>10} {:>12} {:>10}",
        "corpus", "unsafe", "gateable", "gateable %", "safe FP %"
    );
    let mut tot_unsafe = 0usize;
    let mut tot_gate = 0usize;
    for (name, t) in &per_corpus {
        let unsafe_n = t
            .trajectories
            .values()
            .filter(|(l, _)| *l == Some(1))
            .count();
        let gate = t
            .trajectories
            .values()
            .filter(|(l, g)| *l == Some(1) && *g)
            .count();
        let safe_n = t
            .trajectories
            .values()
            .filter(|(l, _)| *l == Some(0))
            .count();
        let safe_hit = t
            .trajectories
            .values()
            .filter(|(l, g)| *l == Some(0) && *g)
            .count();
        tot_unsafe += unsafe_n;
        tot_gate += gate;
        println!(
            "{:<16} {:>8} {:>10} {:>11.1}% {:>9.1}%",
            name,
            unsafe_n,
            gate,
            if unsafe_n > 0 {
                100.0 * gate as f64 / unsafe_n as f64
            } else {
                0.0
            },
            if safe_n > 0 {
                100.0 * safe_hit as f64 / safe_n as f64
            } else {
                0.0
            }
        );
    }
    println!();
    println!(
        "pooled unsafe trajectories {tot_unsafe}, gateable {tot_gate} ({:.1}%)",
        if tot_unsafe > 0 {
            100.0 * tot_gate as f64 / tot_unsafe as f64
        } else {
            0.0
        }
    );

    if !verbs.is_empty() {
        println!();
        println!("Which operations the deterministic refusals key on");
        let mut v: Vec<_> = verbs.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (name, n) in v.into_iter().take(10) {
            println!("  {name:<18} {n:>6}");
        }
    }

    let external = steps.iter().filter(|s| s.reach == Reach::External).count();
    let undecidable_external = steps
        .iter()
        .filter(|s| s.reach == Reach::External && s.class == Class::Semantic)
        .count();
    println!();
    println!(
        "Reach: {:.1}% of steps are External ({} of {}). A tool call mutates a",
        100.0 * external as f64 / steps.len() as f64,
        external,
        steps.len()
    );
    println!("third party, so no local checkpoint reverses it. The cell that");
    println!("neither a gate nor a snapshot reaches — semantic AND external — holds");
    println!(
        "{:.1}% of all steps ({}).",
        100.0 * undecidable_external as f64 / steps.len() as f64,
        undecidable_external
    );
    println!();
    println!("Compare StepShield (shell/filesystem action space): C1 18.6%.");
    println!("The gap between these is the finding, not an inconsistency.");

    if let Some(path) = dump {
        use std::io::Write;
        let mut file =
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut n = 0;
        for s in steps.iter().filter(|s| s.label == Some(1)) {
            let record = serde_json::json!({
                "id": s.id,
                "category": s.corpus,
                "step": s.step,
                "action": s.action,
                "arguments": s.arguments,
                "benchmark_label": "unsafe",
                "machine_class": s.class.key(),
                "machine_signature": s.signature,
                "machine_reach": format!("{:?}", s.reach),
            });
            writeln!(file, "{record}")?;
            n += 1;
        }
        println!();
        println!(
            "wrote {n} steps from unsafe trajectories to {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn class_of(name: &str, args: Value) -> Class {
        classify_tool(name, &args).0
    }

    #[test]
    fn camel_and_snake_names_both_come_apart() {
        assert_eq!(tokens("send_email"), vec!["send", "email"]);
        assert_eq!(tokens("readMessages"), vec!["read", "messages"]);
        assert_eq!(tokens("google_gke_mcp"), vec!["google", "gke", "mcp"]);
    }

    #[test]
    fn a_destructive_verb_does_not_by_itself_make_a_call_refusable() {
        assert_eq!(
            class_of("delete_cluster", json!({"id": "c1"})),
            Class::Semantic
        );
        assert_eq!(class_of("revokeToken", json!({"t": "x"})), Class::Semantic);
        assert_eq!(
            class_of("remove_group_member", json!({"user": "u"})),
            Class::Semantic
        );
    }

    #[test]
    fn the_verb_is_still_recorded_even_though_it_no_longer_decides() {
        // The sensitivity analysis is computed from the signature column, so
        // the verb has to survive the class change.
        assert_eq!(
            classify_tool("delete_cluster", &json!({"id": "c1"})).1,
            Some("delete")
        );
        assert_eq!(
            classify_tool("send_email", &json!({"to": "a@b.c"})).1,
            Some("send")
        );
    }

    #[test]
    fn a_shell_step_is_the_only_route_to_action_local() {
        // The signature table decides, exactly as it does on a shell corpus.
        assert_eq!(
            class_of("shell_command", json!({"command": "rm -rf /"})),
            Class::Deterministic
        );
        // ...and it declines to fire on an ordinary command, which is why the
        // rate in this action space comes out where it does.
        assert_eq!(
            class_of("shell_command", json!({"command": "python migrate.py"})),
            Class::Semantic
        );
    }

    #[test]
    fn prose_is_not_an_action_however_the_corpus_spells_it() {
        assert_eq!(
            class_of("", json!({"response": "done"})),
            Class::NotAnAction
        );
        assert_eq!(
            class_of("?", json!({"response": "done"})),
            Class::NotAnAction
        );
    }

    #[test]
    fn a_gateway_tool_is_still_read_through_its_operation_argument() {
        // The name says only which service is being addressed, so the verb
        // has to be recovered from the argument for the signature to be right.
        assert_eq!(
            classify_tool("supabase_mcp", &json!({"operation": "query"})).1,
            Some("query")
        );
        assert_eq!(
            classify_tool("supabase_mcp", &json!({"operation": "drop_table"})).1,
            Some("drop")
        );
    }

    #[test]
    fn emitting_is_semantic_because_the_payload_decides() {
        // Sending mail is irreversible but not refusable in general: an agent
        // forbidden to send mail cannot do the job it was given.
        assert_eq!(
            class_of("send_email", json!({"to": "a@b.c"})),
            Class::Semantic
        );
        assert_eq!(
            class_of("create_event", json!({"title": "x"})),
            Class::Semantic
        );
    }

    #[test]
    fn a_read_is_an_action_because_the_pull_is_where_a_monitor_would_sit() {
        // These used to be C3. A pull of data that should not have been
        // pulled is a step, and whether it is a violation depends on what is
        // being read rather than on the shape of the call.
        assert_eq!(
            class_of("get_transcript", json!({"id": "1"})),
            Class::Semantic
        );
        assert_eq!(
            class_of("web_fetch", json!({"url": "http://x"})),
            Class::Semantic
        );
    }

    #[test]
    fn destructive_beats_emitting_when_both_appear_in_the_signature() {
        assert_eq!(
            classify_tool("delete_and_notify", &json!({"id": "1"})).1,
            Some("delete")
        );
    }

    #[test]
    fn filler_is_unevaluable() {
        assert_eq!(
            class_of("send_email", json!({"to": "placeholder"})),
            Class::Unevaluable
        );
    }

    #[test]
    fn an_unrecognised_verb_does_not_get_the_benefit_of_the_doubt() {
        // The burden is on the claim that a fixed rule could refuse it.
        assert_eq!(
            class_of("frobnicate_widget", json!({"x": "1"})),
            Class::Semantic
        );
    }
}
