use anyhow::Result;
use sentinel_guard::{evaluate, Ctx, GuardConfig, Verdict};
use sentinel_store::Store;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

pub struct Outcome {
    pub tool: String,
    pub summary: String,
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub reason: Option<String>,
}

pub struct Report {
    pub outcomes: Vec<Outcome>,
    /// Calls whose argument payload is no longer in the blob store, so the
    /// command text cannot be recovered and the call cannot be judged.
    pub unrecoverable: usize,
    pub branch: Option<String>,
}

impl Report {
    pub fn denied(&self) -> Vec<&Outcome> {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Deny)
            .collect()
    }

    pub fn warned(&self) -> Vec<&Outcome> {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Warn)
            .collect()
    }

    pub fn by_rule(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for o in &self.outcomes {
            if o.verdict == Verdict::Allow {
                continue;
            }
            let rule = o.rule.clone().unwrap_or_else(|| "unknown".into());
            *counts.entry(rule).or_insert(0) += 1;
        }
        counts
    }
}

fn current_branch(repo: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!name.is_empty()).then_some(name)
}

pub fn run(store: &Store, limit: u32) -> Result<Report> {
    let repo = store.repo().to_path_buf();
    let branch = current_branch(&repo);

    let mut ctx = Ctx::new(repo.clone());
    ctx.branch = branch.clone();
    ctx.config = GuardConfig::load(&repo);

    let mut outcomes = Vec::new();
    let mut unrecoverable = 0;

    for event in store.events_json(None, limit)? {
        if event["kind"] != "tool_call" {
            continue;
        }
        let tool = event["tool"].as_str().unwrap_or("").to_string();
        let Some(hash) = event["args_hash"].as_str() else {
            unrecoverable += 1;
            continue;
        };
        // The payload is content-addressed by the same hash the event carries,
        // so a miss means retention swept it, not that the log is wrong.
        let Ok(bytes) = store.cas.get(hash) else {
            unrecoverable += 1;
            continue;
        };
        let Ok(input) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            unrecoverable += 1;
            continue;
        };

        let action = sentineld::hooks::tool_action(&tool, &input);
        let decision = evaluate(&action, &ctx);
        outcomes.push(Outcome {
            tool,
            summary: event["args_summary"].as_str().unwrap_or("").to_string(),
            verdict: decision.verdict,
            rule: decision.rule.map(String::from),
            reason: decision.reason,
        });
    }

    Ok(Report {
        outcomes,
        unrecoverable,
        branch,
    })
}
