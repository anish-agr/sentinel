pub mod config;
pub mod normalize;
pub mod rules;

pub use config::{GuardConfig, RuleMode};
pub use normalize::Shell;
pub use rules::Ctx;

use normalize::parse;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Warn,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub rule: Option<&'static str>,
    pub reason: Option<String>,
    /// Identifies this exact command+rule pair for "allow always in this repo".
    pub fingerprint: Option<String>,
    pub allowlisted: bool,
}

impl Decision {
    pub fn allow() -> Decision {
        Decision {
            verdict: Verdict::Allow,
            rule: None,
            reason: None,
            fingerprint: None,
            allowlisted: false,
        }
    }

    pub fn is_blocking(&self) -> bool {
        self.verdict == Verdict::Deny
    }
}

#[derive(Debug, Clone)]
pub enum Action<'a> {
    Shell { command: &'a str, shell: Shell },
    Write { path: &'a str },
    Other,
}

pub fn fingerprint(rule: &str, subject: &str) -> String {
    let mut h = Sha256::new();
    h.update(rule.as_bytes());
    h.update(b"|");
    h.update(subject.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn evaluate(action: &Action, ctx: &Ctx) -> Decision {
    if !ctx.config.enabled {
        return Decision::allow();
    }
    match action {
        Action::Shell { command, shell } => evaluate_shell(command, *shell, ctx),
        Action::Write { path } => evaluate_write(path, ctx),
        Action::Other => Decision::allow(),
    }
}

fn decide(ctx: &Ctx, rule: &'static str, reason: String, subject: &str) -> Option<Decision> {
    let fp = fingerprint(rule, subject);
    let verdict = match ctx.config.mode(rule) {
        RuleMode::Off => return None,
        RuleMode::Warn => Verdict::Warn,
        RuleMode::Deny => Verdict::Deny,
    };
    if ctx.config.is_allowed(&fp) {
        return Some(Decision {
            verdict: Verdict::Allow,
            rule: Some(rule),
            reason: Some(format!(
                "{reason}\n\nPermitted by an allowlist entry for this fingerprint in guard.toml. \
                 The rule fired and was overridden; this is recorded as `allowlisted`."
            )),
            fingerprint: Some(fp),
            allowlisted: true,
        });
    }
    Some(Decision {
        verdict,
        rule: Some(rule),
        reason: Some(reason),
        fingerprint: Some(fp),
        allowlisted: false,
    })
}

fn evaluate_shell(command: &str, shell: Shell, ctx: &Ctx) -> Decision {
    let mut warning: Option<Decision> = None;
    let mut allowlisted: Option<Decision> = None;
    for pipeline in parse(command, shell) {
        for cmd in &pipeline.cmds {
            for rule in rules::RULES {
                let Some(reason) = (rule.check)(cmd, &pipeline, ctx) else {
                    continue;
                };
                let Some(decision) = decide(ctx, rule.id, reason, command) else {
                    continue;
                };
                if decision.allowlisted {
                    allowlisted.get_or_insert(decision);
                    continue;
                }
                if decision.is_blocking() {
                    return decision;
                }
                warning.get_or_insert(decision);
            }
        }
    }
    warning.or(allowlisted).unwrap_or_else(Decision::allow)
}

fn evaluate_write(path: &str, ctx: &Ctx) -> Decision {
    if let Some(pattern) = ctx.control_path(path) {
        let reason = format!(
            "writes to `{path}`, which is Sentinel's own control plane (`{pattern}`) — the guard reloads it within two seconds, so this is a live policy change"
        );
        return decide(ctx, "guard.control_plane", reason, path).unwrap_or_else(Decision::allow);
    }
    let Some(pattern) = ctx.protected_path(path) else {
        return Decision::allow();
    };
    let reason = format!("writes to `{path}`, which matches the protected path `{pattern}`");
    decide(ctx, "fs.credential_write", reason, path).unwrap_or_else(Decision::allow)
}

/// Every rule id, for `sentinel doctor` and the settings UI.
pub fn rule_ids() -> Vec<(&'static str, &'static str)> {
    rules::RULES.iter().map(|r| (r.id, r.summary)).collect()
}
