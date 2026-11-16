use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    A,
    B,
    C,
}

impl Tier {
    fn label(self) -> &'static str {
        match self {
            Tier::A => "A (native hooks)",
            Tier::B => "B (MCP proxy)",
            Tier::C => "C (filesystem observation)",
        }
    }

    fn coverage(self) -> &'static str {
        match self {
            Tier::A => "structured tool calls, blocking guard, per-step checkpoints",
            Tier::B => "structured tool calls and blocking for anything routed through MCP",
            Tier::C => {
                "file changes observed and checkpointed; blocking only for shimmed commands; no tool-level metadata"
            }
        }
    }
}

pub struct Runtime {
    pub name: &'static str,
    pub tier: Tier,
    pub detected: bool,
}

fn on_path(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let exts: Vec<String> = if cfg!(windows) {
        vec![".exe".into(), ".cmd".into(), ".bat".into(), "".into()]
    } else {
        vec!["".into()]
    };
    std::env::split_paths(&paths).any(|dir| {
        exts.iter()
            .any(|ext| dir.join(format!("{program}{ext}")).is_file())
    })
}

fn home_has(relative: &str) -> bool {
    let path: PathBuf = sentineld::home_dir().join(relative);
    path.exists()
}

fn local_app_data_has(relative: &str) -> bool {
    std::env::var_os("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join(relative).exists())
        .unwrap_or(false)
}

fn vscode_extension(prefix: &str) -> bool {
    let dir = sentineld::home_dir().join(".vscode").join("extensions");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with(prefix))
}

pub fn detect_runtimes() -> Vec<Runtime> {
    vec![
        Runtime {
            name: "Claude Code (terminal, VS Code, JetBrains)",
            tier: Tier::A,
            detected: on_path("claude") || home_has(".claude"),
        },
        Runtime {
            name: "Codex CLI and other MCP runtimes",
            tier: Tier::B,
            detected: on_path("codex") || home_has(".codex"),
        },
        Runtime {
            name: "Cursor",
            tier: Tier::C,
            detected: on_path("cursor")
                || home_has(".cursor")
                || local_app_data_has("Programs/cursor"),
        },
        Runtime {
            name: "Windsurf",
            tier: Tier::C,
            detected: home_has(".codeium/windsurf") || on_path("windsurf"),
        },
        Runtime {
            name: "GitHub Copilot agent mode (VS Code)",
            tier: Tier::C,
            detected: vscode_extension("github.copilot"),
        },
        Runtime {
            name: "Cline",
            tier: Tier::C,
            detected: vscode_extension("saoudrizwan.claude-dev"),
        },
        Runtime {
            name: "Zed",
            tier: Tier::C,
            detected: on_path("zed") || home_has(".zed"),
        },
        Runtime {
            name: "Aider",
            tier: Tier::C,
            detected: on_path("aider"),
        },
    ]
}

pub fn report() -> String {
    let mut out = String::new();
    let daemon = sentineld::running();
    let repos = sentineld::registry::list();
    let installed = crate::install::is_installed();

    out.push_str("Sentinel status\n");
    out.push_str(&format!("  version        {}\n", sentineld::VERSION));
    out.push_str(&match &daemon {
        Some(info) => format!(
            "  daemon         running on 127.0.0.1:{} (pid {})\n",
            info.port, info.pid
        ),
        None => "  daemon         not running — start it with `sentinel start`\n".to_string(),
    });
    out.push_str(&format!(
        "  claude hooks   {}\n",
        if installed {
            "installed"
        } else {
            "not installed — run `sentinel install`"
        }
    ));
    out.push_str(&format!(
        "  guard rules    {} active\n",
        sentinel_guard::rule_ids().len()
    ));
    out.push_str(&format!("  repositories   {} enrolled\n", repos.len()));
    for repo in &repos {
        out.push_str(&format!("                 {}\n", repo.display()));
    }
    if repos.is_empty() {
        out.push_str("                 none — run `sentinel init` inside a repository\n");
    }

    out.push_str("\nAgent runtimes on this machine\n");
    let runtimes = detect_runtimes();
    for rt in runtimes.iter().filter(|r| r.detected) {
        let state = match (rt.tier, daemon.is_some()) {
            (_, false) => "inactive until the daemon runs (`sentinel start`)",
            (Tier::A, true) if installed => "covered",
            (Tier::A, true) => "run `sentinel install` to cover this",
            (Tier::B, true) => "covered when launched through `sentinel mcp -- <server>`",
            (Tier::C, true) => "observed in enrolled repositories",
        };
        out.push_str(&format!("  [found] {}\n", rt.name));
        out.push_str(&format!("          tier {} — {}\n", rt.tier.label(), state));
        out.push_str(&format!("          gives you: {}\n", rt.tier.coverage()));
    }
    let missing: Vec<&Runtime> = runtimes.iter().filter(|r| !r.detected).collect();
    if !missing.is_empty() {
        out.push_str(&format!(
            "  not installed: {}\n",
            missing
                .iter()
                .map(|r| r.name)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    out.push_str("\nWhat each tier honestly gives you\n");
    out.push_str("  Tier A (Claude Code): full — structured calls, blocking guard, checkpoints.\n");
    out.push_str(
        "  Tier B (MCP): full, but only for servers launched via `sentinel mcp -- <cmd>`;\n",
    );
    out.push_str(
        "               an MCP runtime configured to call servers directly is not seen.\n",
    );
    out.push_str(
        "  Tier C (everything else): file changes and checkpoints in enrolled repos only.\n",
    );
    out.push_str(
        "               No tool metadata, and nothing is blocked unless you activate the\n",
    );
    out.push_str("               PATH shims (`sentinel shim enable`) — an editor's own actions\n");
    out.push_str("               cannot be intercepted, only observed after the fact.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_runtime_states_its_tier_and_coverage() {
        for rt in detect_runtimes() {
            assert!(!rt.tier.label().is_empty());
            assert!(!rt.tier.coverage().is_empty());
        }
    }

    #[test]
    fn report_is_explicit_about_gaps() {
        let text = report();
        // Whatever else changes, doctor must keep stating tier C's limits.
        assert!(
            text.contains("only observed")
                || text.contains("only, ")
                || text.contains("cannot be intercepted")
        );
        assert!(text.contains("shim"), "must say blocking needs the shims");
    }
}
