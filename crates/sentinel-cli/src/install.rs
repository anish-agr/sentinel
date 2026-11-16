use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

/// Stop fires when the agent finishes its turn, which is the only reliable
/// signal for checks that can only be answered once a session is over.
const HOOK_EVENTS: [(&str, &str); 3] = [
    ("PreToolUse", "pre"),
    ("PostToolUse", "post"),
    ("Stop", "stop"),
];

pub fn claude_settings_path() -> PathBuf {
    sentineld::home_dir().join(".claude").join("settings.json")
}

pub fn hook_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("locating the sentinel binary")?;
    let name = if cfg!(windows) {
        "sentinel-hook.exe"
    } else {
        "sentinel-hook"
    };
    let path = dir.join(name);
    if !path.exists() {
        bail!(
            "{} not found next to the sentinel binary; build the workspace first",
            path.display()
        );
    }
    Ok(path)
}

fn read_settings(path: &PathBuf) -> Result<Value> {
    match fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => {
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
        }
        _ => Ok(json!({})),
    }
}

fn is_sentinel_entry(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains("sentinel-hook"))
            })
        })
        .unwrap_or(false)
}

/// Removes our entries wherever they appear, leaving every other hook intact.
fn strip_sentinel(settings: &mut Value) -> usize {
    let mut removed = 0;
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return 0;
    };
    for (_, groups) in hooks.iter_mut() {
        if let Some(list) = groups.as_array_mut() {
            let before = list.len();
            list.retain(|g| !is_sentinel_entry(g));
            removed += before - list.len();
        } else if is_sentinel_entry(groups) {
            // An entry stored as a bare object still has to be removable.
            *groups = json!([]);
            removed += 1;
        }
    }
    removed
}

pub fn install() -> Result<PathBuf> {
    let binary = hook_binary()?;
    let path = claude_settings_path();
    let mut settings = read_settings(&path)?;
    strip_sentinel(&mut settings);

    if !settings.is_object() {
        bail!("{} does not contain a JSON object", path.display());
    }
    let root = settings.as_object_mut().expect("checked above");
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    for (event, phase) in HOOK_EVENTS {
        let entry = json!({
            "matcher": "*",
            "hooks": [{
                // The exec form takes command and args separately, so a path
                // with spaces needs no shell quoting on any platform.
                "type": "command",
                "command": binary.to_string_lossy(),
                "args": [phase],
                "timeout": 5
            }]
        });
        let slot = hooks
            .as_object_mut()
            .context("hooks must be an object")?
            .entry(event)
            .or_insert_with(|| json!([]));
        // Claude Code requires an array of matcher groups here. A single object
        // is silently ignored, so an entry written that way never fires; wrap it
        // rather than refusing to install over it.
        if !slot.is_array() {
            *slot = if slot.is_object() {
                json!([slot.clone()])
            } else {
                json!([])
            };
        }
        slot.as_array_mut()
            .context("hook event must hold an array")?
            .push(entry);
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, serde_json::to_string_pretty(&settings)? + "\n")?;
    Ok(path)
}

pub fn uninstall() -> Result<(PathBuf, usize)> {
    let path = claude_settings_path();
    let mut settings = read_settings(&path)?;
    let removed = strip_sentinel(&mut settings);
    if removed > 0 {
        fs::write(&path, serde_json::to_string_pretty(&settings)? + "\n")?;
    }
    Ok((path, removed))
}

pub fn is_installed() -> bool {
    read_settings(&claude_settings_path())
        .ok()
        .and_then(|s| s.get("hooks").cloned())
        .and_then(|h| h.as_object().cloned())
        .map(|events| {
            events
                .values()
                .filter_map(Value::as_array)
                .flatten()
                .any(is_sentinel_entry)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_hooks_survive_install_and_uninstall() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "/x/sentinel-hook", "args": ["pre"]}]}
                ]
            },
            "model": "claude-fable-5"
        });
        let removed = strip_sentinel(&mut settings);
        assert_eq!(removed, 1);
        let remaining = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["hooks"][0]["command"], "my-linter");
        assert_eq!(settings["model"], "claude-fable-5");
    }

    #[test]
    fn stripping_is_a_no_op_when_we_were_never_installed() {
        let mut settings = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}});
        assert_eq!(strip_sentinel(&mut settings), 0);
    }

    #[test]
    fn a_hook_event_stored_as_an_object_is_repaired_not_rejected() {
        // Claude Code ignores an object here, so a hook written that way never
        // runs. Observed in the wild after a third-party tool rewrote settings.
        let mut settings = json!({
            "hooks": {
                "PostToolUse": {"matcher": "*", "hooks": [{"type": "command", "command": "other-tool"}]}
            }
        });
        assert_eq!(
            strip_sentinel(&mut settings),
            0,
            "another tool's hook is not ours to remove"
        );

        let slot = settings["hooks"].get_mut("PostToolUse").unwrap();
        if !slot.is_array() {
            *slot = json!([slot.clone()]);
        }
        slot.as_array_mut().unwrap().push(json!({"matcher": "*"}));
        assert_eq!(
            slot.as_array().unwrap().len(),
            2,
            "the existing hook must survive repair"
        );
    }

    #[test]
    fn settings_without_hooks_are_left_alone() {
        let mut settings = json!({"theme": "dark"});
        assert_eq!(strip_sentinel(&mut settings), 0);
        assert_eq!(settings["theme"], "dark");
    }
}
