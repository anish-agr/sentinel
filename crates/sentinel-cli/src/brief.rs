use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sentinel_events::{Event, EventKind};
use sentinel_store::Store;
use std::collections::BTreeMap;
use std::fmt::Write;

const WRITE_TOOLS: &[&str] = &["write", "edit", "multiedit", "notebookedit"];

pub fn build(store: &Store, since_hours: Option<i64>) -> Result<String> {
    let cutoff: Option<DateTime<Utc>> = since_hours.map(|h| Utc::now() - Duration::hours(h));
    let runs = store.runs()?;
    let mut out = String::new();

    writeln!(out, "# Session brief\n")?;
    writeln!(
        out,
        "Repository: `{}`  \nGenerated: {}  \nSource: `.sentinel/events.jsonl` only — every line below is derived from recorded events, not from any model's memory.\n",
        store.repo().display(),
        Utc::now().to_rfc3339()
    )?;

    let mut all: Vec<Event> = Vec::new();
    let mut kept_runs = 0;
    for run in &runs {
        let id = match uuid::Uuid::parse_str(&run.run_id) {
            Ok(id) => id,
            Err(_) => continue,
        };
        let events = store.load_run(id)?;
        let in_window = events.iter().any(|e| cutoff.is_none_or(|c| e.ts >= c));
        if !in_window {
            continue;
        }
        kept_runs += 1;
        all.extend(events);
    }

    if all.is_empty() {
        writeln!(out, "No recorded activity in this window.")?;
        return Ok(out);
    }

    writeln!(out, "## Sessions\n")?;
    writeln!(out, "{kept_runs} run(s), {} recorded events.\n", all.len())?;
    for run in runs.iter().take(kept_runs) {
        writeln!(
            out,
            "- `{}` — {} steps, {} → {}{}",
            &run.run_id[..8],
            run.steps,
            &run.started[..run.started.len().min(19)],
            &run.ended[..run.ended.len().min(19)],
            if run.blocks > 0 {
                format!(", {} blocked by guard", run.blocks)
            } else {
                String::new()
            }
        )?;
    }
    writeln!(out)?;

    section_files_changed(&mut out, &all)?;
    section_failures(&mut out, &all)?;
    section_guard(&mut out, &all)?;
    section_detections(&mut out, &all)?;
    section_final_state(&mut out, store, &all)?;

    Ok(out)
}

fn section_files_changed(out: &mut String, events: &[Event]) -> Result<()> {
    let mut counts: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ToolResult) {
        let tool = ev.tool.as_deref().unwrap_or("").to_ascii_lowercase();
        if !WRITE_TOOLS.contains(&tool.as_str()) {
            continue;
        }
        for file in &ev.files_touched {
            counts.entry(file).or_default().push(ev.step);
        }
    }
    writeln!(out, "## Files actually changed\n")?;
    if counts.is_empty() {
        writeln!(
            out,
            "None — no write or edit tool call completed in this window.\n"
        )?;
        return Ok(());
    }
    for (file, steps) in &counts {
        writeln!(
            out,
            "- `{file}` — {} edit(s) <!-- steps {:?} -->",
            steps.len(),
            steps
        )?;
    }
    writeln!(out)?;
    Ok(())
}

fn section_failures(out: &mut String, events: &[Event]) -> Result<()> {
    let failures: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == EventKind::ToolResult && e.exit_code.is_some_and(|c| c != 0))
        .collect();
    writeln!(out, "## Commands that failed\n")?;
    if failures.is_empty() {
        writeln!(out, "None recorded.\n")?;
        return Ok(());
    }
    for ev in failures.iter().take(25) {
        writeln!(
            out,
            "- exit {} — `{}` <!-- step {} -->",
            ev.exit_code.unwrap_or(-1),
            ev.args_summary.as_deref().unwrap_or(""),
            ev.step
        )?;
    }
    if failures.len() > 25 {
        writeln!(out, "- ...and {} more", failures.len() - 25)?;
    }
    writeln!(out)?;
    Ok(())
}

fn section_guard(out: &mut String, events: &[Event]) -> Result<()> {
    let blocks: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == EventKind::GuardDecision)
        .collect();
    writeln!(out, "## Guard decisions\n")?;
    if blocks.is_empty() {
        writeln!(out, "Nothing was blocked.\n")?;
        return Ok(());
    }
    for ev in &blocks {
        let reason = ev
            .meta
            .as_ref()
            .and_then(|m| m.get("reason"))
            .and_then(|r| r.as_str())
            .unwrap_or("");
        writeln!(
            out,
            "- `{}` — {reason} <!-- step {} -->",
            ev.args_summary.as_deref().unwrap_or(""),
            ev.step
        )?;
    }
    writeln!(out)?;
    Ok(())
}

fn section_detections(out: &mut String, events: &[Event]) -> Result<()> {
    let found: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == EventKind::Detection)
        .collect();
    writeln!(out, "## Detector findings\n")?;
    if found.is_empty() {
        writeln!(
            out,
            "No loops, repeated errors, or redundant reads detected.\n"
        )?;
        return Ok(());
    }
    for ev in &found {
        let message = ev
            .meta
            .as_ref()
            .and_then(|m| m.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        writeln!(
            out,
            "- **{}** — {message} <!-- step {} -->",
            ev.tool.as_deref().unwrap_or(""),
            ev.step
        )?;
    }
    writeln!(out)?;
    Ok(())
}

fn section_final_state(out: &mut String, store: &Store, events: &[Event]) -> Result<()> {
    writeln!(out, "## State at the last checkpoint\n")?;
    let Some(last) = events
        .iter()
        .filter(|e| e.checkpoint_id.is_some())
        .max_by_key(|e| e.ts)
    else {
        writeln!(out, "No checkpoint was taken in this window.\n")?;
        return Ok(());
    };
    let id = last.checkpoint_id.as_deref().unwrap_or_default();
    let checkpoint = store.read_checkpoint(id)?;
    writeln!(
        out,
        "Checkpoint `{}` at {}.\n",
        &id[..12.min(id.len())],
        checkpoint.ts.to_rfc3339()
    )?;
    writeln!(
        out,
        "- branch: `{}`",
        checkpoint.git.branch.as_deref().unwrap_or("unknown")
    )?;
    writeln!(out, "- tracked files: {}", checkpoint.files)?;
    writeln!(
        out,
        "- uncommitted: {} staged, {} unstaged, {} untracked",
        checkpoint.git.staged.len(),
        checkpoint.git.unstaged.len(),
        checkpoint.git.untracked.len()
    )?;
    for path in checkpoint.git.unstaged.iter().take(20) {
        writeln!(out, "  - modified `{path}`")?;
    }
    writeln!(
        out,
        "\nRestore this exact state with:\n\n```bash\nsentinel restore {}\n```\n",
        &id[..12.min(id.len())]
    )?;
    writeln!(out, "<!-- checkpoint from step {} -->", last.step)?;
    Ok(())
}
