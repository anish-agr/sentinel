mod ablation;
mod analyze;
mod atbench;
mod bench;
mod brief;
mod doctor;
mod enforceability;
mod export;
mod install;
mod replay;
mod reversal;
mod stats;
mod stepshield;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use sentinel_store::{checkpoint, Store};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Records what your coding agent does, checkpoints every step, and blocks the irreversible ones."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enrol a repository so its agent activity is recorded
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Stop recording a repository (its history is kept)
    Forget {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Register Sentinel's hooks with Claude Code
    Install,
    /// Remove Sentinel's hooks from Claude Code
    Uninstall,
    /// Report what is installed, what is running, and what is not covered
    Doctor,
    /// Start the daemon in the background
    Start,
    /// Stop the daemon
    Stop,
    /// Show whether the daemon is running
    Status,
    /// Run the daemon in the foreground
    Daemon,
    /// Print the timeline URL
    Timeline,
    /// Print recorded events
    Log {
        #[arg(long)]
        run: Option<String>,
        #[arg(long, default_value_t = 40)]
        limit: u32,
    },
    /// List checkpoints that can be restored
    Checkpoints {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Restore the worktree to a checkpoint (shows a dry run first)
    Restore {
        checkpoint: String,
        /// Apply the restore instead of only showing what would change
        #[arg(long)]
        yes: bool,
    },
    /// Write SESSION.md from the event log
    Brief {
        /// Only include the last N hours
        #[arg(long)]
        since: Option<i64>,
    },
    /// List the guard rules
    Rules,
    /// Demonstrate that shell mutations a gate cannot refuse can still be undone
    Reversal,
    /// Compare argv normalisation against pattern matching under rewriting
    Ablation {
        /// List every case, not just the summary
        #[arg(long)]
        verbose: bool,
    },
    /// Evaluate the guard against a checkout of the StepShield benchmark
    Stepshield {
        /// The benchmark's data/ directory
        #[arg(long)]
        data: PathBuf,
        /// Disable these rule ids, to reproduce an earlier ruleset on the same
        /// data (e.g. --without secret.exposure,fs.system_write)
        #[arg(long, value_delimiter = ',')]
        without: Vec<String>,
        /// Restrict to one split subdirectory (e.g. --split test_holdout, the
        /// set StepShield's own headline numbers are measured on)
        #[arg(long)]
        split: Option<String>,
        /// Write every rogue trajectory's violating step to this JSONL file,
        /// so the enforceability classes can be re-rated by hand
        #[arg(long)]
        dump: Option<PathBuf>,
    },
    /// Replicate the ceiling measurement on ATBench, whose action space is
    /// remote tool calls rather than shell commands
    Atbench {
        /// The JSONL written by paper/scripts/corpora/fetch.py atbench
        #[arg(long, default_value = "paper/data/atbench-actions.jsonl")]
        data: PathBuf,
        /// Write every step from an unsafe trajectory to this JSONL file, so
        /// the classes can be re-rated by hand with paper/scripts/label.py
        #[arg(long)]
        dump: Option<PathBuf>,
    },
    /// Write a redacted, shareable copy of this repository's corpus
    Export {
        /// Directory to write events.jsonl and manifest.json into
        #[arg(long, default_value = "corpus")]
        out: PathBuf,
        #[arg(long, default_value_t = 200000)]
        limit: u32,
    },
    /// Analyse the corpus: reversibility, response to denials, detector effect
    Analyze {
        #[arg(long, default_value_t = 200000)]
        limit: u32,
        /// Analyse exported corpora in this directory instead of this
        /// repository, so several machines' data can be studied together
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Measure hook latency against the 25ms budget, on a scratch daemon
    Bench {
        #[arg(long, default_value_t = 100)]
        n: usize,
    },
    /// Summarise what has been recorded, and whether the recorder is healthy
    Stats {
        #[arg(long, default_value_t = 200000)]
        limit: u32,
    },
    /// Re-evaluate every recorded tool call against the current guard
    Replay {
        #[arg(long, default_value_t = 200000)]
        limit: u32,
        /// Print every non-allow decision with its command and reason
        #[arg(long)]
        verbose: bool,
    },
    /// Show what the guard has blocked in this repository
    Blocks {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    Allow {
        /// Fingerprint from `sentinel blocks`
        fingerprint: Option<String>,
        /// Allow the most recent block instead
        #[arg(long)]
        last: bool,
        /// Permit one retry only (the default; accepted for explicitness)
        #[arg(long)]
        once: bool,
        /// Permit this command permanently, by writing it into guard.toml
        #[arg(long, conflicts_with = "once")]
        always: bool,
    },
    /// Wrap an MCP server so its tool calls are recorded and guarded
    Mcp {
        /// The real server command, e.g. `sentinel mcp -- npx my-server`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Manage guard shims for editors without hooks (tier C blocking)
    Shim {
        #[command(subcommand)]
        action: ShimCmd,
    },
    /// Rewind to the state before the last recorded change
    Undo {
        /// Apply instead of only showing what would change
        #[arg(long)]
        yes: bool,
    },
    /// Reclaim disk by pruning old checkpoints (the event log is never touched)
    Gc {
        /// Keep every checkpoint from the last N days
        #[arg(long, default_value_t = 7)]
        days: i64,
        /// Apply instead of only reporting what would be freed
        #[arg(long)]
        yes: bool,
    },
}

/// One checkpoint as the retention policy sees it.
struct Point {
    id: String,
    run: String,
    step: u64,
    ts: DateTime<Utc>,
}

fn checkpoints(store: &Store) -> Result<Vec<Point>> {
    let mut out: Vec<Point> = store
        .events_json(None, u32::MAX)?
        .iter()
        .filter_map(|e| {
            Some(Point {
                id: e.get("checkpoint_id")?.as_str()?.to_string(),
                run: e.get("run_id")?.as_str()?.to_string(),
                step: e.get("step")?.as_u64()?,
                ts: e.get("ts")?.as_str()?.parse().ok()?,
            })
        })
        .collect();
    out.sort_by_key(|p| p.step);
    Ok(out)
}

/// Recent history in full, then only the points worth returning to: run
/// boundaries and anything the guard or a detector flagged.
fn retain(store: &Store, points: &[Point], days: i64) -> Result<BTreeSet<String>> {
    let cutoff = Utc::now() - Duration::days(days);
    let mut keep: BTreeSet<String> = points
        .iter()
        .filter(|p| p.ts >= cutoff)
        .map(|p| p.id.clone())
        .collect();

    let mut by_run: BTreeMap<&str, Vec<&Point>> = BTreeMap::new();
    for p in points {
        by_run.entry(p.run.as_str()).or_default().push(p);
    }
    for run in by_run.values() {
        if let (Some(first), Some(last)) = (run.first(), run.last()) {
            keep.insert(first.id.clone());
            keep.insert(last.id.clone());
        }
    }

    // Whatever a guard block or detection pointed at is exactly what someone
    // will want to inspect later, however old it is.
    for ev in store.events_json(None, u32::MAX)? {
        let kind = ev.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if kind != "guard_decision" && kind != "detection" {
            continue;
        }
        let (Some(run), Some(step)) = (
            ev.get("run_id").and_then(|r| r.as_str()),
            ev.get("step").and_then(|s| s.as_u64()),
        ) else {
            continue;
        };
        if let Some(nearest) = points
            .iter()
            .filter(|p| p.run == run)
            .min_by_key(|p| p.step.abs_diff(step))
        {
            keep.insert(nearest.id.clone());
        }
    }
    Ok(keep)
}

fn gc(days: i64, apply: bool) -> Result<()> {
    let store = current_store()?;
    let points = checkpoints(&store)?;
    if points.is_empty() {
        println!("No checkpoints recorded yet.");
        return Ok(());
    }
    let keep = retain(&store, &points, days)?;
    let ids: Vec<String> = keep.iter().cloned().collect();
    let live = store.live_objects(&ids)?;
    let stats = store.gc(&live, apply, std::time::Duration::from_secs(600))?;

    let pruned = points.len().saturating_sub(keep.len());
    println!(
        "{} checkpoint(s): keeping {}, pruning {} older than {days} day(s).",
        points.len(),
        keep.len(),
        pruned
    );
    println!(
        "{} object(s) {}, freeing {:.1} MB. {} kept.",
        stats.removed,
        if apply { "removed" } else { "would be removed" },
        stats.freed_bytes as f64 / 1_048_576.0,
        stats.kept
    );
    println!("\nThe event log is untouched — history stays readable, only the ability");
    println!("to restore those older worktrees is given up.");
    if !apply {
        println!("\nThis was a dry run. Re-run with --yes to apply.");
    }
    Ok(())
}

fn undo(apply: bool) -> Result<()> {
    let mut store = current_store()?;
    let points = checkpoints(&store)?;
    let Some(target) = points.iter().rev().nth(1) else {
        bail!("need at least two checkpoints to undo; there is nothing to go back to");
    };
    let id = target.id.clone();
    let plan = store.restore_plan(&id)?;
    if plan.is_empty() {
        println!("Already at the state before the last change.");
        return Ok(());
    }
    println!(
        "Rewinding to checkpoint {} (step {}) would:",
        &id[..12],
        target.step
    );
    for f in &plan.added {
        println!("  + {f}");
    }
    for f in &plan.modified {
        println!("  ~ {f}");
    }
    for f in &plan.deleted {
        println!("  - {f}");
    }
    if !apply {
        println!("\nThis was a dry run. Re-run with --yes to apply.");
        return Ok(());
    }
    let (_, safety) = store.restore(&id)?;
    println!(
        "\nDone. To undo this undo:\n  sentinel restore {} --yes",
        &safety[..12]
    );
    Ok(())
}

#[derive(Subcommand)]
enum ShimCmd {
    /// Place guarded copies of dangerous binaries in .sentinel/shims
    Enable,
    /// Remove the shims
    Disable,
    /// Show what is shimmed here
    Status,
}

/// Binaries worth shimming first: the ones agents reach for when they destroy
/// something.
const SHIMMED: &[&str] = &["git", "rm"];

fn shim_dir(repo: &std::path::Path) -> PathBuf {
    repo.join(".sentinel").join("shims")
}

fn shim(action: ShimCmd) -> Result<()> {
    let store = current_store()?;
    let dir = shim_dir(store.repo());
    match action {
        ShimCmd::Enable => {
            let source = std::env::current_exe()?
                .parent()
                .context("locating sentinel")?
                .join(if cfg!(windows) {
                    "sentinel-shim.exe"
                } else {
                    "sentinel-shim"
                });
            if !source.exists() {
                bail!("{} not found; build the workspace first", source.display());
            }
            std::fs::create_dir_all(&dir)?;
            let ext = if cfg!(windows) { ".exe" } else { "" };
            for name in SHIMMED {
                std::fs::copy(&source, dir.join(format!("{name}{ext}")))?;
            }
            println!(
                "Shims for {} written to {}",
                SHIMMED.join(", "),
                dir.display()
            );
            println!("\nSentinel does not change your PATH for you. To activate, put the shim");
            println!("directory first in PATH for the shells you want guarded:");
            println!(
                "\n  PowerShell:  $env:PATH = \"{};$env:PATH\"",
                dir.display()
            );
            println!(
                "  bash/zsh:    export PATH=\"{}:$PATH\"",
                dir.display().to_string().replace('\\', "/")
            );
            println!("\nRemove everything with `sentinel shim disable`.");
        }
        ShimCmd::Disable => {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
                println!("Removed {}", dir.display());
            } else {
                println!("No shims installed here.");
            }
            println!(
                "If you added the directory to PATH in a shell profile, remove that line too."
            );
        }
        ShimCmd::Status => {
            if !dir.exists() {
                println!(
                    "No shims installed here. `sentinel shim enable` guards {} at the PATH level.",
                    SHIMMED.join(", ")
                );
                return Ok(());
            }
            let on_path = std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).any(|d| d == dir))
                .unwrap_or(false);
            println!("Shims present in {}", dir.display());
            println!(
                "PATH activation: {}",
                if on_path {
                    "active in this shell"
                } else {
                    "NOT active in this shell — commands here are not being intercepted"
                }
            );
        }
    }
    Ok(())
}

const STALE_BLOCK_SECS: i64 = 600;

/// One guard decision that is still standing, as `sentinel blocks` prints it
/// and as `allow --last` picks it: (fingerprint, rule, command, timestamp).
type Block = (String, String, String, String);

const NON_BLOCKING_VERDICTS: [&str; 2] = ["warn", "allow"];

/// Guard decisions that are still standing, newest last.
fn blocks(store: &Store) -> Result<Vec<Block>> {
    Ok(outstanding_blocks(&store.events_json(None, 20000)?))
}

fn outstanding_blocks(events: &[serde_json::Value]) -> Vec<Block> {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();

    let mut ordered: Vec<(Option<i64>, usize, &serde_json::Value)> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e["kind"] == "guard_decision")
        .map(|(i, e)| (e["seq"].as_i64(), i, e))
        .collect();
    ordered.sort_by_key(|(seq, i, _)| (seq.is_none(), seq.unwrap_or(0), *i));

    // Slots are nulled rather than removed so the indices held below stay valid,
    // and so the surviving rows keep their ascending order for `--last`.
    let mut found: Vec<Option<Block>> = Vec::new();
    // fingerprint -> indices into `found` of its refusals that no override has
    // claimed yet, oldest first, so `pop` takes the most recent.
    let mut unreleased: HashMap<&str, Vec<usize>> = HashMap::new();

    for (seq, _, e) in ordered {
        let fingerprint = e["args_hash"].as_str().unwrap_or("");
        let verdict = e["meta"]["verdict"].as_str().unwrap_or("");
        if verdict == "overridden" {
            if seq.is_some() {
                if let Some(released) = unreleased.get_mut(fingerprint).and_then(|q| q.pop()) {
                    found[released] = None;
                }
            }
            continue;
        }
        found.push(Some((
            fingerprint.to_string(),
            text(&e["meta"]["rule"]),
            text(&e["args_summary"]),
            text(&e["ts"]),
        )));
        if seq.is_some() && !NON_BLOCKING_VERDICTS.contains(&verdict) {
            unreleased
                .entry(fingerprint)
                .or_default()
                .push(found.len() - 1);
        }
    }
    found.into_iter().flatten().collect()
}

/// Seconds since an RFC3339 timestamp, or None if it cannot be read.
fn age_secs(ts: &str) -> Option<i64> {
    let then = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    Some((chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds())
}

fn human_age(secs: i64) -> String {
    if secs < 120 {
        format!("{secs}s")
    } else if secs < 7200 {
        format!("{}m", secs / 60)
    } else if secs < 172_800 {
        format!("{}h", secs / 3600)
    } else {
        format!("{} days", secs / 86_400)
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("sentinel: {e:#}");
        std::process::exit(1);
    }
}

fn reject_if_too_broad(root: &Path) -> Result<()> {
    let root = sentineld::canonical(root);
    let home = sentineld::canonical(&sentineld::home_dir());
    let sentinel_home = sentineld::canonical(&sentineld::sentinel_home());
    check_not_too_broad(&root, &home, &sentinel_home)
}

/// The actual check, taking `home`/`sentinel_home` as arguments so it can be
/// tested without depending on process environment variables.
fn check_not_too_broad(root: &Path, home: &Path, sentinel_home: &Path) -> Result<()> {
    if root == home || root == sentinel_home {
        bail!(
            "{} is your home directory. Enrolling it would checkpoint your \
             entire profile — browser data, downloads, everything under \
             AppData — not a project.\n\
             \n\
             cd into the repository you want recorded and run `sentinel init` there.",
            root.display()
        );
    }

    let s = root.to_string_lossy();
    let trimmed = s.trim_end_matches(['/', '\\']);
    let is_drive_root = trimmed.len() == 2 && trimmed.as_bytes()[1] == b':';
    if trimmed.is_empty() || is_drive_root {
        bail!(
            "{} is a filesystem root, not a project. cd into the repository \
             you want recorded and run `sentinel init` there.",
            root.display()
        );
    }
    Ok(())
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = Command::new("xdg-open").arg(url).spawn();
}

fn repo_root(path: &std::path::Path) -> Result<PathBuf> {
    let abs = sentineld::canonical(path);
    checkpoint::find_repo_root(&abs).with_context(|| {
        format!(
            "no git repository or .sentinel directory at or above {}",
            abs.display()
        )
    })
}

fn current_store() -> Result<Store> {
    let root = repo_root(&PathBuf::from("."))?;
    if !Store::is_enrolled(&root) {
        bail!(
            "{} is not enrolled — run `sentinel init` there first",
            root.display()
        );
    }
    // While the daemon is up it owns the index; reading without syncing keeps
    // the two processes from fighting over the write lock.
    if sentineld::running().is_some() {
        Store::open_reader(&root)
    } else {
        Store::open(&root)
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Cmd::Init { path } => {
            let root = repo_root(&path)?;
            reject_if_too_broad(&root)?;
            let mut store = Store::init(&root)?;
            sentineld::registry::add(&root)?;
            let snap = store.snapshot()?;
            println!("Recording {}", root.display());
            println!(
                "  baseline checkpoint {} ({} files)",
                &snap.id[..12],
                snap.checkpoint.files
            );
            println!("  state lives in {}", store.dir().display());
            if sentineld::running().is_none() {
                println!("\nThe daemon is not running yet. Start it with `sentinel start`.");
            }
        }
        Cmd::Forget { path } => {
            let root = repo_root(&path)?;
            sentineld::registry::remove(&root)?;
            println!("No longer recording {}", root.display());
            println!(
                "History is untouched; delete {}/.sentinel to remove it.",
                root.display()
            );
        }
        Cmd::Install => {
            let path = install::install()?;
            println!("Claude Code hooks written to {}", path.display());
            println!("Sentinel now sees every tool call in new Claude Code sessions.");
            println!("Undo at any time with `sentinel uninstall`.");
        }
        Cmd::Uninstall => {
            let (path, removed) = install::uninstall()?;
            println!("Removed {removed} Sentinel hook(s) from {}", path.display());
        }
        Cmd::Doctor => print!("{}", doctor::report()),
        Cmd::Start => start_daemon()?,
        Cmd::Stop => stop_daemon()?,
        Cmd::Status => match sentineld::running() {
            Some(info) => println!(
                "running — http://127.0.0.1:{} (pid {}, version {})",
                info.port, info.pid, info.version
            ),
            None => println!("not running"),
        },
        Cmd::Daemon => sentineld::run_foreground()?,
        Cmd::Timeline => match sentineld::running() {
            Some(info) => {
                let url = format!("http://127.0.0.1:{}/", info.port);
                println!("{url}");
                open_browser(&url);
            }
            None => bail!("the daemon is not running — start it with `sentinel start`"),
        },
        Cmd::Log { run, limit } => {
            let store = current_store()?;
            let run = run.map(|r| resolve_run(&store, &r)).transpose()?;
            for ev in store.events_json(run, limit)? {
                let get = |k: &str| ev.get(k).cloned().unwrap_or(serde_json::Value::Null);
                println!(
                    "{:>5}  {:<15} {:<12} {}",
                    get("step"),
                    get("kind").as_str().unwrap_or(""),
                    get("tool").as_str().unwrap_or(""),
                    get("args_summary").as_str().unwrap_or("")
                );
            }
        }
        Cmd::Checkpoints { limit } => {
            let store = current_store()?;
            let mut shown = 0;
            for ev in store.events_json(None, 5000)? {
                let Some(id) = ev.get("checkpoint_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                println!(
                    "{}  step {:<5} {}",
                    &id[..12],
                    ev.get("step").and_then(|s| s.as_u64()).unwrap_or(0),
                    ev.get("ts").and_then(|t| t.as_str()).unwrap_or("")
                );
                shown += 1;
                if shown >= limit {
                    break;
                }
            }
            if shown == 0 {
                println!("No checkpoints recorded yet.");
            }
        }
        Cmd::Restore {
            checkpoint: prefix,
            yes,
        } => restore(&prefix, yes)?,
        Cmd::Brief { since } => {
            let store = current_store()?;
            let text = brief::build(&store, since)?;
            let path = store.repo().join("SESSION.md");
            std::fs::write(&path, &text)?;
            println!("Wrote {}", path.display());
        }
        Cmd::Rules => {
            for (id, summary) in sentinel_guard::rule_ids() {
                println!("{id:<32} {summary}");
            }
        }
        Cmd::Reversal => reversal::run()?,
        Cmd::Ablation { verbose } => {
            let r = ablation::run();
            let (total, guard, prefix, substring) = r.totals();
            let pct = |n: usize| n as f64 / total.max(1) as f64 * 100.0;

            println!(
                "{} dangerous commands rewritten into {total} semantically identical forms.",
                ablation::DANGEROUS.len()
            );
            println!("\nRefused by");
            println!(
                "  argv normalisation      {guard:>4} of {total}  ({:.0}%)",
                pct(guard)
            );
            println!(
                "  substring match         {substring:>4} of {total}  ({:.0}%)",
                pct(substring)
            );
            println!(
                "  prefix match            {prefix:>4} of {total}  ({:.0}%)",
                pct(prefix)
            );
            println!("\n  Prefix matching is the shape `permissions.deny` uses; substring is");
            println!("  the more generous form most published deny-lists take. Both are");
            println!("  included so the comparison is not against a straw man.");

            println!("\nBy rewrite (cases / normalised / substring / prefix)");
            for (name, (n, g, p, s)) in r.by_rewrite() {
                println!("  {name:<20} {n:>3} {g:>12} {s:>10} {p:>8}");
            }

            let misses = r.guard_misses();
            if misses.is_empty() {
                println!("\nThe guard refused every rewrite.");
            } else {
                println!("\nRewrites the guard also missed ({})", misses.len());
                for m in &misses {
                    println!("  {:<22} {:<18} {}", m.label, m.rewrite, m.command);
                }
                println!("\n  Reported rather than omitted: a guard measured only where it");
                println!("  wins is not measured. These are the normaliser's own gaps.");
            }

            if verbose {
                println!("\nEvery case");
                for c in &r.cases {
                    println!(
                        "  {}{}{}  {:<20} {}",
                        if c.guard { "G" } else { "." },
                        if c.substring { "S" } else { "." },
                        if c.prefix { "P" } else { "." },
                        c.rewrite,
                        c.command
                    );
                }
                println!("\n  G = argv normalisation, S = substring, P = prefix.");
            }
        }
        Cmd::Atbench { data, dump } => {
            atbench::run(&data, dump.as_deref())?;
        }
        Cmd::Stepshield {
            data,
            without,
            split,
            dump,
        } => {
            let r = stepshield::run(&data, &without, split.as_deref())?;
            if let Some(path) = &dump {
                let n = stepshield::dump(&r, path)?;
                println!("Wrote {n} violating steps to {}\n", path.display());
            }
            if let Some(s) = &split {
                println!("Split: {s}\n");
            }
            if !without.is_empty() {
                println!("Rules disabled for this run: {}\n", without.join(", "));
            }
            let rogue = r.rogue();
            let benign = r.benign();
            println!(
                "StepShield — {} trajectories ({} rogue, {} benign)",
                r.trajectories.len(),
                rogue.len(),
                benign.len()
            );

            println!("\nWhat could any deterministic gate refuse? (enforceability composition)");
            let n = rogue.len().max(1);
            for (class, (count, caught)) in r.by_class() {
                println!(
                    "  {:<4} {:<36} {count:>4}  {:>5.1}%   caught {caught}",
                    class.key(),
                    class.label(),
                    count as f64 / n as f64 * 100.0
                );
            }

            let (ceiling, caught, exact) = r.ceiling();
            println!(
                "\n  CEILING: {:.1}% of violations admit a deterministic predicate.",
                ceiling as f64 / n as f64 * 100.0
            );
            println!("  The rest are outside what any pre-action gate can reach — a claim");
            println!("  has nothing to intercept, and a semantically-wrong action is");
            println!("  indistinguishable in form from its correct use.");

            println!("\nPerformance against the ceiling, not against the corpus");
            println!(
                "  refused                             {caught} of {ceiling}  ({:.0}% of reachable)",
                caught as f64 / ceiling.max(1) as f64 * 100.0
            );
            println!(
                "  refused exactly at the violating step  {exact} of {ceiling}  ({:.0}% EIR at k=0)",
                exact as f64 / ceiling.max(1) as f64 * 100.0
            );
            let stray = r.catches_outside_ceiling();
            if stray > 0 {
                println!("  refusals outside the reachable class   {stray}  (not evidence the rules work)");
            }

            println!("\nWhere the residual risk is (decidable in advance x undoable after)");
            for ((decidable, reach), count) in r.residual() {
                println!(
                    "  {:<14} {:<10} {count:>4}{}",
                    if decidable {
                        "decidable"
                    } else {
                        "undecidable"
                    },
                    if reach == stepshield::Reach::Local {
                        "local"
                    } else {
                        "external"
                    },
                    if !decidable && reach == stepshield::Reach::External {
                        "   <- neither gate nor checkpoint reaches this"
                    } else {
                        ""
                    }
                );
            }

            println!("\nBy signature (reachable violations / caught by this ruleset)");
            for (sig, (total, caught)) in r.by_signature() {
                println!("  {sig:<24} {total:>4} {caught:>7}");
            }

            let missed = r.reachable_misses();
            if !missed.is_empty() {
                println!(
                    "\nReachable violations this ruleset missed ({})",
                    missed.len()
                );
                let mut by_sig: std::collections::BTreeMap<&str, usize> = BTreeMap::new();
                for t in &missed {
                    *by_sig.entry(t.signature.unwrap_or("?")).or_insert(0) += 1;
                }
                for (sig, count) in by_sig {
                    println!("  {sig:<24} {count}");
                }
                println!("  These are the enumerated missing predicates — the honest gap");
                println!("  between what is reachable and what this ruleset reaches.");
            }

            println!("\nBy category (rogue / reachable / caught)");
            for (cat, (n, act, caught)) in r.by_category() {
                println!("  {cat:<6} {n:>4} {act:>11} {caught:>7}");
            }

            println!("\nFalse positives on benign trajectories");
            let fp = r.false_positives();
            println!(
                "  {} of {} benign trajectories had something refused  ({:.2}%)",
                fp.len(),
                benign.len(),
                fp.len() as f64 / benign.len().max(1) as f64 * 100.0
            );
            for t in fp.iter().take(10) {
                println!(
                    "    {:<22} step {:<4} {}",
                    t.id,
                    t.first_denial.unwrap_or(0),
                    t.denial_rule.as_deref().unwrap_or("-")
                );
            }

            println!("\nRules that fired");
            for (rule, n) in r.rules_fired() {
                println!("  {rule:<28} {n}");
            }

            let rates = r.rates();
            let (rl, rh) = stepshield::Rates::wilson(rates.recall_num, rates.recall_den);
            let (fl, fh) = stepshield::Rates::wilson(rates.fpr_num, rates.fpr_den);
            println!("\nRates, with 95% Wilson intervals");
            println!(
                "  recall  {:.1}%  [{:.1}, {:.1}]   ({}/{})",
                rates.recall() * 100.0,
                rl * 100.0,
                rh * 100.0,
                rates.recall_num,
                rates.recall_den
            );
            println!(
                "  FPR     {:.2}%  [{:.2}, {:.2}]   ({}/{})",
                rates.fpr() * 100.0,
                fl * 100.0,
                fh * 100.0,
                rates.fpr_num,
                rates.fpr_den
            );

            let bench_base = rogue.len() as f64 / r.trajectories.len().max(1) as f64;
            println!("\nPrecision collapses as rogue actions get rarer (base-rate reality)");
            println!("  base rate   precision   false alarms per real catch");
            for base in [bench_base, 0.02, 0.005, 0.001] {
                let p = rates.precision_at(base);
                let ratio = if p > 0.0 {
                    (1.0 - p) / p
                } else {
                    f64::INFINITY
                };
                let note = if (base - bench_base).abs() < 1e-9 {
                    "  <- this corpus's measured rogue rate"
                } else {
                    ""
                };
                println!(
                    "  {:>7.1}%     {:>6.1}%     {:>6.1}{note}",
                    base * 100.0,
                    p * 100.0,
                    ratio
                );
            }
            println!("\n  Even at this false-positive rate, once rogue actions are rare the");
            println!("  gate raises more false alarms than true ones. That is not an argument");
            println!("  against the gate — it is the argument for not trusting it alone, and");
            println!("  for pairing it with recording so a false alarm costs a retry, not a halt.");
        }
        Cmd::Export { out, limit } => {
            let store = current_store()?;
            let s = export::run(&store, &out, limit)?;
            println!("Exported {} events across {} runs", s.events, s.runs);
            println!("  source id       {}", s.source);
            println!("  substitutions   {}", s.redacted_paths);
            println!("  written to      {}", s.path.display());
            if s.residual > 0 {
                println!(
                    "\n  NOT SAFE TO PUBLISH: {} lines still contain the username.",
                    s.residual
                );
                println!(
                    "  Redaction missed a form it does not recognise. Inspect before sharing."
                );
            } else {
                println!("\n  Self-check passed: no line contains the username.");
            }
            println!("\nBlob payloads are not included: full tool arguments and responses");
            println!("were never scrubbed, because they were never meant to leave the");
            println!("machine. The self-check covers one known identifier, not every");
            println!("possible one — read manifest.json before publishing.");
        }
        Cmd::Analyze { limit, corpus } => {
            let a = match &corpus {
                Some(dir) => analyze::from_corpus(dir)?,
                None => analyze::run(&current_store()?, limit)?,
            };
            let total: usize = a.reversibility.values().sum();

            println!("Corpus — {} calls across {} runs", total, a.runs);
            if a.unrecoverable_payloads > 0 {
                println!(
                    "  ({} payloads no longer in the blob store, classified as unknown)",
                    a.unrecoverable_payloads
                );
            }

            println!("\nWhat could be undone, and by whom");
            for (class, n) in &a.reversibility {
                let pct = *n as f64 / total.max(1) as f64 * 100.0;
                println!("  {:<38} {n:>5}  {pct:>5.1}%", class.label());
            }
            match a.vendor_blind_share() {
                Some(share) => {
                    println!("\n  Of {} calls that changed the worktree,", a.mutating());
                    println!(
                        "  {:.0}% arrived through a shell and are therefore invisible",
                        share * 100.0
                    );
                    println!("  to editor-level checkpointing.");
                }
                None => println!("\n  Nothing in this corpus changed the worktree."),
            }

            println!("\nWhat the agent did after being blocked");
            if a.denials.is_empty() {
                println!("  (nothing has been blocked)");
            }
            for (response, n) in a.responses() {
                println!("  {:<32} {n}", response.label());
            }
            for d in &a.denials {
                let command: String = d.summary.chars().take(56).collect();
                println!("    {:<24} {:<28} {command}", d.rule, d.response.label());
            }

            println!("\nDid a detector's finding change the behaviour?");
            let summary = a.detector_summary();
            if summary.is_empty() {
                println!("  (no detections, or none of a measurable kind)");
            }
            for (detector, (fired, changed)) in &summary {
                println!("  {detector:<20} {changed} of {fired} followed by a change");
            }
            println!("\n  'Followed by' is not 'caused by' — this is an upper bound on");
            println!("  effect, and the honest reading is that a low number rules the");
            println!("  intervention out while a high one only fails to.");
        }
        Cmd::Bench { n } => bench::run(n)?,
        Cmd::Stats { limit } => {
            let store = current_store()?;
            let s = stats::collect(&store, limit)?;
            println!("Corpus — {}", store.repo().display());
            println!("  events         {}", s.total());
            println!("  runs           {}", s.runs);
            if let (Some(a), Some(b)) = (&s.first_ts, &s.last_ts) {
                println!(
                    "  span           {} .. {}",
                    &a[..10.min(a.len())],
                    &b[..10.min(b.len())]
                );
            }
            println!("\nBy kind");
            for (kind, n) in &s.kinds {
                println!("  {kind:<16} {n}");
            }

            println!("\nRecorder health — result/call per day");
            for (day, (calls, results)) in s.by_day.iter().rev().take(10) {
                let r = if *calls == 0 {
                    0.0
                } else {
                    *results as f64 / *calls as f64
                };
                let flag = if r < 0.95 { "  <- results dropped" } else { "" };
                println!("  {day}  {r:>4.2}  {results:>5} / {calls:<5}{flag}");
            }
            println!(
                "  lifetime       {:.2}  ({} results for {} calls)",
                s.result_ratio(),
                s.results(),
                s.calls()
            );
            match s.latest_day() {
                Some((day, r, _)) if r < 0.5 => {
                    println!(
                        "\n  BROKEN on {day}: the post hook dropped {}% of results.",
                        ((1.0 - r) * 100.0).round() as i64
                    );
                    println!("           Exit codes are gone and `error_identity` cannot fire.");
                    println!("           Check `sentinel doctor` and that the daemon is running.");
                }
                Some((day, r, _)) if r < 0.95 => {
                    println!(
                        "\n  partial on {day} — {}% of results missing. Expected mid-session",
                        ((1.0 - r) * 100.0).round() as i64
                    );
                    println!("           (calls still in flight); investigate if it persists.");
                }
                Some((day, _, n)) => {
                    println!("\n  healthy on {day} — all {n} calls have their results")
                }
                None => println!("\n  nothing recorded yet"),
            }

            println!("\nDetectors fired");
            if s.detectors.is_empty() {
                println!("  (none)");
            }
            for (d, n) in &s.detectors {
                println!("  {d:<20} {n}");
            }
            let silent = s.silent_detectors();
            if !silent.is_empty() {
                println!(
                    "  never fired:   {} ({} of {})",
                    silent.join(", "),
                    silent.len(),
                    sentinel_detect::detector_ids().len()
                );
            }

            println!("\nGuard decisions recorded");
            if s.rules.is_empty() {
                println!("  (none)");
            }
            for (r, n) in &s.rules {
                println!("  {r:<28} {n}");
            }
            if s.blocks + s.overrides > 0 {
                println!("  ---");
                println!("  blocks stood                 {}", s.blocks);
                println!("  overridden by the agent      {}", s.overrides);
                // A guard cleared every time it fires is a logging feature
                // wearing a guard's name, so the rate is worth stating plainly.
                let rate = s.overrides as f64 / (s.blocks + s.overrides) as f64 * 100.0;
                println!("  override rate                {rate:.0}%");
            }

            if !s.models.is_empty() {
                println!("\nBy model (calls / guard decisions / rate)");
                for (model, (calls, decisions)) in &s.models {
                    println!(
                        "  {model:<22} {calls:>6} {decisions:>6}   {:.2}%",
                        *decisions as f64 / (*calls).max(1) as f64 * 100.0
                    );
                }
                println!("  Whether a weaker model trips the guard more often is a question");
                println!("  this can answer once the corpus spans models evenly.");
            }

            println!("\nMost-called tools");
            let mut tools: Vec<_> = s.tools.iter().collect();
            tools.sort_by(|a, b| b.1.cmp(a.1));
            for (tool, n) in tools.iter().take(10) {
                println!("  {tool:<20} {n}");
            }
        }
        Cmd::Replay { limit, verbose } => {
            let store = current_store()?;
            let report = replay::run(&store, limit)?;
            let total = report.outcomes.len();
            let denied = report.denied();
            let warned = report.warned();

            println!("Replayed {total} recorded tool calls through the current guard.");
            if report.unrecoverable > 0 {
                println!(
                    "  {} skipped — argument payload no longer in the blob store.",
                    report.unrecoverable
                );
            }
            println!("  deny   {}", denied.len());
            println!("  warn   {}", warned.len());
            println!("  allow  {}", total - denied.len() - warned.len());
            if total > 0 {
                println!(
                    "\n  intervention rate {:.2}% of all recorded calls",
                    (denied.len() + warned.len()) as f64 / total as f64 * 100.0
                );
            }

            let by_rule = report.by_rule();
            if !by_rule.is_empty() {
                println!("\nBy rule");
                for (rule, n) in &by_rule {
                    println!("  {rule:<28} {n}");
                }
            }

            if verbose {
                println!("\nEvery non-allow decision");
                for o in denied.iter().chain(warned.iter()) {
                    println!(
                        "  [{:?}] {:<24} {:<12} {}",
                        o.verdict,
                        o.rule.as_deref().unwrap_or("-"),
                        o.tool,
                        o.summary
                    );
                    if let Some(reason) = &o.reason {
                        println!("      {reason}");
                    }
                }
            }

            // Every one of these needs a human verdict before it can be called
            // a false positive, so say what the number does and does not mean.
            println!("\nEach decision above still needs judging by hand — the guard being");
            println!("certain is not the guard being right. Branch-dependent rules replayed");
            println!(
                "against branch `{}`, which may differ from record time.",
                report.branch.as_deref().unwrap_or("unknown")
            );
        }
        Cmd::Blocks { limit } => {
            let store = current_store()?;
            let found = blocks(&store)?;
            if found.is_empty() {
                println!("Nothing has been blocked in this repository.");
            }
            // Age is shown because the fix for a stale grant starts with
            // noticing the block is old.
            for (fingerprint, rule, command, ts) in found.iter().rev().take(limit) {
                let age = age_secs(ts).map(human_age).unwrap_or_default();
                println!(
                    "{}  {age:>7}  {rule:<28} {command}",
                    &fingerprint[..12.min(fingerprint.len())]
                );
            }
        }
        Cmd::Allow {
            fingerprint,
            last,
            once: _once,
            always,
        } => {
            let store = current_store()?;
            let found = blocks(&store)?;
            let chosen = match (fingerprint, last) {
                (Some(prefix), _) => found
                    .iter()
                    .rev()
                    .find(|(f, _, _, _)| f.starts_with(&prefix))
                    .cloned()
                    .with_context(|| format!("no block matches `{prefix}`"))?,
                (None, true) => {
                    let last = found
                        .last()
                        .cloned()
                        .context("nothing has been blocked yet")?;
                    if let Some(age) = age_secs(&last.3) {
                        if age > STALE_BLOCK_SECS {
                            bail!(
                                "the newest block in {} is {} old, so it is \
                                 probably not the one you mean:\n  {}\n\n\
                                 A command is recorded in the store of the \
                                 repository the guard resolved, which is not \
                                 always the directory you ran it from. Check \
                                 `sentinel blocks` there, or name the \
                                 fingerprint explicitly:\n  \
                                 sentinel allow <fingerprint> --once",
                                store.repo().display(),
                                human_age(age),
                                last.2
                            );
                        }
                    }
                    last
                }
                (None, false) => bail!("pass a fingerprint from `sentinel blocks`, or --last"),
            };
            // One retry unless the permanent grant is asked for by name.
            if always {
                sentinel_guard::GuardConfig::allow_always(store.repo(), &chosen.0)?;
                println!(
                    "Allowed always in {}:\n  {}",
                    store.repo().display(),
                    chosen.2
                );
                println!("\nThis exact command will no longer be blocked here. Every future");
                println!("occurrence is recorded as `allowlisted` rather than refused, so the");
                println!("weakening stays visible in `sentinel timeline`.");
                println!(
                    "Undo by editing {}",
                    sentinel_guard::config::repo_path(store.repo()).display()
                );
            } else {
                sentineld::oneshot::grant(store.repo(), &chosen.0)?;
                println!(
                    "Allowed once in {}:\n  {}",
                    store.repo().display(),
                    chosen.2
                );
                println!("\nRetry the command now. The grant covers one attempt, is spent");
                println!("whether or not the command succeeds, and is recorded in the log");
                println!("as an override rather than as an allow.");
                println!("\nUse --always if you meant to permit this command permanently.");
            }
        }
        Cmd::Mcp { command } => {
            let target: Vec<String> = command.into_iter().skip_while(|a| a == "--").collect();
            let code = sentineld::mcp::run(&target)?;
            std::process::exit(code);
        }
        Cmd::Shim { action } => shim(action)?,
        Cmd::Undo { yes } => undo(yes)?,
        Cmd::Gc { days, yes } => gc(days, yes)?,
    }
    Ok(())
}

fn resolve_run(store: &Store, prefix: &str) -> Result<uuid::Uuid> {
    let runs = store.runs()?;
    let matches: Vec<&str> = runs
        .iter()
        .map(|r| r.run_id.as_str())
        .filter(|id| id.starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [one] => Ok(uuid::Uuid::parse_str(one)?),
        [] => bail!("no run starts with `{prefix}`"),
        many => bail!("`{prefix}` matches {} runs; be more specific", many.len()),
    }
}

fn resolve_checkpoint(store: &Store, prefix: &str) -> Result<String> {
    let mut found: Vec<String> = store
        .events_json(None, 20000)?
        .iter()
        .filter_map(|ev| {
            ev.get("checkpoint_id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .filter(|id| id.starts_with(prefix))
        .collect();
    found.sort();
    found.dedup();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!("no checkpoint starts with `{prefix}`"),
        n => bail!("`{prefix}` matches {n} checkpoints; be more specific"),
    }
}

fn restore(prefix: &str, apply: bool) -> Result<()> {
    let mut store = current_store()?;
    let id = resolve_checkpoint(&store, prefix)?;
    let plan = store.restore_plan(&id)?;

    if plan.is_empty() {
        println!("The worktree already matches checkpoint {}.", &id[..12]);
        return Ok(());
    }
    println!("Restoring to {} would:", &id[..12]);
    for f in &plan.added {
        println!("  + {f}");
    }
    for f in &plan.modified {
        println!("  ~ {f}");
    }
    for f in &plan.deleted {
        println!("  - {f}");
    }
    println!(
        "\n{} added, {} modified, {} deleted",
        plan.added.len(),
        plan.modified.len(),
        plan.deleted.len()
    );

    if !apply {
        println!("\nThis was a dry run. Re-run with --yes to apply.");
        return Ok(());
    }
    let (_, safety) = store.restore(&id)?;
    println!("\nRestored. The previous state was snapshotted first:");
    println!("  sentinel restore {} --yes", &safety[..12]);
    Ok(())
}

fn daemon_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("locating the sentinel binary")?;
    let name = if cfg!(windows) {
        "sentineld.exe"
    } else {
        "sentineld"
    };
    let path = dir.join(name);
    if !path.exists() {
        bail!("{} not found; build the workspace first", path.display());
    }
    Ok(path)
}

fn start_daemon() -> Result<()> {
    if let Some(info) = sentineld::running() {
        println!("Already running on http://127.0.0.1:{}", info.port);
        return Ok(());
    }
    sentineld::clear_info();
    let log_path = sentineld::sentinel_home().join("daemon.log");
    std::fs::create_dir_all(sentineld::sentinel_home())?;
    let log = std::fs::File::create(&log_path)?;

    let mut command = Command::new(daemon_binary()?);
    // Both streams go to a file. A console process with nowhere to write would
    // otherwise make Windows allocate a console window the first time it prints.
    command
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW only: DETACHED_PROCESS would leave the daemon with no
        // console at all, and Windows would pop a new one on the first write.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn().context("starting the daemon")?;

    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Some(info) = sentineld::running() {
            println!(
                "Daemon started — timeline at http://127.0.0.1:{}/",
                info.port
            );
            println!("Logs: {}", log_path.display());
            return Ok(());
        }
    }
    bail!("the daemon did not start; see {}", log_path.display())
}

fn stop_daemon() -> Result<()> {
    let Some(info) = sentineld::read_info() else {
        println!("not running");
        return Ok(());
    };
    #[cfg(windows)]
    let killed = Command::new("taskkill")
        .args(["/PID", &info.pid.to_string(), "/F"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    #[cfg(not(windows))]
    let killed = Command::new("kill")
        .arg(info.pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    sentineld::clear_info();
    println!(
        "{}",
        if killed {
            "Daemon stopped."
        } else {
            "Daemon was not running; cleared stale state."
        }
    );
    Ok(())
}

#[cfg(test)]
mod too_broad_tests {
    use super::*;

    /// A grant that releases a block from another day is worse than no grant:
    /// it is spent, it is logged as an override, and the command the operator
    /// actually wanted is refused again with nothing to explain why.
    #[test]
    fn a_block_from_another_session_is_stale() {
        let ago = |secs| (chrono::Utc::now() - chrono::Duration::seconds(secs)).to_rfc3339();
        let stale = |ts: &str| age_secs(ts).map(|a| a > STALE_BLOCK_SECS);
        // The retry that follows the refusal immediately: releasable.
        assert_eq!(stale(&ago(5)), Some(false));
        assert_eq!(stale(&ago(60)), Some(false));
        // The case that motivated the check: a block recorded in another
        // repository a day and a half earlier.
        assert_eq!(stale(&ago(35 * 3600)), Some(true));
        assert_eq!(stale(&ago(4 * 86_400)), Some(true));
        // Unreadable timestamps release rather than block: the guard should
        // never become unusable because a record is malformed.
        assert_eq!(stale("not a timestamp"), None);
    }

    #[test]
    fn age_is_read_from_the_events_own_timestamp() {
        let recent = chrono::Utc::now() - chrono::Duration::seconds(30);
        let age = age_secs(&recent.to_rfc3339()).expect("rfc3339 parses");
        assert!((25..=45).contains(&age), "got {age}");
        assert_eq!(age_secs("not a timestamp"), None);
    }

    #[test]
    fn ages_read_in_the_unit_a_person_would_use() {
        assert_eq!(human_age(45), "45s");
        assert_eq!(human_age(600), "10m");
        assert_eq!(human_age(7200), "2h");
        assert_eq!(human_age(35 * 3600), "35h");
        assert_eq!(human_age(4 * 86_400), "4 days");
    }

    #[test]
    fn the_home_directory_itself_is_rejected() {
        let home = PathBuf::from("/home/author");
        let sentinel_home = home.join(".sentinel");
        // Reproduces the incident: `sentinel init` run from a bare shell in
        // the home directory resolved its root to the home directory itself.
        assert!(check_not_too_broad(&home, &home, &sentinel_home).is_err());
    }

    #[test]
    fn sentinel_home_itself_is_rejected_even_if_relocated() {
        // SENTINEL_HOME can be overridden away from the default `~/.sentinel`.
        // Wherever it ends up, it must never be enrollable — it is Sentinel's
        // own state, not a project.
        let home = PathBuf::from("/home/author");
        let sentinel_home = PathBuf::from("/mnt/data/sentinel-state");
        assert!(check_not_too_broad(&sentinel_home, &home, &sentinel_home).is_err());
    }

    #[test]
    fn a_drive_root_is_rejected() {
        let home = PathBuf::from("C:/Users/author");
        let sentinel_home = home.join(".sentinel");
        assert!(check_not_too_broad(&PathBuf::from("C:/"), &home, &sentinel_home).is_err());
    }

    #[test]
    fn an_ordinary_project_directory_is_accepted() {
        let home = PathBuf::from("/home/author");
        let sentinel_home = home.join(".sentinel");
        let project = home.join("code").join("myproject");
        assert!(check_not_too_broad(&project, &home, &sentinel_home).is_ok());
    }
}

/// Which refusals `sentinel blocks` and `allow --last` are still looking at,
/// once overrides have been matched against the denials they released.
#[cfg(test)]
mod outstanding_block_tests {
    use super::*;
    use serde_json::json;

    const RESTORE: &str = "fp-git-restore";
    const CHMOD: &str = "fp-chmod-777";

    /// A `guard_decision` row shaped the way `events_json` hands one over.
    fn row(seq: i64, verdict: &str, fingerprint: &str, command: &str) -> serde_json::Value {
        json!({
            "seq": seq,
            "kind": "guard_decision",
            "step": seq,
            "ts": stamp(seq),
            "args_hash": fingerprint,
            "args_summary": command,
            "meta": {"verdict": verdict, "rule": "rule.under.test", "command": command},
        })
    }

    /// Timestamps differ per `seq`, so a test can say WHICH of two otherwise
    /// identical denials of the same command survived.
    fn stamp(seq: i64) -> String {
        format!("2026-08-22T10:00:{seq:02}Z")
    }

    fn stamps(found: &[Block]) -> Vec<String> {
        found.iter().map(|b| b.3.clone()).collect()
    }

    fn commands(found: &[Block]) -> Vec<&str> {
        found.iter().map(|b| b.2.as_str()).collect()
    }

    #[test]
    fn a_deny_after_an_override_is_still_outstanding() {
        let found = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "overridden", RESTORE, "git restore ."),
            row(3, "deny", RESTORE, "git restore ."),
        ]);
        assert_eq!(
            stamps(&found),
            vec![stamp(3)],
            "the override at seq 2 released the deny at seq 1 and nothing else"
        );
    }

    /// An override buys one attempt. `oneshot::consume` removes exactly one
    /// grant, so it must retire exactly one refusal.
    #[test]
    fn one_override_retires_exactly_one_earlier_deny() {
        let found = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "deny", RESTORE, "git restore ."),
            row(3, "overridden", RESTORE, "git restore ."),
        ]);
        assert_eq!(
            stamps(&found),
            vec![stamp(1)],
            "one grant was spent, so one of the two denials is still standing"
        );
    }

    /// The bug this was an over-correction of: an override writes a second row
    /// and leaves the deny in place, so dropping only rows whose own verdict is
    /// `overridden` left the released deny visible for ever.
    #[test]
    fn a_released_deny_does_not_remain_visible() {
        let found = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "overridden", RESTORE, "git restore ."),
        ]);
        assert!(
            found.is_empty(),
            "the deny was released; nothing is outstanding, got {found:?}"
        );
    }

    #[test]
    fn a_spent_grant_is_not_re_issuable_and_a_fresh_block_still_is() {
        let ledger = [
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "overridden", RESTORE, "git restore ."),
            row(3, "deny", RESTORE, "git restore ."),
            row(4, "overridden", RESTORE, "git restore ."),
            row(5, "deny", RESTORE, "git restore ."),
        ];
        // Two grants issued, two spent, three refusals: exactly one is left to
        // be released, and it is the newest.
        let found = outstanding_blocks(&ledger);
        assert_eq!(stamps(&found), vec![stamp(5)]);

        // With that one released too, `--last` has nothing to spend a grant on.
        let mut settled = ledger.to_vec();
        settled.push(row(6, "overridden", RESTORE, "git restore ."));
        let found = outstanding_blocks(&settled);
        assert!(found.last().is_none(), "got {found:?}");
    }

    #[test]
    fn last_targets_the_newest_block_not_an_unrelated_one() {
        let found = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "overridden", RESTORE, "git restore ."),
            row(3, "deny", CHMOD, "chmod -R 777 ."),
            row(4, "deny", RESTORE, "git restore ."),
        ]);
        assert_eq!(commands(&found), vec!["chmod -R 777 .", "git restore ."]);
        let last = found.last().expect("a block is outstanding");
        assert_eq!(
            last.2, "git restore .",
            "`--last` must take the newest outstanding block"
        );
        assert_eq!(last.0, RESTORE, "and grant against its fingerprint");
    }

    /// Overrides are matched per fingerprint, so a release of one command must
    /// not retire a refusal of another interleaved with it.
    #[test]
    fn interleaved_fingerprints_do_not_release_each_other() {
        let found = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            row(2, "deny", CHMOD, "chmod -R 777 ."),
            row(3, "overridden", RESTORE, "git restore ."),
            row(4, "deny", RESTORE, "git restore ."),
            row(5, "overridden", CHMOD, "chmod -R 777 ."),
            row(6, "deny", CHMOD, "chmod -R 777 ."),
        ]);
        assert_eq!(
            stamps(&found),
            vec![stamp(4), stamp(6)],
            "each override retired one refusal of its own command"
        );
        assert_eq!(commands(&found), vec!["git restore .", "chmod -R 777 ."]);
    }

    #[test]
    fn an_override_does_not_retire_a_warning_sharing_its_fingerprint() {
        let found = outstanding_blocks(&[
            row(1, "warn", RESTORE, "git restore ."),
            row(2, "deny", RESTORE, "git restore ."),
            row(3, "overridden", RESTORE, "git restore ."),
        ]);
        assert_eq!(
            stamps(&found),
            vec![stamp(1)],
            "the deny was released, the warning was not the thing released"
        );
    }

    /// Ordering is taken from `seq` rather than from the order rows arrive in,
    /// so `--last` still means newest if that query is ever changed.
    #[test]
    fn rows_are_matched_and_returned_in_seq_order_however_they_arrive() {
        let mut descending = vec![
            row(4, "deny", RESTORE, "git restore ."),
            row(3, "deny", CHMOD, "chmod -R 777 ."),
            row(2, "overridden", RESTORE, "git restore ."),
            row(1, "deny", RESTORE, "git restore ."),
        ];
        let found = outstanding_blocks(&descending);
        assert_eq!(
            stamps(&found),
            vec![stamp(3), stamp(4)],
            "newest last, and the seq-2 override still released the seq-1 deny"
        );
        descending.reverse();
        assert_eq!(
            stamps(&outstanding_blocks(&descending)),
            vec![stamp(3), stamp(4)],
            "the answer must not depend on the order rows are handed over in"
        );
    }

    /// An override whose deny fell off the far end of the 20000-row window has
    /// nothing to retire. It must not reach forward and retire the next one.
    #[test]
    fn an_override_with_no_earlier_deny_retires_nothing() {
        let found = outstanding_blocks(&[
            row(1, "overridden", RESTORE, "git restore ."),
            row(2, "deny", RESTORE, "git restore ."),
        ]);
        assert_eq!(stamps(&found), vec![stamp(2)]);
    }

    /// Nothing here may panic or silently drop a refusal on a window that is
    /// empty, unrelated, or missing the fields this reads.
    #[test]
    fn an_empty_or_degenerate_window_is_handled() {
        assert!(outstanding_blocks(&[]).is_empty());

        // Rows of other kinds are not guard decisions.
        assert!(outstanding_blocks(&[
            json!({"seq": 1, "kind": "tool_call", "args_hash": RESTORE}),
            json!({"seq": 2, "kind": "checkpoint"}),
            json!({"seq": 3, "kind": "detection", "meta": {"verdict": "deny"}}),
        ])
        .is_empty());

        // A guard decision missing everything this reads is still a refusal
        // that happened; it is reported with blank fields rather than dropped.
        let bare = outstanding_blocks(&[json!({"seq": 1, "kind": "guard_decision"})]);
        assert_eq!(bare.len(), 1);
        assert_eq!(
            bare[0],
            (String::new(), String::new(), String::new(), String::new())
        );

        // A row with no `seq` cannot be placed in time, so an override carrying
        // one releases nothing rather than guessing.
        let unplaceable = outstanding_blocks(&[
            row(1, "deny", RESTORE, "git restore ."),
            json!({
                "kind": "guard_decision",
                "args_hash": RESTORE,
                "args_summary": "git restore .",
                "meta": {"verdict": "overridden", "rule": "rule.under.test"},
            }),
        ]);
        assert_eq!(stamps(&unplaceable), vec![stamp(1)]);
    }
}
