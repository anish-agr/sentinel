use crate::state::{lock, Daemon};
use anyhow::Result;
use ignore::gitignore::GitignoreBuilder;
use sentinel_events::{run_id, Event, EventKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long after a tier A hook event this repo is considered hook-covered.
pub const HOOK_COVERAGE: Duration = Duration::from_secs(20);
const QUIET: Duration = Duration::from_millis(500);

fn ignored(root: &Path, rel: &str) -> bool {
    if rel.starts_with(".git/") || rel.starts_with(".sentinel/") || rel == ".git" {
        return true;
    }
    let mut builder = GitignoreBuilder::new(root);
    builder.add(root.join(".gitignore"));
    builder
        .build()
        .map(|gi| {
            gi.matched_path_or_any_parents(Path::new(rel), false)
                .is_ignore()
        })
        .unwrap_or(false)
}

/// Records one debounced batch of observed mutations. Returns how many events
/// were written (0 when suppressed or everything was ignorable).
pub fn record_mutations(daemon: &Arc<Daemon>, root: &Path, paths: &[PathBuf]) -> Result<usize> {
    let repo = daemon.repo(root)?;
    if repo.hook_recent(HOOK_COVERAGE) {
        return Ok(0);
    }
    let mut files: Vec<String> = paths
        .iter()
        .filter_map(|p| p.strip_prefix(root).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .filter(|rel| !rel.is_empty() && !ignored(root, rel))
        .collect();
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Ok(0);
    }

    // One run per calendar day of ambient observation: there is no session
    // boundary to go on, and a day scrubs well on the timeline.
    let day = chrono::Utc::now().format("%Y-%m-%d");
    let run = run_id(&root.to_string_lossy(), &format!("observed-{day}"));
    let mut store = lock(&repo.store);
    let step = store.next_step(run)?;
    store.append(&Event::new(run, step, EventKind::FileMutation).files(files))?;
    drop(store);
    daemon.queue_checkpoint(repo, run);
    Ok(1)
}

/// Watches every enrolled repository, picking up newly enrolled ones as they
/// appear. Runs for the life of the daemon; any error just disables tier C
/// rather than harming anything else.
pub fn start(daemon: Arc<Daemon>) {
    std::thread::spawn(move || {
        let (tx, rx) = channel();
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res {
                    let _ = tx.send(ev.paths);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("sentinel: tier C watcher unavailable: {e}");
                    return;
                }
            };

        use notify::{RecursiveMode, Watcher};
        let mut watched: HashSet<PathBuf> = HashSet::new();
        let mut pending: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        let mut last = Instant::now();
        loop {
            for root in crate::registry::list() {
                if watched.insert(root.clone()) {
                    if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
                        eprintln!("sentinel: cannot watch {}: {e}", root.display());
                    }
                }
            }
            match rx.recv_timeout(QUIET) {
                Ok(paths) => {
                    last = Instant::now();
                    for path in paths {
                        if let Some(root) = watched.iter().find(|r| path.starts_with(r)) {
                            pending.entry(root.clone()).or_default().push(path);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !pending.is_empty() && last.elapsed() >= QUIET {
                        for (root, paths) in pending.drain() {
                            if let Err(e) = record_mutations(&daemon, &root, &paths) {
                                eprintln!("sentinel: tier C record failed: {e:#}");
                            }
                        }
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    });
}
