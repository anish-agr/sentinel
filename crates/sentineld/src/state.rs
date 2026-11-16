use anyhow::{Context, Result};
use sentinel_detect::Detection;
use sentinel_events::{Event, EventKind};
use sentinel_guard::GuardConfig;
use sentinel_store::{checkpoint, Store};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A poisoned lock means some other request panicked; the data itself is still
/// consistent and the daemon must keep serving.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Default)]
pub struct GitCtx {
    pub branch: Option<String>,
    pub dirty: bool,
    pub untracked: bool,
}

pub struct RepoState {
    pub root: PathBuf,
    pub store: Mutex<Store>,
    pub git: RwLock<GitCtx>,
    config: RwLock<GuardConfig>,
    pending: Mutex<HashMap<Uuid, Instant>>,
    emitted: Mutex<HashSet<String>>,
    last_hook: Mutex<Option<Instant>>,
}

impl RepoState {
    pub fn git(&self) -> GitCtx {
        self.git.read().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn guard_config(&self) -> GuardConfig {
        self.config.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Refreshed on a timer rather than per call: `git status` on a large repo
    /// costs more than the whole latency budget for a hook.
    pub fn refresh(&self) {
        let state = checkpoint::git_state(&self.root);
        if let Ok(mut g) = self.git.write() {
            *g = GitCtx {
                branch: state.branch.clone(),
                dirty: state.dirty,
                untracked: !state.untracked.is_empty(),
            };
        }
        if let Ok(mut c) = self.config.write() {
            *c = GuardConfig::load(&self.root);
        }
    }

    /// Tier A is live on this repo; tier C observation stands down.
    pub fn mark_hook(&self) {
        *lock(&self.last_hook) = Some(Instant::now());
    }

    pub fn hook_recent(&self, window: std::time::Duration) -> bool {
        lock(&self.last_hook).is_some_and(|t| t.elapsed() < window)
    }

    pub fn mark_call_start(&self, run: Uuid) {
        lock(&self.pending).insert(run, Instant::now());
    }

    pub fn take_call_duration(&self, run: Uuid) -> Option<u64> {
        lock(&self.pending)
            .remove(&run)
            .map(|start| start.elapsed().as_millis() as u64)
    }
}

pub struct CheckpointJob {
    pub repo: Arc<RepoState>,
    pub run_id: Uuid,
}

pub struct Daemon {
    pub token: String,
    pub port: u16,
    pub pricing: crate::transcript::Pricing,
    repos: Mutex<HashMap<PathBuf, Arc<RepoState>>>,
    checkpoints: Sender<CheckpointJob>,
}

impl Daemon {
    pub fn new(port: u16, token: String) -> Arc<Daemon> {
        let (tx, rx) = channel::<CheckpointJob>();
        let daemon = Arc::new(Daemon {
            token,
            port,
            pricing: crate::transcript::Pricing::load(),
            repos: Mutex::new(HashMap::new()),
            checkpoints: tx,
        });

        // Snapshots run off the request path: the hook must return in
        // milliseconds regardless of repository size.
        std::thread::spawn(move || {
            for job in rx {
                if let Err(e) = take_checkpoint(&job) {
                    eprintln!(
                        "sentinel: checkpoint failed for {}: {e:#}",
                        job.repo.root.display()
                    );
                }
            }
        });

        let watcher = Arc::clone(&daemon);
        std::thread::spawn(move || loop {
            for repo in watcher.known_repos() {
                repo.refresh();
            }
            std::thread::sleep(Duration::from_secs(2));
        });

        daemon
    }

    pub fn repo(&self, root: &Path) -> Result<Arc<RepoState>> {
        let key = root.to_path_buf();
        let mut repos = lock(&self.repos);
        if let Some(existing) = repos.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let store =
            Store::open(root).with_context(|| format!("opening store for {}", root.display()))?;
        let state = Arc::new(RepoState {
            root: key.clone(),
            store: Mutex::new(store),
            git: RwLock::new(GitCtx::default()),
            config: RwLock::new(GuardConfig::load(root)),
            pending: Mutex::new(HashMap::new()),
            emitted: Mutex::new(HashSet::new()),
            last_hook: Mutex::new(None),
        });
        state.refresh();
        repos.insert(key, Arc::clone(&state));
        Ok(state)
    }

    pub fn known_repos(&self) -> Vec<Arc<RepoState>> {
        lock(&self.repos).values().map(Arc::clone).collect()
    }

    pub fn queue_checkpoint(&self, repo: Arc<RepoState>, run_id: Uuid) {
        let _ = self.checkpoints.send(CheckpointJob { repo, run_id });
    }
}

fn take_checkpoint(job: &CheckpointJob) -> Result<()> {
    let mut store = lock(&job.repo.store);
    let snap = store.snapshot()?;
    let step = store.next_step(job.run_id)?;
    let mut ev = Event::new(job.run_id, step, EventKind::Checkpoint);
    ev.checkpoint_id = Some(snap.id.clone());
    ev.repo_state_hash = Some(snap.checkpoint.tree.clone());
    ev.files_touched = Vec::new();
    ev.meta = Some(serde_json::json!({
        "files": snap.checkpoint.files,
        "bytes": snap.checkpoint.bytes,
        "branch": snap.checkpoint.git.branch,
        "dirty": snap.checkpoint.git.dirty,
    }));
    store.append(&ev)?;
    Ok(())
}

pub fn run_detectors(repo: &Arc<RepoState>, run_id: Uuid) -> Result<Vec<String>> {
    let events = {
        let store = lock(&repo.store);
        store.load_run(run_id)?
    };
    let found: Vec<Detection> = sentinel_detect::detect(&events);
    if found.is_empty() {
        return Ok(Vec::new());
    }
    let mut store = lock(&repo.store);
    let mut emitted = lock(&repo.emitted);
    let mut fresh = Vec::new();
    for detection in found {
        let key = format!(
            "{}:{}:{}",
            run_id, detection.key.detector, detection.key.subject
        );
        if !emitted.insert(key) {
            continue;
        }
        let step = store.next_step(run_id)?;
        let ev = Event::new(run_id, step, EventKind::Detection)
            .tool(detection.meta.detector.clone())
            .meta(serde_json::to_value(&detection.meta)?);
        store.append(&ev)?;
        fresh.push(detection.meta.message);
    }
    Ok(fresh)
}
