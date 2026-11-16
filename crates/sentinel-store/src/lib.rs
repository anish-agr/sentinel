//! Storage for one enrolled repository: an append-only event log, a
//! content-addressed blob store, and a SQLite index derived from the log.

pub mod cas;
pub mod checkpoint;
pub mod index;
pub mod log;
pub mod scrub;

use anyhow::{bail, Context, Result};
use cas::Cas;
use checkpoint::{Checkpoint, RestorePlan, ScanCache, Snapshot};
use index::{Index, RunRow};
use log::EventLog;
use sentinel_events::Event;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Default, Clone, Copy)]
pub struct GcStats {
    pub kept: usize,
    pub removed: usize,
    pub freed_bytes: u64,
}

const INDEXED_BYTES: &str = "indexed_bytes";

pub struct Store {
    repo: PathBuf,
    dir: PathBuf,
    pub cas: Cas,
    log: EventLog,
    index: Index,
    cache: ScanCache,
}

impl Store {
    pub fn is_enrolled(repo: &Path) -> bool {
        repo.join(".sentinel").join("events.jsonl").exists()
    }

    pub fn init(repo: &Path) -> Result<Store> {
        let dir = repo.join(".sentinel");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // Sentinel's own state must never end up in the user's commits.
        let ignore = dir.join(".gitignore");
        if !ignore.exists() {
            fs::write(&ignore, "*\n")?;
        }
        Store::open_at(repo, &dir, true)
    }

    pub fn open(repo: &Path) -> Result<Store> {
        Store::open_inner(repo, true)
    }

    /// Opens without bringing the index up to date. The daemon is the only
    /// writer; a second process syncing concurrently would contend for the write
    /// lock on every row and could insert the same events twice.
    pub fn open_reader(repo: &Path) -> Result<Store> {
        Store::open_inner(repo, false)
    }

    fn open_inner(repo: &Path, sync: bool) -> Result<Store> {
        let dir = repo.join(".sentinel");
        if !dir.is_dir() {
            bail!(
                "{} is not enrolled; run `sentinel init` there first",
                repo.display()
            );
        }
        Store::open_at(repo, &dir, sync)
    }

    fn open_at(repo: &Path, dir: &Path, sync: bool) -> Result<Store> {
        let cas = Cas::new(dir.join("objects"))?;
        let log = EventLog::open(dir.join("events.jsonl"))?;
        let index = Index::open(&dir.join("index.db"))?;
        let cache = ScanCache::load(&dir.join("scan-cache.json"));
        let mut store = Store {
            repo: repo.to_path_buf(),
            dir: dir.to_path_buf(),
            cas,
            log,
            index,
            cache,
        };
        if sync {
            store.sync_index()?;
        }
        Ok(store)
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn append(&mut self, ev: &Event) -> Result<()> {
        self.log.append(ev)?;
        self.sync_index()?;
        Ok(())
    }

    /// Brings the index up to date with the log. Cheap and idempotent, so it is
    /// safe to call after every append.
    pub fn sync_index(&mut self) -> Result<usize> {
        let offset: u64 = self
            .index
            .get_meta(INDEXED_BYTES)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let (events, new_offset) = self.log.read_from(offset)?;
        for ev in &events {
            self.index.insert(ev)?;
        }
        if new_offset != offset {
            self.index
                .set_meta(INDEXED_BYTES, &new_offset.to_string())?;
        }
        Ok(events.len())
    }

    /// Throws the index away and replays the log. The log is authoritative; this
    /// is the recovery path if the index is ever lost or corrupted.
    pub fn reindex(&mut self) -> Result<usize> {
        self.index.clear()?;
        self.index.set_meta(INDEXED_BYTES, "0")?;
        self.sync_index()
    }

    pub fn next_step(&self, run: Uuid) -> Result<u64> {
        self.index.next_step(run)
    }

    pub fn event_count(&self) -> Result<u64> {
        self.index.count()
    }

    pub fn runs(&self) -> Result<Vec<RunRow>> {
        self.index.runs()
    }

    pub fn events_json(&self, run: Option<Uuid>, limit: u32) -> Result<Vec<serde_json::Value>> {
        self.index.events_json(run, limit)
    }

    pub fn load_run(&self, run: Uuid) -> Result<Vec<Event>> {
        self.index.load(run)
    }

    pub fn snapshot(&mut self) -> Result<Snapshot> {
        let snap = checkpoint::snapshot(&self.repo, &self.cas, &mut self.cache)?;
        self.cache.save(&self.dir.join("scan-cache.json"))?;
        Ok(snap)
    }

    pub fn read_checkpoint(&self, id: &str) -> Result<Checkpoint> {
        checkpoint::read(&self.cas, id)
    }

    /// Computes what a restore would do without touching the worktree.
    pub fn restore_plan(&mut self, checkpoint_id: &str) -> Result<RestorePlan> {
        let target = self.read_checkpoint(checkpoint_id)?;
        let current = checkpoint::scan(&self.repo, &self.cas, &mut self.cache)?;
        let want = checkpoint::tree_files(&self.cas, &target.tree)?;
        Ok(checkpoint::diff(&current, &want))
    }

    /// Restores the worktree, taking an automatic safety snapshot of the current
    /// state first so the restore itself is always undoable.
    pub fn restore(&mut self, checkpoint_id: &str) -> Result<(RestorePlan, String)> {
        let target = self.read_checkpoint(checkpoint_id)?;
        let safety = self.snapshot()?;
        let plan = checkpoint::restore(&self.repo, &self.cas, &target.tree, &mut self.cache)?;
        self.cache.save(&self.dir.join("scan-cache.json"))?;
        Ok((plan, safety.id))
    }

    /// Blobs referenced directly by log lines: argument payloads, stderr, agent
    /// message text. Small, and the log points at them forever, so they are
    /// never candidates for collection.
    pub fn referenced_blobs(&self) -> Result<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        for ev in self.index.events_json(None, u32::MAX)? {
            for key in ["args_hash", "stderr_norm_hash"] {
                if let Some(h) = ev.get(key).and_then(|v| v.as_str()) {
                    out.insert(h.to_string());
                }
            }
            if let Some(h) = ev.pointer("/meta/response_hash").and_then(|v| v.as_str()) {
                out.insert(h.to_string());
            }
        }
        Ok(out)
    }

    /// Everything reachable from the checkpoints we intend to keep, plus the
    /// directly referenced blobs.
    pub fn live_objects(&self, keep_checkpoints: &[String]) -> Result<BTreeSet<String>> {
        let mut live = self.referenced_blobs()?;
        for id in keep_checkpoints {
            let Ok(checkpoint) = self.read_checkpoint(id) else {
                continue;
            };
            live.insert(id.clone());
            checkpoint::collect_objects(&self.cas, &checkpoint.tree, &mut live)?;
        }
        Ok(live)
    }

    /// Sweeps objects no longer reachable. Objects newer than `grace` are spared
    /// regardless: a checkpoint in flight has already written its blobs but may
    /// not yet have appended the event that references them.
    pub fn gc(
        &self,
        live: &BTreeSet<String>,
        apply: bool,
        grace: std::time::Duration,
    ) -> Result<GcStats> {
        let mut stats = GcStats::default();
        let root = self.dir.join("objects");
        for shard in fs::read_dir(&root)? {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            let prefix = shard.file_name().to_string_lossy().to_string();
            for object in fs::read_dir(shard.path())? {
                let object = object?;
                let meta = object.metadata()?;
                let hash = format!("{prefix}{}", object.file_name().to_string_lossy());
                if live.contains(&hash) {
                    stats.kept += 1;
                    continue;
                }
                if meta
                    .modified()
                    .is_ok_and(|m| m.elapsed().is_ok_and(|e| e < grace))
                {
                    stats.kept += 1;
                    continue;
                }
                stats.removed += 1;
                stats.freed_bytes += meta.len();
                if apply {
                    let _ = fs::remove_file(object.path());
                }
            }
        }
        Ok(stats)
    }

    pub fn files_at(&self, checkpoint_id: &str) -> Result<Vec<(String, String)>> {
        let cp = self.read_checkpoint(checkpoint_id)?;
        Ok(checkpoint::tree_files(&self.cas, &cp.tree)?
            .into_iter()
            .map(|(path, (hash, _))| (path, hash))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_events::{run_id, EventKind};
    use std::collections::BTreeMap;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in fs::read_dir(&dir).unwrap().flatten() {
                let name = e.file_name();
                if name == ".sentinel" || name == ".git" {
                    continue;
                }
                let p = e.path();
                if e.file_type().unwrap().is_dir() {
                    stack.push(p);
                } else {
                    let rel = p
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, fs::read(&p).unwrap());
                }
            }
        }
        out
    }

    fn mutate(root: &Path, rng: &mut Rng, rounds: u64) {
        for _ in 0..rounds {
            let files: Vec<String> = read_tree(root).keys().cloned().collect();
            match rng.below(4) {
                0 => {
                    let name = format!("new_{}.txt", rng.next());
                    let dir = if rng.below(2) == 0 {
                        root.join("sub")
                    } else {
                        root.to_path_buf()
                    };
                    fs::create_dir_all(&dir).unwrap();
                    fs::write(dir.join(name), format!("content {}", rng.next())).unwrap();
                }
                1 if !files.is_empty() => {
                    let f = &files[rng.below(files.len() as u64) as usize];
                    fs::write(root.join(f), format!("changed {}", rng.next())).unwrap();
                }
                2 if !files.is_empty() => {
                    let f = &files[rng.below(files.len() as u64) as usize];
                    fs::remove_file(root.join(f)).unwrap();
                }
                _ => {
                    let dir = root.join(format!("d{}", rng.below(3)));
                    fs::create_dir_all(&dir).unwrap();
                    fs::write(dir.join("f.txt"), format!("{}", rng.next())).unwrap();
                }
            }
        }
    }

    #[test]
    fn restore_is_byte_identical_after_arbitrary_mutations() {
        for seed in 0..12u64 {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);

            fs::write(root.join("README.md"), "hello").unwrap();
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

            let mut store = Store::init(root).unwrap();
            let rounds = 1 + rng.below(6);
            mutate(root, &mut rng, rounds);

            let before = read_tree(root);
            let snap = store.snapshot().unwrap();

            let rounds = 1 + rng.below(8);
            mutate(root, &mut rng, rounds);
            assert_ne!(read_tree(root), before, "seed {seed}: mutation was a no-op");

            store.restore(&snap.id).unwrap();
            assert_eq!(
                read_tree(root),
                before,
                "seed {seed}: restore was not byte-identical"
            );
        }
    }

    #[test]
    fn restore_plan_matches_what_restore_does() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("keep.txt"), "a").unwrap();
        fs::write(root.join("edit.txt"), "before").unwrap();
        let mut store = Store::init(root).unwrap();
        let snap = store.snapshot().unwrap();

        fs::write(root.join("edit.txt"), "after").unwrap();
        fs::write(root.join("extra.txt"), "new").unwrap();

        let plan = store.restore_plan(&snap.id).unwrap();
        assert_eq!(plan.modified, vec!["edit.txt"]);
        assert_eq!(plan.deleted, vec!["extra.txt"]);
        assert!(plan.added.is_empty());
        assert!(
            root.join("extra.txt").exists(),
            "plan must not mutate the worktree"
        );

        let (applied, safety) = store.restore(&snap.id).unwrap();
        assert_eq!(applied.len(), plan.len());
        assert_eq!(fs::read_to_string(root.join("edit.txt")).unwrap(), "before");
        assert!(!root.join("extra.txt").exists());

        // The safety snapshot can put the pre-restore state back.
        store.restore(&safety).unwrap();
        assert_eq!(fs::read_to_string(root.join("edit.txt")).unwrap(), "after");
        assert!(root.join("extra.txt").exists());
    }

    #[test]
    fn gitignored_files_are_neither_snapshotted_nor_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".gitignore"), "ignored/\n*.log\n").unwrap();
        fs::create_dir_all(root.join("ignored")).unwrap();
        fs::write(root.join("ignored/big.bin"), "junk").unwrap();
        fs::write(root.join("debug.log"), "noise").unwrap();
        fs::write(root.join("tracked.txt"), "v1").unwrap();

        let mut store = Store::init(root).unwrap();
        let snap = store.snapshot().unwrap();
        let files = store.files_at(&snap.id).unwrap();
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(names.contains(&"tracked.txt"));
        assert!(!names.iter().any(|n| n.starts_with("ignored")));
        assert!(!names.contains(&"debug.log"));

        fs::write(root.join("tracked.txt"), "v2").unwrap();
        store.restore(&snap.id).unwrap();
        assert!(
            root.join("ignored/big.bin").exists(),
            "restore deleted an ignored file"
        );
        assert!(root.join("debug.log").exists());
        assert_eq!(fs::read_to_string(root.join("tracked.txt")).unwrap(), "v1");
    }

    #[test]
    fn index_rebuilds_from_the_log_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut store = Store::init(root).unwrap();
        let run = run_id("/r", "s");
        for step in 1..=5 {
            store
                .append(&Event::new(run, step, EventKind::ToolCall).tool("bash"))
                .unwrap();
        }
        assert_eq!(store.event_count().unwrap(), 5);
        assert_eq!(store.next_step(run).unwrap(), 6);

        drop(store);
        fs::remove_file(root.join(".sentinel/index.db")).unwrap();

        let store = Store::open(root).unwrap();
        assert_eq!(store.event_count().unwrap(), 5);
        assert_eq!(store.runs().unwrap().len(), 1);
        assert_eq!(store.load_run(run).unwrap().len(), 5);
    }

    #[test]
    fn reindex_does_not_duplicate_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::init(tmp.path()).unwrap();
        let run = run_id("/r", "s");
        store
            .append(&Event::new(run, 1, EventKind::ToolCall))
            .unwrap();
        store.sync_index().unwrap();
        assert_eq!(store.event_count().unwrap(), 1);
        store.reindex().unwrap();
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn the_event_window_is_the_newest_rows_in_ascending_seq() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::init(tmp.path()).unwrap();
        let run = run_id("/r", "s");
        for step in 1..=10 {
            store
                .append(&Event::new(run, step, EventKind::ToolCall).tool(format!("t{step}")))
                .unwrap();
        }

        let all = store.events_json(None, 100).unwrap();
        let seqs: Vec<i64> = all.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
        assert_eq!(
            seqs,
            (1..=10).collect::<Vec<i64>>(),
            "ascending, oldest first"
        );

        // A limit smaller than the log keeps the newest rows, still ascending,
        // so the last element is the most recent event.
        let window = store.events_json(None, 3).unwrap();
        let seqs: Vec<i64> = window.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
        assert_eq!(seqs, vec![8, 9, 10]);
        assert_eq!(window.last().unwrap()["tool"], "t10");

        // Scoped to a run it is ascending too, so both callers agree.
        let scoped = store.events_json(Some(run), 100).unwrap();
        let seqs: Vec<i64> = scoped.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
        assert_eq!(seqs, (1..=10).collect::<Vec<i64>>());
    }

    #[test]
    fn gc_keeps_what_is_reachable_and_drops_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("keep.txt"), "v1").unwrap();
        let mut store = Store::init(root).unwrap();

        let first = store.snapshot().unwrap();
        fs::write(root.join("keep.txt"), "v2").unwrap();
        let second = store.snapshot().unwrap();

        // Nothing is collectable while both checkpoints are kept.
        let none = std::time::Duration::ZERO;
        let live = store
            .live_objects(&[first.id.clone(), second.id.clone()])
            .unwrap();
        let dry = store.gc(&live, false, none).unwrap();
        assert_eq!(dry.removed, 0, "reachable objects must never be swept");

        // Dropping the older checkpoint frees exactly its unshared objects, and
        // the surviving checkpoint still restores.
        let live = store
            .live_objects(std::slice::from_ref(&second.id))
            .unwrap();
        assert!(!live.contains(&first.id));
        let stats = store.gc(&live, true, none).unwrap();
        assert!(
            stats.removed > 0,
            "the pruned checkpoint should free something"
        );

        // A fresh object is spared while inside the grace window.
        let fresh = store.cas.put(b"in flight").unwrap();
        let spared = store
            .gc(&live, true, std::time::Duration::from_secs(600))
            .unwrap();
        assert!(
            store.cas.has(&fresh),
            "objects in flight must survive: {spared:?}"
        );

        fs::write(root.join("keep.txt"), "v3").unwrap();
        store.restore(&second.id).unwrap();
        assert_eq!(fs::read_to_string(root.join("keep.txt")).unwrap(), "v2");
    }

    #[test]
    fn gc_never_touches_blobs_the_log_points_at() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::init(tmp.path()).unwrap();
        let hash = store.cas.put(b"an argument payload").unwrap();
        let run = run_id("/r", "s");
        store
            .append(&Event::new(run, 1, EventKind::ToolCall).args(hash.clone(), "cmd"))
            .unwrap();

        let live = store.live_objects(&[]).unwrap();
        assert!(live.contains(&hash), "a blob the log references stays live");
    }

    #[test]
    fn unchanged_files_are_stored_once_across_checkpoints() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for i in 0..20 {
            fs::write(root.join(format!("f{i}.txt")), format!("content {i}")).unwrap();
        }
        let mut store = Store::init(root).unwrap();
        let a = store.snapshot().unwrap();
        let objects = count_objects(&root.join(".sentinel/objects"));

        fs::write(root.join("f0.txt"), "changed").unwrap();
        let b = store.snapshot().unwrap();
        let grew = count_objects(&root.join(".sentinel/objects")) - objects;

        assert_ne!(a.id, b.id);
        // one blob, one new root tree, one checkpoint object
        assert!(grew <= 3, "a one-file edit created {grew} new objects");
    }

    fn count_objects(dir: &Path) -> usize {
        let mut n = 0;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                } else {
                    n += 1;
                }
            }
        }
        n
    }
}
