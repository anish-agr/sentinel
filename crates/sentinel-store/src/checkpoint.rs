//! Worktree snapshots as content-addressed trees. Unchanged files are already
//! in the store, so a checkpoint after a one-line edit costs one blob.

use crate::cas::Cas;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type FileMap = BTreeMap<String, (String, bool)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
    pub hash: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exec: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitState {
    pub branch: Option<String>,
    pub head: Option<String>,
    pub dirty: bool,
    pub staged: Vec<String>,
    pub unstaged: Vec<String>,
    pub untracked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvEntry {
    pub name: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub tree: String,
    pub ts: DateTime<Utc>,
    pub git: GitState,
    /// Names and value hashes only — values are never stored. Observed from the
    /// daemon's environment, which is not necessarily the agent's.
    pub env: Vec<EnvEntry>,
    pub env_source: String,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub checkpoint: Checkpoint,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RestorePlan {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

impl RestorePlan {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }

    pub fn len(&self) -> usize {
        self.added.len() + self.modified.len() + self.deleted.len()
    }
}

/// mtime+size keyed hash cache. Re-hashing every file on every step boundary is
/// the whole cost of checkpointing; this keeps steady-state snapshots cheap.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanCache {
    entries: BTreeMap<String, CacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    mtime: i64,
    size: u64,
    hash: String,
}

impl ScanCache {
    pub fn load(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, serde_json::to_vec(self)?)?;
        Ok(())
    }
}

fn file_meta(path: &Path) -> Result<(i64, u64, bool)> {
    let md = fs::metadata(path)?;
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    #[cfg(unix)]
    let exec = {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let exec = false;
    Ok((mtime, md.len(), exec))
}

fn rel_path(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
}

/// Walks the worktree honouring .gitignore, storing every file's content in the
/// CAS. `.git/` and `.sentinel/` are always excluded.
pub fn scan(repo: &Path, cas: &Cas, cache: &mut ScanCache) -> Result<FileMap> {
    let mut builder = WalkBuilder::new(repo);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|e| {
            let n = e.file_name();
            n != ".git" && n != ".sentinel"
        });

    let mut files = FileMap::new();
    let mut fresh = BTreeMap::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(rel) = rel_path(repo, path) else {
            continue;
        };
        let (mtime, size, exec) = match file_meta(path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let hash = match cache.entries.get(&rel) {
            Some(c) if c.mtime == mtime && c.size == size && cas.has(&c.hash) => c.hash.clone(),
            _ => match cas.put_file(path) {
                Ok(h) => h,
                Err(_) => continue,
            },
        };
        fresh.insert(
            rel.clone(),
            CacheEntry {
                mtime,
                size,
                hash: hash.clone(),
            },
        );
        files.insert(rel, (hash, exec));
    }
    cache.entries = fresh;
    Ok(files)
}

enum Node {
    File { hash: String, exec: bool },
    Dir(BTreeMap<String, Node>),
}

fn insert_node(dir: &mut BTreeMap<String, Node>, parts: &[&str], hash: &str, exec: bool) {
    match parts {
        [] => {}
        [name] => {
            dir.insert(
                (*name).to_string(),
                Node::File {
                    hash: hash.to_string(),
                    exec,
                },
            );
        }
        [head, rest @ ..] => {
            let child = dir
                .entry((*head).to_string())
                .or_insert_with(|| Node::Dir(BTreeMap::new()));
            if let Node::Dir(map) = child {
                insert_node(map, rest, hash, exec);
            }
        }
    }
}

fn write_tree(cas: &Cas, dir: &BTreeMap<String, Node>) -> Result<String> {
    let mut entries = Vec::with_capacity(dir.len());
    for (name, node) in dir {
        entries.push(match node {
            Node::File { hash, exec } => TreeEntry {
                name: name.clone(),
                kind: EntryKind::File,
                hash: hash.clone(),
                exec: *exec,
            },
            Node::Dir(children) => TreeEntry {
                name: name.clone(),
                kind: EntryKind::Dir,
                hash: write_tree(cas, children)?,
                exec: false,
            },
        });
    }
    cas.put_json(&entries)
}

pub fn build_tree(cas: &Cas, files: &FileMap) -> Result<String> {
    let mut root = BTreeMap::new();
    for (path, (hash, exec)) in files {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        insert_node(&mut root, &parts, hash, *exec);
    }
    write_tree(cas, &root)
}

/// Every object a tree reaches: the tree itself, its subtrees, and its blobs.
/// Used as a garbage-collection root set.
pub fn collect_objects(
    cas: &Cas,
    tree: &str,
    out: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    if !out.insert(tree.to_string()) {
        return Ok(());
    }
    for entry in cas.get_json::<Vec<TreeEntry>>(tree)? {
        match entry.kind {
            EntryKind::File => {
                out.insert(entry.hash);
            }
            EntryKind::Dir => collect_objects(cas, &entry.hash, out)?,
        }
    }
    Ok(())
}

pub fn tree_files(cas: &Cas, tree: &str) -> Result<FileMap> {
    let mut out = FileMap::new();
    collect_tree(cas, tree, "", &mut out)?;
    Ok(out)
}

fn collect_tree(cas: &Cas, tree: &str, prefix: &str, out: &mut FileMap) -> Result<()> {
    let entries: Vec<TreeEntry> = cas.get_json(tree)?;
    for e in entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        match e.kind {
            EntryKind::File => {
                out.insert(path, (e.hash, e.exec));
            }
            EntryKind::Dir => collect_tree(cas, &e.hash, &path, out)?,
        }
    }
    Ok(())
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(["--no-optional-locks"])
        .args(args)
        .current_dir(repo)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn git_state(repo: &Path) -> GitState {
    let mut st = GitState {
        branch: git(repo, &["rev-parse", "--abbrev-ref", "HEAD"]),
        head: git(repo, &["rev-parse", "HEAD"]),
        ..Default::default()
    };
    if let Some(status) = git(repo, &["status", "--porcelain"]) {
        for line in status.lines() {
            if line.len() < 3 {
                continue;
            }
            let (code, path) = line.split_at(2);
            let path = path.trim().to_string();
            let mut chars = code.chars();
            let (idx, tree) = (chars.next().unwrap_or(' '), chars.next().unwrap_or(' '));
            if idx == '?' {
                st.untracked.push(path);
            } else {
                if idx != ' ' {
                    st.staged.push(path.clone());
                }
                if tree != ' ' {
                    st.unstaged.push(path);
                }
            }
        }
    }
    st.dirty = !st.staged.is_empty() || !st.unstaged.is_empty();
    st
}

fn env_snapshot() -> Vec<EnvEntry> {
    let mut v: Vec<EnvEntry> = std::env::vars_os()
        .map(|(k, val)| EnvEntry {
            name: k.to_string_lossy().to_string(),
            hash: crate::cas::sha256_hex(val.to_string_lossy().as_bytes()),
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

pub fn snapshot(repo: &Path, cas: &Cas, cache: &mut ScanCache) -> Result<Snapshot> {
    let files = scan(repo, cas, cache)?;
    let bytes = files
        .values()
        .filter_map(|(h, _)| cas.get(h).ok().map(|b| b.len() as u64))
        .sum();
    let checkpoint = Checkpoint {
        tree: build_tree(cas, &files)?,
        ts: Utc::now(),
        git: git_state(repo),
        env: env_snapshot(),
        env_source: "daemon".into(),
        files: files.len() as u64,
        bytes,
    };
    let id = cas.put_json(&checkpoint)?;
    Ok(Snapshot { id, checkpoint })
}

pub fn read(cas: &Cas, id: &str) -> Result<Checkpoint> {
    cas.get_json(id)
        .with_context(|| format!("checkpoint {id} not found"))
}

pub fn diff(current: &FileMap, target: &FileMap) -> RestorePlan {
    let mut plan = RestorePlan::default();
    for (path, (hash, _)) in target {
        match current.get(path) {
            None => plan.added.push(path.clone()),
            Some((cur, _)) if cur != hash => plan.modified.push(path.clone()),
            _ => {}
        }
    }
    for path in current.keys() {
        if !target.contains_key(path) {
            plan.deleted.push(path.clone());
        }
    }
    plan
}

/// Materialises `tree` into the worktree. The only write path Sentinel has into
/// a user's repo, and only ever reached through an explicit restore.
pub fn restore(repo: &Path, cas: &Cas, tree: &str, cache: &mut ScanCache) -> Result<RestorePlan> {
    let current = scan(repo, cas, cache)?;
    let target = tree_files(cas, tree)?;
    let plan = diff(&current, &target);

    for path in plan.added.iter().chain(plan.modified.iter()) {
        let (hash, exec) = &target[path];
        let dest = repo.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = cas.get(hash)?;
        fs::write(&dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;
        set_exec(&dest, *exec);
    }
    for path in &plan.deleted {
        let dest = repo.join(path);
        if dest.exists() {
            fs::remove_file(&dest).with_context(|| format!("removing {}", dest.display()))?;
        }
    }
    prune_empty_dirs(repo)?;
    cache.entries.clear();
    Ok(plan)
}

#[allow(unused_variables)]
fn set_exec(path: &Path, exec: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = fs::metadata(path) {
            let mut perm = md.permissions();
            let mode = perm.mode();
            perm.set_mode(if exec { mode | 0o755 } else { mode & !0o111 });
            let _ = fs::set_permissions(path, perm);
        }
    }
}

fn prune_empty_dirs(repo: &Path) -> Result<()> {
    fn walk(dir: &Path, depth: usize) -> Result<bool> {
        if depth > 64 {
            return Ok(false);
        }
        let mut empty = true;
        for entry in fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if name == ".git" || name == ".sentinel" {
                empty = false;
                continue;
            }
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                if walk(&path, depth + 1)? {
                    let _ = fs::remove_dir(&path);
                } else {
                    empty = false;
                }
            } else {
                empty = false;
            }
        }
        Ok(empty)
    }
    walk(repo, 0)?;
    Ok(())
}

pub fn sentinel_dir(repo: &Path) -> PathBuf {
    repo.join(".sentinel")
}

/// Walks up from `start` looking for a git repo or an existing enrolment.
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() {
        start
    } else {
        start.parent()?
    };
    loop {
        if dir.join(".git").exists() || dir.join(".sentinel").join("events.jsonl").is_file() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

pub fn require_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_sentinel_home_is_not_mistaken_for_a_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let sentinel_home = home.join(".sentinel");
        fs::create_dir_all(&sentinel_home).unwrap();
        fs::write(sentinel_home.join("daemon.json"), "{}").unwrap();
        let subdir = home.join("some").join("nested").join("dir");
        fs::create_dir_all(&subdir).unwrap();

        assert_eq!(find_repo_root(&subdir), None);
    }

    #[test]
    fn a_repo_actually_initialised_is_still_found() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("project");
        let dot = repo.join(".sentinel");
        fs::create_dir_all(&dot).unwrap();
        fs::write(dot.join("events.jsonl"), "").unwrap();
        let subdir = repo.join("src").join("nested");
        fs::create_dir_all(&subdir).unwrap();

        assert_eq!(find_repo_root(&subdir), Some(repo));
    }

    #[test]
    fn a_git_repo_is_still_found_without_any_sentinel_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("project");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let subdir = repo.join("src");
        fs::create_dir_all(&subdir).unwrap();

        assert_eq!(find_repo_root(&subdir), Some(repo));
    }
}
