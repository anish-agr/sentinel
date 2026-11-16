use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

fn path(repo: &Path) -> PathBuf {
    repo.join(".sentinel").join("allow-once.json")
}

fn read(repo: &Path) -> Vec<String> {
    fs::read(path(repo))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .unwrap_or_default()
}

fn write(repo: &Path, grants: &[String]) -> Result<()> {
    let p = path(repo);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, serde_json::to_vec_pretty(grants)?)?;
    Ok(())
}

/// Permits the next single occurrence of this exact command+rule pair.
pub fn grant(repo: &Path, fingerprint: &str) -> Result<()> {
    let mut grants = read(repo);
    if !grants.iter().any(|g| g == fingerprint) {
        grants.push(fingerprint.to_string());
    }
    write(repo, &grants)
}

pub fn consume(repo: &Path, fingerprint: &str) -> bool {
    let grants = read(repo);
    let remaining: Vec<String> = grants
        .iter()
        .filter(|g| *g != fingerprint)
        .cloned()
        .collect();
    if remaining.len() == grants.len() {
        return false;
    }
    // A grant that cannot be removed must not be honoured, or it becomes a
    // permanent allow by accident — exactly what one-shot exists to avoid.
    write(repo, &remaining).is_ok()
}

pub fn pending(repo: &Path) -> Vec<String> {
    read(repo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_is_spent_by_the_first_use() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        grant(repo, "abc").unwrap();
        assert!(consume(repo, "abc"), "the first attempt should be allowed");
        assert!(!consume(repo, "abc"), "the second must not be");
    }

    #[test]
    fn grants_do_not_leak_across_fingerprints() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        grant(repo, "abc").unwrap();
        assert!(
            !consume(repo, "def"),
            "a different command must stay blocked"
        );
        assert!(consume(repo, "abc"));
    }

    #[test]
    fn granting_twice_still_permits_only_one_attempt() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        grant(repo, "abc").unwrap();
        grant(repo, "abc").unwrap();
        assert!(consume(repo, "abc"));
        assert!(!consume(repo, "abc"));
    }

    #[test]
    fn consuming_from_a_repo_with_no_grants_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!consume(tmp.path(), "abc"));
        assert!(pending(tmp.path()).is_empty());
    }
}
