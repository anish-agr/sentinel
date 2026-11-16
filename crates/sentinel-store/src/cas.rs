use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn is_object_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Content-addressed blob store, git-object style: `objects/ab/cdef...`.
/// Writes are idempotent, so unchanged files cost nothing across checkpoints.
#[derive(Debug, Clone)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
        Ok(Cas { root })
    }

    /// `None` for anything that is not a well-formed key, so no caller can
    /// reach the slice below without having passed the check.
    fn path_for(&self, hash: &str) -> Option<PathBuf> {
        is_object_hash(hash).then(|| self.root.join(&hash[..2]).join(&hash[2..]))
    }

    pub fn has(&self, hash: &str) -> bool {
        self.path_for(hash).is_some_and(|p| p.exists())
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        let hash = sha256_hex(bytes);
        let dest = self
            .path_for(&hash)
            .context("sha256_hex must produce a well-formed object hash")?;
        if dest.exists() {
            return Ok(hash);
        }
        let dir = dest.parent().expect("object path has a parent");
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{}.tmp{}", &hash[2..10], std::process::id()));
        fs::write(&tmp, bytes)?;
        // Another process may have won the race; its content is identical.
        if fs::rename(&tmp, &dest).is_err() {
            let _ = fs::remove_file(&tmp);
            if !dest.exists() {
                fs::write(&dest, bytes)?;
            }
        }
        Ok(hash)
    }

    pub fn put_file(&self, path: &Path) -> Result<String> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        self.put(&bytes)
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>> {
        let p = self
            .path_for(hash)
            .context("not a 64-character hex sha256 object hash")?;
        fs::read(&p).with_context(|| format!("object {hash} missing from store"))
    }

    pub fn put_json<T: serde::Serialize>(&self, value: &T) -> Result<String> {
        self.put(&serde_json::to_vec(value)?)
    }

    pub fn get_json<T: serde::de::DeserializeOwned>(&self, hash: &str) -> Result<T> {
        Ok(serde_json::from_slice(&self.get(hash)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_stores_once() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = Cas::new(tmp.path()).unwrap();
        let a = cas.put(b"hello world").unwrap();
        let b = cas.put(b"hello world").unwrap();
        assert_eq!(a, b);
        assert_eq!(cas.get(&a).unwrap(), b"hello world");

        let count = walkdir_count(tmp.path());
        cas.put(b"hello world").unwrap();
        assert_eq!(
            walkdir_count(tmp.path()),
            count,
            "re-put created a new object"
        );
    }

    #[test]
    fn different_content_gets_different_hashes() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = Cas::new(tmp.path()).unwrap();
        assert_ne!(cas.put(b"a").unwrap(), cas.put(b"b").unwrap());
    }

    #[test]
    fn missing_object_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = Cas::new(tmp.path()).unwrap();
        assert!(cas.get(&"0".repeat(64)).is_err());
        assert!(!cas.has(&"0".repeat(64)));
    }

    #[test]
    fn a_malformed_hash_is_rejected_rather_than_panicking() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = Cas::new(tmp.path()).unwrap();
        for bad in [
            "",                  // the request the audit actually sent
            "a",                 // one byte: shorter than the shard prefix
            "ab",                // exactly the prefix, with no object name left
            "é",                 // two BYTES but one char: a slice on a char boundary
            "aé",                // splits a multi-byte char at index 2
            "../../../etc/pass", // traversal, which is not hex either
            "0123456789abcdef",  // right alphabet, wrong length
            &"0".repeat(63),
            &"0".repeat(65),
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ] {
            assert!(
                cas.get(bad).is_err(),
                "hash {bad:?} must be an error, not a panic and not a read"
            );
            assert!(
                !cas.has(bad),
                "hash {bad:?} must not be reported as present"
            );
        }
    }

    /// A well-formed hash still has to work, or the fix above is just a
    /// denial of service with extra steps.
    #[test]
    fn a_well_formed_hash_still_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let cas = Cas::new(tmp.path()).unwrap();
        let hash = cas.put(b"payload").unwrap();
        assert_eq!(hash.len(), 64);
        assert!(cas.has(&hash));
        assert_eq!(cas.get(&hash).unwrap(), b"payload");
    }

    fn walkdir_count(root: &Path) -> usize {
        let mut n = 0;
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
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
