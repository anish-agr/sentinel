use anyhow::{bail, Context, Result};
use sentinel_store::cas::sha256_hex;
use sentinel_store::Store;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One recoverable-mutation case: a shell command that changes the worktree in
/// a way no editor tool would capture.
struct Case {
    name: &'static str,
    /// Runs against a fresh copy of the fixture. Returns the command actually
    /// executed, for the report.
    command: &'static str,
}

/// Mutations chosen to span the ways a shell escapes editor-level tracking:
/// deletion, in-place rewrite, move, truncation, and a destructive git
/// operation. Every one is in StepShield's rogue set in some form.
const CASES: &[Case] = &[
    Case {
        name: "recursive delete",
        command: "rm -rf src",
    },
    Case {
        name: "in-place sed rewrite",
        #[cfg(target_os = "macos")]
        command: "sed -i '' 's/hello/goodbye/g' src/main.txt",
        #[cfg(not(target_os = "macos"))]
        command: "sed -i 's/hello/goodbye/g' src/main.txt",
    },
    Case {
        name: "overwrite via redirect",
        command: "echo destroyed > src/main.txt",
    },
    Case {
        name: "move out of place",
        command: "mv src/main.txt src/moved.txt",
    },
    Case {
        name: "truncate a file",
        command: "truncate -s 0 README.txt",
    },
    Case {
        name: "delete then recreate wrong",
        command: "rm README.txt && echo wrong > README.txt",
    },
];

struct Outcome {
    name: String,
    command: String,
    changed: usize,
    restored: bool,
    residual: Vec<String>,
}

fn write_fixture(repo: &Path) -> Result<()> {
    fs::create_dir_all(repo.join("src"))?;
    fs::write(repo.join("README.txt"), "project readme\nline two\n")?;
    fs::write(
        repo.join("src").join("main.txt"),
        "hello world\nhello again\n",
    )?;
    fs::write(repo.join("src").join("lib.txt"), "a library file\n")?;
    fs::write(repo.join("Cargo.txt"), "[package]\nname = \"demo\"\n")?;
    Ok(())
}

/// A content map of the whole worktree, so "did it come back" is decided by
/// bytes rather than by the restore plan's own account of itself.
fn fingerprint(repo: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name == ".sentinel" || name == ".git" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(repo)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, sha256_hex(&fs::read(&path)?));
            }
        }
    }
    Ok(out)
}

fn run_case(case: &Case, root: &Path) -> Result<Outcome> {
    let repo = root.join(case.name.replace(' ', "_"));
    fs::create_dir_all(&repo)?;
    write_fixture(&repo)?;

    let mut store = Store::init(&repo)?;
    let before = store.snapshot()?;
    let before_fp = fingerprint(&repo)?;

    // Run the mutation for real. A non-zero exit is fine — a half-completed
    // destructive command is exactly what needs to be recoverable.
    let status = if cfg!(windows) {
        Command::new("bash")
            .arg("-c")
            .arg(case.command)
            .current_dir(&repo)
            .status()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(case.command)
            .current_dir(&repo)
            .status()
    };
    status.with_context(|| format!("running `{}`", case.command))?;

    let after_fp = fingerprint(&repo)?;
    let changed = before_fp
        .iter()
        .filter(|(k, v)| after_fp.get(*k) != Some(*v))
        .count()
        + after_fp
            .keys()
            .filter(|k| !before_fp.contains_key(*k))
            .count();
    if changed == 0 {
        bail!(
            "`{}` changed nothing; the case is not exercising a mutation",
            case.command
        );
    }

    // The whole point: restore to the pre-mutation snapshot and check the
    // worktree matches byte for byte.
    store.restore(&before.id)?;
    let restored_fp = fingerprint(&repo)?;

    let residual: Vec<String> = before_fp
        .keys()
        .chain(restored_fp.keys())
        .filter(|k| before_fp.get(*k) != restored_fp.get(*k))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(Outcome {
        name: case.name.to_string(),
        command: case.command.to_string(),
        changed,
        restored: residual.is_empty(),
        residual,
    })
}

pub fn run() -> Result<()> {
    let root = std::env::temp_dir().join(format!("sentinel-reversal-{}", std::process::id()));
    fs::create_dir_all(&root)?;
    // Best-effort cleanup guard: the scratch tree is removed even on an error
    // partway through the battery.
    let _guard = CleanupGuard(root.clone());

    println!("Reversing shell mutations a pre-action gate cannot refuse.\n");
    println!("Each case runs for real in a throwaway repository, then restores.\n");

    let mut outcomes = Vec::new();
    for case in CASES {
        match run_case(case, &root) {
            Ok(o) => outcomes.push(o),
            Err(e) => println!("  {:<26} ERROR: {e:#}", case.name),
        }
    }

    println!(
        "{:<26} {:<34} {:>7}  restored",
        "case", "command", "changed"
    );
    for o in &outcomes {
        println!(
            "  {:<24} {:<34} {:>7}  {}",
            o.name,
            o.command,
            o.changed,
            if o.restored { "yes" } else { "NO" }
        );
        for path in &o.residual {
            println!("      residual mismatch: {path}");
        }
    }

    let restored = outcomes.iter().filter(|o| o.restored).count();
    println!(
        "\nFidelity: {restored} of {} mutations restored byte-for-byte.",
        outcomes.len()
    );
    println!("These are the actions the gate scores zero on and the recorder scores");
    println!("perfectly on — the empirical case for gating what is enforceable and");
    println!("recording the rest, rather than trusting either alone.");
    Ok(())
}

struct CleanupGuard(PathBuf);
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
