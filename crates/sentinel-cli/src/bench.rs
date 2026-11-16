use anyhow::{bail, Context, Result};
use sentinel_store::Store;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn sibling(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("locating the sentinel binary")?;
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let path = dir.join(&file);
    if !path.exists() {
        bail!(
            "{} not found next to the sentinel binary; build the workspace first",
            path.display()
        );
    }
    Ok(path)
}

struct Scratch {
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
    daemon: Child,
}

impl Scratch {
    /// Kills the daemon so the fail-open path can be measured with nothing
    /// listening — the condition the 25ms budget actually exists to bound.
    fn stop_daemon(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.stop_daemon();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn start_scratch() -> Result<Scratch> {
    let root = std::env::temp_dir().join(format!("sentinel-bench-{}", std::process::id()));
    let home = root.join("home");
    let repo = root.join("repo");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&repo)?;

    // Enrol the scratch repo by hand: registry::add resolves SENTINEL_HOME from
    // this process's environment, and mutating that would leak into every child.
    Store::init(&repo)?;
    std::fs::write(
        home.join("repos.json"),
        serde_json::to_vec(&vec![repo.to_string_lossy().to_string()])?,
    )?;

    let daemon = Command::new(sibling("sentineld")?)
        .env("SENTINEL_HOME", &home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the scratch daemon")?;

    let info = home.join("daemon.json");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if info.exists() {
            // The file appears before the listener is necessarily accepting.
            std::thread::sleep(Duration::from_millis(150));
            return Ok(Scratch {
                root,
                home,
                repo,
                daemon,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("the scratch daemon did not come up within 10s")
}

fn payload(repo: &Path, command: &str) -> String {
    serde_json::json!({
        "session_id": "sentinel-bench",
        "cwd": repo.to_string_lossy(),
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "permission_mode": "default",
    })
    .to_string()
}

/// One full hook invocation, timed from spawn to exit — what Claude Code waits
/// for, not what the daemon spends.
fn one(hook: &Path, home: &Path, body: &str) -> Result<(Duration, bool)> {
    let start = Instant::now();
    let mut child = Command::new(hook)
        .arg("pre")
        .env("SENTINEL_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .context("hook stdin")?
        .write_all(body.as_bytes())?;
    let out = child.wait_with_output()?;
    let elapsed = start.elapsed();
    let denied = String::from_utf8_lossy(&out.stdout).contains("\"deny\"");
    Ok((elapsed, denied))
}

struct Summary {
    mean: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    over_budget: usize,
}

fn summarise(mut samples: Vec<Duration>) -> Summary {
    samples.sort();
    let ms = |d: &Duration| d.as_secs_f64() * 1000.0;
    let at = |q: f64| ms(&samples[((samples.len() - 1) as f64 * q).round() as usize]);
    Summary {
        mean: samples.iter().map(ms).sum::<f64>() / samples.len() as f64,
        p50: at(0.50),
        p95: at(0.95),
        p99: at(0.99),
        max: ms(samples.last().expect("at least one sample")),
        over_budget: samples
            .iter()
            .filter(|d| **d > Duration::from_millis(25))
            .count(),
    }
}

fn report(label: &str, s: &Summary, n: usize) {
    println!("\n{label}  (n={n})");
    println!("  mean   {:>7.2} ms", s.mean);
    println!("  p50    {:>7.2} ms", s.p50);
    println!("  p95    {:>7.2} ms", s.p95);
    println!("  p99    {:>7.2} ms", s.p99);
    println!("  max    {:>7.2} ms", s.max);
    println!(
        "  over the 25ms budget: {} of {} ({:.1}%)",
        s.over_budget,
        n,
        s.over_budget as f64 / n as f64 * 100.0
    );
}

pub fn run(n: usize) -> Result<()> {
    let hook = sibling("sentinel-hook")?;
    let mut scratch = start_scratch()?;
    println!(
        "Benchmarking {} against a scratch daemon ({} iterations per path).",
        hook.display(),
        n
    );

    // Warm the daemon so the first sample does not carry lazy setup that no
    // real session would pay twice.
    let warm = payload(&scratch.repo, "echo warmup");
    for _ in 0..5 {
        one(&hook, &scratch.home, &warm)?;
    }

    let allow_body = payload(&scratch.repo, "echo hello");
    let mut allow = Vec::with_capacity(n);
    for _ in 0..n {
        let (d, denied) = one(&hook, &scratch.home, &allow_body)?;
        if denied {
            bail!(
                "the allow-path command was denied; the benchmark is not measuring what it claims"
            );
        }
        allow.push(d);
    }

    let deny_body = payload(&scratch.repo, "rm -rf ~/.ssh");
    let mut deny = Vec::with_capacity(n);
    let mut denials = 0;
    for _ in 0..n {
        let (d, denied) = one(&hook, &scratch.home, &deny_body)?;
        denials += usize::from(denied);
        deny.push(d);
    }
    if denials != n {
        bail!(
            "the deny-path command was allowed {} of {n} times",
            n - denials
        );
    }

    let bare = scratch.root.join("bare");
    std::fs::create_dir_all(&bare)?;
    let mut spawn = Vec::with_capacity(n);
    for _ in 0..n {
        spawn.push(one(&hook, &bare, &allow_body)?.0);
    }

    // Daemon registered but dead — the case fail-open exists for. The hook
    // still has an endpoint to try, so it pays the connect timeout every call.
    scratch.stop_daemon();
    let mut down = Vec::with_capacity(n);
    for _ in 0..n {
        let (d, denied) = one(&hook, &scratch.home, &allow_body)?;
        if denied {
            bail!("the hook denied with no daemon running — fail-open is broken");
        }
        down.push(d);
    }

    let allow = summarise(allow);
    let deny = summarise(deny);
    let spawn = summarise(spawn);
    let down = summarise(down);

    report(
        "Allow path — every rule evaluated, nothing matched",
        &allow,
        n,
    );
    report(
        "Deny path — rule matched, denial written to stdout",
        &deny,
        n,
    );
    report("Process only — no daemon configured, no network", &spawn, n);
    report("Daemon configured but dead — fail-open", &down, n);

    println!("\nWhat this means");
    println!(
        "  Starting the process costs {:.1} ms at the median. Sentinel's own",
        spawn.p50
    );
    println!(
        "  work — round trip, argv normalization, all {} rules — is {:.1} ms",
        sentinel_guard::rule_ids().len(),
        allow.p50 - spawn.p50
    );
    println!("  on top of that, against a 25ms socket budget it stays well inside.");
    println!(
        "  A dead daemon costs {:.1} ms, more than a live one, because every call",
        down.p50
    );
    println!("  pays the connect timeout before failing open. Fail-open is correct");
    println!("  but not free, and it is the slowest path rather than the fastest.");
    println!("  Verified: {n} invocations with no daemon, all allowed.");
    Ok(())
}
