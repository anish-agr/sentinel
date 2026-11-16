use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::time::Duration;

const BUDGET: Duration = Duration::from_millis(400);

fn main() {
    let exe = std::env::current_exe().unwrap_or_default();
    let name = exe
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();

    if name == "sentinel-shim" || name.is_empty() {
        eprintln!("sentinel-shim runs under the name of the binary it guards; install with `sentinel shim enable`");
        exit(2);
    }

    let command = std::iter::once(name.clone())
        .chain(args.iter().cloned())
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    if let Some(reason) = deny(&command) {
        eprintln!("sentinel: blocked: {reason}");
        eprintln!("sentinel: if this was intended, run `sentinel allow --last` and retry.");
        exit(125);
    }

    let Some(real) = find_real(&name, exe.parent()) else {
        eprintln!("sentinel-shim: `{name}` not found on PATH beyond the shim directory");
        exit(127);
    };
    run(real, &args);
}

/// Some(reason) only on an explicit deny from the daemon.
fn deny(command: &str) -> Option<String> {
    let home = std::env::var_os("SENTINEL_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| PathBuf::from(h).join(".sentinel"))
        })?;
    let info: Value =
        serde_json::from_slice(&std::fs::read(home.join("daemon.json")).ok()?).ok()?;
    let port = info.get("port")?.as_u64()? as u16;
    let token = info.get("token")?.as_str()?;

    let payload = json!({
        "phase": "pre",
        "payload": {
            "session_id": "shim",
            "cwd": std::env::current_dir().ok()?.to_string_lossy(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        }
    })
    .to_string();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let mut stream = TcpStream::connect_timeout(&addr, BUDGET).ok()?;
    stream.set_read_timeout(Some(BUDGET)).ok()?;
    stream.set_write_timeout(Some(BUDGET)).ok()?;
    let request = format!(
        "POST /hook HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Sentinel-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    let body: Value = serde_json::from_str(text.split_once("\r\n\r\n")?.1.trim()).ok()?;
    if body.get("decision")?.as_str()? != "deny" {
        return None;
    }
    Some(
        body.get("reason")
            .and_then(Value::as_str)
            .unwrap_or("blocked by Sentinel")
            .to_string(),
    )
}

/// The real binary: first PATH match outside the shim's own directory.
fn find_real(name: &str, own_dir: Option<&Path>) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    let own = own_dir.and_then(|d| d.canonicalize().ok());
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        if dir.canonicalize().ok() == own && own.is_some() {
            continue;
        }
        for ext in exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn run(real: PathBuf, args: &[String]) -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&real).args(args).exec();
        eprintln!("sentinel-shim: exec {} failed: {err}", real.display());
        exit(126);
    }
    #[cfg(not(unix))]
    {
        match Command::new(&real).args(args).status() {
            Ok(status) => exit(status.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("sentinel-shim: running {} failed: {e}", real.display());
                exit(126);
            }
        }
    }
}
