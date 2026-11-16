//! The Sentinel daemon: one local process, out of band from every agent,
//! consuming normalized events over loopback HTTP.

pub mod hooks;
pub mod mcp;
pub mod oneshot;
pub mod server;
pub mod state;
pub mod transcript;
pub mod watcher;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Canonicalises without Windows extended-length syntax. `\\?\C:\x` and `C:\x`
/// name the same directory, and letting both into the registry would key two
/// stores against one repository.
pub fn canonical(path: &std::path::Path) -> PathBuf {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match abs.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(stripped) => PathBuf::from(stripped),
        None => abs,
    }
}

pub fn sentinel_home() -> PathBuf {
    std::env::var_os("SENTINEL_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".sentinel"))
}

pub fn info_path() -> PathBuf {
    sentinel_home().join("daemon.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub port: u16,
    pub token: String,
    pub pid: u32,
    pub version: String,
    pub started: String,
}

pub fn read_info() -> Option<DaemonInfo> {
    serde_json::from_slice(&fs::read(info_path()).ok()?).ok()
}

pub fn write_info(info: &DaemonInfo) -> Result<()> {
    let path = info_path();
    fs::create_dir_all(path.parent().unwrap_or(&PathBuf::from(".")))?;
    fs::write(&path, serde_json::to_vec_pretty(info)?)?;
    Ok(())
}

pub fn clear_info() {
    let _ = fs::remove_file(info_path());
}

/// A minimal HTTP client so the hook and CLI need no dependencies to talk to
/// the daemon, and so the timeout is exactly what we say it is.
pub fn request(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Result<String> {
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()?
        .next()
        .context("resolving loopback address")?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true).ok();

    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Sentinel-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).to_string();
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or(text))
}

/// Returns the running daemon's info, or None if nothing answers.
pub fn running() -> Option<DaemonInfo> {
    let info = read_info()?;
    let body = request(
        info.port,
        &info.token,
        "GET",
        "/api/health",
        None,
        Duration::from_millis(500),
    )
    .ok()?;
    body.contains("\"ok\":true").then_some(info)
}

/// Which repositories have been enrolled with `sentinel init`.
pub mod registry {
    use super::sentinel_home;
    use anyhow::Result;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn path() -> PathBuf {
        sentinel_home().join("repos.json")
    }

    fn decode(bytes: &[u8]) -> Vec<String> {
        let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        serde_json::from_slice(body).unwrap_or_default()
    }

    pub fn list() -> Vec<PathBuf> {
        fs::read(path())
            .map(|b| decode(&b))
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| p.join(".sentinel").is_dir())
            .collect()
    }

    pub fn add(repo: &Path) -> Result<()> {
        let mut repos: Vec<String> = list()
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let entry = super::canonical(repo).to_string_lossy().to_string();
        if !repos.contains(&entry) {
            repos.push(entry);
        }
        let p = path();
        fs::create_dir_all(p.parent().unwrap_or(Path::new(".")))?;
        fs::write(p, serde_json::to_vec_pretty(&repos)?)?;
        Ok(())
    }

    pub fn remove(repo: &Path) -> Result<()> {
        let entry = repo.to_string_lossy().to_string();
        let repos: Vec<String> = list()
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .filter(|p| *p != entry)
            .collect();
        fs::write(path(), serde_json::to_vec_pretty(&repos)?)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::decode;

        #[test]
        fn a_utf8_bom_does_not_empty_the_registry() {
            let mut bytes = vec![0xEF, 0xBB, 0xBF];
            bytes.extend_from_slice(br#"["/tmp/repo"]"#);
            assert_eq!(decode(&bytes), vec!["/tmp/repo".to_string()]);
        }

        #[test]
        fn plain_json_is_unaffected() {
            assert_eq!(
                decode(br#"["/a","/b"]"#),
                vec!["/a".to_string(), "/b".to_string()]
            );
        }

        #[test]
        fn an_unreadable_registry_is_empty_rather_than_fatal() {
            assert!(decode(b"not json at all").is_empty());
        }
    }
}

fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub fn run_foreground() -> Result<()> {
    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|e| anyhow::anyhow!("binding loopback port: {e}"))?;
    let port = server
        .server_addr()
        .to_ip()
        .context("daemon must be bound to a TCP port")?
        .port();
    let token = random_token();

    write_info(&DaemonInfo {
        port,
        token: token.clone(),
        pid: std::process::id(),
        version: VERSION.to_string(),
        started: chrono::Utc::now().to_rfc3339(),
    })?;

    let daemon = state::Daemon::new(port, token);
    for repo in registry::list() {
        if let Err(e) = daemon.repo(&repo) {
            eprintln!("sentinel: skipping {}: {e:#}", repo.display());
        }
    }

    watcher::start(daemon.clone());
    println!("sentinel daemon listening on http://127.0.0.1:{port}");
    println!("timeline: http://127.0.0.1:{port}/");
    let outcome = server::serve(daemon, server);
    clear_info();
    outcome
}
