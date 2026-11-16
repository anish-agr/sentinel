use crate::state::{lock, Daemon};
use crate::{hooks, registry, VERSION};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server};
use uuid::Uuid;

const UI_HTML: &str = include_str!("../../../ui/index.html");

struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
}

impl Reply {
    fn json(value: Value) -> Reply {
        Reply {
            status: 200,
            content_type: "application/json",
            body: value.to_string(),
        }
    }

    fn error(status: u16, message: impl std::fmt::Display) -> Reply {
        Reply {
            status,
            content_type: "application/json",
            body: json!({"error": message.to_string()}).to_string(),
        }
    }
}

const WORKERS: usize = 4;

pub fn serve(daemon: Arc<Daemon>, server: Server) -> anyhow::Result<()> {
    let server = Arc::new(server);
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let server = Arc::clone(&server);
        let daemon = Arc::clone(&daemon);
        handles.push(std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let daemon = Arc::clone(&daemon);
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    dispatch(&daemon, request)
                }));
                if caught.is_err() {
                    // Dropping the Request without responding makes tiny_http
                    // send a 500, so the client is answered either way.
                    eprintln!(
                        "sentinel: a request handler panicked; the worker survived it. \
                         This is a bug — please report it."
                    );
                }
            }
        }));
    }
    supervise(handles.into_iter().map(|h| h.join()).collect())
}

/// What the daemon's exit status should be, given how its workers ended.
fn supervise(outcomes: Vec<std::thread::Result<()>>) -> anyhow::Result<()> {
    let lost = outcomes.iter().filter(|r| r.is_err()).count();
    if lost == 0 {
        return Ok(());
    }
    anyhow::bail!(
        "{lost} of {} HTTP worker threads died; the daemon was no longer answering every \
         request. Exiting non-zero rather than lingering as a guard that cannot be reached.",
        outcomes.len()
    )
}

fn dispatch(daemon: &Arc<Daemon>, mut request: Request) {
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = request.method().clone();
    let authorized = request
        .headers()
        .iter()
        .any(|h| h.field.equiv("x-sentinel-token") && h.value.as_str() == daemon.token);

    let reply = route(daemon, &method, &path, &url, &body, authorized);
    let header = Header::from_bytes(&b"Content-Type"[..], reply.content_type.as_bytes())
        .expect("static content type is valid");
    let response = Response::from_string(reply.body)
        .with_status_code(reply.status)
        .with_header(header);
    let _ = request.respond(response);
}

fn route(
    daemon: &Arc<Daemon>,
    method: &Method,
    path: &str,
    url: &str,
    body: &str,
    authorized: bool,
) -> Reply {
    if path == "/" || path == "/index.html" {
        // The token is injected rather than fetched so the page works with no
        // login and no storage, on loopback only.
        let html = UI_HTML.replace("__SENTINEL_TOKEN__", &daemon.token);
        return Reply {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: html,
        };
    }
    if path == "/api/health" {
        return Reply::json(json!({
            "ok": true,
            "version": VERSION,
            "port": daemon.port,
            "repos": daemon.known_repos().len(),
        }));
    }
    if !authorized {
        return Reply::error(401, "missing or invalid X-Sentinel-Token");
    }

    match (method, path) {
        (Method::Post, "/hook") => {
            let payload: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return Reply::error(400, e),
            };
            let phase = payload
                .get("phase")
                .and_then(Value::as_str)
                .unwrap_or("pre");
            let inner = payload.get("payload").cloned().unwrap_or(Value::Null);
            Reply::json(hooks::handle(daemon, phase, &inner))
        }
        (Method::Get, "/api/repos") => Reply::json(json!(repo_summaries(daemon))),
        (Method::Get, "/api/runs") => with_repo(daemon, url, |daemon, repo| {
            let state = daemon.repo(&repo)?;
            let store = lock(&state.store);
            Ok(json!(store.runs()?))
        }),
        (Method::Get, "/api/events") => with_repo(daemon, url, |daemon, repo| {
            let params = query(url);
            let run = params.get("run").and_then(|r| Uuid::parse_str(r).ok());
            let limit = params
                .get("limit")
                .and_then(|l| l.parse::<u32>().ok())
                .unwrap_or(2000);
            let state = daemon.repo(&repo)?;
            let store = lock(&state.store);
            Ok(json!(store.events_json(run, limit)?))
        }),
        (Method::Get, "/api/checkpoint") => with_repo(daemon, url, |daemon, repo| {
            let params = query(url);
            let id = params.get("id").cloned().unwrap_or_default();
            let state = daemon.repo(&repo)?;
            let store = lock(&state.store);
            let checkpoint = store.read_checkpoint(&id)?;
            let files = store.files_at(&id)?;
            Ok(json!({
                "id": id,
                "ts": checkpoint.ts,
                "git": checkpoint.git,
                "files": files.iter().map(|(p, h)| json!({"path": p, "hash": h})).collect::<Vec<_>>(),
                "file_count": checkpoint.files,
                "bytes": checkpoint.bytes,
            }))
        }),
        (Method::Get, "/api/blob") => {
            let hash = query(url).get("hash").cloned().unwrap_or_default();
            if !sentinel_store::cas::is_object_hash(&hash) {
                return Reply::error(400, "hash must be a 64-character hex sha256");
            }
            with_repo(daemon, url, |daemon, repo| {
                let state = daemon.repo(&repo)?;
                let store = lock(&state.store);
                let bytes = store.cas.get(&hash)?;
                let text = String::from_utf8_lossy(&bytes).to_string();
                let binary = bytes.iter().take(8000).any(|b| *b == 0);
                Ok(
                    json!({"hash": hash, "binary": binary, "text": if binary { String::new() } else { text }}),
                )
            })
        }
        (Method::Post, "/api/restore") => {
            let req: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return Reply::error(400, e),
            };
            let repo = PathBuf::from(req.get("repo").and_then(Value::as_str).unwrap_or_default());
            let id = req
                .get("checkpoint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let apply = req.get("apply").and_then(Value::as_bool).unwrap_or(false);
            let result = (|| -> anyhow::Result<Value> {
                let state = daemon.repo(&repo)?;
                let mut store = lock(&state.store);
                if apply {
                    let (plan, safety) = store.restore(&id)?;
                    Ok(json!({"applied": true, "plan": plan, "safety_checkpoint": safety}))
                } else {
                    Ok(json!({"applied": false, "plan": store.restore_plan(&id)?}))
                }
            })();
            match result {
                Ok(v) => Reply::json(v),
                Err(e) => Reply::error(500, format!("{e:#}")),
            }
        }
        (Method::Post, "/api/allow") => {
            let req: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return Reply::error(400, e),
            };
            let repo = PathBuf::from(req.get("repo").and_then(Value::as_str).unwrap_or_default());
            let fingerprint = req
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let always = req.get("always").and_then(Value::as_bool).unwrap_or(false);
            let outcome = if always {
                sentinel_guard::GuardConfig::allow_always(&repo, fingerprint)
            } else {
                crate::oneshot::grant(&repo, fingerprint)
            };
            match outcome {
                Ok(()) => {
                    if let Ok(state) = daemon.repo(&repo) {
                        state.refresh();
                    }
                    Reply::json(
                        json!({"ok": true, "scope": if always { "always" } else { "once" }}),
                    )
                }
                Err(e) => Reply::error(500, format!("{e:#}")),
            }
        }
        _ => Reply::error(404, format!("no route for {path}")),
    }
}

fn repo_summaries(daemon: &Arc<Daemon>) -> Vec<Value> {
    registry::list()
        .into_iter()
        .map(|root| {
            let (runs, events) = daemon
                .repo(&root)
                .ok()
                .map(|state| {
                    let store = lock(&state.store);
                    (
                        store.runs().map(|r| r.len()).unwrap_or(0),
                        store.event_count().unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));
            json!({
                "path": root.to_string_lossy(),
                "name": root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                "runs": runs,
                "events": events,
            })
        })
        .collect()
}

fn with_repo(
    daemon: &Arc<Daemon>,
    url: &str,
    f: impl Fn(&Arc<Daemon>, PathBuf) -> anyhow::Result<Value>,
) -> Reply {
    let params = query(url);
    let Some(repo) = params.get("repo") else {
        return Reply::error(400, "missing repo parameter");
    };
    match f(daemon, PathBuf::from(repo)) {
        Ok(v) => Reply::json(v),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

fn query(url: &str) -> HashMap<String, String> {
    let Some(raw) = url.split_once('?').map(|(_, q)| q) else {
        return HashMap::new();
    };
    raw.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params_are_decoded() {
        let q = query("/api/events?repo=C%3A%2FUsers%2Fdev%2Fproj&run=abc");
        assert_eq!(q.get("repo").unwrap(), "C:/Users/dev/proj");
        assert_eq!(q.get("run").unwrap(), "abc");
        assert!(query("/api/runs").is_empty());
    }

    #[test]
    fn ui_has_a_token_placeholder_to_fill() {
        assert!(
            UI_HTML.contains("__SENTINEL_TOKEN__"),
            "UI must receive the API token"
        );
    }

    /// A dead worker must end the process unsuccessfully. The old code joined
    /// the handles as `let _ = h.join()`, so the daemon exited 0 after losing
    /// every thread — the guard was gone and the exit status said all was well.
    #[test]
    fn a_dead_worker_is_a_failed_daemon_rather_than_a_clean_exit() {
        let died = std::thread::spawn(|| panic!("worker died")).join();
        assert!(died.is_err(), "the probe thread should have panicked");

        assert!(
            supervise(vec![Ok(()), Ok(()), Ok(()), Ok(())]).is_ok(),
            "four healthy workers is a clean shutdown"
        );
        let err = supervise(vec![Ok(()), Ok(()), Ok(()), died])
            .expect_err("a lost worker must be an error");
        let text = err.to_string();
        assert!(
            text.contains('1') && text.to_lowercase().contains("worker"),
            "the error must say how many workers were lost: {text}"
        );
    }

    /// A blob hash is validated at the edge, before it can reach the slice in
    /// the store that used to panic on it.
    #[test]
    fn malformed_blob_hashes_are_rejected_at_the_route() {
        for bad in ["", "a", "ab", "é", &"0".repeat(63), &"z".repeat(64)] {
            assert!(
                !sentinel_store::cas::is_object_hash(bad),
                "{bad:?} must not be accepted as an object hash"
            );
        }
        assert!(sentinel_store::cas::is_object_hash(&"0a".repeat(32)));
    }
}
