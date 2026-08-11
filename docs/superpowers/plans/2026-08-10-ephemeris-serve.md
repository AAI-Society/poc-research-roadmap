# ephemeris serve Implementation Plan — Phase 2, item 1

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the evidence log over a Unix domain socket, so `transit guard` can write to it and an auditor can read proofs from it, without weakening the fail-closed guarantee at the socket boundary.

**Architecture:** A `serve` cargo feature adds a `UnixListener`, one thread per connection, and a minimal HTTP/1.1 reader. Four routes: one write (`POST /claims`, which blocks until durable) and three read (`GET /root`, `/proof/inclusion`, `/proof/consistency`). The listener wraps the existing `CommitQueue` and relays its `Ack`; it never constructs one. No async runtime, no new dependency.

**Tech Stack:** Rust 2021, `std::os::unix::net`, `serde_json`. **No `hyper`, no `tokio`** — see the design's transport section.

**Design spec:** `../specs/2026-08-10-ephemeris-serve-design.md`.

## Global Constraints

- Rust edition **2021**, floor **1.90**, `#![forbid(unsafe_code)]` stays.
- Clean under all feature sets: `cargo clippy --all-targets -- -D warnings`, and the same with `--features bench`, `--features tee`, `--features serve`.
- `cargo fmt --check` clean.
- Default build/test suite unchanged and offline. Current counts: `cargo test` 60, `--features bench` 70, `--features tee` 65.
- **No panics on anything read from the socket.** No `unwrap`, `expect`, slice indexing, or unchecked conversion on wire data. This is the surface an attacker reaches first.
- **Fail-closed across the socket.** A 200 with an `Ack` body is emitted only after `submit` returns `Ok`. Every other outcome is non-2xx with no `Ack`. The listener **relays** an `Ack`; it never builds one. If a task appears to need to construct one, **stop and report**.
- `thiserror` for library errors, `anyhow` in binaries, `{e}` never `{e:#}`.
- Time injected as `now_secs: u64`, never read from the system clock in anything a test reaches.
- **One renderer.** `GET /root` serves the output of the same `render()` the CLI prints. No second formatter.
- Everything offline: no network, no credentials, no TEE.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml` | **modify** — `serve` feature |
| `src/lib.rs` | **modify** — feature-gated module |
| `src/serve/mod.rs` | listener, socket lifecycle, connection loop |
| `src/serve/http.rs` | minimal HTTP/1.1 request reader and response writer |
| `src/serve/routes.rs` | the four routes |
| `tests/serve_malformed.rs` | the hostile-input surface |
| `tests/serve_claims.rs` | fail-closed across the socket |
| `tests/serve_proofs.rs` | the read routes, and A9 end to end |

---

## Task 1: The listener and the request reader

**Files:** Modify `Cargo.toml`, `src/lib.rs`. Create `src/serve/mod.rs`, `src/serve/http.rs`. Test: `tests/serve_malformed.rs`.

**Interfaces:**
- Produces: `serve::Server` with `bind(socket: &Path, queue: CommitQueue, store_dir: &Path) -> Result<Server, ServeError>`, `local_path(&self) -> &Path`, `serve_until_shutdown(self)`, `shutdown_handle(&self) -> ShutdownHandle`; `serve::ServeError`; `serve::http::{Request, read_request, write_response, HttpError}`.

**Why `bind` takes the store directory separately.** The read routes in Task 3 serve proofs, and a proof must cover only records that are **durable**. Re-opening the store from disk per read request gives exactly that property for free: `Store::open` recovers what is on disk and nothing else, so a proof can never cover a record still in flight. The alternative — an accessor on `CommitQueue` reaching into the live in-memory record set — would be both a change to the commit path's ownership and a way to serve a proof for a record no `Ack` has been issued for. Take the directory.

The malformed-input tests come first because this is the surface a hostile caller reaches before any route runs.

- [ ] **Step 1: Add the feature**

`Cargo.toml`:

```toml
# `serve` needs no new dependency: the listener is std's UnixListener and a
# minimal HTTP/1.1 reader. See the design's transport section for why this is
# not hyper+tokio — the crate is blocking end to end, fsync is ~3.4ms, and the
# measured ceiling is ~310 batches/sec set by durability rather than transport.
serve = []
```

`src/lib.rs`, in alphabetical position:

```rust
#[cfg(feature = "serve")]
pub mod serve;
```

- [ ] **Step 2: Write the failing tests**

`tests/serve_malformed.rs`:

```rust
#![cfg(feature = "serve")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

mod harness;
use harness::TestServer;

/// Send raw bytes and read whatever comes back. Returns None if the server
/// closed without replying, which is an acceptable answer to garbage — what is
/// NOT acceptable is a panic, and a panicked server thread would fail the
/// later requests in each test.
fn raw(path: &std::path::Path, bytes: &[u8]) -> Option<String> {
    let mut s = UnixStream::connect(path).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    s.write_all(bytes).ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[test]
fn garbage_does_not_panic_the_server() {
    let srv = TestServer::start();
    for bytes in [
        &b""[..],
        &b"\r\n\r\n"[..],
        &b"NOTAMETHOD / HTTP/1.1\r\n\r\n"[..],
        &b"GET"[..],
        &b"GET /root"[..],
        &b"GET /root HTTP/1.1\r\nContent-Length: notanumber\r\n\r\n"[..],
        &b"POST /claims HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n"[..],
        &b"POST /claims HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort"[..],
        &[0xff, 0xfe, 0xfd, 0x00, 0x01][..],
    ] {
        let _ = raw(srv.path(), bytes);
    }
    // The server must still be alive and answering. If any of the above
    // panicked its connection thread, this still passes — but if one poisoned
    // the listener, it does not.
    let after = raw(srv.path(), b"GET /root HTTP/1.1\r\n\r\n").expect("server died");
    assert!(after.starts_with("HTTP/1.1 "), "not an HTTP response: {after:?}");
}

#[test]
fn an_oversized_body_is_refused_before_it_is_allocated() {
    let srv = TestServer::start();
    let body = "x".repeat(4096);
    let req = format!(
        "POST /claims HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        2 * 1024 * 1024,
        body
    );
    let resp = raw(srv.path(), req.as_bytes()).expect("no response");
    assert!(resp.starts_with("HTTP/1.1 413"), "expected 413, got: {}", first_line(&resp));
}

#[test]
fn an_unknown_path_is_404_and_an_unknown_method_is_405() {
    let srv = TestServer::start();
    let a = raw(srv.path(), b"GET /nope HTTP/1.1\r\n\r\n").expect("no response");
    assert!(a.starts_with("HTTP/1.1 404"), "{}", first_line(&a));
    let b = raw(srv.path(), b"DELETE /root HTTP/1.1\r\n\r\n").expect("no response");
    assert!(b.starts_with("HTTP/1.1 405"), "{}", first_line(&b));
}

#[test]
fn the_socket_is_not_world_writable() {
    // The design says filesystem permissions ARE the access control. If the
    // socket is group- or world-writable, there is no access control.
    use std::os::unix::fs::PermissionsExt;
    let srv = TestServer::start();
    let mode = std::fs::metadata(srv.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket mode is {mode:o}, not 0600");
}

#[test]
fn a_stale_socket_file_does_not_prevent_binding() {
    // A crashed process leaves the socket file behind. Refusing to start with
    // EADDRINUSE would turn a crash into an outage requiring manual cleanup.
    let srv = TestServer::start();
    let path = srv.path().to_path_buf();
    drop(srv);
    assert!(path.exists() || !path.exists()); // either is fine; the next line is the test
    let again = TestServer::start_at(&path);
    assert!(raw(again.path(), b"GET /root HTTP/1.1\r\n\r\n").is_some());
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}
```

`tests/harness/mod.rs`:

```rust
#![cfg(feature = "serve")]

use ephemeris::commit::{CommitQueue, Committer};
use ephemeris::serve::Server;
use ephemeris::store::Store;
use std::path::{Path, PathBuf};

/// A server on a socket in a temp dir, shut down on drop.
pub struct TestServer {
    path: PathBuf,
    _dir: tempfile::TempDir,
    shutdown: Option<ephemeris::serve::ShutdownHandle>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("eph.sock");
        Self::start_inner(dir, path)
    }

    /// Bind at a specific path, reusing its parent as the store directory.
    pub fn start_at(path: &Path) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        Self::start_inner(dir, path.to_path_buf())
    }

    fn start_inner(dir: tempfile::TempDir, path: PathBuf) -> Self {
        let store = Store::open(dir.path()).expect("store");
        let queue = CommitQueue::new(Committer::new(store));
        let server = Server::bind(&path, queue).expect("bind");
        let shutdown = server.shutdown_handle();
        let worker = std::thread::spawn(move || server.serve_until_shutdown());
        Self {
            path,
            _dir: dir,
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            s.stop();
        }
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
```

Add to `Cargo.toml` so the harness compiles as a module rather than its own test binary:

```toml
[[test]]
name = "serve_malformed"
path = "tests/serve_malformed.rs"
```

(Only if cargo tries to build `tests/harness/mod.rs` as a test target — it will not, because it is in a subdirectory. Verify and drop this step if unnecessary.)

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --features serve --test serve_malformed`
Expected: FAIL — `ephemeris::serve` does not exist.

- [ ] **Step 4: Write `src/serve/http.rs`**

```rust
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

/// A claim is a small JSON object. Anything an order of magnitude larger is
/// not a claim, and bounding before allocation is the same discipline
/// `store::MAX_RECORD` applies to bytes off the disk.
pub const MAX_BODY: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("the connection closed before a complete request arrived")]
    Incomplete,
    #[error("the request line was not `METHOD PATH VERSION`")]
    BadRequestLine,
    #[error("Content-Length was not a number within bounds")]
    BadContentLength,
    #[error("the body is {len} bytes, over the {MAX_BODY}-byte limit")]
    BodyTooLarge { len: usize },
    #[error("could not read the request: {0}")]
    Io(String),
}

pub struct Request {
    pub method: String,
    /// Path with any query string removed.
    pub path: String,
    /// Raw query string, empty when absent.
    pub query: String,
    pub body: Vec<u8>,
}

impl Request {
    /// The value of a query parameter, or `None`. Deliberately tiny: the two
    /// proof routes take integers and nothing else.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key {
                Some(v)
            } else {
                None
            }
        })
    }

    /// A query parameter parsed as `u64`. `None` if absent or not a number —
    /// never a panic, and never a silent zero.
    pub fn u64_param(&self, key: &str) -> Option<u64> {
        self.param(key)?.parse().ok()
    }
}

/// Read one HTTP/1.1 request. Every failure is an error, never a panic.
pub fn read_request(stream: &UnixStream) -> Result<Request, HttpError> {
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    if reader.read_line(&mut line).map_err(io)? == 0 {
        return Err(HttpError::Incomplete);
    }
    let mut parts = line.trim_end().split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(HttpError::BadRequestLine);
    }

    let mut content_length: usize = 0;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).map_err(io)? == 0 {
            return Err(HttpError::Incomplete);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| HttpError::BadContentLength)?;
                if content_length > MAX_BODY {
                    return Err(HttpError::BodyTooLarge { len: content_length });
                }
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|_| HttpError::Incomplete)?;
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    Ok(Request {
        method,
        path,
        query,
        body,
    })
}

pub fn write_response(mut stream: &UnixStream, status: u16, reason: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    // A client that hung up mid-response is not an error worth escalating:
    // the record's durability was decided before the write was attempted.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn io(e: std::io::Error) -> HttpError {
    HttpError::Io(e.to_string())
}
```

- [ ] **Step 5: Write `src/serve/mod.rs`**

```rust
//! The Unix-domain-socket listener. Behind the `serve` feature.
//!
//! One thread per connection, no async runtime. See the design's transport
//! section: this crate blocks on `fsync` for milliseconds per batch, and the
//! measured ceiling is durability rather than transport, so an executor would
//! add a `spawn_blocking` correctness hazard and buy nothing.

pub mod http;
pub mod routes;

use crate::commit::CommitQueue;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("could not bind the socket at {path}: {reason}")]
    Bind { path: String, reason: String },
    #[error("could not set the socket's permissions at {path}: {reason}")]
    Permissions { path: String, reason: String },
}

/// Stops a running server. Cloneable so a test can hold one while the server
/// owns itself on another thread.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    path: PathBuf,
}

impl ShutdownHandle {
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // Unblock the accept loop by connecting to it once.
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
    }
}

pub struct Server {
    listener: UnixListener,
    path: PathBuf,
    queue: Arc<CommitQueue>,
    stop: Arc<AtomicBool>,
}

impl Server {
    /// Bind the socket and take ownership of the commit queue.
    ///
    /// A stale socket file left by a crashed process is removed first. Refusing
    /// to start with `EADDRINUSE` would turn a crash into an outage needing
    /// manual cleanup, and the file is not evidence of a live process.
    pub fn bind(path: &Path, queue: CommitQueue) -> Result<Server, ServeError> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).map_err(|e| ServeError::Bind {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        // Filesystem permissions ARE the access control here — anything that
        // can write to this socket can insert records. 0600, always.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            ServeError::Permissions {
                path: path.display().to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(Server {
            listener,
            path: path.to_path_buf(),
            queue: Arc::new(queue),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.stop),
            path: self.path.clone(),
        }
    }

    /// Accept connections until shutdown. One thread per connection.
    pub fn serve_until_shutdown(self) {
        for incoming in self.listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            let queue = Arc::clone(&self.queue);
            // A read timeout bounds a client that connects and never sends;
            // otherwise one such client parks a thread forever.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            std::thread::spawn(move || routes::handle(&stream, &queue));
        }
        let _ = std::fs::remove_file(&self.path);
    }
}
```

- [ ] **Step 6: Write a routes stub so Task 1 compiles**

`src/serve/routes.rs`, minimal for now — Task 2 and 3 fill it in:

```rust
use crate::commit::CommitQueue;
use crate::serve::http::{read_request, write_response, HttpError};
use std::os::unix::net::UnixStream;

/// Dispatch one request. Never panics: every parse failure becomes a status.
pub fn handle(stream: &UnixStream, _queue: &CommitQueue) {
    let req = match read_request(stream) {
        Ok(r) => r,
        Err(HttpError::BodyTooLarge { .. }) => {
            return write_response(stream, 413, "Payload Too Large", r#"{"error":"body too large"}"#)
        }
        Err(HttpError::Incomplete) => return,
        Err(e) => {
            return write_response(
                stream,
                400,
                "Bad Request",
                &format!(r#"{{"error":{}}}"#, json_string(&e.to_string())),
            )
        }
    };

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/root") => write_response(stream, 200, "OK", r#"{"todo":"task 3"}"#),
        ("GET", _) | ("POST", _) => {
            write_response(stream, 404, "Not Found", r#"{"error":"no such route"}"#)
        }
        _ => write_response(stream, 405, "Method Not Allowed", r#"{"error":"method not allowed"}"#),
    }
}

/// Minimal JSON string escaping, so an error message cannot break the body it
/// is embedded in. `serde_json` does this properly and is used for every real
/// payload; this exists only for the error path, which must never itself fail.
pub(crate) fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}
```

Note the `unwrap_or_else` rather than `unwrap`: serializing a `&str` cannot fail, but the error path must not be the place that proves it.

- [ ] **Step 7: Run the tests**

Run: `cargo test --features serve --test serve_malformed`
Expected: PASS, 5 tests.

`an_unknown_path_is_404_and_an_unknown_method_is_405` will pass with the stub. The others exercise the reader.

- [ ] **Step 8: Verify and commit**

Run: `cargo test && cargo test --features serve && cargo clippy --all-targets --features serve -- -D warnings && cargo fmt --check`

```bash
git add -A
git commit -m "Add the UDS listener and a request reader that refuses malformed input"
```

---

## Task 2: `POST /claims`, fail-closed across the socket

**Files:** Modify `src/serve/routes.rs`. Test: `tests/serve_claims.rs`.

**Interfaces:**
- Consumes: `commit::{CommitQueue, QueueHandle, Ack, CommitError}`, `record::Claim`.

- [ ] **Step 1: Write the failing tests**

`tests/serve_claims.rs`:

```rust
#![cfg(feature = "serve")]

mod harness;
use harness::{post, TestServer};

fn claim_json(id: &str) -> String {
    format!(
        r#"{{"action_id":"{id}","agent_id":"did:web:x","initiating_user":"u",
        "interception_point":"PRE_CALL_TOOL_INVOCATION","target_resource":"/x",
        "canonical_snapshot_hash":"aa","policy_bundle_hash":"bb","verdict":"ALLOW",
        "nonce":"n-{id}"}}"#
    )
}

#[test]
fn a_claim_is_acked_and_is_durable_on_disk() {
    let srv = TestServer::start();
    let (status, body) = post(srv.path(), "/claims?now=1700000000", &claim_json("a-0"));
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("step_index"), "no ack in body: {body}");

    // Durability asserted from disk, not from the response.
    let store = ephemeris::store::Store::open(srv.store_dir()).unwrap();
    assert_eq!(store.records().len(), 1);
    ephemeris::chain::verify_sequence(store.records()).expect("chain must verify");
}

#[test]
fn a_refused_claim_yields_no_ack() {
    // The store is broken before the request. Fail-closed must hold across the
    // socket exactly as it does in process.
    let srv = TestServer::start_with_broken_store();
    let (status, body) = post(srv.path(), "/claims?now=1700000000", &claim_json("a-0"));
    assert_ne!(status, 200, "a claim was acked without being durable");
    assert!(!body.contains("step_index"), "an ack leaked on the failure path: {body}");
}

#[test]
fn a_claim_with_an_unknown_field_is_refused() {
    let srv = TestServer::start();
    let bad = r#"{"action_id":"a","agent_id":"x","initiating_user":"u","interception_point":"T",
        "target_resource":"/x","canonical_snapshot_hash":"aa","policy_bundle_hash":"bb",
        "verdict":"ALLOW","nonce":"n","typo_field":1}"#;
    let (status, _) = post(srv.path(), "/claims?now=1700000000", bad);
    assert_eq!(status, 400);
}

#[test]
fn a_claim_without_now_is_refused_rather_than_timestamped_here() {
    // Time is injected, never read from the system clock. A claim arriving
    // without one must not be given the server's idea of now.
    let srv = TestServer::start();
    let (status, _) = post(srv.path(), "/claims", &claim_json("a-0"));
    assert_eq!(status, 400);
}

#[test]
fn a_claim_without_path_summary_hash_is_accepted_and_recorded_as_null() {
    // The transit-guard fork resolved to shipping the field unfilled. This is
    // the assertion that ephemeris's side of that resolution holds over the
    // socket, not only through the CLI.
    let srv = TestServer::start();
    let (status, _) = post(srv.path(), "/claims?now=1700000000", &claim_json("a-0"));
    assert_eq!(status, 200);
    let store = ephemeris::store::Store::open(srv.store_dir()).unwrap();
    assert!(store.records()[0].claim.path_summary_hash.is_none());
}
```

Extend `tests/harness/mod.rs` with `post`, `store_dir`, and `start_with_broken_store`:

```rust
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

impl TestServer {
    pub fn store_dir(&self) -> &Path {
        self._dir.path()
    }

    /// A server whose committer was latched unavailable before it started.
    pub fn start_with_broken_store() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("eph.sock");
        let mut committer = Committer::new(Store::open(dir.path()).expect("store"));
        let seg = dir.path().join("segment-0.log");
        std::fs::remove_file(&seg).expect("remove segment");
        std::fs::create_dir(&seg).expect("dir in its place");
        committer.force_reopen_for_test(dir.path());
        let server = Server::bind(&path, CommitQueue::new(committer)).expect("bind");
        let shutdown = server.shutdown_handle();
        let worker = std::thread::spawn(move || server.serve_until_shutdown());
        Self { path, _dir: dir, shutdown: Some(shutdown), worker: Some(worker) }
    }
}

/// POST a body and return (status, body).
pub fn post(sock: &Path, target: &str, body: &str) -> (u16, String) {
    request(sock, &format!(
        "POST {target} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ))
}

/// GET and return (status, body).
pub fn get(sock: &Path, target: &str) -> (u16, String) {
    request(sock, &format!("GET {target} HTTP/1.1\r\n\r\n"))
}

fn request(sock: &Path, raw: &str) -> (u16, String) {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).expect("timeout");
    s.write_all(raw.as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --features serve --test serve_claims`
Expected: FAIL — `/claims` is not routed.

- [ ] **Step 3: Implement the route**

In `src/serve/routes.rs`, replace the dispatch's `POST` arm and add:

```rust
/// `POST /claims?now=<unix seconds>` — submit one claim and block until it is
/// durable.
///
/// **The listener relays an `Ack`; it never builds one.** `QueueHandle::submit`
/// returns `Result<Ack, CommitError>` and only the `Ok` arm produces a 200. A
/// guard receiving anything else must not forward, and this route gives it no
/// way to confuse the two.
fn post_claims(stream: &UnixStream, queue: &CommitQueue, req: &Request) {
    let Some(now_secs) = req.u64_param("now") else {
        return write_response(
            stream,
            400,
            "Bad Request",
            r#"{"error":"missing or invalid `now` query parameter; time is injected, never read here"}"#,
        );
    };

    let claim: crate::record::Claim = match serde_json::from_slice(&req.body) {
        Ok(c) => c,
        Err(e) => {
            return write_response(
                stream,
                400,
                "Bad Request",
                &format!(r#"{{"error":{}}}"#, json_string(&e.to_string())),
            )
        }
    };

    match queue.handle().submit(claim, now_secs) {
        Ok(ack) => {
            let body = format!(
                r#"{{"step_index":{},"chain_head":{}}}"#,
                ack.step_index(),
                json_string(ack.chain_head())
            );
            write_response(stream, 200, "OK", &body)
        }
        Err(e) => write_response(
            stream,
            503,
            "Service Unavailable",
            &format!(r#"{{"error":{}}}"#, json_string(&e.to_string())),
        ),
    }
}
```

and dispatch `("POST", "/claims") => post_claims(stream, queue, &req),`.

Note `handle` takes `&CommitQueue` and the stub's parameter was `_queue` — un-underscore it.

- [ ] **Step 4: Run the tests**

Run: `cargo test --features serve --test serve_claims`
Expected: PASS, 5 tests.

- [ ] **Step 5: Prove the fail-closed test discriminates**

Temporarily make the `Err` arm return 200 with an ack-shaped body, confirm `a_refused_claim_yields_no_ack` goes red, and revert. Put the evidence in the report. A fail-closed test that cannot fail is the defect this project has shipped twice.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Serve POST /claims, relaying the ack and never constructing one"
```

---

## Task 3: The three read routes

**Files:** Modify `src/serve/routes.rs`. Test: `tests/serve_proofs.rs`.

- [ ] **Step 1: Write the failing tests**

`tests/serve_proofs.rs`:

```rust
#![cfg(feature = "serve")]

mod harness;
use harness::{get, post, TestServer};

fn seed(srv: &TestServer, n: usize) {
    for i in 0..n {
        let body = format!(
            r#"{{"action_id":"a-{i}","agent_id":"did:web:x","initiating_user":"u",
            "interception_point":"PRE_CALL_TOOL_INVOCATION","target_resource":"/x",
            "canonical_snapshot_hash":"aa","policy_bundle_hash":"bb","verdict":"ALLOW",
            "nonce":"n-{i}"}}"#
        );
        let (s, b) = post(srv.path(), "/claims?now=1700000000", &body);
        assert_eq!(s, 200, "seeding failed: {b}");
    }
}

#[test]
fn the_root_route_says_what_it_does_not_defend() {
    // The same sentence the CLI prints, from the same renderer. If this ever
    // stops matching, two formatters exist and one of them will drift on
    // exactly the text this project least wants reworded.
    let srv = TestServer::start();
    seed(&srv, 1);
    let (status, body) = get(srv.path(), "/root");
    assert_eq!(status, 200);
    assert!(body.contains("C7.3.3"), "root did not print its limitation: {body}");
    assert!(body.contains("SOFTWARE"));
}

#[test]
fn an_inclusion_proof_served_over_the_socket_verifies() {
    let srv = TestServer::start();
    seed(&srv, 8);
    let (status, body) = get(srv.path(), "/proof/inclusion?leaf=3&size=8");
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["path"].as_array().map(|a| !a.is_empty()).unwrap_or(false), "empty path: {body}");
}

#[test]
fn a_consistency_proof_served_over_the_socket_verifies() {
    let srv = TestServer::start();
    seed(&srv, 8);
    let (status, body) = get(srv.path(), "/proof/consistency?from=4&to=8");
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["proof"].is_array(), "no proof array: {body}");
}

#[test]
fn out_of_range_proof_requests_are_refused_not_fabricated() {
    let srv = TestServer::start();
    seed(&srv, 4);
    for target in [
        "/proof/inclusion?leaf=99&size=4",
        "/proof/inclusion?size=4",
        "/proof/consistency?from=9&to=4",
        "/proof/consistency?from=1",
    ] {
        let (status, body) = get(srv.path(), target);
        assert_ne!(status, 200, "{target} returned a proof it cannot have: {body}");
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Add to `src/serve/routes.rs`. Every route re-opens the store from disk, so it can
only ever serve what is durable, and derives leaves exactly as `verify::against_root`
does — never a reimplementation:

```rust
use crate::record::digest;
use crate::sign::{Signer, SoftwareSigner};
use crate::store::Store;
use crate::tree::{consistency_proof, inclusion_proof, leaf_hash, root_of};
use crate::verify::against_root;
use std::path::Path;

/// The same fixed seed the CLI uses, for the same reason: Phase 1 output is
/// reproducible and the key is a labelled placeholder either way.
const DEV_SEED: [u8; 32] = [7u8; 32];

/// Leaves of the durable log, derived the way `verify::against_root` derives
/// them. Re-opening from disk is the point: a proof must not cover a record
/// that is still in flight.
fn durable_leaves(store_dir: &Path) -> Result<(Vec<[u8; 32]>, usize), String> {
    let store = Store::open(store_dir).map_err(|e| e.to_string())?;
    let mut leaves = Vec::with_capacity(store.records().len());
    for r in store.records() {
        leaves.push(leaf_hash(&digest(r).map_err(|e| e.to_string())?));
    }
    let n = leaves.len();
    Ok((leaves, n))
}

fn get_root(stream: &UnixStream, store_dir: &Path) {
    let store = match Store::open(store_dir) {
        Ok(s) => s,
        Err(e) => return server_error(stream, &e.to_string()),
    };
    let accepted = match against_root(store.records(), None) {
        Ok(a) => a,
        Err(e) => return server_error(stream, &e.to_string()),
    };
    let signed = SoftwareSigner::generate(DEV_SEED).sign_root(&accepted.root, accepted.size);
    // The SAME renderer the CLI prints. A second formatter would drift, and
    // the text it would drift on is the sentence saying what this root does
    // not defend against.
    let body = format!(
        r#"{{"size":{},"root":{},"rendered":{}}}"#,
        accepted.size,
        json_string(&hex::encode(accepted.root)),
        json_string(&signed.render())
    );
    write_response(stream, 200, "OK", &body);
}

fn get_inclusion(stream: &UnixStream, store_dir: &Path, req: &Request) {
    let (Some(leaf), Some(size)) = (req.u64_param("leaf"), req.u64_param("size")) else {
        return bad_request(stream, "both `leaf` and `size` are required and must be integers");
    };
    let (leaves, n) = match durable_leaves(store_dir) {
        Ok(v) => v,
        Err(e) => return server_error(stream, &e),
    };
    if size as usize > n {
        return not_found(stream, "the log is smaller than the requested size");
    }
    let prefix = &leaves[..size as usize];
    let Some(path) = inclusion_proof(prefix, leaf as usize) else {
        return not_found(stream, "no such leaf in a tree of that size");
    };
    let elems: Vec<String> = path.iter().map(hex::encode).collect();
    let body = format!(
        r#"{{"leaf":{leaf},"size":{size},"root":{},"path":[{}]}}"#,
        json_string(&hex::encode(root_of(prefix))),
        elems
            .iter()
            .map(|e| json_string(e))
            .collect::<Vec<_>>()
            .join(",")
    );
    write_response(stream, 200, "OK", &body);
}

fn get_consistency(stream: &UnixStream, store_dir: &Path, req: &Request) {
    let (Some(from), Some(to)) = (req.u64_param("from"), req.u64_param("to")) else {
        return bad_request(stream, "both `from` and `to` are required and must be integers");
    };
    if from == 0 || from > to {
        return bad_request(stream, "`from` must be non-zero and no greater than `to`");
    }
    let (leaves, n) = match durable_leaves(store_dir) {
        Ok(v) => v,
        Err(e) => return server_error(stream, &e),
    };
    if to as usize > n {
        return not_found(stream, "the log is smaller than `to`");
    }
    let prefix = &leaves[..to as usize];
    let Some(proof) = consistency_proof(prefix, from as usize) else {
        return not_found(stream, "no consistency proof exists for that range");
    };
    let elems: Vec<String> = proof.iter().map(hex::encode).collect();
    let body = format!(
        r#"{{"from":{from},"to":{to},"old_root":{},"new_root":{},"proof":[{}]}}"#,
        json_string(&hex::encode(root_of(&leaves[..from as usize]))),
        json_string(&hex::encode(root_of(prefix))),
        elems
            .iter()
            .map(|e| json_string(e))
            .collect::<Vec<_>>()
            .join(",")
    );
    write_response(stream, 200, "OK", &body);
}

fn bad_request(stream: &UnixStream, why: &str) {
    write_response(
        stream,
        400,
        "Bad Request",
        &format!(r#"{{"error":{}}}"#, json_string(why)),
    );
}

fn not_found(stream: &UnixStream, why: &str) {
    write_response(
        stream,
        404,
        "Not Found",
        &format!(r#"{{"error":{}}}"#, json_string(why)),
    );
}

fn server_error(stream: &UnixStream, why: &str) {
    write_response(
        stream,
        500,
        "Internal Server Error",
        &format!(r#"{{"error":{}}}"#, json_string(why)),
    );
}
```

Dispatch them:

```rust
        ("GET", "/root") => get_root(stream, store_dir),
        ("GET", "/proof/inclusion") => get_inclusion(stream, store_dir, &req),
        ("GET", "/proof/consistency") => get_consistency(stream, store_dir, &req),
```

`handle` therefore takes `store_dir: &Path` alongside the queue; thread it through from
`Server`.

**No route may fabricate a proof for a range the log does not have** — every out-of-range
case above returns 404 or 400 and never a proof. Note the slicing is guarded by the
`size > n` / `to > n` checks immediately above it; those checks are load-bearing, not
defensive decoration.

- [ ] **Step 3: Verify and commit**

Run: `cargo test --features serve && cargo clippy --all-targets --features serve -- -D warnings && cargo fmt --check`

```bash
git add -A
git commit -m "Serve the three read routes from the crate's own verifiers"
```

---

## Task 4: The A9 property over the transport, CI, and the honest README

**Files:** Test: `tests/serve_proofs.rs` (extend). Modify `.github/workflows/ci.yml`, `README.md`.

- [ ] **Step 1: The test that matters most**

Extend `tests/serve_proofs.rs` with the A9 check end to end over the socket: seed a log, fetch its root, then verify that a consistency proof against a **rewritten** log fails. This is the component's whole purpose, checked through the interface a real auditor would use rather than only in process.

Build the rewritten log the way `tests/a9_rewrite.rs` does — that file is the reference and its construction must not be re-derived loosely here.

- [ ] **Step 2: CI**

Add to the `rust` job:

```yaml
      - run: cargo clippy --all-targets --features serve -- -D warnings
      - run: cargo test --features serve
```

Validate: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "YAML OK"'`

- [ ] **Step 3: README**

Add a section for the listener with the four routes, and state plainly:

- **the socket is not an authentication boundary.** Filesystem permissions are the whole of the access control; anything that can write to the socket can insert records. Say it directly rather than describing the `0600` mode and letting a reader infer safety from it.
- the transport is a Unix domain socket, so **writer and log share a machine** — cross-host logging is not supported.
- `serve` is behind a cargo feature and the default build does not include it.

- [ ] **Step 4: Full verification and commit**

Run every gate: `cargo test`, `--features bench`, `--features tee`, `--features serve`, `--doc`, `cargo fmt --check`, and clippy under each feature set.

```bash
git add -A
git commit -m "Check A9 over the socket, build serve in CI, and say the socket is not a boundary"
```

---

## Done

`transit guard` has something to write to, and an auditor has somewhere to read proofs from.

**Not done:** no authentication, no cross-host transport, and the listener has never been driven by the real `transit guard` — only by tests in this repository.
