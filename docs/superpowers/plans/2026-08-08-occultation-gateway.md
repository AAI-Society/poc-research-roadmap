# occultation-gateway Implementation Plan — Phase 1

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `occultation-gateway`, a fail-open reverse proxy a relying party puts in front of its agent-facing API, which verifies real TDX attestation, measures what each request gave away, and never rejects.

**Architecture:** A second binary in the `occultation` repository. `hyper` reverse proxy forwards every request unconditionally; alongside the forward it extracts an attestation via a pluggable `AttestationSource`, verifies it with `dcap-qvl` against out-of-band cached collateral, feeds the TCB configuration to a `LinkabilityMeter` that holds salted frequency counts and no session-to-fingerprint map, and emits a finding. Every stage is individually fault-injectable and every fault forwards the request.

**Tech Stack:** Rust 2021, `hyper` 1 + `hyper-util` (proxy), `dcap-qvl` 0.6 (quote verification), `tokio`, `sha2` (already present), `serde` + `serde_json`, `clap` 4 derive, `thiserror`, `anyhow`, `prometheus-client`, `humantime`.

---

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**. **`#![forbid(unsafe_code)]`** stays in `src/lib.rs`.
- **Fail-open is the only behaviour in phase 1.** Every internal error, verification failure, meter fault or panic in gateway code forwards the request upstream and records a finding. `--enforce` does not exist yet. The proxy must not be able to take down the API it fronts. Asserted by fault-injection test at every stage.
- **`dcap_qvl::verify::dangerous_verify_with_tcb_override` must never be called.** It is public, it is well named, and it is the single API that would turn this into a verifier that verifies nothing. Asserted by a grep test in CI.
- **A stale or missing collateral cache degrades to `Unverified { why }`, never to `Verified`.** Asserted by test.
- **The PPID must never be stored, logged, rendered, or serialized.** `dcap_qvl`'s `VerifiedReport` carries `ppid: Vec<u8>` — a unique per-platform hardware identifier. A gateway built to stop a relying party accumulating a dossier is handed a hardware serial on every successful verification. It is dropped at the verifier boundary and never crosses into a finding, a metric label, or the meter. Asserted by test on the finding's serialized form.

  > **AMENDMENT (verified against the 0.6.1 source before Task 4).** This is
  > sharper than the plan first stated, and the mechanism matters. `verify.rs:244`
  > reads `#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]` on
  > `VerifiedReport`, and `ppid` carries an explicit `#[serde(with = "serde_bytes")]`.
  > So the type is **directly serializable and the PPID field is deliberately
  > wired for it**: a single `serde_json::to_string(&report)` — or a
  > `#[derive(Serialize)]` on any struct that holds one, or a `{report:?}` in a
  > log line, since `Debug` is derived too — emits the hardware serial with no
  > warning. The constraint is therefore not merely "do not write it out"; it is
  > **`VerifiedReport` must never be stored in a field, returned from a public
  > function, or passed to any formatter.** Destructure it at the verifier
  > boundary, take only `status`, `advisory_ids`, and the TCB fields off
  > `report`, and let the rest drop in that scope.
  >
  > Two fields the plan did not know about also exist: `qe_status` and
  > `platform_status`, both `TcbStatusWithAdvisory { status: TcbStatus,
  > advisory_ids: Vec<String> }`. These are richer than the flat
  > `status: String` the plan uses. `status: String` remains correct and is what
  > Task 4 reads; the others are noted so a later task can report *which* of the
  > QE and the platform is stale rather than only that something is.
- **The meter holds no session-to-fingerprint map and no joint distribution across attributes.** It cannot answer "has this agent been here before," and that refusal is asserted by test, not documented.
- **Every reported number carries its provenance**, following the existing `occultation` convention: `Source::MeasuredHere` / `Published` / and here also `Unverified`. Nothing untagged.
- Library errors use `thiserror`; the binary uses `anyhow`. **No panics on malformed input** — this parses hostile bytes by design.
- Licensing: **Apache-2.0 throughout**, unchanged. Copyright "Advanced AI Society and the Proof-of-Control contributors".
- Every commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

---

## What phase 1 is not

Recorded here so a task does not quietly grow one:

- **No `--enforce`.** Not a flag that defaults off — absent.
- **No RA-TLS.** `AttestationSource` is a trait with one implementation, `HeaderSource`. The trait exists so phase 1b can add `RaTlsSource` without reshaping anything.
- **No credential verification.** The gateway does not parse, validate or comment on the OAuth token, mTLS certificate or `agent_id` beyond noting their presence.
- **No BBS+.** Phase 2, gated on separate conformance work.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/gateway/mod.rs` | module wiring and public re-exports |
| `src/gateway/config.rs` | `GatewayConfig`, loaded from CLI + TOML |
| `src/gateway/source.rs` | `AttestationSource` trait, `SessionBinding`, `HeaderSource` |
| `src/gateway/verify.rs` | `QuoteVerifier`, `QuoteVerdict`, PPID scrubbing at the boundary |
| `src/gateway/collateral.rs` | out-of-band collateral fetch and TTL cache |
| `src/gateway/meter.rs` | `LinkabilityMeter` — salted counts, marginals, and its refusals |
| `src/gateway/finding.rs` | `Finding`, table and JSON rendering, Prometheus metrics |
| `src/gateway/proxy.rs` | the hyper service: forward-always, measure-alongside |
| `src/bin/gateway.rs` | clap CLI and process wiring |
| `tests/gateway_hostile.rs` | the hostile agent fixture and its cases |
| `tests/gateway_failopen.rs` | fault injection at every stage |

---

### Task 1: Gateway skeleton and the fail-open proxy shell

**Files:**
- Create: `src/gateway/mod.rs`, `src/gateway/config.rs`, `src/gateway/proxy.rs`, `src/bin/gateway.rs`
- Modify: `Cargo.toml`, `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `gateway::config::GatewayConfig { listen: SocketAddr, upstream: Uri, salt_rotation: Duration, pccs_url: String }`; `gateway::proxy::serve(cfg: GatewayConfig, hooks: Hooks) -> Result<(), ProxyError>`; `gateway::proxy::Hooks` — a struct of boxed closures the later tasks fill in, so the proxy never depends on the meter or verifier directly.

The proxy forwards before it measures. That ordering is the fail-open guarantee, and it is established in this task so no later task can invert it.

**AMENDMENT (supersedes the code blocks below where they conflict).** The Task 1
review found two defects that this plan mandated, both approved for change
because they constrain the interface Tasks 2-6 build against.

**A1 — Bodies stream; they are not buffered.** The original signature
`Response<Full<Bytes>>` forces `collect()` on both bodies. An agent-facing API
normally serves SSE or token streams, and `collect()` on `text/event-stream`
does not resolve until the stream ends — so every streaming endpoint behind
the gateway hangs while its buffer grows. N large bodies also OOM the process,
which unlike a panic is a total outage rather than one dropped connection.

```rust
use http_body_util::{BodyExt, Limited, combinators::BoxBody};

/// Cap the request body. A proxy that buffers on an attacker's say-so is a
/// denial-of-service primitive.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

async fn forward(req: Request<Incoming>, upstream: hyper::Uri)
    -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible>;
```

The response body is passed through unbuffered — `resp.into_body().boxed()` —
so SSE reaches the client token by token. The request body is wrapped in
`Limited::new(body, MAX_REQUEST_BODY)`; over-cap becomes a 502 like every other
failure, never a dropped connection.

**A2 — The hook runs AFTER the forward, on an owned snapshot.** The prose above
said "forward first, measure second" and the original code did the opposite.
`catch_unwind` bounds panics but not *time*: with a synchronous `Fn` invoked on
the connection's task ahead of the forward, a hook doing blocking I/O — a PCCS
collateral fetch is the obvious Task 3 candidate — stalls a runtime worker with
the request still in hand. That is the exact hazard the ordering existed to
prevent.

```rust
/// What a hook sees: an owned copy of the head, never the live request.
///
/// Owned so the hook can run *after* the forward, which is what makes a slow
/// hook unable to delay a response. The body is deliberately absent — no
/// measurement in this design needs it.
#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: hyper::Method,
    pub path_and_query: String,
    pub headers: hyper::HeaderMap,
}

pub struct Hooks {
    pub on_request: Box<dyn Fn(&RequestHead) + Send + Sync>,
}
```

and `handle` becomes:

```rust
let head = RequestHead::snapshot(&req);
let resp = forward(req, upstream).await;          // FIRST
if std::panic::catch_unwind(AssertUnwindSafe(|| (hooks.on_request)(&head))).is_err() {
    log::error!("gateway hook panicked; request already forwarded, no finding recorded");
}
resp
```

**A3 — Strip hop-by-hop headers in BOTH directions.** The original copies the
request `HeaderMap` wholesale and removes only `Host`, while re-framing the
body — so a client sending `Transfer-Encoding: chunked` produces an upstream
request carrying both `Transfer-Encoding` and `Content-Length`, which is the
canonical request-smuggling shape. The response side already strips
`Transfer-Encoding` for exactly this reason. Strip the full RFC 9110 set —
`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
`Proxy-Authenticate`, `Proxy-Authorization` — plus anything named in
`Connection`, on both request and response.

**A4 — `forward` returns `Infallible`, not `hyper::Error`.** "This never returns
`Err`" was a doc comment; one `?` added in a later task would silently
reintroduce the dropped connection this task exists to prevent, and no test
would fail. Make the compiler enforce it.

**A5 — Validate the upstream at startup, in `serve`, before binding.** Reject a
non-`http` scheme or a missing authority. `HttpConnector` is plaintext-only, so
`--upstream https://api.internal` currently starts cleanly and answers 100% of
traffic with a synthesised 502 — fail-open in the narrow sense, and the fronted
API entirely unreachable, which is the outcome this task exists to prevent.

**A6 — Two more tests, because the three below verify only the path.** Deleting
the response-header copy leaves all three green while stripping `Content-Type`,
`Set-Cookie` and CORS off every response; the request side is likewise untested
on method, headers and body.

```rust
#[tokio::test]
async fn method_headers_and_body_all_reach_the_upstream() {
    // `..._is_forwarded_unchanged` below asserts only the path. This asserts
    // the rest of "unchanged", and kills the mutations that drop the request
    // headers, hard-code GET, or send an empty body.
    let upstream = spawn_reflecting_upstream().await;   // echoes method, a header, body len
    let gw = spawn_gateway(upstream, Hooks::noop()).await;
    let body = post(&gw, "/x", &[("x-agent", "acme")], b"hello").await.unwrap();
    assert!(body.contains("POST"), "{body}");
    assert!(body.contains("x-agent=acme"), "{body}");
    assert!(body.contains("len=5"), "{body}");
}

#[tokio::test]
async fn upstream_response_headers_reach_the_client() {
    // Deleting the response header copy silently strips Content-Type,
    // Set-Cookie and CORS off every response, and nothing else notices.
    let upstream = spawn_upstream_with_header("content-type", "application/json").await;
    let gw = spawn_gateway(upstream, Hooks::noop()).await;
    assert_eq!(header_of(&gw, "/x", "content-type").await.unwrap(), "application/json");
}
```


- [ ] **Step 1: Add dependencies**

Add to `Cargo.toml`:

```toml
hyper = { version = "1", features = ["server", "client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "client-legacy", "server"] }
http-body-util = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time"] }
dcap-qvl = "0.6"
prometheus-client = "0.23"

[[bin]]
name = "occultation-gateway"
path = "src/bin/gateway.rs"
```

- [ ] **Step 2: Write the failing test**

Create `src/gateway/proxy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The whole design rests on this: a hook that panics must not stop the
    /// request. If this test ever fails, the gateway can take down the API it
    /// fronts, which is the one thing it must never do.
    #[tokio::test]
    async fn a_panicking_hook_still_forwards_the_request() {
        let upstream = spawn_echo_upstream().await;
        let hooks = Hooks {
            on_request: Box::new(|_| panic!("hook exploded")),
        };
        let gw = spawn_gateway(upstream, hooks).await;

        let body = get(&gw, "/hello").await.expect("the request must complete");
        assert_eq!(body, "echo:/hello");
    }

    #[tokio::test]
    async fn a_request_with_no_attestation_is_forwarded_unchanged() {
        let upstream = spawn_echo_upstream().await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        assert_eq!(get(&gw, "/plain").await.unwrap(), "echo:/plain");
    }

    #[tokio::test]
    async fn the_upstreams_status_and_body_are_preserved() {
        let upstream = spawn_status_upstream(503, "upstream sad").await;
        let gw = spawn_gateway(upstream, Hooks::noop()).await;
        let (status, body) = get_full(&gw, "/x").await.unwrap();
        assert_eq!(status, 503, "the gateway must not rewrite upstream failures");
        assert_eq!(body, "upstream sad");
    }
}
```

The test helpers `spawn_echo_upstream`, `spawn_status_upstream`, `spawn_gateway`, `get` and `get_full` are written as part of this step, in the same `mod tests`. `spawn_echo_upstream` binds `127.0.0.1:0`, returns its `SocketAddr`, and replies `echo:<path>`.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib gateway::proxy`
Expected: FAIL — `cannot find type Hooks in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `src/gateway/proxy.rs`:

```rust
use crate::gateway::config::GatewayConfig;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// What the proxy calls alongside forwarding. Boxed closures rather than a
/// trait object over the meter, so `proxy.rs` never depends on the verifier
/// or the meter and can be tested with neither.
pub struct Hooks {
    pub on_request: Box<dyn Fn(&Request<Incoming>) + Send + Sync>,
}

impl Hooks {
    pub fn noop() -> Self {
        Hooks { on_request: Box::new(|_| {}) }
    }
}

/// Forward first, measure second, and never let the second affect the first.
///
/// `catch_unwind` is deliberate. A hook is the only place gateway logic runs
/// on the request path, and a panic there must degrade to "no finding for
/// this request" rather than to a dropped connection. The unwind is recorded
/// so the operator learns the hook is broken.
async fn handle(
    req: Request<Incoming>,
    upstream: hyper::Uri,
    hooks: Arc<Hooks>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if std::panic::catch_unwind(AssertUnwindSafe(|| (hooks.on_request)(&req))).is_err() {
        log::error!("gateway hook panicked; request forwarded, no finding recorded");
    }
    forward(req, upstream).await
}
```

`forward` performs the upstream request with `hyper_util`'s legacy client, copying method, path, headers and body, and returning the upstream's status and body verbatim. `serve` binds the listener and runs the accept loop, passing `Arc<Hooks>` into each connection.

- [ ] **Step 5: Write the config**

Create `src/gateway/config.rs`:

```rust
use serde::Deserialize;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    #[serde(with = "http_serde::uri")]
    pub upstream: hyper::Uri,
    /// How often the meter's salt rotates, ageing out correlation.
    #[serde(with = "humantime_serde")]
    pub salt_rotation: Duration,
    /// Provisioning Certification Caching Service, for collateral.
    pub pccs_url: String,
}
```

Add `http-serde = "2"` and `humantime-serde = "1"` to `Cargo.toml`.

- [ ] **Step 6: Wire the module and the binary**

Add `pub mod gateway;` to `src/lib.rs`, and create `src/gateway/mod.rs`:

```rust
//! A fail-open reverse proxy that measures what a relying party learns.
//!
//! Forwards every request. Measures alongside. Never rejects — `--enforce`
//! does not exist in phase 1.

pub mod config;
pub mod proxy;
```

Create a minimal `src/bin/gateway.rs` that parses `--listen`, `--upstream`, `--pccs-url` and `--salt-rotation` with clap, builds a `GatewayConfig`, and calls `serve(cfg, Hooks::noop())`.

- [ ] **Step 7: Run and verify**

Run: `cargo test --lib gateway && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS, 3 tests.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the gateway skeleton and its fail-open guarantee

The proxy forwards before it measures, and a panicking hook is caught and
logged rather than dropping the connection. That ordering is established
here so no later task can invert it: this binary sits in front of somebody
else's revenue API and must not be able to take it down.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `AttestationSource` and the header transport

**Files:**
- Create: `src/gateway/source.rs`
- Modify: `src/gateway/mod.rs`

**Interfaces:**
- Consumes: nothing from Task 1 beyond the module.
- Produces: `SessionBinding { Bound, Unbound { why: &'static str } }`; `RawAttestation { bytes: Vec<u8> }`; `trait AttestationSource { fn extract(&self, req: &Request<Incoming>) -> Result<Option<RawAttestation>, SourceError>; fn session_binding(&self) -> SessionBinding; fn name(&self) -> &'static str; }`; `HeaderSource::new(header: &str) -> HeaderSource`.

`session_binding()` is not decoration. Header transport does not tie the quote to the TLS session, so a captured quote is replayable, and the gateway reports that as a finding rather than leaving the operator to infer it.

- [ ] **Step 1: Write the failing test**

Create `src/gateway/source.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(header: Option<(&str, &str)>) -> Request<Incoming> {
        let mut b = Request::builder().uri("/");
        if let Some((k, v)) = header {
            b = b.header(k, v);
        }
        b.body(empty_incoming()).unwrap()
    }

    #[test]
    fn a_base64_header_yields_its_bytes() {
        let s = HeaderSource::new("x-attestation");
        let r = req_with(Some(("x-attestation", "aGVsbG8="))); // "hello"
        assert_eq!(s.extract(&r).unwrap().unwrap().bytes, b"hello");
    }

    #[test]
    fn an_absent_header_is_none_not_an_error() {
        // No attestation is a legitimate state the gateway reports on. It is
        // not a malformed request.
        assert!(HeaderSource::new("x-attestation").extract(&req_with(None)).unwrap().is_none());
    }

    #[test]
    fn undecodable_base64_is_an_error_not_a_panic() {
        let s = HeaderSource::new("x-attestation");
        assert!(s.extract(&req_with(Some(("x-attestation", "not!base64")))).is_err());
    }

    #[test]
    fn a_non_ascii_header_value_is_an_error_not_a_panic() {
        // Header values can carry arbitrary bytes; to_str() fails on them.
        let s = HeaderSource::new("x-attestation");
        let r = Request::builder()
            .uri("/")
            .header("x-attestation", hyper::header::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap())
            .body(empty_incoming())
            .unwrap();
        assert!(s.extract(&r).is_err());
    }

    #[test]
    fn an_oversized_header_is_refused_rather_than_allocated() {
        // A quote is a few kilobytes. Anything past the cap is hostile input,
        // and decoding it would allocate on an attacker's say-so.
        let s = HeaderSource::new("x-attestation");
        let huge = "A".repeat(MAX_ATTESTATION_B64 + 4);
        assert!(s.extract(&req_with(Some(("x-attestation", &huge)))).is_err());
    }

    #[test]
    fn header_transport_declares_itself_unbound() {
        // The finding depends on this being honest.
        match HeaderSource::new("x-attestation").session_binding() {
            SessionBinding::Unbound { why } => assert!(why.contains("replay")),
            SessionBinding::Bound => panic!("a header cannot bind a TLS session"),
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib gateway::source`
Expected: FAIL — `cannot find type HeaderSource in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/gateway/source.rs`:

```rust
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::body::Incoming;
use hyper::Request;

/// A TDX quote is a few kilobytes. Past this the input is hostile and
/// decoding it would allocate on an attacker's say-so.
pub const MAX_ATTESTATION_B64: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("attestation header is not valid UTF-8")]
    NotUtf8,
    #[error("attestation header is not valid base64: {0}")]
    NotBase64(String),
    #[error("attestation header is {got} bytes; the cap is {MAX_ATTESTATION_B64}")]
    TooLarge { got: usize },
}

/// Whether the transport ties the attestation to *this* session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionBinding {
    Bound,
    Unbound { why: &'static str },
}

#[derive(Clone, Debug)]
pub struct RawAttestation {
    pub bytes: Vec<u8>,
}

pub trait AttestationSource: Send + Sync {
    fn extract(&self, req: &Request<Incoming>) -> Result<Option<RawAttestation>, SourceError>;
    fn session_binding(&self) -> SessionBinding;
    fn name(&self) -> &'static str;
}

/// Reads a base64 quote from a request header.
///
/// The simplest transport that works with any client stack, and the weakest:
/// nothing ties the quote to the TLS session it arrived on, so a quote
/// captured once can be replayed forever. `RaTlsSource` in phase 1b is the
/// answer; until then the gateway reports the gap.
pub struct HeaderSource {
    header: String,
}

impl HeaderSource {
    pub fn new(header: &str) -> Self {
        HeaderSource { header: header.to_ascii_lowercase() }
    }
}

impl AttestationSource for HeaderSource {
    fn extract(&self, req: &Request<Incoming>) -> Result<Option<RawAttestation>, SourceError> {
        let Some(v) = req.headers().get(&self.header) else {
            return Ok(None);
        };
        let s = v.to_str().map_err(|_| SourceError::NotUtf8)?;
        if s.len() > MAX_ATTESTATION_B64 {
            return Err(SourceError::TooLarge { got: s.len() });
        }
        let bytes = STANDARD.decode(s).map_err(|e| SourceError::NotBase64(e.to_string()))?;
        Ok(Some(RawAttestation { bytes }))
    }

    fn session_binding(&self) -> SessionBinding {
        SessionBinding::Unbound {
            why: "the quote arrived in a header and is not bound to this TLS \
                  session, so a captured quote is replayable",
        }
    }

    fn name(&self) -> &'static str {
        "header"
    }
}
```

Add `base64 = "0.22"` to `Cargo.toml` and `pub mod source;` to `src/gateway/mod.rs`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib gateway::source`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the attestation source trait and header transport

C7.2.4 says the evidence key digest goes in the attested report body and
says nothing about how the report reaches a relying party, so transport is
pluggable. Header transport ships first because it works with any client
stack; it also declares itself Unbound, because nothing ties the quote to
the TLS session and a captured quote is replayable. The gateway reports
that gap rather than leaving an operator to infer it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Collateral cache

**Files:**
- Create: `src/gateway/collateral.rs`
- Modify: `src/gateway/mod.rs`

**Interfaces:**
- Consumes: `GatewayConfig` (Task 1).
- Produces: `CollateralCache::new(pccs_url: String, ttl: Duration) -> CollateralCache`; `CollateralCache::get(&self, fmspc: &Fmspc) -> CacheLookup` (**AMENDED — see below**); `pub fn fmspc_to_hex(&Fmspc) -> String`; `enum CacheLookup { Fresh(Arc<QuoteCollateralV3>), Stale { age: Duration }, Absent }`; `CollateralCache::refresh(&self, quote: &[u8]) -> Result<(), CollateralError>` (async, called off the request path).

> **AMENDMENT (post-review, coordinator ruling).** Two of this task's API
> assumptions were wrong, confirmed against the `dcap-qvl` 0.6.1 source:
> `quote_fmspc` is `dcap_qvl::intel::quote_fmspc(&Quote) -> Result<Fmspc>`,
> not `dcap_qvl::quote::quote_fmspc(&[u8])`, so raw bytes need `Quote::parse`
> first; and `Fmspc` is `[u8; 6]`, not a `String`.
>
> That makes `get(&self, fmspc: &str)` a divergence surface rather than an
> interface: Task 4 holds an `Fmspc` and would have to render its own hex to
> call it. Two renderings of one platform is exactly the silent-miss failure
> this cache must not have — `refresh` stores under one spelling, `get` reads
> another, the platform misses forever, and the gateway reports `Unverified`
> permanently with nothing failing loudly.
>
> So the signature becomes `get(&self, fmspc: &Fmspc)`, `fmspc_to_hex` becomes
> `pub`, and the `&str` form survives only as a `#[cfg(test)]` helper. One
> renderer, reachable by every caller, and the type system forbids a second.
> Task 4's `verify` is amended to match.

The split exists because `dcap_qvl::verify::verify` is synchronous and takes collateral as an argument, while fetching collateral is an async network call. Keeping them apart is what stops a PCS round trip landing on a request.

- [ ] **Step 1: Write the failing test**

Create `src/gateway/collateral.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_cache_reports_absent_not_an_error() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        assert!(matches!(c.get("00806f050000"), CacheLookup::Absent));
    }

    #[test]
    fn a_fresh_entry_is_returned() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now());
        assert!(matches!(c.get("00806f050000"), CacheLookup::Fresh(_)));
    }

    /// The constraint that matters: age must degrade to Stale, and Stale must
    /// be a distinct state the verifier turns into `Unverified`. If this ever
    /// returned Fresh, the gateway would verify against expired TCB data and
    /// report a revoked platform as up to date.
    #[test]
    fn an_aged_entry_is_stale_and_never_fresh() {
        let ttl = Duration::from_secs(60);
        let c = CollateralCache::new("https://pccs.invalid".into(), ttl);
        c.insert_for_test("00806f050000", fake_collateral(), Instant::now() - Duration::from_secs(61));
        match c.get("00806f050000") {
            CacheLookup::Stale { age } => assert!(age > ttl),
            other => panic!("expired collateral must be Stale, got {other:?}"),
        }
    }

    #[test]
    fn entries_for_different_fmspc_do_not_collide() {
        let c = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(3600));
        c.insert_for_test("aaaaaaaaaaaa", fake_collateral(), Instant::now());
        assert!(matches!(c.get("bbbbbbbbbbbb"), CacheLookup::Absent));
    }

    #[tokio::test]
    async fn an_unreachable_pccs_is_an_error_not_a_panic() {
        let c = CollateralCache::new("http://127.0.0.1:1".into(), Duration::from_secs(60));
        assert!(c.refresh(&[0u8; 8]).await.is_err());
    }
}
```

`fake_collateral()` builds a `QuoteCollateralV3` with empty fields; it is never verified against, only stored and retrieved. `insert_for_test` is `#[cfg(test)]`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib gateway::collateral`
Expected: FAIL — `cannot find type CollateralCache in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/gateway/collateral.rs`:

```rust
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::QuoteCollateralV3;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum CollateralError {
    #[error("could not reach the provisioning service at {url}: {source}")]
    Unreachable {
        url: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("quote does not carry an FMSPC; it may not be a DCAP quote")]
    NoFmspc,
}

#[derive(Debug)]
pub enum CacheLookup {
    Fresh(Arc<QuoteCollateralV3>),
    /// Present but past its TTL. The verifier turns this into `Unverified`,
    /// never into a verification against expired TCB data.
    Stale { age: Duration },
    Absent,
}

struct Entry {
    collateral: Arc<QuoteCollateralV3>,
    fetched: Instant,
}

/// Collateral, fetched off the request path and cached by FMSPC.
///
/// `dcap_qvl::verify::verify` is synchronous and takes collateral as an
/// argument; fetching it is an async network call. Keeping the two apart is
/// what stops a PCS round trip landing on a request.
pub struct CollateralCache {
    pccs_url: String,
    ttl: Duration,
    entries: RwLock<HashMap<String, Entry>>,
}

impl CollateralCache {
    pub fn new(pccs_url: String, ttl: Duration) -> Self {
        CollateralCache { pccs_url, ttl, entries: RwLock::new(HashMap::new()) }
    }

    pub fn get(&self, fmspc: &str) -> CacheLookup {
        let guard = self.entries.read().expect("cache lock is never held across a panic");
        match guard.get(fmspc) {
            None => CacheLookup::Absent,
            Some(e) => {
                let age = e.fetched.elapsed();
                if age > self.ttl {
                    CacheLookup::Stale { age }
                } else {
                    CacheLookup::Fresh(Arc::clone(&e.collateral))
                }
            }
        }
    }

    pub async fn refresh(&self, quote: &[u8]) -> Result<(), CollateralError> {
        let fmspc = dcap_qvl::quote::quote_fmspc(quote).map_err(|_| CollateralError::NoFmspc)?;
        let client = CollateralClient::with_default_http(self.pccs_url.clone())
            .map_err(|e| CollateralError::Unreachable { url: self.pccs_url.clone(), source: e.into() })?;
        let collateral = client
            .fetch(quote)
            .await
            .map_err(|e| CollateralError::Unreachable { url: self.pccs_url.clone(), source: e.into() })?;
        let mut guard = self.entries.write().expect("cache lock is never held across a panic");
        guard.insert(fmspc, Entry { collateral: Arc::new(collateral), fetched: Instant::now() });
        Ok(())
    }
}
```

**Note for the implementer:** `quote_fmspc`'s exact path and signature must be confirmed against `dcap-qvl` 0.6.1 before writing this — the probe found `pub fn quote_fmspc` and `quote_fmspc_with` but did not pin the module. If it lives elsewhere or returns a different type, adjust and say so in your report rather than guessing.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --lib gateway::collateral`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the collateral cache, fetched off the request path

dcap-qvl's verify() is synchronous and takes collateral as an argument
while fetching it is an async network call, so the two are kept apart and
a PCS round trip never lands on a request.

Expired entries return Stale rather than Fresh. That distinction is the
whole point: verifying against expired TCB data would report a revoked
platform as up to date, so the verifier turns Stale into Unverified.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `QuoteVerifier`, and dropping the PPID at the boundary

**Files:**
- Create: `src/gateway/verify.rs`
- Modify: `src/gateway/mod.rs`

**Interfaces:**
- Consumes: `RawAttestation` (Task 2), `CollateralCache` / `CacheLookup` (Task 3).
- Produces: `TcbConfig { attributes: BTreeMap<String, String> }`; `QuoteVerdict { Verified { platform: Platform, tcb_status: String, advisories: Vec<String>, config: TcbConfig }, Invalid { reason: String }, Unverified { why: String } }`; `enum Platform { TdxV10, TdxV15, SgxEnclave }`; `QuoteVerifier::new(cache: Arc<CollateralCache>) -> QuoteVerifier`; `QuoteVerifier::verify(&self, raw: &RawAttestation) -> QuoteVerdict`.

**This task carries the constraint the whole design turns on.** `dcap_qvl`'s `VerifiedReport` contains `ppid: Vec<u8>` — a unique per-platform hardware identifier. It is dropped here and never crosses this boundary. A gateway built to stop a relying party accumulating a dossier, handed a hardware serial on every successful verification, must not be the thing that writes it down.

- [ ] **Step 1: Write the failing test**

Create `src/gateway/verify.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn verifier_with_empty_cache() -> QuoteVerifier {
        QuoteVerifier::new(Arc::new(CollateralCache::new(
            "https://pccs.invalid".into(),
            Duration::from_secs(3600),
        )))
    }

    #[test]
    fn a_quote_with_no_collateral_is_unverified_not_invalid() {
        // Absent collateral is our failure, not the agent's. Reporting it as
        // Invalid would blame a counterparty for our own cold cache.
        let v = verifier_with_empty_cache();
        match v.verify(&RawAttestation { bytes: real_tdx_quote() }) {
            QuoteVerdict::Unverified { why } => assert!(why.contains("collateral")),
            other => panic!("expected Unverified, got {other:?}"),
        }
    }

    #[test]
    fn stale_collateral_is_unverified_never_verified() {
        let cache = CollateralCache::new("https://pccs.invalid".into(), Duration::from_secs(60));
        cache.insert_for_test(&fmspc_of(&real_tdx_quote()), fake_collateral(),
                              Instant::now() - Duration::from_secs(61));
        let v = QuoteVerifier::new(Arc::new(cache));
        assert!(matches!(v.verify(&RawAttestation { bytes: real_tdx_quote() }),
                         QuoteVerdict::Unverified { .. }));
    }

    #[test]
    fn bytes_that_are_not_a_quote_are_invalid_not_a_panic() {
        let v = verifier_with_empty_cache();
        for junk in [vec![], vec![0u8; 3], vec![0xff; 5000], b"not a quote at all".to_vec()] {
            match v.verify(&RawAttestation { bytes: junk }) {
                QuoteVerdict::Invalid { .. } | QuoteVerdict::Unverified { .. } => {}
                QuoteVerdict::Verified { .. } => panic!("junk must never verify"),
            }
        }
    }

    /// The constraint the design turns on. `VerifiedReport` carries a PPID —
    /// a unique per-platform hardware identifier — and it must not survive
    /// this boundary in any form.
    #[test]
    fn the_ppid_never_crosses_the_verifier_boundary() {
        let verdict = QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".into(),
            advisories: vec![],
            config: TcbConfig::for_test(&[("tdx_module", "1.5.05")]),
        };
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(!json.to_lowercase().contains("ppid"), "the PPID reached the verdict: {json}");

        // And structurally: no field of any verdict variant can hold it.
        let fields = std::any::type_name::<QuoteVerdict>();
        let _ = fields; // documentation; the real guard is the grep test below
    }

    #[test]
    fn tcb_config_carries_the_attributes_the_meter_partitions_on() {
        let c = TcbConfig::for_test(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]);
        assert_eq!(c.attributes.len(), 2);
        assert_eq!(c.attributes.get("pce_svn").map(String::as_str), Some("13"));
        // Ordered, so the fingerprint downstream is order-independent.
        assert_eq!(c.attributes.keys().next().map(String::as_str), Some("pce_svn"));
    }
}
```

`real_tdx_quote()` returns a committed fixture under `tests/fixtures/tdx-quote.bin`; if none is available, it returns a syntactically-valid header with a known FMSPC and the tests that need a full verification are marked `#[ignore]` with a comment naming what is missing. **Do not fabricate a quote that appears to verify.**

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib gateway::verify`
Expected: FAIL — `cannot find type QuoteVerifier in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/gateway/verify.rs`:

```rust
use crate::gateway::collateral::{CacheLookup, CollateralCache};
use crate::gateway::source::RawAttestation;
use dcap_qvl::quote::Report;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    TdxV10,
    TdxV15,
    SgxEnclave,
}

/// The TCB attributes the meter partitions on. A `BTreeMap` so the ordering
/// is canonical and the fingerprint downstream cannot depend on insertion
/// order — the same reasoning as `anonymity::Fleet`'s TCB map.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TcbConfig {
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum QuoteVerdict {
    Verified {
        platform: Platform,
        tcb_status: String,
        advisories: Vec<String>,
        config: TcbConfig,
    },
    /// The agent's fault: the bytes are not a valid quote, or the chain fails.
    Invalid { reason: String },
    /// Our fault: we could not check. Never a pass.
    Unverified { why: String },
}

pub struct QuoteVerifier {
    cache: Arc<CollateralCache>,
}

impl QuoteVerifier {
    pub fn new(cache: Arc<CollateralCache>) -> Self {
        QuoteVerifier { cache }
    }

    /// Verify a quote against cached collateral.
    ///
    /// **`dangerous_verify_with_tcb_override` is never called here.** It is a
    /// public API of `dcap-qvl`, it is well named, and it is the one call that
    /// would turn this into a verifier that verifies nothing. A grep test in
    /// CI enforces its absence from the whole crate.
    pub fn verify(&self, raw: &RawAttestation) -> QuoteVerdict {
        // AMENDED after Task 3. The API this originally called does not exist.
        // The real route is `Quote::parse(&[u8])` then
        // `dcap_qvl::intel::quote_fmspc(&Quote) -> Result<Fmspc>`, where
        // `Fmspc = [u8; 6]` — a byte array, not a string, so it neither keys a
        // map nor renders with `{fmspc}` directly. `CollateralCache::get` now
        // takes `&Fmspc` and `fmspc_to_hex` is public, so exactly one hex
        // rendering exists in the crate and a lookup cannot miss because two
        // call sites spelled the same platform differently.
        let parsed = match dcap_qvl::quote::Quote::parse(&raw.bytes) {
            Ok(q) => q,
            Err(e) => return QuoteVerdict::Invalid { reason: format!("not a DCAP quote: {e}") },
        };
        let fmspc = match dcap_qvl::intel::quote_fmspc(&parsed) {
            Ok(f) => f,
            Err(e) => return QuoteVerdict::Invalid { reason: format!("not a DCAP quote: {e}") },
        };
        let fmspc_hex = crate::gateway::collateral::fmspc_to_hex(&fmspc);

        let collateral = match self.cache.get(&fmspc) {
            CacheLookup::Fresh(c) => c,
            CacheLookup::Stale { age } => {
                return QuoteVerdict::Unverified {
                    why: format!(
                        "collateral for FMSPC {fmspc_hex} is {}s old and past its TTL; \
                         verifying against expired TCB data could report a revoked \
                         platform as up to date",
                        age.as_secs()
                    ),
                }
            }
            CacheLookup::Absent => {
                return QuoteVerdict::Unverified {
                    why: format!("no collateral cached for FMSPC {fmspc_hex} yet"),
                }
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match dcap_qvl::verify::verify(&raw.bytes, &collateral, now) {
            Err(e) => QuoteVerdict::Invalid { reason: e.to_string() },
            Ok(report) => {
                // `report.ppid` is a unique per-platform hardware identifier.
                // It is read nowhere and dropped with `report` at the end of
                // this scope. Nothing below may reference it.
                let (platform, config) = match &report.report {
                    Report::TD10(td) => (Platform::TdxV10, tcb_config_from_td10(td)),
                    Report::TD15(td) => (Platform::TdxV15, tcb_config_from_td15(td)),
                    Report::SgxEnclave(e) => (Platform::SgxEnclave, tcb_config_from_sgx(e)),
                };
                QuoteVerdict::Verified {
                    platform,
                    tcb_status: report.status.clone(),
                    advisories: report.advisory_ids.clone(),
                    config,
                }
            }
        }
    }
}
```

The three `tcb_config_from_*` helpers extract only the fields that describe a *configuration* — TDX module version, TCB SVNs, PCE SVN, and the collateral's FMSPC — and never `ppid`, `mrenclave`, `mrsigner`, `report_data` or any other per-instance value. Each returns a `TcbConfig`. **Write the field list explicitly; do not serialize the whole report and filter.**

- [ ] **Step 4: Add the CI grep test**

Append to `src/gateway/verify.rs`'s test module:

```rust
/// A structural guard, not a stylistic one. This call would make the gateway
/// report `Verified` for a platform whose TCB is out of date or revoked.
#[test]
fn the_dangerous_override_is_never_called_anywhere_in_this_crate() {
    let src = std::process::Command::new("grep")
        .args(["-rn", "dangerous_verify_with_tcb_override", "src/"])
        .output()
        .expect("grep runs");
    assert!(
        src.stdout.is_empty(),
        "dangerous_verify_with_tcb_override appears in src/: {}",
        String::from_utf8_lossy(&src.stdout)
    );
}

/// Same shape, for the PPID.
#[test]
fn the_ppid_is_referenced_nowhere_outside_the_comment_explaining_why() {
    let out = std::process::Command::new("grep")
        .args(["-rn", "--include=*.rs", "\\.ppid", "src/"])
        .output()
        .expect("grep runs");
    assert!(
        out.stdout.is_empty(),
        "something reads .ppid: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
```

- [ ] **Step 5: Run and commit**

Run: `cargo test --lib gateway::verify && cargo clippy --all-targets -- -D warnings`
Expected: PASS, 7 tests.

```bash
git add -A
git commit -m "$(cat <<'EOF'
Verify quotes for real, and drop the PPID at the boundary

Real full-chain verification through dcap-qvl. Absent or stale collateral
returns Unverified rather than Invalid, because a cold cache is our
failure and not the counterparty's, and it is never a pass.

dcap-qvl's VerifiedReport carries a PPID — a unique per-platform hardware
identifier — on every successful verification. A gateway built to stop a
relying party accumulating a dossier must not be the thing that writes one
down, so the PPID is dropped here and two grep tests enforce that it and
dangerous_verify_with_tcb_override appear nowhere in src/.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `LinkabilityMeter`, and what it refuses to do

**Files:**
- Create: `src/gateway/meter.rs`
- Modify: `src/gateway/mod.rs`

**Interfaces:**
- Consumes: `TcbConfig` (Task 4), `bls::octets` (existing, for injective encoding).
- Produces: `LinkabilityMeter::new(rotation: Duration, seed: u64) -> LinkabilityMeter`; `LinkabilityMeter::observe(&self, config: &TcbConfig) -> Observation`; `Observation { set_size: u64, total_sessions: u64, distinct_configs: usize, varying_attributes: Vec<String> }`; `LinkabilityMeter::rotate_if_due(&self)`.

**This is the design's central tension, resolved rather than disclosed.** A tool that warns a relying party about silently accumulating a profile of its counterparties must not accumulate that profile itself — and a store of per-session fingerprints would be a high-value target whose breach hands over exactly the correlation the design exists to prevent.

Two structures, and no third:

```rust
counts:    HashMap<[u8; 32], u64>,                    // H(salt ‖ fingerprint) → sessions
marginals: BTreeMap<String, HashMap<[u8; 32], u64>>,  // attribute → H(salt ‖ value) → count
```

Set size, effective set size and entropy come from the size distribution alone. "Which attributes are doing the deanonymizing" comes from the marginals. Neither needs to know *who* was where.

- [ ] **Step 1: Write the failing test**

Create `src/gateway/meter.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> TcbConfig {
        TcbConfig {
            attributes: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn meter() -> LinkabilityMeter {
        LinkabilityMeter::new(Duration::from_secs(3600), 7)
    }

    #[test]
    fn the_first_session_on_a_configuration_is_a_set_of_one() {
        let m = meter();
        let o = m.observe(&cfg(&[("tdx_module", "1.5.05")]));
        assert_eq!(o.set_size, 1);
        assert_eq!(o.total_sessions, 1);
        assert_eq!(o.distinct_configs, 1);
    }

    #[test]
    fn identical_configurations_grow_the_same_set() {
        let m = meter();
        let c = cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]);
        for expected in 1..=5 {
            assert_eq!(m.observe(&c).set_size, expected);
        }
        assert_eq!(m.observe(&c).distinct_configs, 1);
    }

    #[test]
    fn a_differing_attribute_starts_a_new_set() {
        let m = meter();
        m.observe(&cfg(&[("pce_svn", "13")]));
        let o = m.observe(&cfg(&[("pce_svn", "12")]));
        assert_eq!(o.set_size, 1, "a different configuration is a different set");
        assert_eq!(o.distinct_configs, 2);
        assert_eq!(o.total_sessions, 2);
    }

    #[test]
    fn attribute_order_does_not_create_a_new_set() {
        // TcbConfig is a BTreeMap so this holds by construction; pinned
        // because a switch to an insertion-ordered map would silently
        // fragment every set and overstate the leak.
        let m = meter();
        m.observe(&cfg(&[("a", "1"), ("b", "2")]));
        assert_eq!(m.observe(&cfg(&[("b", "2"), ("a", "1")])).distinct_configs, 1);
    }

    #[test]
    fn varying_attributes_are_named_and_constant_ones_are_not() {
        let m = meter();
        m.observe(&cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "13")]));
        let o = m.observe(&cfg(&[("tdx_module", "1.5.05"), ("pce_svn", "12")]));
        assert_eq!(o.varying_attributes, vec!["pce_svn".to_string()]);
    }

    /// The refusal, asserted rather than documented.
    ///
    /// This is the analogue of the pool's no-reuse invariant: the guarantee is
    /// that the store *cannot* answer "has this agent been here before", and a
    /// guarantee nothing tests is a comment.
    #[test]
    fn two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained() {
        let m = meter();
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        let after_one = m.snapshot_for_test();
        m.observe(&c);
        let after_two = m.snapshot_for_test();

        // The only difference is a count. Nothing distinguishes the sessions.
        assert_eq!(after_one.len(), after_two.len(), "no per-session entry was added");
        let (k1, v1) = after_one.iter().next().unwrap();
        assert_eq!(after_two.get(k1), Some(&(v1 + 1)));
    }

    #[test]
    fn the_stored_hash_does_not_reveal_the_configuration() {
        // Salted, so an operator holding the store cannot enumerate plausible
        // TCB configurations offline and recover which ones were seen.
        let a = LinkabilityMeter::new(Duration::from_secs(3600), 1);
        let b = LinkabilityMeter::new(Duration::from_secs(3600), 2);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        a.observe(&c);
        b.observe(&c);
        let (ka, _) = a.snapshot_for_test().into_iter().next().unwrap();
        let (kb, _) = b.snapshot_for_test().into_iter().next().unwrap();
        assert_ne!(ka, kb, "different salts must give different keys");
    }

    #[test]
    fn rotating_the_salt_ages_out_correlation() {
        let m = LinkabilityMeter::new(Duration::from_nanos(1), 7);
        let c = cfg(&[("tdx_module", "1.5.05")]);
        m.observe(&c);
        std::thread::sleep(Duration::from_millis(2));
        m.rotate_if_due();
        // History is gone: the same configuration is a fresh set of one.
        assert_eq!(m.observe(&c).set_size, 1);
    }

    #[test]
    fn an_empty_configuration_is_an_observation_not_a_panic() {
        assert_eq!(meter().observe(&cfg(&[])).set_size, 1);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib gateway::meter`
Expected: FAIL — `cannot find type LinkabilityMeter in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/gateway/meter.rs`:

```rust
use crate::bls::octets;
use crate::gateway::verify::TcbConfig;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, serde::Serialize)]
pub struct Observation {
    /// How many sessions have landed on this configuration since the last
    /// salt rotation.
    pub set_size: u64,
    pub total_sessions: u64,
    pub distinct_configs: usize,
    /// Attributes taking more than one value. Note the wording: varying is not
    /// the same as partitioning — some of these may split nothing another
    /// attribute does not already split.
    pub varying_attributes: Vec<String>,
}

struct Store {
    salt: [u8; 32],
    rotated: Instant,
    counts: HashMap<[u8; 32], u64>,
    marginals: BTreeMap<String, HashMap<[u8; 32], u64>>,
    total: u64,
}

/// Counts what a relying party is accumulating, without accumulating it.
///
/// Holds salted frequency counts and per-attribute marginals. There is **no**
/// session-to-fingerprint map and **no** joint distribution across
/// attributes, so the store cannot answer "has this agent been here before"
/// — which is the one question an operator will ask for, and the answer is
/// no. See `two_sessions_on_one_configuration_are_indistinguishable_in_what_is_retained`.
pub struct LinkabilityMeter {
    rotation: Duration,
    store: RwLock<Store>,
    seed: Mutex<u64>,
}

impl LinkabilityMeter {
    pub fn new(rotation: Duration, seed: u64) -> Self {
        LinkabilityMeter {
            rotation,
            store: RwLock::new(Store {
                salt: derive_salt(seed, 0),
                rotated: Instant::now(),
                counts: HashMap::new(),
                marginals: BTreeMap::new(),
                total: 0,
            }),
            seed: Mutex::new(seed),
        }
    }

    pub fn observe(&self, config: &TcbConfig) -> Observation {
        let mut s = self.store.write().expect("meter lock is never held across a panic");

        // Length-prefixed, so `{a: "b=c"}` cannot collide with
        // `{a: "b", c: ""}` — the same reasoning as the anonymity module's
        // fingerprint, and the reason the set sizes mean anything.
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(config.attributes.len() * 2);
        for (k, v) in &config.attributes {
            parts.push(k.as_bytes().to_vec());
            parts.push(v.as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let key = salted(&s.salt, &octets(&refs));

        let n = s.counts.entry(key).or_insert(0);
        *n += 1;
        let set_size = *n;
        s.total += 1;

        for (k, v) in &config.attributes {
            let vk = salted(&s.salt, v.as_bytes());
            *s.marginals.entry(k.clone()).or_default().entry(vk).or_insert(0) += 1;
        }

        Observation {
            set_size,
            total_sessions: s.total,
            distinct_configs: s.counts.len(),
            varying_attributes: s
                .marginals
                .iter()
                .filter(|(_, vals)| vals.len() > 1)
                .map(|(k, _)| k.clone())
                .collect(),
        }
    }

    pub fn rotate_if_due(&self) {
        let mut s = self.store.write().expect("meter lock is never held across a panic");
        if s.rotated.elapsed() < self.rotation {
            return;
        }
        let mut seed = self.seed.lock().expect("seed lock is never held across a panic");
        *seed = seed.wrapping_add(1);
        s.salt = derive_salt(*seed, s.total);
        s.counts.clear();
        s.marginals.clear();
        s.total = 0;
        s.rotated = Instant::now();
    }
}

fn derive_salt(seed: u64, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"occultation-gateway/meter-salt/v1");
    h.update(seed.to_be_bytes());
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}

fn salted(salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(data);
    h.finalize().into()
}
```

`snapshot_for_test()` is `#[cfg(test)]` and returns a clone of `counts`.

- [ ] **Step 4: Run and commit**

Run: `cargo test --lib gateway::meter`
Expected: PASS, 9 tests.

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the linkability meter, and the correlation it cannot perform

Salted frequency counts and per-attribute marginals. No
session-to-fingerprint map and no joint distribution, so a tool that warns
a relying party about accumulating a profile of its counterparties cannot
accumulate one itself, and a breach of the store hands over nothing.

The cost is real and accepted: it cannot answer "has this agent been here
before". Operators will ask. A test asserts two sessions on one
configuration are indistinguishable in what is retained, which is the
analogue of the pool's no-reuse invariant — a guarantee nothing tests is a
comment.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Findings, rendering and metrics

**Files:**
- Create: `src/gateway/finding.rs`
- Modify: `src/gateway/mod.rs`

**Interfaces:**
- Consumes: `QuoteVerdict` (4), `SessionBinding` (2), `Observation` (5).
- Produces: `Finding { verdict: QuoteVerdict, binding: SessionBinding, observation: Option<Observation> }`; `Finding::render(&self) -> String`; `Finding::to_json(&self) -> serde_json::Value`; `Metrics::new(registry: &mut Registry) -> Metrics`; `Metrics::record(&self, finding: &Finding)`.

Follows `occultation`'s existing report discipline: anything unverified says so on the line that states it, not in a footnote. Metric **labels must be low-cardinality** — verdict kind, platform, TCB status. Never the configuration, never a hash of it, never anything per-counterparty; a Prometheus label is a database, and this one would rebuild the dossier the meter refuses to keep.

- [ ] **Step 1: Write the failing test**

Create `src/gateway/finding.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn verified() -> QuoteVerdict {
        QuoteVerdict::Verified {
            platform: Platform::TdxV10,
            tcb_status: "UpToDate".into(),
            advisories: vec![],
            config: TcbConfig::for_test(&[("tdx_module", "1.5.05")]),
        }
    }

    fn obs(set: u64, total: u64) -> Observation {
        Observation {
            set_size: set,
            total_sessions: total,
            distinct_configs: 4,
            varying_attributes: vec!["microcode".into(), "pce_svn".into()],
        }
    }

    #[test]
    fn a_verified_finding_states_the_set_and_the_attributes() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Unbound { why: "header transport is replayable" },
            observation: Some(obs(3, 1847)),
        };
        let out = f.render();
        assert!(out.contains("VERIFIED"), "{out}");
        assert!(out.contains("3 of 1847"), "the set and the corpus, together: {out}");
        assert!(out.contains("microcode"), "{out}");
    }

    /// The gap between header transport and RA-TLS is a finding, not a
    /// footnote. If this line disappears an operator reads a verified quote
    /// as a bound one.
    #[test]
    fn unbound_transport_is_reported_on_the_finding() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Unbound { why: "a captured quote is reusable" },
            observation: Some(obs(3, 1847)),
        };
        assert!(f.render().contains("captured quote is reusable"));
    }

    #[test]
    fn a_bound_transport_makes_no_replay_claim() {
        let f = Finding { verdict: verified(), binding: SessionBinding::Bound, observation: Some(obs(3, 9)) };
        assert!(!f.render().to_lowercase().contains("replay"));
    }

    #[test]
    fn unverified_is_as_prominent_as_verified_and_says_why() {
        let f = Finding {
            verdict: QuoteVerdict::Unverified { why: "no collateral cached for FMSPC 00806f".into() },
            binding: SessionBinding::Unbound { why: "x" },
            observation: None,
        };
        let out = f.render();
        assert!(out.contains("UNVERIFIED"), "{out}");
        assert!(out.contains("no collateral cached"), "the reason must reach the reader: {out}");
    }

    #[test]
    fn an_unverified_finding_carries_no_anonymity_number() {
        // We did not verify the quote, so we have no trustworthy
        // configuration to partition on. Printing a set size here would be a
        // number with no provenance.
        let f = Finding {
            verdict: QuoteVerdict::Unverified { why: "PCS unreachable".into() },
            binding: SessionBinding::Bound,
            observation: None,
        };
        let out = f.render();
        assert!(!out.contains("anonymity set"), "{out}");
    }

    #[test]
    fn the_json_form_never_contains_the_ppid_or_a_config_hash() {
        let f = Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        };
        let j = serde_json::to_string(&f.to_json()).unwrap().to_lowercase();
        assert!(!j.contains("ppid"));
        assert!(!j.contains("fingerprint"), "a per-counterparty key must not reach the wire");
    }

    #[test]
    fn metric_labels_are_low_cardinality() {
        // A Prometheus label is a database. Anything per-counterparty here
        // rebuilds the dossier the meter refuses to keep.
        let mut reg = Registry::default();
        let m = Metrics::new(&mut reg);
        m.record(&Finding {
            verdict: verified(),
            binding: SessionBinding::Bound,
            observation: Some(obs(3, 1847)),
        });
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &reg).unwrap();
        assert!(buf.contains("tdx_v10"));
        assert!(!buf.contains("1.5.05"), "a TCB value reached a label: {buf}");
    }
}
```

- [ ] **Step 2: Run to verify it fails, then implement**

Run: `cargo test --lib gateway::finding` → FAIL, `cannot find type Finding`.

`Finding::render` produces the shape from the spec:

```
agent authorized ✓   quote: VERIFIED (TDX 1.0, TCB UpToDate)
  anonymity set     3 of 1847 sessions
  varying           tee_tcb_svn, xfam
  session binding   NONE — a captured quote is reusable
```

> **AMENDMENT (pre-flight before Task 5, coordinator).** The sample above
> originally read `varying  microcode, pce_svn`. **Neither attribute exists.**
> Task 4 established against the `dcap-qvl` source that there is no
> `pce_svn` and no `microcode` on any report type, and that reaching the PCK
> extension's PCE SVN would require an API that hands over *two* hardware
> identifiers. The attributes the verifier actually produces are:
>
> - **TDX 1.0** — `fmspc`, `tee_tcb_svn`, `mr_seam`, `mr_signer_seam`,
>   `seam_attributes`, `td_attributes`, `xfam`
> - **TDX 1.5** — the above plus `tee_tcb_svn2`
> - **SGX** — `fmspc`, `cpu_svn`, `attributes`, `misc_select`, `isv_prod_id`,
>   `isv_svn`
>
> Task 5's meter is key-agnostic — it hashes whatever `BTreeMap` it is handed,
> so its synthetic test fixtures may keep any key names they like. **Task 6 and
> Task 8 are not**: a rendered finding and a README are operator-facing, and
> naming an attribute the gateway can never report is the same defect as a
> README describing a caveat the code no longer prints. Any illustrative
> attribute name in a docstring, a sample rendering, or the README must come
> from the lists above.
>
> Note also that `occultation`'s existing README and `docs/STANDARD-MAP.md`
> describe the TCB fingerprint in the desk study's terms — "TDX module version,
> CPU SVN, PCE SVN, microcode revision, QE identity, PCS chain." That prose
> describes the *concept* and predates any measurement. Task 8 should not
> silently contradict it; where the gateway's actual attribute set differs,
> say so rather than quietly substituting one list for the other.

with `UNVERIFIED (<why>)` or `INVALID (<reason>)` replacing the first line's parenthetical, and the anonymity block omitted entirely when `observation` is `None`. `Metrics` registers three counters — `gateway_requests_total{verdict}`, `gateway_quotes_total{platform,tcb_status}`, `gateway_unverified_total{why_kind}` — where `why_kind` is a small enum-derived string (`collateral_absent`, `collateral_stale`, `pcs_unreachable`, `unsupported_platform`), never the free-text reason.

- [ ] **Step 3: Run and commit**

Run: `cargo test --lib gateway::finding`
Expected: PASS, 7 tests.

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add findings, rendering and low-cardinality metrics

Anything unverified says so on the line that states it, and an unverified
finding carries no anonymity number — we did not verify the quote, so we
have no trustworthy configuration to partition on, and printing a set size
would be a number with no provenance.

Metric labels are verdict, platform and TCB status only. A Prometheus
label is a database, and a per-counterparty one would rebuild the dossier
the meter refuses to keep.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Wire it together, and prove fail-open under fault injection

**Files:**
- Create: `tests/gateway_failopen.rs`
- Modify: `src/gateway/proxy.rs`, `src/bin/gateway.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: `Pipeline { source, verifier, meter, metrics, sink }` and `Hooks::from_pipeline(Arc<Pipeline>) -> Hooks`; a background task calling `meter.rotate_if_due()` and `cache.refresh()`.

Collateral refresh runs **off the request path**, in a background task keyed by the FMSPCs seen. A request whose FMSPC is not yet cached gets `Unverified` and triggers a refresh for next time; it never waits.

- [ ] **Step 1: Write the fault-injection test**

Create `tests/gateway_failopen.rs`:

```rust
/// Fail-open is the gateway's one hard guarantee: it sits in front of
/// somebody else's revenue API. Each case injects a fault at a different
/// stage and asserts the request still reaches the upstream unchanged.
#[tokio::test]
async fn every_stage_fails_open() {
    for fault in [
        Fault::SourcePanics,
        Fault::SourceErrors,
        Fault::VerifierPanics,
        Fault::VerifierHangsThenErrors,
        Fault::MeterPanics,
        Fault::MeterLockPoisoned,
        Fault::SinkPanics,
        Fault::MetricsPanic,
    ] {
        let upstream = spawn_echo_upstream().await;
        let gw = spawn_gateway_with_fault(upstream, fault).await;
        let body = get(&gw, "/still-works").await
            .unwrap_or_else(|e| panic!("{fault:?} took down the proxy: {e}"));
        assert_eq!(body, "echo:/still-works", "{fault:?} altered the response");
    }
}

#[tokio::test]
async fn a_poisoned_meter_lock_does_not_wedge_every_later_request() {
    // A panic while holding the lock must not turn one bad request into a
    // permanently broken gateway.
    let upstream = spawn_echo_upstream().await;
    let gw = spawn_gateway_with_fault(upstream, Fault::MeterLockPoisoned).await;
    for _ in 0..5 {
        assert_eq!(get(&gw, "/after").await.unwrap(), "echo:/after");
    }
}

#[tokio::test]
async fn an_unreachable_pccs_does_not_slow_the_request_path() {
    // Collateral refresh is off the request path. If it were not, this would
    // block for the connect timeout.
    let upstream = spawn_echo_upstream().await;
    let gw = spawn_gateway_with_pccs(upstream, "http://127.0.0.1:1").await;
    let t = std::time::Instant::now();
    let _ = get_with_attestation(&gw, "/x", &[0u8; 64]).await.unwrap();
    assert!(t.elapsed() < Duration::from_millis(500), "took {:?}", t.elapsed());
}
```

`Fault::MeterLockPoisoned` is induced by a hook that panics while the meter's write lock is held. The implementation must therefore not use `.expect()` on lock acquisition in the request path — replace those with a match that treats a poisoned lock as "skip the measurement, record a finding," and update Task 5's `expect` messages accordingly.

- [ ] **Step 2: Run to verify it fails, then implement `Pipeline`**

Run: `cargo test --test gateway_failopen` → FAIL, `cannot find type Fault`.

`Hooks::from_pipeline` wraps the whole measure path in `catch_unwind`, already present from Task 1. Within it: extract → verify → observe → render → record. Any `Err` or `None` short-circuits to a finding describing what was skipped.

- [ ] **Step 3: Run and commit**

Run: `cargo test --test gateway_failopen && cargo test`
Expected: PASS, 3 tests; whole suite green.

```bash
git add -A
git commit -m "$(cat <<'EOF'
Wire the pipeline in, and prove every stage fails open

Eight injected faults — a panicking source, verifier, meter, sink and
metrics, an erroring source, a hanging verifier and a poisoned lock — each
assert the request still reaches the upstream unchanged. A poisoned meter
lock additionally must not wedge every later request, so lock acquisition
on the request path treats poisoning as "skip the measurement" rather than
expect().

Collateral refresh runs off the request path: an uncached FMSPC returns
Unverified and schedules a refresh rather than waiting on the PCS.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: The hostile agent, the README, and CI

**Files:**
- Create: `tests/gateway_hostile.rs`, `tests/fixtures/README.md`
- Modify: `README.md`, `.github/workflows/ci.yml`, `docs/STANDARD-MAP.md`, `src/bin/gateway.rs`, `src/gateway/mod.rs`

**Interfaces:**
- Consumes: everything.
- Produces: the shipped artifact.

In the spirit of `transit`'s hostile server: an agent that misbehaves in every way the gateway must survive.

> **AMENDMENT (added after Task 7's review, coordinator).** Two things this
> task must now also do. Neither was in the plan and both were found by review
> rather than by execution.
>
> **A. Serve the metrics.** Task 6 registers `gateway_requests_total`,
> `gateway_quotes_total` and `gateway_unverified_total`, and Task 7 records to
> them — but **the plan specifies a scrape endpoint in no task**, so they are
> write-only for the whole phase and no task owned fixing that. Task 6's entire
> label-cardinality argument and Task 7's `WhyKind` reasoning are currently
> unobservable. Add a `/metrics` endpoint on **its own listener**, bound
> separately from the proxy and defaulting to loopback.
>
> It must not be reachable through the forwarding path: the proxy forwards
> *every* request unconditionally, so a `/metrics` route on the proxy port
> would either be swallowed by the forward or, worse, carve out a path the
> upstream can no longer serve. A separate listener is the only shape that
> preserves "every request forwards." Assert both halves by test — that the
> metrics listener answers, and that `GET /metrics` on the *proxy* port still
> reaches the upstream unchanged.
>
> **B. Inherit five guards from Task 4, not two.** The CI copy of the PPID
> guards must carry all three greps (`\.ppid`, `VerifiedReport`, **and** the
> report's type name), the lexical formatter ban **using `?}` rather than
> `:?`**, and the grep exit-status check. A copy carrying `:?` reproduces
> exactly the `{:#?}` hole that Task 4 spent a second fix round closing, and a
> copy without the exit-status check passes vacuously whenever grep cannot
> search — which is what a wrong working directory in CI looks like.
>
> Task 4's review also left one guard open that this task should close, and it
> is a single line: the lexical ban is scoped to `verify.rs` via
> `include_str!`, so **another file could call `dcap_qvl::verify::verify` and
> format the result** — naming no banned token, in a file the ban cannot see.
> Today that call appears only at `verify.rs:323` and `:536`. A fourth grep
> asserting exactly that closes it.

- [ ] **Step 1: Write the hostile agent tests**

Create `tests/gateway_hostile.rs`, covering: a **replayed** quote (same bytes twice — must verify twice and the finding must say the transport is unbound, because with header transport the gateway genuinely cannot tell); a **malformed** quote (`Invalid`, no panic); **no** attestation (`Observation` absent, finding records it); a quote for an **unsupported platform** (`Unverified`, not `Invalid`); an **oversized** header (refused before decode); a header that is **valid base64 of random bytes** (`Invalid`); and **10,000 distinct synthetic configurations** asserting the meter's memory stays bounded and no single request exceeds a latency ceiling.

The replay case carries a comment stating plainly that detecting it requires RA-TLS and is phase 1b — the test pins today's honest behaviour rather than pretending.

- [ ] **Step 2: Add the CI job**

Append to `.github/workflows/ci.yml`'s `rust` job:

```yaml
      - name: gateway forbids the dangerous override
        run: |
          ! grep -rn "dangerous_verify_with_tcb_override" src/
      - name: gateway never reads the PPID
        run: |
          ! grep -rn --include=*.rs '\.ppid' src/
```

These duplicate the in-crate tests deliberately: they run even if someone marks those tests `#[ignore]`.

- [ ] **Step 3: Write the README section**

Add a `## The gateway` section to `README.md`, before `## How this maps to the standard`, stating: what it does, that it **never rejects** in phase 1, that quote verification is **real** via `dcap-qvl`, that `Unverified` means *we could not check* and is never a pass, that the meter **cannot** answer "has this agent been here before" and why, and that header transport does **not** bind the quote to the session so replay is undetectable until RA-TLS lands.

Update `docs/STANDARD-MAP.md`'s C5.1.4 row to note the gateway measures this against live traffic rather than a synthetic fixture.

- [ ] **Step 4: Run everything and commit**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the hostile agent fixture, CI guards and the gateway README

A replayed quote verifies twice and the finding says so, because with
header transport the gateway genuinely cannot tell — the test pins today's
honest behaviour rather than pretending RA-TLS is here.

The two CI greps duplicate in-crate tests on purpose: they run even if
someone marks those tests ignored.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage.** Every section of the design maps to a task: the fail-open proxy (1, 7), pluggable `AttestationSource` with `HeaderSource` and `session_binding` (2), collateral fetched off the request path and cached (3), real full-chain verification with the two prohibitions (4), the meter and its refusals (5), findings and metrics (6), the hostile agent fixture and fail-open fault injection (7, 8), README and CI (8). The spec's phase-1 scope line — "header transport, quote verification, the meter, findings and metrics, the hostile agent fixture, and a README that says exactly what it does and does not verify" — is covered item for item.

**Deliberately excluded, per the spec's "What phase 1 is not":** `--enforce`, `RaTlsSource`, credential verification, BBS+. The `AttestationSource` trait exists in Task 2 so phase 1b adds an implementation rather than reshaping anything.

**One thing the plan adds that the spec did not have.** The PPID constraint. `dcap_qvl::VerifiedReport` carries `ppid: Vec<u8>`, a unique per-platform hardware identifier, and the spec was written before the probe found it. It is now a global constraint, a boundary rule in Task 4, two grep tests, a JSON assertion in Task 6, and a CI guard in Task 8. **This is the single most important thing in the plan**: the gateway is handed a hardware serial on every successful verification, and writing it down once would be worse than everything the meter is designed to prevent.

**Type consistency.** `TcbConfig`, `QuoteVerdict`, `Platform`, `SessionBinding`, `RawAttestation`, `SourceError`, `CacheLookup`, `CollateralError`, `Observation`, `Finding`, `Metrics`, `Hooks`, `Pipeline`, `GatewayConfig` are each defined once and referenced with matching signatures. `TcbConfig.attributes` is a `BTreeMap<String, String>` from Task 4 through Task 5's fingerprint, which is what makes attribute order irrelevant. `Observation` is `Option` in `Finding` because an unverified quote yields no trustworthy configuration.

**Two places a reviewer should push hardest.** Whether any path lets the PPID or a per-counterparty key reach a log, a metric label or the JSON; and whether the meter can be made to answer "seen before" by any combination of its public API. Both are the same question the pool's no-reuse invariant asked, and both are answered by construction rather than by policy.

**One known gap, stated rather than hidden.** Task 4's tests need a real TDX quote fixture. If none is available, the plan instructs marking the full-verification tests `#[ignore]` with a comment naming what is missing — **not** fabricating a quote that appears to verify. Obtaining a real fixture is the first thing to chase, because without it the verifier's happy path is unexercised.

---

## Plan complete

Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks, fast iteration.

**2. Inline Execution** — tasks executed in this session with batch checkpoints.
