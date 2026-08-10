# transit guard claims Implementation Plan — T3

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the shipped `transit guard` to emit an evidence claim per intercepted action to `ephemeris`, supplying exactly the caller-supplied column of that tool's contract — `action_id`, `agent_id`, `initiating_user`, `interception_point`, `target_resource`, `canonical_snapshot_hash`, `path_summary_hash`, `policy_bundle_hash`, `verdict`, `nonce` — over a Unix domain socket, blocking the forward until the before-record is durably acknowledged. The guard already computes most of a verdict's justification and then discards it. This plan stops the discarding.

**Architecture:** Three new modules in the existing `transit` crate. `src/snapshot.rs` holds `ActionSnapshot` and `Evaluation`, constructed **inside `decide` before the C1/C3/C4 checks** so that every request — including every rejection — yields a canonicalizable snapshot and a tagged digest. `src/policy.rs` holds the `policy_bundle_hash` derivation: a canonical projection of only the `GuardConfig` fields that produce a verdict, with route `Option<bool>` overrides normalized to their effective value, plus a `decide_semantics` integer pinned by a golden-decision corpus. `src/evidence.rs` holds the `Claim`, the extension claims, and a `ClaimSink` trait whose default-build implementation is a no-op and whose `evidence`-feature implementation is a blocking newline-delimited-JSON client over `std::os::unix::net::UnixStream`. `decide`'s public signature does not change; a new `decide_with_snapshot` returns the pair, and `decide` is its `.0`.

**Tech Stack:** Rust 2021, and **no new dependencies**. Canonicalization is `transit::jcs`, the strict decoder is `transit::json`, the digest is `sha2` (already present), the socket is `std::os::unix::net`, the envelope is `serde_json` (already present). See the "no crate dependency on `ephemeris`" note under Global Constraints — this is a correction to the design, not an optimization.

**Not in this plan, deliberately:** `path_summary_hash` (fork 4 — shipped unfilled, and the guard says so on every startup), `agbom_digest` (T4), signing and chaining (`ephemeris`'s column), RA-TLS peer identity as the source of `agent_id` (fork 8's real answer, needing its own spec), and the `poc-audit` cross-check (needs released tags of two other repositories; it is step 7 of the design's build order and the last task here only prepares for it).

---

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**. All of this lands in `/Users/jimschwoebel/Desktop/transit`.
- `cargo clippy --all-targets -- -D warnings` must be clean, **in both feature configurations**. Warnings are errors.
- Library errors use `thiserror`; the binary uses `anyhow`.
- **No panics on malformed input.** This crate eats hostile input by design. Everything read from a socket — including the acknowledgement `ephemeris` sends back — parses through a fallible path. No `unwrap`, `expect`, or slice indexing on it.
- **The existing suite must not need editing.** `cargo test` and `cargo test --features evidence` must both pass with **zero changes to any existing test file**. This constrains three signatures: `decide(&GuardConfig, &Request) -> Decision` keeps its shape, `serve(&GuardConfig)` keeps its shape, and **`GuardConfig` gains no field** — `tests/guard_wire.rs:76` and `tests/guard_blocks_the_attacks.rs:13` construct it as a struct literal, so a new field breaks them under the feature as surely as without it. The `[evidence]` table is therefore parsed *alongside* `GuardConfig`, never into it.
- **Opt-in twice: a cargo feature and a config section.** Without `--features evidence`, a config file containing `[evidence]` is **refused at parse time** rather than silently ignored — you asked for evidence and this binary cannot provide it, which is a fail-closed condition, not a no-op.
- **Fail-closed, and `503` never `502`.** `502` means "upstream unreachable" and is a lie about which component failed. An evidence failure that blocks a forward is `503`. Asserted by test in Task 10.
- **Refuse to start if the socket is absent.** A guard that starts without its recorder and then `503`s every request has already failed; failing at startup is louder and cheaper. The check is a real `connect`, not an `exists`.
- **Nothing under `[evidence]` is overridable from the environment**, for the reason `apply_env_overrides` (`src/guard.rs:725`) already gives for `[enforce]`: a rule an environment variable can switch off is a rule anything that can set one can switch off.
- **`agent_id` and `initiating_user` come from static config and from nowhere else.** Never a request header. Fork 8. Asserted by a test that sends `X-Agent-Id` and observes the emitted claim ignore it.
- **`X-Transit-Digest` stays byte-identical.** It is an established contract and P02's result rests on it. Pinned against literal hex in Task 2, and that test runs in both feature configurations.
- **Any field participating in a value's identity is load-bearing.** `policy_bundle_hash` and `canonical_snapshot_hash` are both identity derivations. Each is written down explicitly and tested **both ways**: semantically identical inputs hash **equal**, and inputs differing in any one contributing field hash **unequal**. Four of `parallax`'s five criticals were failures of exactly this rule; see `docs/parallax-outcomes.md` in the roadmap repository.
- **Time is never read from the system clock on any path a test reaches.** The guard has no injected clock, and rather than add one, no record carries a timestamp. `ephemeris` stamps `iat`. See Task 9 for what this costs against the design's "the same snapshot, plus the dispatch time".
- **Unix only.** `src/evidence.rs`'s socket client is `#[cfg(unix)]`. The `evidence` feature on a non-unix host fails to build, which is the correct answer for a component whose transport is a Unix domain socket.
- **No crate dependency on `ephemeris`.** The design's risk section says "`transit` gains a dependency on `ephemeris`". It cannot: `ephemeris`'s own `Cargo.toml` depends on `transit` by git rev, so the reverse edge is a cycle Cargo will refuse. The dependency is on the **wire protocol only**, which this plan defines in Task 8 and which `ephemeris`'s Phase 2 listener must agree to.
- Every commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- Every test runs **offline**: no network, no credentials, no `ephemeris` binary. The stub is a `UnixListener` in a temp directory.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml` | adds `[features] evidence = []`. No new dependencies |
| `src/lib.rs` | declares `snapshot`, `policy`, `evidence` |
| `src/snapshot.rs` | `ActionSnapshot`, `Evaluation`, `Verdict`, `Modification`, `ResponseSnapshot` |
| `src/policy.rs` | `DECIDE_SEMANTICS`, the bundle projection, `bundle_hash` |
| `src/evidence.rs` | `Claim`, `Extensions`, `ClaimSink`, `NoEvidence`, `Counters`, and (feature-gated) `EvidenceConfig` + `UdsSink` |
| `src/guard.rs` | `decide_inner` / `decide_with_snapshot`, `serve_with`, `handle_one`'s sink parameter, `banner`, `parse_evidence` |
| `src/bin/transit.rs` | wires `[evidence]` into `guard serve` |
| `tests/stub_ephemeris/mod.rs` | a UDS stub with four behaviours: ack, refuse, silent, dead |
| `tests/guard_snapshot.rs` | every request shape yields a canonicalizing snapshot |
| `tests/digest_wire_contract.rs` | `X-Transit-Digest` pinned against literal hex |
| `tests/policy_bundle.rs` | bundle identity, both directions |
| `tests/decide_semantics.rs` | the golden-decision corpus |
| `tests/fixtures/decide-corpus-v1.json` | the corpus itself, named for the semantics version in force |
| `tests/guard_verdict.rs` | `ALLOW` / `MODIFY` / `DENY` and `transit_condition` |
| `tests/claim_shape.rs` | the ten fields, the extensions, and `agent_id`'s source |
| `tests/evidence_config.rs` | the feature gate and the config section |
| `tests/write_before_forward.rs` | asserted at the upstream: no ack, no effect |
| `tests/three_records.rs` | three records, one action ID, the honest middle label |
| `tests/evidence_failure_modes.rs` | `503` not `502`, refuse to start, refused claims, loss counters |

---

## Task 1: `ActionSnapshot`, constructed before the checks

**Files:**
- Create: `src/snapshot.rs`
- Modify: `src/lib.rs`, `src/guard.rs`
- Test: `tests/guard_snapshot.rs`

**Interfaces:**
- Consumes: `crate::hostile::Request`, `crate::json::{Json, Num, Utf16, utf16}`, `crate::jcs::{canonicalize, digest, JcsError}`, `crate::guard::{sanitize, headers_named, normalize_target}`.
- Produces: `snapshot::ActionSnapshot` with `new(&Request) -> ActionSnapshot`, `set_target(&mut self, &str, &str)`, `set_body(&mut self, Json)`, `to_json(&self) -> Json`, `canonical_hash(&self) -> Result<String, JcsError>`, `body_hash(&self) -> Option<Result<String, JcsError>>`, `target_resource(&self, upstream: &str) -> String`; `snapshot::{Verdict, Evaluation, Modification}`; `guard::decide_with_snapshot(&GuardConfig, &Request) -> (Decision, Evaluation)`.
- `guard::decide` keeps its exact existing signature and becomes `decide_with_snapshot(cfg, req).0`.

This is the design's build-order step 1 and the fix for its finding 3, "nothing is computed on a rejection". Every `reject(…)` in `decide` today returns before `src/guard.rs:642`, so a `DENY` record — the record an auditor most wants — has no snapshot under the current control flow.

Two members the design's table does not have, and each closes a real ambiguity:

- **`body_present`.** The design gives `body` = `null` for a request whose payload did not parse, and `body_wire_sha256` "always". For a bodiless `GET` those two are `null` and the SHA-256 of the empty string — so "there was no body" and "there was a body and it did not parse" are distinguished only by a reader recognising `e3b0c442…` as a constant. That is exactly the casual-identity defect this suite exists to avoid. An explicit boolean names it.
- **`method_wire`.** The design says the snapshot's `method` is the raw method sanitized "on a request that never got that far". But `decide` uppercases on its very first line (`src/guard.rs:516`) and the `405` check reads the uppercased value, so the raw method is already gone by the time a rejection is decided. `method` is always the sanitized uppercased value; `method_wire` appears only when it differs, matching how `target_wire` is handled.

`headers_evaluated` holds an **array of values per name, in wire order**, not a single string. A duplicated `Content-Type` is itself a `400`, so multiplicity is verdict-relevant and a scalar member could not represent it. Only `content-type`, `idempotency-key` and `if-match` appear: `connection` is read by `decide`, but it shapes the forwarded header list rather than the verdict, and putting it in would make the snapshot commit to something no rule consulted.

- [ ] **Step 1: Write the failing test**

`tests/guard_snapshot.rs`:

```rust
//! Every request produces a snapshot, and the un-canonicalizable case is
//! named rather than smuggled.

use transit::guard::{decide_with_snapshot, Decision, Enforcement, GuardConfig, RouteRule};
use transit::hostile::Request;
use transit::snapshot::Verdict;

fn cfg() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:8080".into(),
        upstream: "http://ledger.internal:8787".into(),
        enforce: Enforcement::default(),
        route: Vec::new(),
    }
}

fn req(method: &str, target: &str, body: &str, headers: &[(&str, &str)]) -> Request {
    Request {
        method: method.into(),
        path: target.into(),
        headers: headers
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        body: body.into(),
    }
}

fn ok() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Idempotency-Key", "k1"),
        ("If-Match", "0"),
        ("Content-Type", "application/json"),
    ]
}

#[test]
fn every_request_shape_yields_a_tagged_canonical_digest() {
    // Mutation this kills: the `(String::new(), String::new())` of
    // src/guard.rs:643, and every early `reject` return that precedes it.
    // `canonical_snapshot_hash` is required and matches
    // `^(sha-256|...):[0-9a-f]{64,128}$`; the empty string is not a value it
    // can take, and a rejection that produced no digest at all would leave the
    // field unfillable on exactly the records an auditor most wants.
    let cases: Vec<(&str, Request)> = vec![
        ("bodiless GET", req("GET", "/v1/thing", "", &[])),
        ("405 unknown method", req("FROB", "/v1/thing", "", &[])),
        ("400 fragment target", req("GET", "/v1/thing#z", "", &[])),
        (
            "413 oversized body",
            req(
                "POST",
                "/v1/t",
                &format!(r#"{{"a":"{}"}}"#, "x".repeat(2 * 1024 * 1024)),
                &ok(),
            ),
        ),
        (
            "C2 unparseable payload",
            req("POST", "/v1/t", r#"{"a":1,"a":2}"#, &ok()),
        ),
        (
            "428 C3 no idempotency key",
            req("POST", "/v1/t", r#"{"a":1}"#, &[("If-Match", "0")]),
        ),
        (
            "200 forward",
            req("POST", "/v1/t", r#"{"a":1}"#, &ok()),
        ),
    ];

    for (name, r) in cases {
        let (_, eval) = decide_with_snapshot(&cfg(), &r);
        let h = eval
            .snapshot
            .canonical_hash()
            .unwrap_or_else(|e| panic!("{name}: snapshot did not canonicalize: {e}"));
        assert!(h.starts_with("sha-256:"), "{name}: untagged digest {h}");
        assert_eq!(h.len(), 8 + 64, "{name}: {h}");
        assert!(
            h[8..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{name}: {h}"
        );
    }
}

#[test]
fn the_uncanonicalizable_body_is_named_not_smuggled() {
    // Mutation this kills: one field carrying two meanings, which is the
    // C7.7 defect turned inward. A C2 rejection and a valid body must be
    // distinguishable from the record alone.
    let (_, bad) = decide_with_snapshot(&cfg(), &req("POST", "/v1/t", r#"{"a":1,"a":2}"#, &ok()));
    let j = bad.snapshot.to_json();
    assert_eq!(j.get("body"), Some(&transit::json::Json::Null));
    assert_eq!(j.get("body_present"), Some(&transit::json::Json::Bool(true)));
    let wire = j.get("body_wire_sha256").and_then(|v| v.as_string()).unwrap();
    assert!(wire.starts_with("sha-256:"));

    let (_, good) = decide_with_snapshot(&cfg(), &req("POST", "/v1/t", r#"{"a":1}"#, &ok()));
    let j = good.snapshot.to_json();
    assert_ne!(j.get("body"), Some(&transit::json::Json::Null));
    assert_eq!(j.get("body_present"), Some(&transit::json::Json::Bool(true)));
}

#[test]
fn a_bodiless_request_is_not_confused_with_one_that_failed_to_parse() {
    // Mutation this kills: dropping `body_present` and relying on a reader
    // recognising the SHA-256 of the empty string. Both requests have
    // `body: null`; only `body_present` tells them apart.
    let (_, none) = decide_with_snapshot(&cfg(), &req("GET", "/v1/thing", "", &[]));
    let (_, unparsed) =
        decide_with_snapshot(&cfg(), &req("POST", "/v1/t", r#"{"a":1,"a":2}"#, &ok()));
    assert_eq!(
        none.snapshot.to_json().get("body_present"),
        Some(&transit::json::Json::Bool(false))
    );
    assert_eq!(
        unparsed.snapshot.to_json().get("body_present"),
        Some(&transit::json::Json::Bool(true))
    );
    assert_ne!(
        none.snapshot.canonical_hash().unwrap(),
        unparsed.snapshot.canonical_hash().unwrap()
    );
}

#[test]
fn a_rejection_before_normalization_carries_the_wire_target_and_no_resource() {
    // Mutation this kills: inventing a `target_resource` for a target that
    // never parsed, which names a resource the request never addressed.
    let (_, eval) = decide_with_snapshot(&cfg(), &req("GET", "/v1/thing#z", "", &[]));
    let j = eval.snapshot.to_json();
    assert_eq!(j.get("target"), Some(&transit::json::Json::Null));
    assert_eq!(
        j.get("target_wire").and_then(|v| v.as_string()).as_deref(),
        Some("/v1/thing#z")
    );
    assert_eq!(
        eval.snapshot.target_resource("http://ledger.internal:8787"),
        "urn:transit:unresolved-target"
    );
}

#[test]
fn the_target_resource_is_upstream_qualified_and_excludes_the_query() {
    // Fork 2. The path alone names nothing an auditor can locate; the query
    // is a selector rather than a resource and is already committed to inside
    // the snapshot, so C7.1.4(b)'s binding still covers it.
    let (_, eval) = decide_with_snapshot(&cfg(), &req("GET", "/v1/thing?a=1&b=2", "", &[]));
    assert_eq!(
        eval.snapshot.target_resource("http://ledger.internal:8787/"),
        "http://ledger.internal:8787/v1/thing"
    );
    let j = eval.snapshot.to_json();
    assert_eq!(
        j.get("query").and_then(|v| v.as_string()).as_deref(),
        Some("a=1&b=2")
    );
}

#[test]
fn headers_evaluated_shows_the_absence_that_explains_the_verdict() {
    // Mutation this kills: recording a denial as unexplainable. A 428 C3 is
    // only re-derivable if the record shows there was no Idempotency-Key,
    // and an absent member says that where an empty string would not.
    let (d, eval) = decide_with_snapshot(
        &cfg(),
        &req("POST", "/v1/t", r#"{"a":1}"#, &[("If-Match", "0"), ("Content-Type", "application/json")]),
    );
    assert!(matches!(d, Decision::Reject { status: 428, .. }));
    assert_eq!(eval.verdict, Verdict::Deny);
    let he = eval.snapshot.to_json().get("headers_evaluated").cloned().unwrap();
    assert!(he.get("idempotency-key").is_none(), "{he:?}");
    assert!(he.get("if-match").is_some(), "{he:?}");
}

#[test]
fn a_duplicated_header_is_representable_because_multiplicity_is_the_verdict() {
    // Mutation this kills: a scalar `headers_evaluated` member. Two
    // Content-Type headers are themselves a 400, so a snapshot that could
    // only hold one value could not explain the refusal it accompanies.
    let (d, eval) = decide_with_snapshot(
        &cfg(),
        &req(
            "POST",
            "/v1/t",
            r#"{"a":1}"#,
            &[
                ("Idempotency-Key", "k"),
                ("If-Match", "0"),
                ("Content-Type", "application/json"),
                ("Content-Type", "text/plain"),
            ],
        ),
    );
    assert!(matches!(d, Decision::Reject { status: 400, .. }));
    let he = eval.snapshot.to_json().get("headers_evaluated").cloned().unwrap();
    let ct = he.get("content-type").cloned().unwrap();
    match ct {
        transit::json::Json::Array(vs) => assert_eq!(vs.len(), 2, "{vs:?}"),
        other => panic!("content-type should be an array of values, got {other:?}"),
    }
}

#[test]
fn the_snapshot_commits_to_the_target_so_two_endpoints_do_not_collide() {
    // Mutation this kills: reverting `canonical_snapshot_hash` to the
    // body-only digest of src/jcs.rs:26, under which two requests posting the
    // same body to different endpoints have the same digest.
    let body = r#"{"amount":100,"to":"acct-9"}"#;
    let (_, a) = decide_with_snapshot(&cfg(), &req("POST", "/v1/transfer", body, &ok()));
    let (_, b) = decide_with_snapshot(&cfg(), &req("POST", "/v1/refund", body, &ok()));
    assert_ne!(
        a.snapshot.canonical_hash().unwrap(),
        b.snapshot.canonical_hash().unwrap()
    );
    // And the method, likewise.
    let (_, c) = decide_with_snapshot(&cfg(), &req("PUT", "/v1/transfer", body, &ok()));
    assert_ne!(
        a.snapshot.canonical_hash().unwrap(),
        c.snapshot.canonical_hash().unwrap()
    );
}

#[test]
fn the_snapshot_hash_is_the_canonical_form_of_the_same_content_written_by_hand() {
    // The meaningful version of "canonical". Comparing our own serializer
    // against itself proves nothing; this compares it against the canonical
    // form of the same content with its members shuffled, which is what a
    // second implementation would hand us.
    let (_, eval) = decide_with_snapshot(
        &cfg(),
        &req("GET", "/v1/thing?a=1", "", &[("If-Match", "\"e1\"")]),
    );
    let shuffled = r#"{
        "query": "a=1",
        "method": "GET",
        "headers_evaluated": { "if-match": ["\"e1\""] },
        "body_wire_sha256": "sha-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "body_present": false,
        "body": null,
        "target": "/v1/thing"
    }"#;
    let parsed = transit::json::parse_strict(shuffled).unwrap();
    assert_eq!(
        transit::jcs::canonicalize(&eval.snapshot.to_json()).unwrap(),
        transit::jcs::canonicalize(&parsed).unwrap()
    );
}

#[test]
fn a_relaxed_route_still_produces_a_snapshot() {
    // The forward path with a route rule attached, so the snapshot is not
    // only exercised on the no-route default.
    let mut c = cfg();
    c.route.push(RouteRule {
        method: "POST".into(),
        path_prefix: "/v1/search".into(),
        require_idempotency_key: Some(false),
        require_state_precondition: Some(false),
        require_parameters: Vec::new(),
    });
    let (d, eval) = decide_with_snapshot(
        &c,
        &req("POST", "/v1/search", r#"{"q":"x"}"#, &[("Content-Type", "application/json")]),
    );
    assert!(matches!(d, Decision::Forward(_)));
    assert!(eval.snapshot.canonical_hash().unwrap().starts_with("sha-256:"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test guard_snapshot`
Expected: FAIL — `transit::snapshot` does not exist and `decide_with_snapshot` is not defined.

- [ ] **Step 3: Write `src/snapshot.rs`**

Add `pub mod snapshot;` to `src/lib.rs`, after `pub mod probe;`.

`src/snapshot.rs`:

```rust
//! The object a verdict was reached over, and the verdict's own shape.
//!
//! `ActionSnapshot` exists because `jcs::digest` over the request *body* —
//! which is what `X-Transit-Digest` carries — commits to none of the method,
//! the target, or the headers the guard's rules turned on. Two requests
//! posting the same body to different endpoints share that digest. The
//! evidence schema's `canonical_snapshot_hash` is "digest of the canonical
//! snapshot the policy actually evaluated", and this is that snapshot.
//!
//! It is built as a `Json` value **the guard constructs**, never as a
//! reinterpretation of what arrived, so it always canonicalizes: the part of
//! a request that may not canonicalize — the wire body — is represented by a
//! digest of its bytes inside a member that is itself canonical.

use crate::corpus::Condition;
use crate::jcs::{canonicalize, digest, JcsError};
use crate::json::{utf16, Json};
use sha2::{Digest, Sha256};

/// The digest tag every value in an evidence record carries (C7.7.3, and the
/// schema's `digest` pattern). `jcs::digest` returns 64 bare hex characters;
/// leaving them bare is the kind of defect discovered at integration time by
/// a validator three layers from the code that caused it.
pub const TAG: &str = "sha-256:";

fn tagged(hex_digits: &str) -> String {
    format!("{TAG}{hex_digits}")
}

/// What the guard reports when the request target never parsed. A URN rather
/// than a path, so it cannot be mistaken for a resource the upstream serves,
/// and so it is greppable in a log of millions.
pub const UNRESOLVED_TARGET: &str = "urn:transit:unresolved-target";

/// The verdict enum is four wide and this guard reaches three.
///
/// `ESCALATE` is unreachable and there is deliberately no variant for it: the
/// guard has no human-in-the-loop path and no mechanism to suspend an action
/// pending approval, and a variant that no code path constructs is a claim
/// the tool cannot stand behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Modify,
    Deny,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Modify => "MODIFY",
            Verdict::Deny => "DENY",
        }
    }
}

/// A difference between the proposed action and the dispatched one that is
/// **not** a mandated semantics-preserving transformation.
///
/// Fork 5's rule: `ALLOW` only when the difference is confined to RFC 8785
/// canonicalization of a body that parsed to the same JSON value, and RFC
/// 9110 §7.6.1 hop-by-hop removal. Everything else is `MODIFY`. Neither of
/// those two produces a `Modification`, so an empty list is exactly `ALLOW`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modification {
    /// `/v1/tra%6Esfer` in, `/v1/transfer` out. A change to the target the
    /// client named.
    TargetRenormalized { wire: String, dispatched: String },
    /// A header that RFC 9110 §7.6.1 does not license an intermediary to
    /// remove was removed anyway. In practice: a client-supplied digest
    /// header, whatever `digest_header` is configured to be named.
    HeaderDropped { name: String },
    /// `Content-Type` reached the upstream as something other than what the
    /// client sent — a `+json` suffix type, a charset parameter, or a casing.
    ContentTypeRewritten { wire: String, dispatched: String },
}

impl Modification {
    /// The string form that goes into the record's `modifications` extension
    /// claim. Bounded and control-stripped values, because both halves of a
    /// rewrite are attacker-chosen.
    pub fn render(&self) -> String {
        match self {
            Modification::TargetRenormalized { wire, dispatched } => {
                format!("target_renormalized: {wire} -> {dispatched}")
            }
            Modification::HeaderDropped { name } => format!("header_dropped: {name}"),
            Modification::ContentTypeRewritten { wire, dispatched } => {
                format!("content_type_rewritten: {wire} -> {dispatched}")
            }
        }
    }
}

/// The snapshot, plus everything about the decision a record needs and
/// `Decision` does not carry.
///
/// `decide` stays a pure function of `(&GuardConfig, &Request)`; it gains an
/// output rather than a side effect, and `handle_one` does the emitting.
#[derive(Clone, Debug)]
pub struct Evaluation {
    pub snapshot: ActionSnapshot,
    pub verdict: Verdict,
    pub modifications: Vec<Modification>,
    /// transit's own C1–C4 finding, so it is machine-readable inside the
    /// record rather than only in a log line.
    pub condition: Option<Condition>,
}

/// The object the policy evaluated.
#[derive(Clone, Debug)]
pub struct ActionSnapshot {
    /// The uppercased method, sanitized. Always present: `decide` uppercases
    /// on its first line, so by the time any rejection is decided the raw
    /// method is already gone.
    method: String,
    /// The sanitized wire method, present only when it differs from `method`.
    method_wire: String,
    /// `normalize_target`'s decoded path, or `None` when it refused.
    target: Option<String>,
    /// The sanitized raw target, emitted only when `target` is `None`.
    target_wire: String,
    /// The query string as received. `""` on a request that never got far
    /// enough to have one separated out.
    query: String,
    /// The parsed value, or `None` when there was no body or it did not parse.
    body: Option<Json>,
    /// Whether bytes arrived at all, by `decide`'s own definition
    /// (`!req.body.trim().is_empty()`). Without this, "no body" and "a body
    /// that did not parse" are told apart only by recognising the SHA-256 of
    /// the empty string as a constant.
    body_present: bool,
    /// SHA-256 of the wire body bytes, always, tagged.
    body_wire_sha256: String,
    /// The names and values of the headers the rules read, in wire order.
    /// An array per name because a duplicated header is itself a verdict.
    headers_evaluated: Vec<(String, Vec<String>)>,
}

/// The headers `decide`'s rules read. `connection` is deliberately absent: it
/// shapes the forwarded header list, not the verdict, and committing to it
/// would make the snapshot claim a rule consulted something no rule did.
const EVALUATED_HEADERS: &[&str] = &["content-type", "idempotency-key", "if-match"];

impl ActionSnapshot {
    /// Everything computable before a single rule has run.
    pub fn new(req: &crate::hostile::Request) -> Self {
        let method = crate::guard::sanitize(&req.method.to_ascii_uppercase());
        let method_wire = crate::guard::sanitize(&req.method);
        let mut headers_evaluated = Vec::new();
        for name in EVALUATED_HEADERS {
            let values: Vec<String> = crate::guard::headers_named(req, name)
                .map(crate::guard::sanitize)
                .collect();
            if !values.is_empty() {
                headers_evaluated.push(((*name).to_string(), values));
            }
        }
        Self {
            method,
            method_wire,
            target: None,
            target_wire: crate::guard::sanitize(&req.path),
            query: String::new(),
            body: None,
            body_present: !req.body.trim().is_empty(),
            body_wire_sha256: tagged(&hex::encode(Sha256::digest(req.body.as_bytes()))),
            headers_evaluated,
        }
    }

    pub fn set_target(&mut self, path: &str, query: &str) {
        self.target = Some(path.to_string());
        self.query = query.to_string();
    }

    pub fn set_body(&mut self, v: Json) {
        self.body = Some(v);
    }

    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    pub fn body_present(&self) -> bool {
        self.body_present
    }

    /// Fork 2: the upstream-qualified path, query excluded.
    ///
    /// Note the consequence, which is correct for this field and
    /// disqualifying for `policy_bundle_hash`: `upstream` is overridable by
    /// `TRANSIT_UPSTREAM` (`src/guard.rs:729`), so `target_resource` is
    /// deployment-dependent by design.
    pub fn target_resource(&self, upstream: &str) -> String {
        match &self.target {
            Some(p) => format!("{}{}", upstream.trim_end_matches('/'), p),
            None => UNRESOLVED_TARGET.to_string(),
        }
    }

    /// The canonicalizable object. Members are emitted unsorted here; RFC
    /// 8785 sorts them by UTF-16 code unit inside `jcs::canonicalize`, so the
    /// order written below is documentation rather than mechanism.
    pub fn to_json(&self) -> Json {
        let s = |x: &str| Json::String(utf16(x));
        let mut m: Vec<(crate::json::Utf16, Json)> = vec![
            (utf16("method"), s(&self.method)),
            (
                utf16("target"),
                match &self.target {
                    Some(p) => s(p),
                    None => Json::Null,
                },
            ),
            (utf16("query"), s(&self.query)),
            (
                utf16("body"),
                match &self.body {
                    Some(v) => v.clone(),
                    None => Json::Null,
                },
            ),
            (utf16("body_present"), Json::Bool(self.body_present)),
            (utf16("body_wire_sha256"), s(&self.body_wire_sha256)),
        ];
        if self.target.is_none() {
            m.push((utf16("target_wire"), s(&self.target_wire)));
        }
        if self.method_wire != self.method {
            m.push((utf16("method_wire"), s(&self.method_wire)));
        }
        if !self.headers_evaluated.is_empty() {
            let members: Vec<(crate::json::Utf16, Json)> = self
                .headers_evaluated
                .iter()
                .map(|(k, vs)| {
                    (
                        utf16(k),
                        Json::Array(vs.iter().map(|v| s(v)).collect::<Vec<_>>()),
                    )
                })
                .collect();
            m.push((utf16("headers_evaluated"), Json::Object(members)));
        }
        Json::Object(m)
    }

    /// `canonical_snapshot_hash`.
    ///
    /// This can only fail on a value the guard itself built from a
    /// `parse_strict`-clean body, so in practice it does not — but it returns
    /// a `Result` rather than swallowing one, because the fail-closed answer
    /// to "the snapshot has no canonical form" is a 503 and not a record with
    /// a guessed digest in it.
    pub fn canonical_hash(&self) -> Result<String, JcsError> {
        Ok(tagged(&digest(&self.to_json())?))
    }

    /// Fork 1's second half: the body digest, carried alongside as an
    /// additional claim so nothing is lost and the wire contract stays.
    ///
    /// This is the same value `X-Transit-Digest` carries, tagged. The cost is
    /// a record with two digests in it that a careless verifier may compare
    /// to each other; that cost is documented rather than prevented, because
    /// each digest has a consumer — `poc-audit`'s `field/canonical` recomputes
    /// the payload digest, and the record's own field must commit to more.
    pub fn body_hash(&self) -> Option<Result<String, JcsError>> {
        self.body.as_ref().map(|v| digest(v).map(|d| tagged(&d)))
    }

    /// The canonical form, for tests and diagnostics.
    pub fn canonical(&self) -> Result<String, JcsError> {
        canonicalize(&self.to_json())
    }
}
```

- [ ] **Step 4: Restructure `decide` in `src/guard.rs`**

Three mechanical changes first.

Make two helpers visible to `snapshot.rs`. Change `fn sanitize(s: &str) -> String` (`src/guard.rs:279`) to `pub(crate) fn sanitize`, and `fn headers_named<'a>(…)` (`src/guard.rs:464`) to `pub(crate) fn headers_named`.

Add the import at the top of `src/guard.rs`, beside the existing `use crate::jcs::{canonicalize, digest};`:

```rust
use crate::snapshot::{ActionSnapshot, Evaluation, Modification, Verdict};
```

Add the denial helper immediately after `fn reject(…)`:

```rust
/// Pair a rejection with the snapshot as far as the request got.
///
/// Every `reject(…)` site in `decide_inner` returns through here, which is
/// the whole of the fix for "nothing is computed on a rejection". A site that
/// returned a bare `Decision` would compile, and would silently reintroduce
/// the defect, so there is deliberately no other way out of the function.
fn denied(snapshot: ActionSnapshot, d: Decision) -> (Decision, Evaluation) {
    let condition = match &d {
        Decision::Reject { condition, .. } => *condition,
        Decision::Forward(_) => None,
    };
    let eval = Evaluation {
        snapshot,
        verdict: Verdict::Deny,
        modifications: Vec::new(),
        condition,
    };
    (d, eval)
}
```

Now replace the whole of `pub fn decide` (`src/guard.rs:514`–`695`) with the following. The rule ordering, every status code, every condition label and every header-filtering predicate are unchanged — this is the same function with a snapshot threaded through it, and `tests/decide_semantics.rs` in Task 4 exists to prove that claim rather than assert it.

```rust
/// The whole policy and the whole forward plan, as a pure function.
///
/// Unchanged signature. `decide` is the shipped contract and ~30 existing
/// tests call it; the snapshot arrives through `decide_with_snapshot`.
pub fn decide(cfg: &GuardConfig, req: &Request) -> Decision {
    decide_inner(cfg, req).0
}

/// `decide`, plus the object it decided over.
///
/// The `ActionSnapshot` is constructed **before** the C1/C3/C4 rule checks
/// and populated as far as the request got, so every request — including
/// every rejection, including the C2 rejections whose bytes have no canonical
/// form by construction — yields a snapshot that canonicalizes.
pub fn decide_with_snapshot(cfg: &GuardConfig, req: &Request) -> (Decision, Evaluation) {
    decide_inner(cfg, req)
}

fn decide_inner(cfg: &GuardConfig, req: &Request) -> (Decision, Evaluation) {
    let mut snap = ActionSnapshot::new(req);

    let method = req.method.to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return denied(
            snap,
            reject(
                405,
                None,
                format!("method {method} is not allowed through this guard"),
            ),
        );
    }

    let (path, query) = match normalize_target(&req.path) {
        Ok(v) => v,
        Err(why) => return denied(snap, reject(400, None, why)),
    };
    snap.set_target(&path, &query);

    let rule = cfg.route.iter().find(|r| route_matches(r, &method, &path));
    let want_key = rule
        .and_then(|r| r.require_idempotency_key)
        .unwrap_or(cfg.enforce.require_idempotency_key);
    let want_pin = rule
        .and_then(|r| r.require_state_precondition)
        .unwrap_or(cfg.enforce.require_state_precondition);
    let want_params: &[RequiredParam] =
        rule.map(|r| r.require_parameters.as_slice()).unwrap_or(&[]);

    if req.body.len() > cfg.enforce.max_body_bytes {
        return denied(
            snap,
            reject(
                413,
                None,
                format!(
                    "body is {} bytes, over the {}-byte limit",
                    req.body.len(),
                    cfg.enforce.max_body_bytes
                ),
            ),
        );
    }

    let has_body = !req.body.trim().is_empty();
    if has_body && matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return denied(
            snap,
            reject(400, None, format!("{method} carrying a body is refused")),
        );
    }

    let content_type = match single_header(req, "content-type") {
        Ok(v) => v,
        Err(()) => return denied(snap, reject(400, None, "more than one Content-Type header")),
    };

    // C2 — strict ingestion, before anything else looks at the request.
    let parsed = if !has_body {
        None
    } else {
        match content_type {
            Some(ct) if is_json_media_type(ct) => {}
            _ => {
                return denied(
                    snap,
                    reject(
                        415,
                        None,
                        "body is not application/json; this guard forwards only what it can canonicalize",
                    ),
                )
            }
        }
        match parse_strict(&req.body) {
            Ok(v) => {
                // Set before the C1 check, so a C1 denial's record shows the
                // body whose parameters were found wanting.
                snap.set_body(v.clone());
                Some(v)
            }
            Err(e) => return denied(snap, reject(400, Some(Condition::C2), e.to_string())),
        }
    };

    // C1 — the parameters the endpoint would otherwise fill from its own state.
    if let Some(value) = &parsed {
        let missing: Vec<&str> = want_params
            .iter()
            .filter(|p| match value.get(p.name()) {
                Some(v) => !p.param_type().matches(v),
                None => true,
            })
            .map(|p| p.name())
            .collect();
        if !missing.is_empty() {
            return denied(
                snap,
                reject(
                    422,
                    Some(Condition::C1),
                    format!(
                        "required parameters absent or the wrong type: {}",
                        missing.join(", ")
                    ),
                ),
            );
        }
    } else if !want_params.is_empty() && MUTATING_METHODS.contains(&method.as_str()) {
        return denied(
            snap,
            reject(
                422,
                Some(Condition::C1),
                "a body is required and none was sent",
            ),
        );
    }

    // C3 — only where a retry could not be told from a replay.
    if want_key && !IDEMPOTENT_METHODS.contains(&method.as_str()) {
        match single_header(req, "idempotency-key") {
            Err(()) => {
                return denied(
                    snap,
                    reject(400, None, "more than one Idempotency-Key header"),
                )
            }
            Ok(None) => {
                return denied(
                    snap,
                    reject(
                        428,
                        Some(Condition::C3),
                        format!("{method} is not idempotent and carries no Idempotency-Key"),
                    ),
                )
            }
            Ok(Some(_)) => {}
        }
    }

    // C4 — on every method that changes state.
    if want_pin
        && MUTATING_METHODS.contains(&method.as_str())
        && single_header(req, "if-match").unwrap_or(None).is_none()
    {
        return denied(
            snap,
            reject(
                428,
                Some(Condition::C4),
                "no If-Match precondition; the effect could depend on state that moved after signing",
            ),
        );
    }

    let (body, dg) = match &parsed {
        None => (String::new(), String::new()),
        Some(v) => match (canonicalize(v), digest(v)) {
            (Ok(b), Ok(d)) => (b, d),
            (Err(e), _) | (_, Err(e)) => {
                return denied(snap, reject(400, Some(Condition::C2), e.to_string()))
            }
        },
    };

    // Build the header list the upstream will see. Hop-by-hop headers, every
    // header named by `Connection`, and any client-supplied digest header are
    // all dropped before ours is added.
    let connection_named: Vec<String> = headers_named(req, "connection")
        .flat_map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let digest_name = cfg.enforce.digest_header.clone();
    let mut headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&lk.as_str())
                && !connection_named.contains(&lk)
                && !lk.eq_ignore_ascii_case("content-type")
                && !lk.eq_ignore_ascii_case("x-transit-digest")
                && digest_name
                    .as_ref()
                    .map(|d| !lk.eq_ignore_ascii_case(d))
                    .unwrap_or(true)
        })
        .cloned()
        .collect();
    if !body.is_empty() {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    if let (Some(name), false) = (digest_name, dg.is_empty()) {
        headers.push((name, dg.clone()));
    }

    let f = Forward {
        method,
        path,
        query,
        headers,
        body,
        digest: dg,
    };
    let modifications = modifications_of(req, &f, &connection_named, content_type);
    let verdict = if modifications.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Modify
    };
    let eval = Evaluation {
        snapshot: snap,
        verdict,
        modifications,
        condition: None,
    };
    (Decision::Forward(f), eval)
}
```

`modifications_of` is written in Task 5. Until then, add a stub that returns an empty vector so this task compiles and its tests run — and **write the stub with a `todo` marker in its name so it cannot be mistaken for the finished rule**:

```rust
/// Filled in by Task 5. Returning an empty vector here makes every forward
/// `ALLOW`, which is one of the two collapses fork 5 rejects; `tests/guard_verdict.rs`
/// is what proves it stopped being true.
fn modifications_of(
    _req: &Request,
    _f: &Forward,
    _connection_named: &[String],
    _content_type: Option<&str>,
) -> Vec<Modification> {
    Vec::new()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test guard_snapshot && cargo test`
Expected: `guard_snapshot` PASS, 10 tests. The **whole existing suite** PASS with no edits to any existing test file — that is the load-bearing half of this step. If any existing test needed changing, the restructure changed behaviour and the change is a bug in this task, not in the test.

- [ ] **Step 6: Commit**

```bash
cd /Users/jimschwoebel/Desktop/transit
git checkout -b evidence-claims
git add -A
git commit -m "Construct the action snapshot before the checks, so a rejection is evidenced too

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `X-Transit-Digest` is byte-identical, pinned against literal hex

**Files:**
- Modify: `Cargo.toml`
- Test: `tests/digest_wire_contract.rs`

**Interfaces:**
- Consumes: `guard::{decide, Decision, Forward}`.
- Produces: the `evidence` cargo feature. No other code. This task exists to make one contract impossible to break silently.

Fork 1 resolved as **both**: the constructed snapshot in `canonical_snapshot_hash`, the body digest alongside as `snapshot_body_sha256`, and `X-Transit-Digest` byte-identical to what ships today. The existing test `the_digest_is_the_sha256_of_the_canonical_body_not_a_constant` (`src/guard.rs:1302`) re-derives the digest through `jcs::digest`, which catches a constant but not a *changed definition* — if someone repointed both the header and `jcs::digest` at the snapshot, that test would still pass and P02's published result would quietly stop matching the shipped tool. These are literal values, computed once, committed.

- [ ] **Step 1: Declare the feature**

Add to `Cargo.toml`, after the `[dependencies]` block:

```toml
[features]
default = []
# Claim emission to `ephemeris`. Opt-in so the default build and the existing
# 100+ guard tests are untouched, following `parallax-attest`'s pattern for
# its TEE paths. It adds **no dependencies**: the transport is
# `std::os::unix::net`, the canonicalizer is this crate's own `jcs`, and a
# cargo dependency on `ephemeris` is impossible anyway — that crate depends on
# this one by git rev, so the reverse edge is a cycle.
evidence = []
```

- [ ] **Step 2: Write the failing test**

`tests/digest_wire_contract.rs`:

```rust
//! `X-Transit-Digest` is an established wire contract and P02's result rests
//! on it. These are literal SHA-256 values over the RFC 8785 canonical form of
//! each body, not recomputations — a test that recomputes the digest through
//! the same function the implementation uses cannot detect the implementation
//! changing what it digests.
//!
//! Mutation every case here kills: repointing `X-Transit-Digest` at the
//! action snapshot rather than the body, which is exactly what fork 1's
//! option B would have done and exactly what P02's published measurement
//! would then no longer describe.

use transit::guard::{decide, Decision, Enforcement, GuardConfig};
use transit::hostile::Request;

fn cfg() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:8080".into(),
        upstream: "http://127.0.0.1:8787".into(),
        enforce: Enforcement::default(),
        route: Vec::new(),
    }
}

fn forwarded(method: &str, target: &str, body: &str) -> transit::guard::Forward {
    let req = Request {
        method: method.into(),
        path: target.into(),
        headers: vec![
            ("Idempotency-Key".into(), "k1".into()),
            ("If-Match".into(), "0".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: body.into(),
    };
    match decide(&cfg(), &req) {
        Decision::Forward(f) => f,
        other => panic!("expected Forward, got {other:?}"),
    }
}

/// (wire body, canonical form, SHA-256 of the canonical form).
///
/// Regenerate a row only by deciding to change the wire contract, and only
/// with P02 re-run. `printf '%s' '<canonical>' | shasum -a 256`.
const PINNED: &[(&str, &str, &str)] = &[
    (
        r#"{ "to":"acct-9" , "amount":100 }"#,
        r#"{"amount":100,"to":"acct-9"}"#,
        "86de271c773aa0ab2933c24e860c3a70b54fa0a26616ef11acbb1d4f30190781",
    ),
    (
        r#"{"a":1}"#,
        r#"{"a":1}"#,
        "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862",
    ),
    (
        r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#,
        r#"{"amount":100,"fee_tier":"standard","to":"acct-9"}"#,
        "59bc4da1da7e15ebfebaacb8b4d6b3d42fee5405c845bab647d5c33fc99add8c",
    ),
    (
        r#"{ "q" : "x" }"#,
        r#"{"q":"x"}"#,
        "a69fbbcf7209c6f659a75067c9fa03037c2ae23f55a6f854d5994209129bbbf6",
    ),
];

#[test]
fn the_forwarded_digest_is_byte_identical_to_the_shipped_contract() {
    for (wire, canonical, want) in PINNED {
        let f = forwarded("POST", "/v1/transfer", wire);
        assert_eq!(&f.body, canonical, "canonical body drifted for {wire}");
        assert_eq!(&f.digest, want, "X-Transit-Digest drifted for {wire}");
    }
}

#[test]
fn the_header_carries_the_same_bytes_as_the_forward_plan() {
    for (wire, _, want) in PINNED {
        let f = forwarded("POST", "/v1/transfer", wire);
        let (_, v) = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest"))
            .unwrap_or_else(|| panic!("no digest header for {wire}"));
        assert_eq!(v, want, "the header and the plan disagree for {wire}");
    }
}

#[test]
fn the_digest_is_untagged_on_the_wire_and_tagged_only_in_the_record() {
    // Two audiences, two formats, and the seam between them is a place a
    // well-meaning cleanup would "fix" one of them. The wire value is 64 bare
    // hex characters because that is what shipped; the record's value carries
    // `sha-256:` because C7.7.3 and the schema's `digest` pattern require it.
    let f = forwarded("POST", "/v1/transfer", r#"{"a":1}"#);
    assert!(!f.digest.contains(':'), "the wire digest gained a tag: {}", f.digest);
    assert_eq!(f.digest.len(), 64);
}

#[test]
fn a_bodiless_request_still_carries_no_digest_header() {
    // The other half of the shipped behaviour. `dg` is empty for a bodiless
    // request and the header is not added; the record fixes that for the
    // record's own field, and must not fix it here.
    let req = Request {
        method: "GET".into(),
        path: "/v1/thing".into(),
        headers: Vec::new(),
        body: String::new(),
    };
    let f = match decide(&cfg(), &req) {
        Decision::Forward(f) => f,
        other => panic!("expected Forward, got {other:?}"),
    };
    assert!(f.digest.is_empty());
    assert!(!f
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest")));
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test --test digest_wire_contract && cargo test --features evidence --test digest_wire_contract`
Expected: PASS in **both** configurations, 4 tests each. This test is expected to pass immediately — it pins behaviour Task 1 was required not to change. If it fails, Task 1 broke the wire contract and must be fixed before anything else proceeds.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Pin X-Transit-Digest against literal hex, in both feature configurations

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `policy_bundle_hash`, and the normalization that keeps it honest

**Files:**
- Create: `src/policy.rs`
- Modify: `src/lib.rs`
- Test: `tests/policy_bundle.rs`

**Interfaces:**
- Consumes: `guard::{GuardConfig, RouteRule, RequiredParam, ParamType}`, `json::{Json, Num, utf16}`, `jcs::{digest, JcsError}`.
- Produces: `policy::DECIDE_SEMANTICS: u64`, `policy::bundle(&GuardConfig) -> Json`, `policy::bundle_hash(&GuardConfig) -> Result<String, JcsError>`.

The schema: *"Digest of the exact policy that produced the verdict (C4.2). Without it a verdict cannot be re-derived."* `docs/parallax-outcomes.md` records that four of five criticals in that tool traced to one root cause — a field participating in a value's identity specified casually — and both of them produced confident wrong answers rather than errors. This field is the same shape and gets the same discipline: the derivation is written down, and tested in both directions.

**What is in the bundle**, from reading `decide`: `route[]`, `enforce.require_idempotency_key`, `enforce.require_state_precondition`, `enforce.max_body_bytes`, `enforce.strict_ingestion`. **What is not:** `enforce.max_response_bytes` (response direction, after the verdict), `enforce.max_concurrent_requests` (shed in `serve` before `decide` runs), `enforce.digest_header` (shapes the forwarded request, not the decision), `listen` and `upstream` (deployment coordinates, and `TRANSIT_UPSTREAM`-overridable at `src/guard.rs:729`). Putting `listen` and `upstream` in would make the policy hash change when a container moves to a different port — the "12h vs 720m" defect with the sign flipped.

- [ ] **Step 1: Write the failing test**

`tests/policy_bundle.rs`:

```rust
//! Bundle identity, both directions. Every case here is a place where two
//! configs `decide` treats identically would otherwise hash differently, or
//! two configs it treats differently would otherwise hash the same.

use transit::guard::{decide, parse_config, Decision, GuardConfig};
use transit::hostile::Request;
use transit::policy::{bundle, bundle_hash, DECIDE_SEMANTICS};

fn cfg(text: &str) -> GuardConfig {
    parse_config(text).unwrap_or_else(|e| panic!("config did not parse: {e}\n{text}"))
}

fn h(text: &str) -> String {
    bundle_hash(&cfg(text)).expect("the bundle canonicalizes")
}

/// Written the terse way an operator actually writes it.
const TERSE: &str = r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"

[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
"#;

/// The same policy, written out in full, on a different machine, with every
/// default made explicit, every override spelled rather than inherited, the
/// parameters in the other order and the path in the other case.
const VERBOSE: &str = r#"
listen = "0.0.0.0:9999"
upstream = "http://elsewhere.internal:1"

[enforce]
strict_ingestion = true
require_idempotency_key = true
require_state_precondition = true
max_body_bytes = 1048576
max_response_bytes = 999
max_concurrent_requests = 9
digest_header = "X-Something-Else"

[[route]]
method = "POST"
path_prefix = "/V1/T"
require_idempotency_key = true
require_state_precondition = true
require_parameters = [{ name = "amount", type = "number" }, { name = "to", type = "string" }]
"#;

#[test]
fn two_spellings_of_one_policy_hash_equal() {
    // The direction that actually catches the parallax defect. Method case,
    // path_prefix trailing slash and case, `"to"` versus `{name,type}`,
    // ordering within `require_parameters`, omitted-versus-explicit
    // `[enforce]` defaults, and `None`-versus-`Some(true)` route overrides
    // resolved against an identical global — six normalizations, one hash.
    //
    // Mutation this kills: hashing the config file bytes, or hashing route
    // overrides as written. Either makes two operators expressing one policy
    // get two bundles, which is `parallax`'s defect reproduced exactly.
    assert_eq!(h(TERSE), h(VERBOSE));
}

#[test]
fn a_route_override_that_resolves_the_same_way_hashes_the_same() {
    // Fork 3, isolated. `None` with a global of `false`, and `Some(false)`,
    // produce identical decisions for every request.
    let a = r#"
listen = "l"
upstream = "u"
[enforce]
require_idempotency_key = false
[[route]]
method = "POST"
path_prefix = "/v1/t"
"#;
    let b = r#"
listen = "l"
upstream = "u"
[enforce]
require_idempotency_key = false
[[route]]
method = "POST"
path_prefix = "/v1/t"
require_idempotency_key = false
"#;
    assert_eq!(h(a), h(b));
}

#[test]
fn every_contributing_field_changes_the_hash() {
    // The other half of the identity rule, and the half that stops
    // `two_spellings_of_one_policy_hash_equal` from being satisfied by a
    // constant.
    let base = h(TERSE);
    let mutations: &[(&str, &str)] = &[
        (
            "max_body_bytes",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[enforce]
max_body_bytes = 2048
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
        (
            "global require_idempotency_key",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[enforce]
require_idempotency_key = false
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
        (
            "global require_state_precondition",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[enforce]
require_state_precondition = false
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
        (
            "route method",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "put"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
        (
            "route path_prefix",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/other"
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
        (
            "a parameter's name",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["from", { name = "amount", type = "number" }]
"#,
        ),
        (
            "a parameter's type",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "string" }]
"#,
        ),
        (
            "an added parameter",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }, "fee_tier"]
"#,
        ),
        (
            "an added route",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_parameters = ["to", { name = "amount", type = "number" }]
[[route]]
method = "post"
path_prefix = "/v1/u"
"#,
        ),
        (
            "an effective route override",
            r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[[route]]
method = "post"
path_prefix = "/v1/t/"
require_idempotency_key = false
require_parameters = ["to", { name = "amount", type = "number" }]
"#,
        ),
    ];
    for (what, text) in mutations {
        assert_ne!(h(text), base, "changing {what} did not change the bundle");
    }
}

#[test]
fn deployment_coordinates_are_not_policy() {
    // Mutation this kills: the bundle absorbing a field that does not produce
    // a verdict, so moving a container to a different published port reports
    // a policy change and an auditor chases a diff that is not there.
    let base = h(TERSE);
    for (what, text) in [
        (
            "listen",
            TERSE.replace("127.0.0.1:8080", "0.0.0.0:9090"),
        ),
        (
            "upstream",
            TERSE.replace("http://127.0.0.1:8787", "http://ledger.internal:80"),
        ),
    ] {
        assert_eq!(h(&text), base, "changing {what} changed the bundle");
    }
    for (what, extra) in [
        ("max_response_bytes", "max_response_bytes = 12345"),
        ("max_concurrent_requests", "max_concurrent_requests = 3"),
        ("digest_header", r#"digest_header = "X-Other""#),
    ] {
        let text = format!(
            "listen = \"127.0.0.1:8080\"\nupstream = \"http://127.0.0.1:8787\"\n\
             [enforce]\n{extra}\n\
             [[route]]\nmethod = \"post\"\npath_prefix = \"/v1/t/\"\n\
             require_parameters = [\"to\", {{ name = \"amount\", type = \"number\" }}]\n"
        );
        assert_eq!(h(&text), base, "changing {what} changed the bundle");
    }
}

#[test]
fn route_order_is_load_bearing_in_the_hash_and_in_the_decision() {
    // `cfg.route.iter().find(..)` takes the *first* matching rule, so two
    // rules that both match a path resolve by position. The lesson from
    // parallax is not "position is never identity" — it is "know which", and
    // getting it wrong in either direction is a confident wrong answer.
    //
    // Mutation this kills: sorting `route[]` for stability. It would make the
    // bundle claim two genuinely different policies are one.
    let first_wins = r#"
listen = "l"
upstream = "u"
[[route]]
method = "POST"
path_prefix = "/v1"
require_idempotency_key = false
[[route]]
method = "POST"
path_prefix = "/v1/transfer"
require_idempotency_key = true
"#;
    let second_wins = r#"
listen = "l"
upstream = "u"
[[route]]
method = "POST"
path_prefix = "/v1/transfer"
require_idempotency_key = true
[[route]]
method = "POST"
path_prefix = "/v1"
require_idempotency_key = false
"#;
    assert_ne!(h(first_wins), h(second_wins));

    // And the two really do decide differently, so the hash is tracking
    // something real rather than merely tracking the file.
    let r = Request {
        method: "POST".into(),
        path: "/v1/transfer".into(),
        headers: vec![
            ("If-Match".into(), "0".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: r#"{"a":1}"#.into(),
    };
    assert!(matches!(decide(&cfg(first_wins), &r), Decision::Forward(_)));
    assert!(matches!(
        decide(&cfg(second_wins), &r),
        Decision::Reject { status: 428, .. }
    ));
}

#[test]
fn the_bundle_carries_the_semantics_version_and_the_hash_moves_with_it() {
    // A bundle over configuration alone is not sufficient to re-derive a
    // verdict, and this is not hypothetical: `transit`'s own fix rounds are
    // the proof. The pre-fix guard forwarded `/v1/search/../transfer` and
    // matched no route rule against `/v1/tra%6Esfer` — same TOML, different
    // verdict, different code.
    let b = bundle(&cfg(TERSE));
    assert_eq!(
        b.get("decide_semantics").and_then(|v| v.as_f64()),
        Some(DECIDE_SEMANTICS as f64)
    );
}

#[test]
fn the_bundle_hash_is_tagged_and_stable() {
    let a = h(TERSE);
    assert!(a.starts_with("sha-256:"), "{a}");
    assert_eq!(a.len(), 8 + 64);
    assert_eq!(a, h(TERSE), "the same config hashed twice differed");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test policy_bundle`
Expected: FAIL — `transit::policy` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod policy;` to `src/lib.rs`.

`src/policy.rs`:

```rust
//! `policy_bundle_hash`: a stable identity for the policy that produced a
//! verdict — which means the config **and the code that reads it**.

use crate::guard::{GuardConfig, ParamType, RequiredParam, RouteRule};
use crate::jcs::{digest, JcsError};
use crate::json::{utf16, Json, Num, Utf16};

/// The version of `decide`'s behaviour this build implements.
///
/// Bumping an integer by hand is exactly the kind of discipline that rots, so
/// it is pinned by a golden-decision corpus: `tests/fixtures/decide-corpus-v{N}.json`
/// is looked up **by this constant**, so a change to `decide`'s behaviour
/// fails the corpus test, and the only way to make it pass is to write a new
/// corpus file at a new version and bump this — leaving the constant alone
/// keeps loading the old file, which still fails. The test is the mechanism;
/// this integer is where the mechanism writes its answer. See Task 4.
pub const DECIDE_SEMANTICS: u64 = 1;

fn s(v: &str) -> Json {
    Json::String(utf16(v))
}

fn n(v: u64) -> Json {
    Json::Number(Num::Int(v as i128))
}

fn obj(members: Vec<(&str, Json)>) -> Json {
    let m: Vec<(Utf16, Json)> = members.into_iter().map(|(k, v)| (utf16(k), v)).collect();
    Json::Object(m)
}

fn param_type_name(t: ParamType) -> &'static str {
    match t {
        ParamType::String => "string",
        ParamType::Number => "number",
        ParamType::Bool => "bool",
        ParamType::Array => "array",
        ParamType::Object => "object",
    }
}

/// Always the `{name, type}` form. `RequiredParam::param_type()` defaults
/// `Name` to `String`, so `"to"` and `{name="to", type="string"}` produce
/// identical decisions and must produce identical bundles.
fn normalized_param(p: &RequiredParam) -> Json {
    obj(vec![
        ("name", s(p.name())),
        ("type", s(param_type_name(p.param_type()))),
    ])
}

/// One route rule, with every `Option` resolved against the global.
///
/// Fork 3: normalize to the effective value. The field's stated purpose is
/// re-deriving a verdict, and the effective value is what produced it. The
/// "how it was written" information is not lost — it is in the config file,
/// which an auditor gets separately.
fn normalized_route(r: &RouteRule, enforce: &crate::guard::Enforcement) -> Json {
    // `route_matches` compares with `eq_ignore_ascii_case` on the method and
    // trims the trailing `/` and lowercases the prefix, so these three
    // spellings are one rule to `decide` and must be one rule here.
    let method = r.method.to_ascii_uppercase();
    let prefix = r.path_prefix.trim_end_matches('/').to_ascii_lowercase();

    // Sorted by name, then by type. `require_parameters` is used only as a
    // filter source in `decide`, so its order never reaches a decision — but
    // the sort must be *total*, or two rules naming the same parameter twice
    // with different types would order by whatever the input order happened
    // to be, which is the identity defect one level down.
    let mut params: Vec<&RequiredParam> = r.require_parameters.iter().collect();
    params.sort_by(|a, b| {
        a.name()
            .cmp(b.name())
            .then(param_type_name(a.param_type()).cmp(param_type_name(b.param_type())))
    });

    obj(vec![
        ("method", s(&method)),
        ("path_prefix", s(&prefix)),
        (
            "require_idempotency_key",
            Json::Bool(
                r.require_idempotency_key
                    .unwrap_or(enforce.require_idempotency_key),
            ),
        ),
        (
            "require_state_precondition",
            Json::Bool(
                r.require_state_precondition
                    .unwrap_or(enforce.require_state_precondition),
            ),
        ),
        (
            "require_parameters",
            Json::Array(params.into_iter().map(normalized_param).collect()),
        ),
    ])
}

/// The canonical projection of everything that produces a verdict.
///
/// Built from the **resolved struct**, never from the file bytes: `serde`'s
/// defaults fill absent `[enforce]` keys, and an operator who writes a
/// default explicitly is expressing the same policy as one who omits it.
///
/// `route[]` is emitted **in order**. `cfg.route.iter().find(..)` takes the
/// first matching rule, so two rules that both match a path resolve by
/// position, and normalizing that away would make two genuinely different
/// policies hash the same.
pub fn bundle(cfg: &GuardConfig) -> Json {
    obj(vec![
        ("decide_semantics", n(DECIDE_SEMANTICS)),
        (
            "enforce",
            obj(vec![
                // Pinned `true` — `parse_config` refuses `false` outright.
                // Present for the record that it was on, which is the whole
                // reason the config field exists.
                ("strict_ingestion", Json::Bool(cfg.enforce.strict_ingestion)),
                (
                    "require_idempotency_key",
                    Json::Bool(cfg.enforce.require_idempotency_key),
                ),
                (
                    "require_state_precondition",
                    Json::Bool(cfg.enforce.require_state_precondition),
                ),
                ("max_body_bytes", n(cfg.enforce.max_body_bytes as u64)),
            ]),
        ),
        (
            "route",
            Json::Array(
                cfg.route
                    .iter()
                    .map(|r| normalized_route(r, &cfg.enforce))
                    .collect(),
            ),
        ),
    ])
}

/// `policy_bundle_hash`, tagged.
pub fn bundle_hash(cfg: &GuardConfig) -> Result<String, JcsError> {
    Ok(format!("{}{}", crate::snapshot::TAG, digest(&bundle(cfg))?))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test policy_bundle && cargo test`
Expected: `policy_bundle` PASS, 7 tests. The existing suite still PASS, unedited.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Derive policy_bundle_hash from what produces a verdict, normalized to effective values

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `decide_semantics`, pinned by a golden-decision corpus

**Files:**
- Create: `tests/fixtures/decide-corpus-v1.toml`, `tests/fixtures/decide-corpus-v1.json`
- Test: `tests/decide_semantics.rs`

**Interfaces:**
- Consumes: `guard::{decide, parse_config, Decision}`, `policy::DECIDE_SEMANTICS`, `corpus::Condition`.
- Produces: nothing in the library. The mechanism is the fixture's filename.

A bundle hash over configuration alone is not sufficient to re-derive a verdict. `transit`'s own fix rounds prove it: the pre-fix guard forwarded `/v1/search/../transfer` and matched no route rule against `/v1/tra%6Esfer` — same TOML, different verdict, different code. A record claiming its verdict is re-derivable from `policy_bundle_hash` alone would be wrong, so the bundle carries `decide_semantics`, and this task is what stops that integer from rotting into a constant nobody bumps.

**The mechanism, plainly:** the corpus is loaded from `decide-corpus-v{DECIDE_SEMANTICS}.json`. Change `decide`'s behaviour and v1's expectations stop matching. Leaving the constant at 1 keeps loading v1, which keeps failing. The only passing state is a new file at a new version with the constant bumped to match — which changes `policy_bundle_hash` for every deployment, which is the point. It raises the cost of forgetting; it cannot stop somebody editing v1's expectations in place, and this plan does not claim otherwise.

- [ ] **Step 1: Write the corpus**

`tests/fixtures/decide-corpus-v1.toml` — the policy the corpus was generated under. It is a fixture, not an example config; changing it changes every expected outcome below.

```toml
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"

[[route]]
method = "POST"
path_prefix = "/v1/transfer"
require_parameters = ["to", { name = "amount", type = "number" }]

[[route]]
method = "POST"
path_prefix = "/v1/search"
require_idempotency_key = false
require_state_precondition = false
```

`tests/fixtures/decide-corpus-v1.json`:

```json
{
  "decide_semantics": 1,
  "config": "decide-corpus-v1.toml",
  "outcome_format": "forward <METHOD> <path> ?<query> body=<canonical> | reject <status> <condition-title or ->",
  "cases": [
    {
      "name": "a bodiless GET needs neither a key nor a precondition",
      "method": "GET", "target": "/v1/thing", "body": "", "headers": [],
      "outcome": "forward GET /v1/thing ? body="
    },
    {
      "name": "a conforming transfer forwards the canonical body",
      "method": "POST", "target": "/v1/transfer", "body": "{ \"to\":\"a\" , \"amount\":1 }",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "forward POST /v1/transfer ? body={\"amount\":1,\"to\":\"a\"}"
    },
    {
      "name": "C3 fires on a POST with no Idempotency-Key",
      "method": "POST", "target": "/v1/transfer", "body": "{\"to\":\"a\",\"amount\":1}",
      "headers": [["Content-Type", "application/json"], ["If-Match", "0"]],
      "outcome": "reject 428 C3 strict idempotency"
    },
    {
      "name": "C4 fires on a POST with no If-Match",
      "method": "POST", "target": "/v1/transfer", "body": "{\"to\":\"a\",\"amount\":1}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"]],
      "outcome": "reject 428 C4 contextual state pinning"
    },
    {
      "name": "C1 fires on an absent required parameter",
      "method": "POST", "target": "/v1/transfer", "body": "{\"to\":\"a\"}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "reject 422 C1 parameter completeness"
    },
    {
      "name": "C1 fires on a required parameter of the wrong JSON type",
      "method": "POST", "target": "/v1/transfer", "body": "{\"to\":\"a\",\"amount\":\"1\"}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "reject 422 C1 parameter completeness"
    },
    {
      "name": "an unknown method is refused rather than coerced",
      "method": "FROB", "target": "/v1/thing", "body": "", "headers": [],
      "outcome": "reject 405 -"
    },
    {
      "name": "a fragment in the request target is refused",
      "method": "GET", "target": "/v1/thing#z", "body": "", "headers": [],
      "outcome": "reject 400 -"
    },
    {
      "name": "a dot segment cannot borrow a relaxed route",
      "method": "POST", "target": "/v1/search/../transfer", "body": "{\"a\":1}",
      "headers": [["Content-Type", "application/json"]],
      "outcome": "reject 400 -"
    },
    {
      "name": "a relaxed route forwards without a key or a precondition",
      "method": "POST", "target": "/v1/search", "body": "{\"q\":\"x\"}",
      "headers": [["Content-Type", "application/json"]],
      "outcome": "forward POST /v1/search ? body={\"q\":\"x\"}"
    },
    {
      "name": "a duplicate key is a C2 refusal",
      "method": "POST", "target": "/v1/t", "body": "{\"a\":1,\"a\":2}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "reject 400 C2 representation injectivity"
    },
    {
      "name": "a HEAD carrying a body is refused",
      "method": "HEAD", "target": "/v1/t", "body": "{\"a\":1}",
      "headers": [["Content-Type", "application/json"]],
      "outcome": "reject 400 -"
    },
    {
      "name": "a non-JSON media type is refused",
      "method": "POST", "target": "/v1/t", "body": "{\"a\":1}",
      "headers": [["Content-Type", "text/plain"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "reject 415 -"
    },
    {
      "name": "a percent-encoded ordinary letter is decoded before matching",
      "method": "GET", "target": "/v1/tra%6Esfer", "body": "", "headers": [],
      "outcome": "forward GET /v1/transfer ? body="
    },
    {
      "name": "a re-cased path reaches its route rule and keeps its case downstream",
      "method": "POST", "target": "/v1/TRANSFER", "body": "{\"to\":\"a\",\"amount\":1}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "forward POST /v1/TRANSFER ? body={\"amount\":1,\"to\":\"a\"}"
    },
    {
      "name": "PUT is idempotent so it needs no key, and mutating so it needs a precondition",
      "method": "PUT", "target": "/v1/t", "body": "{\"a\":1}",
      "headers": [["Content-Type", "application/json"], ["If-Match", "0"]],
      "outcome": "forward PUT /v1/t ? body={\"a\":1}"
    },
    {
      "name": "a bodiless DELETE with a precondition forwards",
      "method": "DELETE", "target": "/v1/t", "body": "", "headers": [["If-Match", "0"]],
      "outcome": "forward DELETE /v1/t ? body="
    },
    {
      "name": "the query survives normalization",
      "method": "POST", "target": "/v1/transfer?x=1", "body": "{\"to\":\"a\",\"amount\":1}",
      "headers": [["Content-Type", "application/json"], ["Idempotency-Key", "k"], ["If-Match", "0"]],
      "outcome": "forward POST /v1/transfer ?x=1 body={\"amount\":1,\"to\":\"a\"}"
    },
    {
      "name": "a route prefix matches only on a segment boundary",
      "method": "POST", "target": "/v1/searching", "body": "{\"q\":\"x\"}",
      "headers": [["Content-Type", "application/json"]],
      "outcome": "reject 428 C3 strict idempotency"
    },
    {
      "name": "a single-encoded literal percent is left alone",
      "method": "GET", "target": "/v1/50%25off", "body": "", "headers": [],
      "outcome": "forward GET /v1/50%off ? body="
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

`tests/decide_semantics.rs`:

```rust
//! `decide_semantics` is pinned by behaviour, not by intent.
//!
//! Mutation this kills: the semantics version rotting into a constant nobody
//! bumps, so `policy_bundle_hash` claims a re-derivability it does not have.
//! Any change to `decide`'s output — a status, a condition, a canonical body,
//! a normalized path, a query — fails this file.

use transit::corpus::Condition;
use transit::guard::{decide, parse_config, Decision};
use transit::hostile::Request;
use transit::policy::DECIDE_SEMANTICS;

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn condition_title(c: Option<Condition>) -> String {
    c.map(|c| c.title().to_string()).unwrap_or_else(|| "-".into())
}

/// The transcript one decision writes. Everything a relying party could
/// observe about `decide`'s answer, and nothing it could not.
fn outcome(d: &Decision) -> String {
    match d {
        Decision::Forward(f) => format!(
            "forward {} {} ?{} body={}",
            f.method, f.path, f.query, f.body
        ),
        Decision::Reject {
            status, condition, ..
        } => format!("reject {} {}", status, condition_title(*condition)),
    }
}

fn json_str(v: &transit::json::Json, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_string())
        .unwrap_or_else(|| panic!("case is missing a string `{key}`: {v:?}"))
}

#[test]
fn the_golden_corpus_reproduces_every_decision() {
    // The corpus is looked up **by the semantics constant**. Changing
    // `decide` and leaving the constant alone keeps loading v1, which keeps
    // failing; the only passing state is a new corpus at a new version with
    // the constant bumped to match.
    let path = fixture_dir().join(format!("decide-corpus-v{DECIDE_SEMANTICS}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no corpus for semantics v{DECIDE_SEMANTICS} at {path:?}: {e}"));
    let doc = transit::json::parse_strict(&text).expect("the corpus is strict-valid JSON");

    let declared = doc
        .get("decide_semantics")
        .and_then(|v| v.as_f64())
        .expect("the corpus declares a semantics version");
    assert_eq!(
        declared as u64, DECIDE_SEMANTICS,
        "the corpus file's own version disagrees with the constant that found it"
    );

    let cfg_name = json_str(&doc, "config");
    let cfg_text = std::fs::read_to_string(fixture_dir().join(&cfg_name)).expect("the corpus config");
    let cfg = parse_config(&cfg_text).expect("the corpus config parses");

    let cases = match doc.get("cases") {
        Some(transit::json::Json::Array(a)) => a.clone(),
        other => panic!("`cases` must be an array, got {other:?}"),
    };
    assert!(cases.len() >= 20, "the corpus shrank to {} cases", cases.len());

    for case in &cases {
        let name = json_str(case, "name");
        let headers: Vec<(String, String)> = match case.get("headers") {
            Some(transit::json::Json::Array(hs)) => hs
                .iter()
                .map(|pair| match pair {
                    transit::json::Json::Array(kv) if kv.len() == 2 => (
                        kv[0].as_string().unwrap_or_default(),
                        kv[1].as_string().unwrap_or_default(),
                    ),
                    other => panic!("{name}: a header must be a [name, value] pair, got {other:?}"),
                })
                .collect(),
            other => panic!("{name}: `headers` must be an array, got {other:?}"),
        };
        let req = Request {
            method: json_str(case, "method"),
            path: json_str(case, "target"),
            headers,
            body: json_str(case, "body"),
        };
        assert_eq!(
            outcome(&decide(&cfg, &req)),
            json_str(case, "outcome"),
            "case `{name}` decided differently than the corpus records"
        );
    }
}

#[test]
fn no_stale_corpus_is_left_behind_claiming_the_current_version() {
    // A second copy at the same version would make "which file did the test
    // read" a coin toss.
    let want = format!("decide-corpus-v{DECIDE_SEMANTICS}.json");
    let mut matches = 0;
    for entry in std::fs::read_dir(fixture_dir()).expect("the fixture directory") {
        let entry = entry.expect("a directory entry");
        if entry.file_name().to_string_lossy() == want {
            matches += 1;
        }
    }
    assert_eq!(matches, 1, "expected exactly one {want}");
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test --test decide_semantics`
Expected: PASS, 2 tests.

**If a case disagrees, do not edit the corpus first.** The corpus was written by reading `decide`, and a disagreement means one of two things: the corpus records the wrong expectation, or Task 1's restructure changed a decision. Determine which by reading the case against `decide_inner`, and only then fix the side that is wrong. Silently rewriting the expectation to whatever the code now says is precisely the rot this task exists to prevent.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Pin decide_semantics with a golden-decision corpus named for the version in force

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: the verdict rule — `ALLOW` only for mandated transformations

**Files:**
- Modify: `src/guard.rs`
- Test: `tests/guard_verdict.rs`

**Interfaces:**
- Produces: `guard::modifications_of` (private), replacing Task 1's stub. `Evaluation::verdict` and `Evaluation::modifications` become meaningful.

Fork 5's rule: **`ALLOW` when the difference between proposed and dispatched is confined to (i) RFC 8785 canonicalization of a body that parsed to the same JSON value and (ii) RFC 9110 §7.6.1 hop-by-hop removal.** Both are mandated transformations that preserve what was proposed. `MODIFY` otherwise. It is the only option under which the field distinguishes anything.

One detail the design states more narrowly than the code supports. The design says the dropped non-hop-by-hop header is "the client's own `X-Transit-Digest` … the only one". Reading `src/guard.rs:661`–`679`, the filter also drops **whatever `digest_header` is configured to be named** — which an operator may set to anything — and drops `content-type` unconditionally, re-adding `application/json` only when the body is non-empty. So a bodiless request carrying a `Content-Type` has it removed outright. The rule below is written against the code.

The comparison is by **name and value**, not name presence. A client that sends `X-Transit-Digest: forged` has its value dropped and the guard's own added under the same name, so a name-presence check would see a header of that name in the forward plan and report nothing — which is the one case fork 5 most wants flagged.

- [ ] **Step 1: Write the failing test**

`tests/guard_verdict.rs`:

```rust
//! `MODIFY` is reachable and `ALLOW` is not universal.
//!
//! Mutation every case here kills: the verdict hardcoded, or the rule
//! collapsing to one value. A verdict that takes one value carries no
//! information, and both collapses are defensible on the schema's plain text.

use transit::guard::{decide_with_snapshot, Decision, Enforcement, GuardConfig};
use transit::hostile::Request;
use transit::snapshot::{Modification, Verdict};

fn cfg() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:8080".into(),
        upstream: "http://127.0.0.1:8787".into(),
        enforce: Enforcement::default(),
        route: Vec::new(),
    }
}

fn req(method: &str, target: &str, body: &str, headers: &[(&str, &str)]) -> Request {
    Request {
        method: method.into(),
        path: target.into(),
        headers: headers
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        body: body.into(),
    }
}

fn ok() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Idempotency-Key", "k1"),
        ("If-Match", "0"),
        ("Content-Type", "application/json"),
    ]
}

#[test]
fn a_plain_conforming_request_is_allow() {
    // The negative control. Without it, a rule that returned MODIFY for
    // everything would pass every case below.
    let (d, e) = decide_with_snapshot(&cfg(), &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    assert!(matches!(d, Decision::Forward(_)));
    assert_eq!(e.verdict, Verdict::Allow, "{:?}", e.modifications);
    assert!(e.modifications.is_empty(), "{:?}", e.modifications);
}

#[test]
fn canonicalizing_the_body_is_not_a_modification() {
    // RFC 8785 canonicalization of a body that parsed to the same JSON value
    // is a mandated, semantics-preserving transformation. Counting it would
    // make ALLOW unreachable, since this guard canonicalizes every body.
    let (_, e) = decide_with_snapshot(
        &cfg(),
        &req("POST", "/v1/transfer", "{ \"b\":2 ,\n \"a\":1 }", &ok()),
    );
    assert_eq!(e.verdict, Verdict::Allow, "{:?}", e.modifications);
}

#[test]
fn hop_by_hop_removal_is_not_a_modification() {
    // RFC 9110 §7.6.1 requires every intermediary to remove these. An
    // intermediary doing what the RFC obliges it to do has not modified the
    // proposed action.
    let mut h = ok();
    h.extend([
        ("Connection", "X-Secret, keep-alive"),
        ("X-Secret", "leak"),
        ("Keep-Alive", "timeout=5"),
        ("TE", "trailers"),
        ("Expect", "100-continue"),
        ("Host", "elsewhere"),
        ("Content-Length", "9999"),
    ]);
    let (_, e) = decide_with_snapshot(&cfg(), &req("POST", "/v1/transfer", r#"{"a":1}"#, &h));
    assert_eq!(e.verdict, Verdict::Allow, "{:?}", e.modifications);
}

#[test]
fn a_renormalized_target_is_modify() {
    // `/v1/tra%6Esfer` in, `/v1/transfer` out. Everything-is-ALLOW hides a
    // real event: a change to the target the client named.
    let (d, e) = decide_with_snapshot(&cfg(), &req("GET", "/v1/tra%6Esfer", "", &[]));
    assert!(matches!(d, Decision::Forward(_)));
    assert_eq!(e.verdict, Verdict::Modify);
    assert!(
        e.modifications.iter().any(|m| matches!(
            m,
            Modification::TargetRenormalized { dispatched, .. } if dispatched == "/v1/transfer"
        )),
        "{:?}",
        e.modifications
    );
}

#[test]
fn a_client_supplied_digest_header_is_modify() {
    // Mutation this kills: comparing header *names* rather than name and
    // value. The guard drops the client's `X-Transit-Digest` and adds its own
    // under the same name, so a name-presence check reports nothing — and a
    // stripped forged digest header is exactly what an auditor should see.
    let mut h = ok();
    h.push(("X-Transit-Digest", "forged"));
    let (_, e) = decide_with_snapshot(&cfg(), &req("POST", "/v1/transfer", r#"{"a":1}"#, &h));
    assert_eq!(e.verdict, Verdict::Modify, "{:?}", e.modifications);
    assert!(
        e.modifications.iter().any(|m| matches!(
            m,
            Modification::HeaderDropped { name } if name.eq_ignore_ascii_case("x-transit-digest")
        )),
        "{:?}",
        e.modifications
    );
}

#[test]
fn a_dropped_header_under_a_renamed_digest_header_is_also_modify() {
    // The design says X-Transit-Digest is "the only one". The code drops
    // whatever `digest_header` names, so the rule is written against the code.
    let mut c = cfg();
    c.enforce.digest_header = Some("X-House-Digest".into());
    let mut h = ok();
    h.push(("X-House-Digest", "forged"));
    let (_, e) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &h));
    assert_eq!(e.verdict, Verdict::Modify, "{:?}", e.modifications);
}

#[test]
fn a_rewritten_content_type_is_modify() {
    // `application/vnd.acme+json; charset=utf-8` reaches the upstream as
    // `application/json`. The charset is gone and the vendor type is gone;
    // that is a change to what was dispatched, and it is not one RFC 9110
    // obliges an intermediary to make.
    let (_, e) = decide_with_snapshot(
        &cfg(),
        &req(
            "POST",
            "/v1/transfer",
            r#"{"a":1}"#,
            &[
                ("Idempotency-Key", "k1"),
                ("If-Match", "0"),
                ("Content-Type", "application/vnd.acme+json; charset=utf-8"),
            ],
        ),
    );
    assert_eq!(e.verdict, Verdict::Modify, "{:?}", e.modifications);
    assert!(
        e.modifications
            .iter()
            .any(|m| matches!(m, Modification::ContentTypeRewritten { .. })),
        "{:?}",
        e.modifications
    );
}

#[test]
fn a_content_type_on_a_bodiless_request_is_dropped_and_that_is_modify() {
    // `decide` only re-adds Content-Type when the canonical body is
    // non-empty, so a bodiless request carrying one has it removed outright.
    let (_, e) = decide_with_snapshot(
        &cfg(),
        &req("GET", "/v1/thing", "", &[("Content-Type", "application/json")]),
    );
    assert_eq!(e.verdict, Verdict::Modify, "{:?}", e.modifications);
}

#[test]
fn every_rejection_is_deny_and_carries_its_condition() {
    // Mutation this kills: recording a denial as unexplainable, so the
    // verdict cannot be re-derived from the record and the bundle.
    use transit::corpus::Condition;
    let cases: Vec<(Request, u16, Option<Condition>)> = vec![
        (
            req("POST", "/v1/t", r#"{"a":1}"#, &[("If-Match", "0"), ("Content-Type", "application/json")]),
            428,
            Some(Condition::C3),
        ),
        (
            req("POST", "/v1/t", r#"{"a":1}"#, &[("Idempotency-Key", "k"), ("Content-Type", "application/json")]),
            428,
            Some(Condition::C4),
        ),
        (
            req("POST", "/v1/t", r#"{"a":1,"a":2}"#, &ok()),
            400,
            Some(Condition::C2),
        ),
        (req("FROB", "/v1/t", "", &[]), 405, None),
        (req("GET", "/v1/t#z", "", &[]), 400, None),
    ];
    for (r, status, condition) in cases {
        let (d, e) = decide_with_snapshot(&cfg(), &r);
        match d {
            Decision::Reject { status: s, .. } => assert_eq!(s, status, "{r:?}"),
            other => panic!("expected Reject for {r:?}, got {other:?}"),
        }
        assert_eq!(e.verdict, Verdict::Deny, "{r:?}");
        assert_eq!(e.condition, condition, "{r:?}");
        assert!(e.modifications.is_empty(), "a denial dispatched nothing to modify");
    }
}

#[test]
fn the_verdict_only_ever_takes_three_values() {
    // ESCALATE is unreachable and is stated as such: this guard has no
    // human-in-the-loop path and no mechanism to suspend an action pending
    // approval. `Verdict` has no variant for it, and this asserts the three
    // that exist are the three that appear.
    let mut seen = std::collections::BTreeSet::new();
    for r in [
        req("POST", "/v1/t", r#"{"a":1}"#, &ok()),
        req("GET", "/v1/tra%6Esfer", "", &[]),
        req("FROB", "/v1/t", "", &[]),
    ] {
        seen.insert(decide_with_snapshot(&cfg(), &r).1.verdict.as_str());
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        vec!["ALLOW", "DENY", "MODIFY"]
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test guard_verdict`
Expected: FAIL — Task 1's stub returns an empty vector, so every forward is `ALLOW` and five cases fail.

- [ ] **Step 3: Write the implementation**

Replace the `modifications_of` stub in `src/guard.rs` with:

```rust
/// Fork 5's rule, applied to the request the guard holds and the plan it
/// built.
///
/// `ALLOW` when the difference is confined to (i) RFC 8785 canonicalization
/// of a body that parsed to the same JSON value and (ii) RFC 9110 §7.6.1
/// hop-by-hop removal — both mandated transformations that preserve what was
/// proposed. Neither produces a `Modification`, so an empty result **is**
/// `ALLOW`.
fn modifications_of(
    req: &Request,
    f: &Forward,
    connection_named: &[String],
    content_type: Option<&str>,
) -> Vec<Modification> {
    let mut out = Vec::new();

    // The target the client named, minus the query. A fragment never reaches
    // here — `normalize_target` refuses one — so splitting on `?` is enough.
    let wire_path = req.path.split('?').next().unwrap_or("");
    if wire_path != f.path {
        out.push(Modification::TargetRenormalized {
            wire: sanitize(wire_path),
            dispatched: f.path.clone(),
        });
    }

    // Content-Type. Dropped unconditionally by the filter and re-added as
    // `application/json` only when the canonical body is non-empty, so a
    // bodiless request carrying one has it removed outright.
    if let Some(ct) = content_type {
        let dispatched = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if ct != dispatched {
            out.push(Modification::ContentTypeRewritten {
                wire: sanitize(ct),
                dispatched: dispatched.to_string(),
            });
        }
    }

    // Every other header. Compared by name **and value**: the guard drops a
    // client-supplied digest header and adds its own under the same name, so
    // a name-presence check would see a header of that name in the plan and
    // report nothing.
    let mut reported: Vec<String> = Vec::new();
    for (k, v) in &req.headers {
        let lk = k.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lk.as_str())
            || connection_named.contains(&lk)
            || lk == "content-type"
            || reported.contains(&lk)
        {
            continue;
        }
        let survived = f
            .headers
            .iter()
            .any(|(fk, fv)| fk.eq_ignore_ascii_case(k) && fv == v);
        if !survived {
            reported.push(lk.clone());
            out.push(Modification::HeaderDropped { name: lk });
        }
    }

    out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test guard_verdict && cargo test`
Expected: `guard_verdict` PASS, 10 tests. The existing suite still PASS, unedited.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Apply fork 5's rule: ALLOW only for RFC-mandated, semantics-preserving transformations

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: the claim, the extension claims, and the sink that is one code path

**Files:**
- Create: `src/evidence.rs`
- Modify: `src/lib.rs`, `src/snapshot.rs`
- Test: `tests/claim_shape.rs`

**Interfaces:**
- Consumes: `snapshot::{Evaluation, Verdict, ActionSnapshot, TAG}`, `corpus::Condition`, `policy::bundle_hash`.
- Produces: `evidence::{Claim, Extensions, ClaimContext, Identity, Action, Ack, ClaimSink, NoEvidence, Counters, EvidenceError}`; `snapshot::ResponseSnapshot`.

`Claim` carries **exactly the ten fields `ephemeris::record::Claim` declares**, and nothing else. This is not stylistic. That struct is `#[serde(deny_unknown_fields)]` (ephemeris plan, Task 1), so a claim carrying an eleventh member is **refused outright** — the design's reliance on the schema's `additionalProperties: true` does not survive contact with the receiving implementation. The extension claims therefore travel as a **sibling object in the envelope**, `transit_extensions`, and Task 8's protocol note records that `ephemeris` must store it or the extensions are lost.

`ClaimSink` is a trait with a no-op default implementation rather than a `#[cfg]`-gated branch, so the default build and the evidence build run **the same code path** through `handle_one`. A component whose whole thesis is that two code paths diverge should not ship two code paths.

- [ ] **Step 1: Write the failing test**

`tests/claim_shape.rs`:

```rust
//! What goes into a claim, and — just as load-bearing — what does not.

use transit::evidence::{Action, ClaimContext, Identity};
use transit::guard::{decide_with_snapshot, Enforcement, GuardConfig};
use transit::hostile::Request;
use transit::policy::bundle_hash;
use transit::snapshot::ResponseSnapshot;

fn cfg() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:8080".into(),
        upstream: "http://ledger.internal:8787".into(),
        enforce: Enforcement::default(),
        route: Vec::new(),
    }
}

fn identity() -> Identity {
    Identity {
        agent_id: "did:web:example.org:agents:guard-1".into(),
        initiating_user: "user:unattended".into(),
    }
}

fn req(method: &str, target: &str, body: &str, headers: &[(&str, &str)]) -> Request {
    Request {
        method: method.into(),
        path: target.into(),
        headers: headers
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        body: body.into(),
    }
}

fn ok() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Idempotency-Key", "k1"),
        ("If-Match", "0"),
        ("Content-Type", "application/json"),
    ]
}

fn context<'a>(
    c: &'a GuardConfig,
    action: &'a Action,
    id: &'a Identity,
    eval: &'a transit::snapshot::Evaluation,
) -> ClaimContext<'a> {
    ClaimContext {
        action,
        identity: id,
        eval,
        target_resource: eval.snapshot.target_resource(&c.upstream),
        policy_bundle_hash: bundle_hash(c).unwrap(),
    }
}

#[test]
fn a_claim_carries_exactly_the_ten_fields_ephemeris_declares() {
    // Mutation this kills: putting an extension claim inside `claim`.
    // `ephemeris::record::Claim` is `deny_unknown_fields`, so an eleventh
    // member is not an extra fact — it is a refused record, and the guard
    // would 503 every request in production while every test here passed.
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let (claim, _) = context(&c, &a, &id, &eval).before().unwrap();

    let v = serde_json::to_value(&claim).unwrap();
    let mut keys: Vec<String> = v
        .as_object()
        .expect("a claim serializes to an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "action_id",
            "agent_id",
            "canonical_snapshot_hash",
            "initiating_user",
            "interception_point",
            "nonce",
            "path_summary_hash",
            "policy_bundle_hash",
            "target_resource",
            "verdict",
        ]
    );
}

#[test]
fn path_summary_hash_is_present_and_null_and_the_absence_is_explained() {
    // Fork 4: ship it unfilled. Mutation this kills: a sentinel summary — a
    // digest over `{"path_state":"none"}` that makes the record look complete
    // and commits to a structure nothing reads. That is P04's defect
    // committed deliberately. A visible gap beats implied coverage.
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let (claim, ext) = context(&c, &a, &id, &eval).before().unwrap();

    assert!(claim.path_summary_hash.is_none());
    let v = serde_json::to_value(&claim).unwrap();
    assert_eq!(v.get("path_summary_hash"), Some(&serde_json::Value::Null));
    assert!(
        ext.path_summary_hash_absent_because.contains("C4.1.7"),
        "{}",
        ext.path_summary_hash_absent_because
    );
    assert!(
        ext.path_summary_hash_absent_because.contains("path-aware"),
        "{}",
        ext.path_summary_hash_absent_because
    );
}

#[test]
fn agent_id_comes_from_config_and_a_header_cannot_influence_it() {
    // Fork 8. A header is the option that looks like it works and produces a
    // record whose identity fields mean nothing: the agent asserts its own
    // identity to the component whose entire job is not to trust the agent.
    let c = cfg();
    let (_, eval) = decide_with_snapshot(
        &c,
        &req(
            "POST",
            "/v1/transfer",
            r#"{"a":1}"#,
            &[
                ("Idempotency-Key", "k1"),
                ("If-Match", "0"),
                ("Content-Type", "application/json"),
                ("X-Agent-Id", "did:web:attacker.example:agents:root"),
                ("X-Initiating-User", "user:admin"),
                ("Agent-Id", "did:web:attacker.example:agents:root"),
            ],
        ),
    );
    let a = Action::fresh().unwrap();
    let id = identity();
    let (claim, _) = context(&c, &a, &id, &eval).before().unwrap();
    assert_eq!(claim.agent_id, "did:web:example.org:agents:guard-1");
    assert_eq!(claim.initiating_user, "user:unattended");
    let text = serde_json::to_string(&claim).unwrap();
    assert!(!text.contains("attacker"), "{text}");
    assert!(!text.contains("user:admin"), "{text}");
}

#[test]
fn one_action_id_and_one_nonce_link_all_three_records() {
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let ctx = context(&c, &a, &id, &eval);
    let resp = ResponseSnapshot::new(200, &["etag".into()], b"{}");

    let (before, be) = ctx.before().unwrap();
    let (during, de) = ctx.during().unwrap();
    let (after, ae) = ctx.after(&resp).unwrap();

    assert_eq!(before.action_id, during.action_id);
    assert_eq!(before.action_id, after.action_id);
    assert_eq!(before.nonce, during.nonce);
    assert_eq!(before.nonce, after.nonce);

    assert_eq!(before.interception_point, "PRE_CALL_TOOL_INVOCATION");
    assert_eq!(during.interception_point, "PRE_CALL_TOOL_INVOCATION");
    assert_eq!(after.interception_point, "POST_CALL_TOOL_RESULT");

    assert_eq!(be.record_phase, "before");
    assert_eq!(de.record_phase, "during");
    assert_eq!(ae.record_phase, "after");

    // Finding 5. The middle record means *dispatched*, and says so, because
    // an interception gateway cannot witness an effect — it witnesses that it
    // wrote a request to a socket.
    assert_eq!(be.observed, "request_received");
    assert_eq!(de.observed, "request_dispatched");
    assert_eq!(ae.observed, "response_relayed");
    assert!(!de.observed.contains("effect"));
}

#[test]
fn the_after_record_commits_to_the_response_and_not_to_the_request() {
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let ctx = context(&c, &a, &id, &eval);

    let (before, _) = ctx.before().unwrap();
    let (after, _) = ctx.after(&ResponseSnapshot::new(200, &["etag".into()], b"{}")).unwrap();
    assert_ne!(before.canonical_snapshot_hash, after.canonical_snapshot_hash);

    // And a different response commits differently, so the field is tracking
    // the response rather than being a constant.
    let (other, _) = ctx.after(&ResponseSnapshot::new(500, &["etag".into()], b"{}")).unwrap();
    assert_ne!(after.canonical_snapshot_hash, other.canonical_snapshot_hash);
    let (body_differs, _) = ctx
        .after(&ResponseSnapshot::new(200, &["etag".into()], b"{\"x\":1}"))
        .unwrap();
    assert_ne!(after.canonical_snapshot_hash, body_differs.canonical_snapshot_hash);
}

#[test]
fn two_actions_get_two_ids_and_a_nonce_is_not_the_action_id() {
    // Mutation this kills: deriving the action ID from the request, which
    // would make two identical requests share an ID and collapse two actions
    // into one in the log.
    let a = Action::fresh().unwrap();
    let b = Action::fresh().unwrap();
    assert_ne!(a.id, b.id);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.id, a.nonce);
    assert_eq!(a.id.len(), 32, "128 bits, hex");
    assert_eq!(a.nonce.len(), 32);
}

#[test]
fn the_nonce_says_where_it_came_from_because_nobody_issued_a_challenge() {
    // Finding 8: the top-level `nonce` is required and nothing in the
    // ecosystem issues one. C7.1.4's challenge comes from the relying party,
    // and a challenge minted by the party being challenged resists no replay
    // at all. The guard mints one because the field is required, and labels
    // it so no reader mistakes it for a challenge.
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let (_, ext) = context(&c, &a, &id, &eval).before().unwrap();
    assert_eq!(ext.nonce_source, "guard_minted");
}

#[test]
fn a_denial_carries_its_condition_and_a_forward_does_not() {
    let c = cfg();
    let a = Action::fresh().unwrap();
    let id = identity();

    let (_, denied) = decide_with_snapshot(
        &c,
        &req("POST", "/v1/t", r#"{"a":1}"#, &[("If-Match", "0"), ("Content-Type", "application/json")]),
    );
    let (claim, ext) = context(&c, &a, &id, &denied).before().unwrap();
    assert_eq!(claim.verdict, "DENY");
    assert_eq!(ext.transit_condition, Some(transit::corpus::Condition::C3));
    assert_eq!(
        serde_json::to_value(&ext).unwrap().get("transit_condition"),
        Some(&serde_json::Value::String("C3".into()))
    );

    let (_, allowed) = decide_with_snapshot(&c, &req("POST", "/v1/t", r#"{"a":1}"#, &ok()));
    let (claim, ext) = context(&c, &a, &id, &allowed).before().unwrap();
    assert_eq!(claim.verdict, "ALLOW");
    assert!(ext.transit_condition.is_none());
    assert!(serde_json::to_value(&ext)
        .unwrap()
        .get("transit_condition")
        .is_none());
}

#[test]
fn the_body_digest_travels_as_an_extension_and_equals_the_wire_header() {
    // Fork 1's cost, made explicit: two digests in one record. The extension
    // claim is named unambiguously so a careless verifier comparing them to
    // each other at least has to ignore the names to do it.
    let c = cfg();
    let (d, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer", r#"{"a":1}"#, &ok()));
    let f = match d {
        transit::guard::Decision::Forward(f) => f,
        other => panic!("expected Forward, got {other:?}"),
    };
    let a = Action::fresh().unwrap();
    let id = identity();
    let (claim, ext) = context(&c, &a, &id, &eval).before().unwrap();
    assert_eq!(
        ext.snapshot_body_sha256.as_deref(),
        Some(format!("sha-256:{}", f.digest).as_str())
    );
    assert_ne!(claim.canonical_snapshot_hash, format!("sha-256:{}", f.digest));
}

#[test]
fn the_target_resource_is_the_one_the_snapshot_names() {
    let c = cfg();
    let (_, eval) = decide_with_snapshot(&c, &req("POST", "/v1/transfer?x=1", r#"{"a":1}"#, &ok()));
    let a = Action::fresh().unwrap();
    let id = identity();
    let (claim, _) = context(&c, &a, &id, &eval).before().unwrap();
    assert_eq!(claim.target_resource, "http://ledger.internal:8787/v1/transfer");
}

#[test]
fn a_no_op_sink_is_enabled_false_so_no_claim_is_built_for_it() {
    use transit::evidence::{ClaimSink, NoEvidence};
    let s = NoEvidence::default();
    assert!(!s.enabled());
    assert_eq!(s.counters().lost_during.load(std::sync::atomic::Ordering::SeqCst), 0);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test claim_shape`
Expected: FAIL — `transit::evidence` does not exist and `ResponseSnapshot` is not defined.

- [ ] **Step 3: Add `ResponseSnapshot` to `src/snapshot.rs`**

Append to `src/snapshot.rs`:

```rust
/// What the after-record commits to: the response the guard relayed.
///
/// The response body is committed to by digest rather than by value. A
/// response is not necessarily JSON, is not necessarily canonicalizable, and
/// may be megabytes; a digest of its bytes is a fact the guard observed and
/// can stand behind.
#[derive(Clone, Debug)]
pub struct ResponseSnapshot {
    status: u16,
    /// The names of the headers relayed to the client, lowercased and sorted.
    /// Names, not values: `Set-Cookie` and `WWW-Authenticate` carry secrets,
    /// and an evidence log is not a place to put them.
    headers_relayed: Vec<String>,
    body_sha256: String,
}

impl ResponseSnapshot {
    pub fn new(status: u16, header_names: &[String], body: &[u8]) -> Self {
        let mut headers_relayed: Vec<String> =
            header_names.iter().map(|n| n.to_ascii_lowercase()).collect();
        headers_relayed.sort();
        headers_relayed.dedup();
        Self {
            status,
            headers_relayed,
            body_sha256: tagged(&hex::encode(Sha256::digest(body))),
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            (
                utf16("status"),
                Json::Number(crate::json::Num::Int(self.status as i128)),
            ),
            (
                utf16("headers_relayed"),
                Json::Array(
                    self.headers_relayed
                        .iter()
                        .map(|n| Json::String(utf16(n)))
                        .collect(),
                ),
            ),
            (utf16("body_sha256"), Json::String(utf16(&self.body_sha256))),
        ])
    }

    pub fn canonical_hash(&self) -> Result<String, JcsError> {
        Ok(tagged(&digest(&self.to_json())?))
    }
}
```

- [ ] **Step 4: Write `src/evidence.rs`**

Add `pub mod evidence;` to `src/lib.rs`.

`src/evidence.rs`:

```rust
//! The claim `transit guard` sends, and the sink it sends it to.
//!
//! **Why the claim type is duplicated rather than imported.** `ephemeris`
//! depends on this crate by git rev, so a cargo dependency in the other
//! direction is a cycle Cargo refuses. The coupling is on the wire protocol
//! in `UdsSink`, and this struct is that protocol's request half. Keeping the
//! two in step is the version-pinning risk every pair in this programme
//! carries; the cross-check test named in Task 11 is what makes a drift loud.

use crate::corpus::Condition;
use crate::jcs::JcsError;
use crate::snapshot::{Evaluation, ResponseSnapshot};
use serde::Serialize;
use std::sync::atomic::AtomicU64;

/// Exactly the ten fields `ephemeris::record::Claim` declares, and nothing
/// else.
///
/// That struct is `#[serde(deny_unknown_fields)]`, so an eleventh member is
/// not an extra fact — it is a refused claim, and a refused claim is a 503 on
/// every request. The design's reliance on the evidence schema's
/// `additionalProperties: true` is correct about the schema and wrong about
/// the receiving implementation; extensions travel in `Extensions`.
#[derive(Clone, Debug, Serialize)]
pub struct Claim {
    pub action_id: String,
    pub agent_id: String,
    pub initiating_user: String,
    pub interception_point: String,
    pub target_resource: String,
    pub canonical_snapshot_hash: String,
    /// Fork 4: shipped unfilled, serialized as an explicit `null`.
    ///
    /// `transit guard` is not a path-aware authorization point. `decide` is a
    /// pure function of one request and the config; `serve` spawns a thread
    /// per admitted request with no ordering across them, no agent identity
    /// anywhere in `hostile::Request`, and no state that survives a restart.
    /// A summary living in this process's memory would be reset by a
    /// `SIGTERM`, which is P04's eviction attack with no attack required.
    pub path_summary_hash: Option<String>,
    pub policy_bundle_hash: String,
    pub verdict: String,
    pub nonce: String,
}

/// Everything the guard knows that `Claim` has no room for.
///
/// Sent as a sibling of `claim` in the envelope. `ephemeris` must store this
/// object for these facts to survive; if it discards it, the extensions are
/// lost and the ten fields still arrive intact. That degradation is
/// deliberate — no extension is load-bearing for a record's validity.
#[derive(Clone, Debug, Serialize)]
pub struct Extensions {
    /// `"before"` | `"during"` | `"after"`, per C7.1.2's three-record axis.
    pub record_phase: String,
    /// What the guard actually witnessed. The middle record says
    /// `request_dispatched`, never `effect_performed`: an interception
    /// gateway cannot observe whether an upstream performed an effect, and a
    /// record claiming it would be a claim the emitter has no basis for.
    /// See `docs/standard-findings.md` finding 5.
    pub observed: String,
    /// `"guard_minted"`. C7.1.4's challenge comes from the relying party and
    /// nothing in this ecosystem issues one; the field is required, so the
    /// guard mints a value and labels it rather than implying a freshness
    /// property it does not have. Finding 8.
    pub nonce_source: String,
    /// Why `path_summary_hash` is null, in the record rather than in a
    /// footnote.
    pub path_summary_hash_absent_because: String,
    /// Fork 1's other half: the digest of the canonical **body**, which is
    /// what `X-Transit-Digest` carries and what `poc-audit`'s
    /// `field/canonical` recomputes. Absent when there was no parsed body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_body_sha256: Option<String>,
    /// transit's own C1–C4 finding, machine-readable inside the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transit_condition: Option<Condition>,
    /// Why the verdict is `MODIFY`. Empty exactly when it is `ALLOW`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modifications: Vec<String>,
    /// The response the after-record commits to, in readable form beside its
    /// digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
}

pub const PATH_SUMMARY_ABSENT: &str =
    "transit guard is not a path-aware authorization point: it holds no per-agent path state, \
     so it cannot claim C4.1.7 and does not fabricate a summary. See P04.";

/// Where identity comes from: static config, and nowhere else.
///
/// Fork 8. Not a request header — the agent asserting its own identity to the
/// component whose job is not to trust it produces a record whose identity
/// fields mean nothing. RA-TLS verified peer identity is the real answer and
/// needs its own spec.
#[derive(Clone, Debug)]
pub struct Identity {
    pub agent_id: String,
    pub initiating_user: String,
}

/// One intercepted action: the ID linking its three records, and the nonce
/// they share.
///
/// **Random, never derived from the request.** A derived ID would make two
/// identical requests share an action ID and collapse two actions into one in
/// the log — which is exactly the property C7.1.2's linkability exists to
/// provide.
#[derive(Clone, Debug)]
pub struct Action {
    pub id: String,
    pub nonce: String,
}

impl Action {
    pub fn fresh() -> Result<Self, EvidenceError> {
        Ok(Self {
            id: random_128()?,
            nonce: random_128()?,
        })
    }
}

#[cfg(unix)]
fn random_128() -> Result<String, EvidenceError> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| EvidenceError::Entropy(e.to_string()))?;
    let mut b = [0u8; 16];
    f.read_exact(&mut b)
        .map_err(|e| EvidenceError::Entropy(e.to_string()))?;
    Ok(hex::encode(b))
}

#[cfg(not(unix))]
fn random_128() -> Result<String, EvidenceError> {
    Err(EvidenceError::Unsupported)
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("could not read 128 bits of entropy: {0}")]
    Entropy(String),
    #[error("evidence claims require a Unix domain socket and this is not a Unix host")]
    Unsupported,
    #[error("the action snapshot has no canonical form: {0}")]
    Canonicalize(#[from] JcsError),
    #[error("could not reach the evidence store at {path}: {detail}")]
    Unreachable { path: String, detail: String },
    #[error("the evidence store did not acknowledge within {ms} ms")]
    Timeout { ms: u64 },
    #[error("the evidence store refused the claim: {0}")]
    Refused(String),
    #[error("the evidence store's acknowledgement could not be read: {0}")]
    BadAck(String),
}

/// What `ephemeris` returns once, and only once, a record is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub step_index: u64,
    pub chain_head: String,
}

/// Losses that are alerted rather than fatal (C7.6.1).
///
/// Every one of these is a place the evidence log undercounts what happened,
/// and an auditor computing a rate from the log without them will be wrong.
#[derive(Debug, Default)]
pub struct Counters {
    /// Requests shed at admission, past `max_concurrent_requests`. `decide`
    /// never ran on them, so there is no snapshot, no verdict and no record —
    /// correct, because the request was never intercepted, and still a gap.
    pub shed: AtomicU64,
    pub lost_during: AtomicU64,
    pub lost_after: AtomicU64,
}

/// Where a claim goes.
///
/// A trait with a no-op implementation rather than a `#[cfg]`-gated branch in
/// `handle_one`, so the default build and the evidence build run **one code
/// path**. A component built to demonstrate that two implementations of one
/// operation diverge should not ship two implementations of its own hot path.
pub trait ClaimSink: Send + Sync {
    /// Emit one claim and block until it is durably acknowledged.
    fn emit(&self, claim: &Claim, ext: &Extensions) -> Result<Ack, EvidenceError>;
    /// `false` when nothing is emitted, so the caller can skip building a
    /// claim whose digests cost a hash apiece.
    fn enabled(&self) -> bool;
    fn counters(&self) -> &Counters;
}

/// The default build's sink, and the behaviour of a guard with no
/// `[evidence]` section: claims are not emitted and the guard behaves as it
/// does today.
#[derive(Debug, Default)]
pub struct NoEvidence {
    counters: Counters,
}

impl ClaimSink for NoEvidence {
    fn emit(&self, _claim: &Claim, _ext: &Extensions) -> Result<Ack, EvidenceError> {
        Ok(Ack {
            step_index: 0,
            chain_head: String::new(),
        })
    }
    fn enabled(&self) -> bool {
        false
    }
    fn counters(&self) -> &Counters {
        &self.counters
    }
}

/// Everything the three records of one action share.
pub struct ClaimContext<'a> {
    pub action: &'a Action,
    pub identity: &'a Identity,
    pub eval: &'a Evaluation,
    pub target_resource: String,
    pub policy_bundle_hash: String,
}

impl ClaimContext<'_> {
    fn base(
        &self,
        interception_point: &str,
        canonical_snapshot_hash: String,
    ) -> Claim {
        Claim {
            action_id: self.action.id.clone(),
            agent_id: self.identity.agent_id.clone(),
            initiating_user: self.identity.initiating_user.clone(),
            interception_point: interception_point.to_string(),
            target_resource: self.target_resource.clone(),
            canonical_snapshot_hash,
            path_summary_hash: None,
            policy_bundle_hash: self.policy_bundle_hash.clone(),
            verdict: self.eval.verdict.as_str().to_string(),
            nonce: self.action.nonce.clone(),
        }
    }

    fn ext(&self, record_phase: &str, observed: &str) -> Result<Extensions, EvidenceError> {
        let snapshot_body_sha256 = match self.eval.snapshot.body_hash() {
            Some(r) => Some(r?),
            None => None,
        };
        Ok(Extensions {
            record_phase: record_phase.to_string(),
            observed: observed.to_string(),
            nonce_source: "guard_minted".to_string(),
            path_summary_hash_absent_because: PATH_SUMMARY_ABSENT.to_string(),
            snapshot_body_sha256,
            transit_condition: self.eval.condition,
            modifications: self.eval.modifications.iter().map(|m| m.render()).collect(),
            response_status: None,
        })
    }

    /// C7.1.2's first record: request received. Written and acknowledged
    /// **before** anything is forwarded, per C7.1.3.
    pub fn before(&self) -> Result<(Claim, Extensions), EvidenceError> {
        let h = self.eval.snapshot.canonical_hash()?;
        Ok((
            self.base("PRE_CALL_TOOL_INVOCATION", h),
            self.ext("before", "request_received")?,
        ))
    }

    /// C7.1.2's middle record, meaning **dispatched**.
    ///
    /// `interception_point` reuses `PRE_CALL_TOOL_INVOCATION` because the
    /// enum has no value between before and after — finding 5 — and
    /// `record_phase` plus `observed` carry the honest meaning. It commits to
    /// the same snapshot as the before-record: the proposed action has not
    /// changed, and adding a dispatch timestamp would put a system clock on a
    /// path every test reaches, which this crate does not do.
    pub fn during(&self) -> Result<(Claim, Extensions), EvidenceError> {
        let h = self.eval.snapshot.canonical_hash()?;
        Ok((
            self.base("PRE_CALL_TOOL_INVOCATION", h),
            self.ext("during", "request_dispatched")?,
        ))
    }

    /// C7.1.2's third record: result returned. Commits to the **response**,
    /// not to the request.
    pub fn after(&self, r: &ResponseSnapshot) -> Result<(Claim, Extensions), EvidenceError> {
        let h = r.canonical_hash()?;
        let mut ext = self.ext("after", "response_relayed")?;
        ext.response_status = Some(r.status());
        Ok((self.base("POST_CALL_TOOL_RESULT", h), ext))
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test claim_shape && cargo test`
Expected: `claim_shape` PASS, 11 tests. The existing suite still PASS, unedited.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add the claim, its extensions, and a sink trait that keeps one code path

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: the `[evidence]` section, parsed alongside `GuardConfig` and never into it

**Files:**
- Modify: `src/guard.rs`, `src/evidence.rs`
- Test: `tests/evidence_config.rs`, `tests/evidence_feature_gate.rs`

**Interfaces:**
- Produces: `evidence::EvidenceConfig`; `guard::parse_evidence(&str) -> Result<Option<EvidenceConfig>, GuardError>`; `guard::load_evidence(&Path) -> Result<Option<EvidenceConfig>, GuardError>`; `guard::GuardError::EvidenceUnsupported`.
- `GuardConfig` gains **no field**, and `parse_config` keeps its exact signature and its `deny_unknown_fields` behaviour for every other key.

The constraint that shapes this task is `tests/guard_wire.rs:76` and `tests/guard_blocks_the_attacks.rs:13`, which construct `GuardConfig` as struct literals. A new field breaks them, in both feature configurations, and the brief is that no existing test may be edited. So `parse_config` removes the `evidence` table from the document before deserializing the rest, and a second function reads that table on its own.

Without the feature, a config carrying `[evidence]` is **refused** rather than ignored. A silently ignored evidence section is a guard that an operator believes is recording and that is not — the same failure shape as a silently ignored typo in a security-relevant key, which `deny_unknown_fields` already exists to prevent.

- [ ] **Step 1: Write the failing tests**

`tests/evidence_config.rs`:

```rust
#![cfg(feature = "evidence")]
//! The evidence section: what it accepts, what it refuses, and what it will
//! not read from the environment.

use transit::guard::{parse_config, parse_evidence, GuardError};

const WITH: &str = r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"

[enforce]
max_body_bytes = 4096

[[route]]
method = "POST"
path_prefix = "/v1/transfer"

[evidence]
socket = "/run/ephemeris/claims.sock"
agent_id = "did:web:example.org:agents:guard-1"
initiating_user = "user:unattended"
ack_timeout_ms = 2000
"#;

#[test]
fn the_rest_of_the_config_parses_exactly_as_before() {
    // Mutation this kills: routing `GuardConfig` through `toml::Value`
    // changing what it accepts. The existing config suite is the real guard
    // on this; here we pin that the sibling table does not disturb it.
    let cfg = parse_config(WITH).expect("a config with [evidence] parses");
    assert_eq!(cfg.listen, "127.0.0.1:8080");
    assert_eq!(cfg.enforce.max_body_bytes, 4096);
    assert_eq!(cfg.route.len(), 1);
    assert!(cfg.enforce.strict_ingestion);
}

#[test]
fn the_evidence_section_is_read_from_the_same_file() {
    let ev = parse_evidence(WITH).unwrap().expect("an [evidence] section");
    assert_eq!(ev.socket, "/run/ephemeris/claims.sock");
    assert_eq!(ev.agent_id, "did:web:example.org:agents:guard-1");
    assert_eq!(ev.initiating_user, "user:unattended");
    assert_eq!(ev.ack_timeout_ms, 2000);
}

#[test]
fn a_config_without_the_section_yields_none() {
    let text = "listen = \"l\"\nupstream = \"u\"\n";
    assert!(parse_evidence(text).unwrap().is_none());
    assert!(parse_config(text).is_ok());
}

#[test]
fn the_evidence_section_rejects_an_unknown_key() {
    // A silently ignored typo in a security-relevant config is a gate that
    // fails open. `socket_path` is the typo an operator actually makes.
    let text = r#"
listen = "l"
upstream = "u"
[evidence]
socket_path = "/run/ephemeris/claims.sock"
agent_id = "a"
initiating_user = "u"
"#;
    assert!(matches!(parse_evidence(text), Err(GuardError::Parse { .. })));
}

#[test]
fn the_evidence_section_refuses_a_missing_identity() {
    // `agent_id` has no default. A guard that invented one would emit records
    // whose identity fields mean nothing, which is the class of defect
    // `poc-audit` was built to find.
    let text = r#"
listen = "l"
upstream = "u"
[evidence]
socket = "/run/ephemeris/claims.sock"
"#;
    assert!(matches!(parse_evidence(text), Err(GuardError::Parse { .. })));
}

#[test]
fn the_ack_timeout_has_a_default_and_it_is_not_zero() {
    // A zero timeout is not "wait forever" to `set_read_timeout`; it is an
    // `EINVAL` at the moment the guard is already committed to blocking.
    let text = r#"
listen = "l"
upstream = "u"
[evidence]
socket = "/run/ephemeris/claims.sock"
agent_id = "a"
initiating_user = "u"
"#;
    let ev = parse_evidence(text).unwrap().unwrap();
    assert!(ev.ack_timeout_ms > 0);
}

#[test]
fn no_evidence_setting_is_reachable_from_the_environment() {
    // The same rule `apply_env_overrides` already enforces for `[enforce]`,
    // for the same reason. `apply_env_overrides` takes a lookup and touches
    // only `listen` and `upstream`; there is no evidence equivalent, and
    // this asserts a hostile lookup changes nothing about the parsed section.
    let mut cfg = parse_config(WITH).unwrap();
    transit::guard::apply_env_overrides(&mut cfg, |_| Some("attacker".into()));
    let ev = parse_evidence(WITH).unwrap().unwrap();
    assert_eq!(ev.socket, "/run/ephemeris/claims.sock");
    assert_eq!(ev.agent_id, "did:web:example.org:agents:guard-1");
    // And the two that *are* overridable took the value, so this is not
    // passing because the lookup went unused.
    assert_eq!(cfg.listen, "attacker");
}
```

`tests/evidence_feature_gate.rs`:

```rust
#![cfg(not(feature = "evidence"))]
//! Without the feature, an evidence section is refused rather than ignored.
//!
//! Mutation this kills: silently dropping the table in a build that cannot
//! act on it, which gives an operator a guard they believe is recording and
//! which is not.

use transit::guard::{parse_config, GuardError};

#[test]
fn a_default_build_refuses_a_config_that_asks_for_evidence() {
    let text = r#"
listen = "l"
upstream = "u"
[evidence]
socket = "/run/ephemeris/claims.sock"
agent_id = "a"
initiating_user = "u"
"#;
    assert!(matches!(
        parse_config(text),
        Err(GuardError::EvidenceUnsupported)
    ));
}

#[test]
fn a_default_build_still_parses_a_config_without_one() {
    assert!(parse_config("listen = \"l\"\nupstream = \"u\"\n").is_ok());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features evidence --test evidence_config && cargo test --test evidence_feature_gate`
Expected: FAIL on both — `parse_evidence` and `GuardError::EvidenceUnsupported` do not exist.

- [ ] **Step 3: Add `EvidenceConfig` to `src/evidence.rs`**

Append to `src/evidence.rs`:

```rust
/// The `[evidence]` table.
///
/// Not a field of `GuardConfig`: that struct is constructed as a literal by
/// tests that must not be edited, and — more durably — the evidence section
/// is a property of the deployment's recording arrangement rather than of the
/// policy, and `policy_bundle_hash` would have had to exclude it anyway.
///
/// **Nothing here is overridable from the environment.** `apply_env_overrides`
/// reaches `listen` and `upstream` and nothing else, and this table is not an
/// exception waiting to be made.
#[cfg(feature = "evidence")]
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    /// The `ephemeris` Unix domain socket. Absent at startup is a
    /// refuse-to-start condition, not a degrade-to-503 one.
    pub socket: String,
    /// Fork 8: static config, one guard one agent, honest about the
    /// limitation. Never a request header.
    pub agent_id: String,
    pub initiating_user: String,
    /// How long to wait for a durable acknowledgement before refusing the
    /// action. C7.2.3's commentary budgets 15 ms per action across three
    /// records; this is the ceiling, not the target.
    #[serde(default = "default_ack_timeout_ms")]
    pub ack_timeout_ms: u64,
}

#[cfg(feature = "evidence")]
fn default_ack_timeout_ms() -> u64 {
    2000
}
```

- [ ] **Step 4: Change `parse_config` and add `parse_evidence` in `src/guard.rs`**

Add a variant to `GuardError`:

```rust
    #[error(
        "this build has no evidence support and the config asks for it. \
         Rebuild with `--features evidence`, or remove the [evidence] section. \
         Ignoring it would give you a guard you believe is recording and that is not."
    )]
    EvidenceUnsupported,
```

Replace `parse_config` with:

```rust
pub fn parse_config(text: &str) -> Result<GuardConfig, GuardError> {
    let mut doc: toml::Table = toml::from_str(text).map_err(|source| GuardError::Parse {
        path: "<config>".to_string(),
        source,
    })?;
    // `[evidence]` is parsed alongside `GuardConfig` and never into it. Two
    // reasons, and the second is the durable one: `GuardConfig` is
    // constructed as a struct literal by tests that must not be edited, and
    // the recording arrangement is not policy — `policy_bundle_hash` would
    // have had to exclude it in any case.
    //
    // `cfg!` rather than `#[cfg]` so there is one statement here in both
    // builds, and no `unused_mut` for clippy to reject.
    if doc.remove("evidence").is_some() && !cfg!(feature = "evidence") {
        return Err(GuardError::EvidenceUnsupported);
    }
    let cfg: GuardConfig =
        toml::Value::Table(doc)
            .try_into()
            .map_err(|source| GuardError::Parse {
                path: "<config>".to_string(),
                source,
            })?;
    if !cfg.enforce.strict_ingestion {
        return Err(GuardError::StrictIngestionOff);
    }
    Ok(cfg)
}

/// The `[evidence]` table, if there is one.
///
/// Reads the same text `parse_config` read. Deliberately a second pass rather
/// than one function returning a pair: `parse_config` is a shipped signature
/// with existing callers, and a tuple return would have been a breaking change
/// in service of saving one TOML parse of a file read once at startup.
#[cfg(feature = "evidence")]
pub fn parse_evidence(text: &str) -> Result<Option<crate::evidence::EvidenceConfig>, GuardError> {
    let doc: toml::Table = toml::from_str(text).map_err(|source| GuardError::Parse {
        path: "<config>".to_string(),
        source,
    })?;
    match doc.get("evidence") {
        None => Ok(None),
        Some(v) => {
            let ev: crate::evidence::EvidenceConfig =
                v.clone().try_into().map_err(|source| GuardError::Parse {
                    path: "<config>[evidence]".to_string(),
                    source,
                })?;
            Ok(Some(ev))
        }
    }
}

#[cfg(feature = "evidence")]
pub fn load_evidence(path: &Path) -> Result<Option<crate::evidence::EvidenceConfig>, GuardError> {
    let text = std::fs::read_to_string(path).map_err(|source| GuardError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_evidence(&text).map_err(|e| match e {
        GuardError::Parse { source, .. } => GuardError::Parse {
            path: path.display().to_string(),
            source,
        },
        other => other,
    })
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cargo test --features evidence --test evidence_config
cargo test --test evidence_feature_gate
cargo test && cargo test --features evidence
```
Expected: 7 tests, then 2 tests, then the whole suite in both configurations, all unedited.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Parse [evidence] alongside GuardConfig, and refuse it outright without the feature

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: the UDS client, and write-before-forward asserted at the upstream

**Files:**
- Modify: `src/evidence.rs`, `src/guard.rs`
- Create: `tests/stub_ephemeris/mod.rs`
- Test: `tests/write_before_forward.rs`

**Interfaces:**
- Produces: `evidence::UdsSink` with `connect_or_refuse(&EvidenceConfig) -> Result<UdsSink, EvidenceError>`; `ClaimSink::identity(&self) -> Option<&Identity>`; `guard::serve_with(&GuardConfig, Arc<dyn ClaimSink>) -> Result<(), GuardError>`; `guard::serve` unchanged, delegating with a `NoEvidence` sink.

**The wire protocol, defined here because `ephemeris`'s UDS listener does not exist yet.** Its own plan ends at a CLI and puts the listener first in Phase 2. This is therefore a protocol *proposal* that Phase 2 must adopt, and it is deliberately the smallest thing that works: no `tokio`, no `hyper`, no framing library, no new dependency on either side.

```
client → server   one line: {"claim":{...},"transit_extensions":{...}}\n
server → client   one line: {"ok":true,"step_index":N,"chain_head":"<hex>"}\n
                        or: {"ok":false,"error":"<why>"}\n
                  then the server closes.
```

One connection per claim. Blocking. `ephemeris` acknowledges after `fsync` and never before, so **the ack is the mechanism** by which the guard learns it may proceed; nothing else needs verifying on this side. Concurrent connections are what `ephemeris`'s group commit batches, and the guard's thread-per-request model feeds that naturally — 256 in-flight requests present up to 256 concurrent claims to one flush.

**Two notes for whoever implements the `ephemeris` side.** First, `ephemeris::record::Claim` is `deny_unknown_fields`, so `transit_extensions` must be a sibling of `claim` in the envelope, not a member of it; if `ephemeris` discards the sibling, the ten fields still arrive and the extensions are lost. Second, `ephemeris`'s `Claim` has `path_summary_hash: Option<String>` with `#[serde(default)]`, so a `null` is accepted — the design's fear that the pair would produce **no record at all** does not materialise against the shipped contract, and fork 4 is cheaper than it was written to be.

- [ ] **Step 1: Write the stub and the failing test**

`tests/stub_ephemeris/mod.rs`:

```rust
#![allow(dead_code)]
//! A stub `ephemeris` over a Unix domain socket, and a recording upstream.
//! Fully offline: no network, no credentials, no `ephemeris` binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum Behaviour {
    /// Acknowledge after "durability", which the stub simulates by replying.
    Ack,
    /// Accept the connection and refuse the claim, the way `ephemeris` refuses
    /// a claim missing a caller-supplied field.
    Refuse,
    /// Read the claim and never answer. The guard must time out and refuse.
    Silent,
}

pub struct Stub {
    dir: PathBuf,
    pub socket: PathBuf,
    received: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Stub {
    /// The socket path is kept short on purpose: `sun_path` is 104 bytes on
    /// macOS and a long temp directory plus a descriptive filename overruns it
    /// with a confusing `EINVAL`.
    pub fn start(name: &str, behaviour: Behaviour) -> Stub {
        let dir = std::env::temp_dir().join(format!("tg-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("stub dir");
        let socket = dir.join("e.sock");
        let listener = UnixListener::bind(&socket).expect("bind the stub socket");
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let rx_received = received.clone();
        let rx_stop = stop.clone();
        std::thread::spawn(move || {
            let mut step = 0u64;
            for conn in listener.incoming() {
                if rx_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut s) = conn else { return };
                let mut line = String::new();
                let mut r = BufReader::new(s.try_clone().expect("clone the stub stream"));
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                if let Ok(mut v) = rx_received.lock() {
                    v.push(line.trim().to_string());
                }
                match behaviour {
                    Behaviour::Ack => {
                        let reply = format!(
                            "{{\"ok\":true,\"step_index\":{step},\"chain_head\":\"{}\"}}\n",
                            "00".repeat(32)
                        );
                        step += 1;
                        let _ = s.write_all(reply.as_bytes());
                    }
                    Behaviour::Refuse => {
                        let _ = s.write_all(
                            b"{\"ok\":false,\"error\":\"claim refused: unknown field\"}\n",
                        );
                    }
                    Behaviour::Silent => {
                        // Hold the connection open, answering nothing. The
                        // guard's read timeout is the only thing that ends it.
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
            }
        });

        Stub {
            dir,
            socket,
            received,
            stop,
        }
    }

    /// Every envelope the stub has been handed, parsed.
    pub fn envelopes(&self) -> Vec<serde_json::Value> {
        self.received
            .lock()
            .map(|v| {
                v.iter()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.received.lock().map(|v| v.len()).unwrap_or(0)
    }

    /// Stop listening and delete the socket, so a later connect fails the way
    /// a crashed `ephemeris` would.
    pub fn kill(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A one-shot upstream that records the request head and body verbatim.
/// Copied in shape from `tests/guard_wire.rs`, because the only convincing
/// form of the write-before-forward test is one asserted at the upstream.
pub fn recording_upstream(reply: &'static str) -> (u16, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { return };
            let Ok(clone) = s.try_clone() else { return };
            let mut r = BufReader::new(clone);
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let len: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            head.push_str(&String::from_utf8_lossy(&body));
            let _ = tx.send(head);
            let _ = s.write_all(reply.as_bytes());
        }
    });
    (port, rx)
}

/// Bind a guard on a free port with the given sink, and wait until it accepts.
pub fn guard_on(
    upstream_port: u16,
    sink: Arc<dyn transit::evidence::ClaimSink>,
) -> u16 {
    for _ in 0..20 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let cfg = transit::guard::GuardConfig {
            listen: format!("127.0.0.1:{port}"),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            enforce: transit::guard::Enforcement::default(),
            route: Vec::new(),
        };
        let sink = sink.clone();
        std::thread::spawn(move || {
            let _ = transit::guard::serve_with(&cfg, sink);
        });
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return port;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    panic!("could not stand a guard up on any probed port");
}

/// Send one request and return `(status, body)`.
pub fn send(port: u16, head: &str, body: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to the guard");
    s.set_read_timeout(Some(Duration::from_secs(15))).expect("timeout");
    let req = format!(
        "{head}\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).expect("write the request");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let status = out
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, out)
}
```

`tests/write_before_forward.rs`:

```rust
#![cfg(all(unix, feature = "evidence"))]
//! C7.1.3: the gateway does not forward the action to the tool until the
//! before record is durably written.
//!
//! **Asserted at the upstream, not at the guard.** The only convincing form
//! of this test is that the effect did not happen. A test that checked the
//! guard's own state would pass for a guard that emitted the claim after
//! forwarding.

mod stub_ephemeris;

use std::sync::Arc;
use std::time::Duration;
use stub_ephemeris::{guard_on, recording_upstream, send, Behaviour, Stub};
use transit::evidence::{ClaimSink, EvidenceConfig, UdsSink};

const OK_REPLY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

fn sink(stub: &Stub, timeout_ms: u64) -> Arc<dyn ClaimSink> {
    let cfg = EvidenceConfig {
        socket: stub.socket.display().to_string(),
        agent_id: "did:web:example.org:agents:guard-1".into(),
        initiating_user: "user:unattended".into(),
        ack_timeout_ms: timeout_ms,
    };
    Arc::new(UdsSink::connect_or_refuse(&cfg).expect("the stub socket is live"))
}

const CONFORMING: &str = "POST /v1/transfer HTTP/1.1\r\n\
     Content-Type: application/json\r\n\
     Idempotency-Key: k1\r\n\
     If-Match: 0";

#[test]
fn without_an_acknowledgement_the_upstream_receives_nothing() {
    // Mutation this kills: an ack that precedes durability, or a forward that
    // precedes an ack. Either removes C7.1.3 entirely, and neither is visible
    // from anywhere except the upstream.
    let stub = Stub::start("wbf-silent", Behaviour::Silent);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub, 300));

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 503, "an unacknowledged claim must refuse the action");
    assert!(
        rx.recv_timeout(Duration::from_millis(750)).is_err(),
        "the upstream received a request whose before-record was never acknowledged"
    );
    // And the claim really was sent, so the test is not passing because the
    // guard never tried.
    assert_eq!(stub.count(), 1, "the guard did not emit a before-record");
}

#[test]
fn with_an_acknowledgement_the_upstream_receives_the_request() {
    // The negative control. Without it, a guard that refused everything would
    // pass the test above.
    let stub = Stub::start("wbf-ack", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub, 2000));

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 200);
    let seen = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the upstream received nothing after a successful ack");
    assert!(seen.contains("POST /v1/transfer"), "{seen}");
    assert!(seen.contains(r#"{"a":1}"#), "{seen}");
}

#[test]
fn a_refused_claim_is_not_a_silent_forward() {
    // Mutation this kills: a claim rejection degrading into a warning. A
    // refused claim is a bug in this component and must not become a retry
    // loop or a shrug.
    let stub = Stub::start("wbf-refuse", Behaviour::Refuse);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub, 2000));

    let (status, body) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 503);
    assert!(
        rx.recv_timeout(Duration::from_millis(750)).is_err(),
        "a refused claim still forwarded the action"
    );
    assert!(!body.contains("upstream"), "the 503 must not blame the upstream: {body}");
}

#[test]
fn the_before_record_is_emitted_before_the_forward_and_not_after() {
    // Ordering, asserted directly: with the stub silent the upstream sees
    // nothing, and the stub still holds exactly one envelope. A guard that
    // emitted after forwarding would show the reverse.
    let stub = Stub::start("wbf-order", Behaviour::Silent);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub, 300));
    let _ = send(port, CONFORMING, r#"{"a":1}"#);

    let envelopes = stub.envelopes();
    assert_eq!(envelopes.len(), 1);
    let claim = envelopes[0].get("claim").expect("an envelope carries a claim");
    assert_eq!(
        claim.get("interception_point").and_then(|v| v.as_str()),
        Some("PRE_CALL_TOOL_INVOCATION")
    );
    assert_eq!(
        envelopes[0]
            .get("transit_extensions")
            .and_then(|e| e.get("record_phase"))
            .and_then(|v| v.as_str()),
        Some("before")
    );
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn a_denial_also_blocks_on_its_records_durability() {
    // Fork 7: block. A lost ALLOW record is an unevidenced effect and a lost
    // DENY record is an unevidenced probe — and the probe is the
    // reconnaissance phase of the attack this component exists to stop.
    //
    // Mutation this kills: gating only the forward, so a rejection answers
    // its 4xx immediately and an attacker mapping the guard's rules leaves no
    // trace at all.
    let stub = Stub::start("wbf-deny", Behaviour::Silent);
    let (up, _rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub, 300));

    // No Idempotency-Key: a 428 C3 refusal.
    let (status, _) = send(
        port,
        "POST /v1/transfer HTTP/1.1\r\nContent-Type: application/json\r\nIf-Match: 0",
        r#"{"a":1}"#,
    );
    assert_eq!(
        status, 503,
        "a denial whose record was never acknowledged must not answer 428"
    );
    assert_eq!(stub.count(), 1);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --features evidence --test write_before_forward`
Expected: FAIL — `UdsSink` and `serve_with` do not exist.

- [ ] **Step 3: Write `UdsSink` in `src/evidence.rs`**

Add `identity` to the trait and to `NoEvidence`:

```rust
pub trait ClaimSink: Send + Sync {
    fn emit(&self, claim: &Claim, ext: &Extensions) -> Result<Ack, EvidenceError>;
    fn enabled(&self) -> bool;
    fn counters(&self) -> &Counters;
    /// Who the guard says it is, from static config. `None` when nothing is
    /// emitted, which is why claim construction is skipped for `NoEvidence`.
    fn identity(&self) -> Option<&Identity>;
}
```

`NoEvidence` gains `fn identity(&self) -> Option<&Identity> { None }`.

Append to `src/evidence.rs`:

```rust
/// The envelope on the wire. `transit_extensions` is a **sibling** of
/// `claim`, not a member: `ephemeris::record::Claim` is `deny_unknown_fields`
/// and would refuse an eleventh member outright.
#[cfg(all(unix, feature = "evidence"))]
#[derive(Serialize)]
struct Envelope<'a> {
    claim: &'a Claim,
    transit_extensions: &'a Extensions,
}

/// The acknowledgement, decoded permissively.
///
/// Not `deny_unknown_fields`: `ephemeris` adding a field to its response must
/// not turn every request into a 503. The two fields this side needs are
/// optional so a malformed ack is an error rather than a panic.
#[cfg(all(unix, feature = "evidence"))]
#[derive(serde::Deserialize)]
struct AckWire {
    ok: bool,
    #[serde(default)]
    step_index: Option<u64>,
    #[serde(default)]
    chain_head: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// A blocking, one-connection-per-claim client for `ephemeris`.
///
/// One connection per claim rather than a pooled or multiplexed one, for two
/// reasons: `ephemeris` group-commits, so concurrent connections are exactly
/// what it wants to batch, and a shared connection behind a mutex would
/// serialize the claims of 256 in-flight requests into one queue, which is
/// the opposite of what C7.2.3's budget needs.
#[cfg(all(unix, feature = "evidence"))]
pub struct UdsSink {
    path: std::path::PathBuf,
    timeout: std::time::Duration,
    identity: Identity,
    counters: Counters,
}

#[cfg(all(unix, feature = "evidence"))]
impl UdsSink {
    /// Connect once, now, or refuse to start.
    ///
    /// A real `connect`, not an `exists`: a stale socket file left behind by a
    /// crashed `ephemeris` exists and refuses every connection, and a guard
    /// that started against one would 503 every request for as long as nobody
    /// noticed. Failing here is louder and cheaper.
    pub fn connect_or_refuse(cfg: &EvidenceConfig) -> Result<Self, EvidenceError> {
        if cfg.ack_timeout_ms == 0 {
            return Err(EvidenceError::Refused(
                "ack_timeout_ms = 0 is not `wait forever`; it is EINVAL at the moment the guard \
                 is already committed to blocking"
                    .to_string(),
            ));
        }
        let path = std::path::PathBuf::from(&cfg.socket);
        let probe = std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
            EvidenceError::Unreachable {
                path: cfg.socket.clone(),
                detail: e.to_string(),
            }
        })?;
        drop(probe);
        Ok(Self {
            path,
            timeout: std::time::Duration::from_millis(cfg.ack_timeout_ms),
            identity: Identity {
                agent_id: cfg.agent_id.clone(),
                initiating_user: cfg.initiating_user.clone(),
            },
            counters: Counters::default(),
        })
    }

    fn io(&self, e: std::io::Error) -> EvidenceError {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                EvidenceError::Timeout {
                    ms: self.timeout.as_millis() as u64,
                }
            }
            _ => EvidenceError::Unreachable {
                path: self.path.display().to_string(),
                detail: e.to_string(),
            },
        }
    }
}

#[cfg(all(unix, feature = "evidence"))]
impl ClaimSink for UdsSink {
    fn emit(&self, claim: &Claim, ext: &Extensions) -> Result<Ack, EvidenceError> {
        use std::io::{BufRead, BufReader, Write};
        let mut s = std::os::unix::net::UnixStream::connect(&self.path).map_err(|e| {
            EvidenceError::Unreachable {
                path: self.path.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        s.set_write_timeout(Some(self.timeout)).map_err(|e| self.io(e))?;
        s.set_read_timeout(Some(self.timeout)).map_err(|e| self.io(e))?;

        let line = serde_json::to_string(&Envelope {
            claim,
            transit_extensions: ext,
        })
        .map_err(|e| EvidenceError::BadAck(e.to_string()))?;
        s.write_all(line.as_bytes()).map_err(|e| self.io(e))?;
        s.write_all(b"\n").map_err(|e| self.io(e))?;
        s.flush().map_err(|e| self.io(e))?;

        let mut resp = String::new();
        let mut r = BufReader::new(&s);
        match r.read_line(&mut resp) {
            Ok(0) => {
                return Err(EvidenceError::BadAck(
                    "the evidence store closed the connection without acknowledging".to_string(),
                ))
            }
            Ok(_) => {}
            Err(e) => return Err(self.io(e)),
        }

        let a: AckWire = serde_json::from_str(resp.trim())
            .map_err(|e| EvidenceError::BadAck(format!("{e}: {}", resp.trim())))?;
        if !a.ok {
            // Logged verbatim by the caller. A refused claim is a bug in this
            // component, and swallowing the reason makes it an unfindable one.
            return Err(EvidenceError::Refused(
                a.error.unwrap_or_else(|| "no reason given".to_string()),
            ));
        }
        Ok(Ack {
            step_index: a.step_index.unwrap_or_default(),
            chain_head: a.chain_head.unwrap_or_default(),
        })
    }

    fn enabled(&self) -> bool {
        true
    }

    fn counters(&self) -> &Counters {
        &self.counters
    }

    fn identity(&self) -> Option<&Identity> {
        Some(&self.identity)
    }
}
```

- [ ] **Step 4: Thread the sink through `serve` and `handle_one`**

In `src/guard.rs`, add the import:

```rust
use crate::evidence::{Action, ClaimContext, ClaimSink, NoEvidence};
use std::sync::Arc;
```

Replace `pub fn serve` with:

```rust
/// The shipped entry point. Unchanged signature, unchanged behaviour: a guard
/// with no `[evidence]` section emits nothing and behaves as it does today.
pub fn serve(cfg: &GuardConfig) -> Result<(), GuardError> {
    serve_with(cfg, Arc::new(NoEvidence::default()))
}

/// `serve`, with somewhere to send claims.
pub fn serve_with(cfg: &GuardConfig, sink: Arc<dyn ClaimSink>) -> Result<(), GuardError> {
    // Computed once. It is a pure function of the config, the config does not
    // reload, and recomputing a SHA-256 over the whole policy projection on
    // every request would put a measurable cost on the default build's hot
    // path for no gain.
    let bundle = crate::policy::bundle_hash(cfg)
        .map_err(|e| GuardError::Bind {
            addr: cfg.listen.clone(),
            detail: format!("the policy bundle has no canonical form: {e}"),
        })?;

    let server = tiny_http::Server::http(&cfg.listen).map_err(|e| GuardError::Bind {
        addr: cfg.listen.clone(),
        detail: e.to_string(),
    })?;
    println!("{}", banner(cfg, sink.as_ref()));

    let cfg = Arc::new(cfg.clone());
    let bundle: Arc<str> = Arc::from(bundle.as_str());
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .redirects(0)
        .build();
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    while let Ok(raw) = server.recv() {
        match try_admit(&inflight, cfg.enforce.max_concurrent_requests) {
            Some(permit) => {
                let cfg = cfg.clone();
                let agent = agent.clone();
                let sink = sink.clone();
                let bundle = bundle.clone();
                std::thread::spawn(move || {
                    let _permit = permit;
                    handle_one(&cfg, &agent, sink.as_ref(), &bundle, raw);
                });
            }
            None => {
                // Shedding is an **unevidenced refusal**: `decide` never ran,
                // so there is no snapshot, no verdict and no record. That is
                // correct — the request was never intercepted — and it means
                // the evidence log undercounts refusals, so it is counted
                // here and reported rather than recorded per-request.
                sink.counters()
                    .shed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = raw.respond(json_response(
                    503,
                    r#"{"error":"transit guard is at capacity"}"#,
                ));
            }
        }
    }
    Ok(())
}

/// The startup line, extracted so it is testable.
pub fn banner(cfg: &GuardConfig, sink: &dyn ClaimSink) -> String {
    let evidence = if sink.enabled() {
        "evidence: claims emitted to ephemeris, fail-closed (no ack, no action)"
    } else {
        "evidence: not configured; this guard records nothing"
    };
    format!(
        "transit guard on http://{} → {}\nfail-closed: strict I-JSON ingestion; \
         idempotency key {}; state precondition {}; at most {} requests in flight\n{}\n\
         NOT A PATH-AWARE AUTHORIZATION POINT — this guard holds no per-agent path state, \
         so it does not claim C4.1.7 and emits path_summary_hash as null. See P04.",
        cfg.listen,
        cfg.upstream,
        if cfg.enforce.require_idempotency_key {
            "required"
        } else {
            "not required"
        },
        if cfg.enforce.require_state_precondition {
            "required"
        } else {
            "not required"
        },
        cfg.enforce.max_concurrent_requests,
        evidence,
    )
}
```

Change `handle_one`'s signature and its decision block. The framing checks above it are untouched.

```rust
fn handle_one(
    cfg: &GuardConfig,
    agent: &ureq::Agent,
    sink: &dyn ClaimSink,
    bundle: &str,
    mut raw: tiny_http::Request,
) {
    // ... every framing check unchanged, up to and including the construction
    // of `req` ...

    let (decision, eval) = decide_with_snapshot(cfg, &req);
    let response = dispatch(cfg, agent, sink, bundle, &req, decision, eval);
    let _ = raw.respond(response);
}

/// `503`, and deliberately **not** `502`.
///
/// `502` means "upstream unreachable" and would be a lie about which
/// component failed. An operator debugging a `502` looks at the ledger; an
/// operator debugging this needs to look at `ephemeris`.
fn evidence_unavailable() -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        503,
        r#"{"error":"evidence store unavailable","detail":"no record, no action"}"#,
    )
}

fn dispatch(
    cfg: &GuardConfig,
    agent: &ureq::Agent,
    sink: &dyn ClaimSink,
    bundle: &str,
    req: &Request,
    decision: Decision,
    eval: Evaluation,
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    // Only built when something will consume it: the snapshot digest costs a
    // SHA-256 and the claim costs two more.
    let action = match sink.identity() {
        Some(_) => match Action::fresh() {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("EVIDENCE ERROR could not mint an action id: {e}");
                return evidence_unavailable();
            }
        },
        None => None,
    };
    let ctx = match (&action, sink.identity()) {
        (Some(a), Some(id)) => Some(ClaimContext {
            action: a,
            identity: id,
            eval: &eval,
            target_resource: eval.snapshot.target_resource(&cfg.upstream),
            policy_bundle_hash: bundle.to_string(),
        }),
        _ => None,
    };

    // C7.1.3, and fork 7: nothing is released — not a forward, not a 4xx —
    // until the before record is durable.
    if let Some(ctx) = &ctx {
        let (claim, ext) = match ctx.before() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("EVIDENCE ERROR could not build the before-record: {e}");
                return evidence_unavailable();
            }
        };
        if let Err(e) = sink.emit(&claim, &ext) {
            eprintln!("EVIDENCE BLOCKED before-record not durable: {e}");
            return evidence_unavailable();
        }
    }

    match decision {
        Decision::Reject {
            status,
            condition,
            reason,
        } => {
            eprintln!(
                "REJECT {} {} [{}] {}",
                sanitize(&req.method),
                sanitize(&req.path),
                condition.map(|c| c.title()).unwrap_or("policy"),
                reason
            );
            let body = format!(
                r#"{{"error":"rejected by transit guard","condition":{},"reason":{}}}"#,
                serde_json::to_string(&condition.map(|c| c.title()))
                    .unwrap_or_else(|_| "null".into()),
                serde_json::to_string(&reason).unwrap_or_else(|_| "\"\"".into())
            );
            json_response(status, &body)
        }
        Decision::Forward(f) => match forward(cfg, agent, &f) {
            Ok(r) => r,
            Err(detail) => json_response(
                502,
                &format!(
                    r#"{{"error":"upstream unreachable","detail":{}}}"#,
                    serde_json::to_string(&sanitize(&detail)).unwrap_or_else(|_| "\"\"".into())
                ),
            ),
        },
    }
}
```

Task 9 adds the during and after records inside the `Decision::Forward` arm.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --features evidence --test write_before_forward && cargo test && cargo test --features evidence`
Expected: `write_before_forward` PASS, 5 tests. Both whole-suite runs PASS, unedited.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Block the action on a durable acknowledgement, asserted at the upstream

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: three records, one action ID, and an honest middle label

**Files:**
- Modify: `src/guard.rs`
- Test: `tests/three_records.rs`

**Interfaces:**
- Changes: `guard::forward` (private) returns `Result<(tiny_http::Response<…>, ResponseSnapshot), String>`.

Fork 6 resolved as **three**, with the middle one meaning *dispatched* and labelled `observed = "request_dispatched"` so nothing reads it as an effect claim. Emitting two and describing them as three would be the failure mode this programme attacks; emitting three and calling the middle one an effect record would be a second one.

**Two places the code shape forces a departure from the design's table, both flagged rather than papered over.**

*The during-record is emitted immediately before `forward` is called, not "after `forward` writes the request".* `forward` uses a blocking `ureq` call that returns only once the upstream has responded, so this process has exactly two observable moments — about-to-write, and response-complete — and there is no seam between them to hook. Emitting before the write is the choice that serves the requirement's stated purpose: a forward which never returns stays distinguishable from one that was never made.

*The during-record carries the same snapshot digest as the before-record, not "the same snapshot plus the dispatch time".* Adding a dispatch time would put a system clock on a path every test reaches, which this crate does not do, and would make the digest non-reproducible. The two records are distinguished by `record_phase` and `observed`, which is where the difference actually lives.

- [ ] **Step 1: Write the failing test**

`tests/three_records.rs`:

```rust
#![cfg(all(unix, feature = "evidence"))]
//! C7.1.2: three records per intercepted action, independently emitted and
//! linkable by one action ID.

mod stub_ephemeris;

use std::sync::Arc;
use std::time::Duration;
use stub_ephemeris::{guard_on, recording_upstream, send, Behaviour, Stub};
use transit::evidence::{ClaimSink, EvidenceConfig, UdsSink};

const OK_REPLY: &str =
    "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nETag: \"v2\"\r\nConnection: close\r\n\r\n{\"ok\":1}\n";

const CONFORMING: &str = "POST /v1/transfer HTTP/1.1\r\n\
     Content-Type: application/json\r\n\
     Idempotency-Key: k1\r\n\
     If-Match: 0";

fn sink(stub: &Stub) -> Arc<dyn ClaimSink> {
    Arc::new(
        UdsSink::connect_or_refuse(&EvidenceConfig {
            socket: stub.socket.display().to_string(),
            agent_id: "did:web:example.org:agents:guard-1".into(),
            initiating_user: "user:unattended".into(),
            ack_timeout_ms: 2000,
        })
        .expect("the stub socket is live"),
    )
}

fn field<'a>(v: &'a serde_json::Value, a: &str, b: &str) -> &'a str {
    v.get(a)
        .and_then(|x| x.get(b))
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing {a}.{b} in {v}"))
}

#[test]
fn a_successful_forward_produces_before_during_and_after() {
    let stub = Stub::start("3r-ok", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub));

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 200);
    rx.recv_timeout(Duration::from_secs(5)).expect("the upstream saw the request");
    std::thread::sleep(Duration::from_millis(300));

    let e = stub.envelopes();
    assert_eq!(e.len(), 3, "expected three records, got {}", e.len());

    let phases: Vec<&str> = e
        .iter()
        .map(|v| field(v, "transit_extensions", "record_phase"))
        .collect();
    assert_eq!(phases, vec!["before", "during", "after"]);

    let observed: Vec<&str> = e
        .iter()
        .map(|v| field(v, "transit_extensions", "observed"))
        .collect();
    assert_eq!(
        observed,
        vec!["request_received", "request_dispatched", "response_relayed"]
    );

    // Finding 5, pinned. The enum has no value for "effect performed" and this
    // component could not honestly emit one if it did: it witnesses a
    // dispatch, not an effect.
    assert_eq!(
        field(&e[1], "claim", "interception_point"),
        "PRE_CALL_TOOL_INVOCATION"
    );
    assert_eq!(
        field(&e[2], "claim", "interception_point"),
        "POST_CALL_TOOL_RESULT"
    );
    for v in &e {
        let text = v.to_string();
        assert!(
            !text.contains("effect_performed") && !text.contains("EFFECT"),
            "a record claimed an effect it did not witness: {text}"
        );
    }
}

#[test]
fn the_three_share_one_action_id_and_one_nonce() {
    let stub = Stub::start("3r-link", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub));
    let _ = send(port, CONFORMING, r#"{"a":1}"#);
    let _ = rx.recv_timeout(Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    let e = stub.envelopes();
    assert_eq!(e.len(), 3);
    let ids: std::collections::BTreeSet<&str> =
        e.iter().map(|v| field(v, "claim", "action_id")).collect();
    let nonces: std::collections::BTreeSet<&str> =
        e.iter().map(|v| field(v, "claim", "nonce")).collect();
    assert_eq!(ids.len(), 1, "the three records did not share one action id");
    assert_eq!(nonces.len(), 1);
}

#[test]
fn two_identical_concurrent_requests_get_two_action_ids() {
    // Mutation this kills: deriving the action ID from the request. Two
    // identical requests would then share an ID and collapse two actions into
    // one in the log, which is the linkability property inverted.
    let stub = Stub::start("3r-distinct", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub));

    let handles: Vec<_> = (0..2)
        .map(|_| std::thread::spawn(move || send(port, CONFORMING, r#"{"a":1}"#)))
        .collect();
    for h in handles {
        let (status, _) = h.join().expect("the request thread");
        assert_eq!(status, 200);
    }
    let _ = rx.recv_timeout(Duration::from_secs(5));
    let _ = rx.recv_timeout(Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(400));

    let e = stub.envelopes();
    assert_eq!(e.len(), 6, "expected six records, got {}", e.len());
    let ids: std::collections::BTreeSet<&str> =
        e.iter().map(|v| field(v, "claim", "action_id")).collect();
    assert_eq!(ids.len(), 2, "two actions produced {} ids", ids.len());
}

#[test]
fn a_rejection_produces_exactly_one_record() {
    // C7.1.3 gates the forward, and a rejection has no forward. A during
    // record for an action that was never dispatched would be a fabrication.
    let stub = Stub::start("3r-deny", Behaviour::Ack);
    let (up, _rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub));

    let (status, _) = send(
        port,
        "POST /v1/transfer HTTP/1.1\r\nContent-Type: application/json\r\nIf-Match: 0",
        r#"{"a":1}"#,
    );
    assert_eq!(status, 428);
    std::thread::sleep(Duration::from_millis(300));

    let e = stub.envelopes();
    assert_eq!(e.len(), 1, "a denial emitted {} records", e.len());
    assert_eq!(field(&e[0], "transit_extensions", "record_phase"), "before");
    assert_eq!(field(&e[0], "claim", "verdict"), "DENY");
    assert_eq!(field(&e[0], "transit_extensions", "transit_condition"), "C3");
}

#[test]
fn the_after_record_commits_to_the_response_the_client_received() {
    let stub = Stub::start("3r-response", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, sink(&stub));
    let _ = send(port, CONFORMING, r#"{"a":1}"#);
    let _ = rx.recv_timeout(Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(300));

    let e = stub.envelopes();
    assert_eq!(e.len(), 3);
    assert_eq!(
        e[2].get("transit_extensions")
            .and_then(|x| x.get("response_status"))
            .and_then(|x| x.as_u64()),
        Some(200)
    );
    // The after record commits to the response; the first two commit to the
    // request. A single digest across all three would mean the after record
    // said nothing about what came back.
    let before = field(&e[0], "claim", "canonical_snapshot_hash");
    let during = field(&e[1], "claim", "canonical_snapshot_hash");
    let after = field(&e[2], "claim", "canonical_snapshot_hash");
    assert_eq!(before, during);
    assert_ne!(before, after);
    assert!(after.starts_with("sha-256:"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --features evidence --test three_records`
Expected: FAIL — only the before-record is emitted, so every count is 1.

- [ ] **Step 3: Make `forward` hand back what it observed**

In `src/guard.rs`, change `forward`'s signature and its tail. Everything between is unchanged.

```rust
fn forward(
    cfg: &GuardConfig,
    agent: &ureq::Agent,
    f: &Forward,
) -> Result<(tiny_http::Response<std::io::Cursor<Vec<u8>>>, ResponseSnapshot), String> {
```

and, replacing the final `Ok(out)`:

```rust
    // Built before the bytes move into the response, and from the same bytes
    // the client will receive — so the after record commits to what was
    // actually relayed rather than to what the upstream was believed to have
    // sent.
    let names: Vec<String> = relayed.iter().map(|(k, _)| k.clone()).collect();
    let observed = ResponseSnapshot::new(status, &names, &bytes);

    let mut out = tiny_http::Response::from_data(bytes).with_status_code(status);
    for (k, v) in relayed {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            out.add_header(h);
        }
    }
    Ok((out, observed))
}
```

Add `ResponseSnapshot` to the `use crate::snapshot::{…}` line at the top of the file.

- [ ] **Step 4: Emit the during and after records in `dispatch`**

Replace the `Decision::Forward` arm of `dispatch`:

```rust
        Decision::Forward(f) => {
            // C7.1.2's middle record, emitted immediately before the socket
            // write. `forward` blocks until the upstream answers, so there is
            // no seam between "wrote the request" and "read the response" to
            // hook; emitting here is what keeps a forward that never returns
            // distinguishable from one that was never made.
            //
            // Best-effort, deliberately. The before-record was the
            // precondition of release and it was met; the socket dying now is
            // a loss to alert on (C7.6.1), not a reason to withhold an action
            // the guard has already been cleared to take.
            if let Some(ctx) = &ctx {
                match ctx.during() {
                    Ok((c, e)) => {
                        if let Err(err) = sink.emit(&c, &e) {
                            lost(sink, "during", &err.to_string());
                        }
                    }
                    Err(err) => lost(sink, "during", &err.to_string()),
                }
            }

            match forward(cfg, agent, &f) {
                Ok((response, observed)) => {
                    // The effect has already been performed. Withholding the
                    // response would not un-perform it, and the action would
                    // still be in the log with a before and no after — which
                    // is exactly what happened.
                    if let Some(ctx) = &ctx {
                        match ctx.after(&observed) {
                            Ok((c, e)) => {
                                if let Err(err) = sink.emit(&c, &e) {
                                    lost(sink, "after", &err.to_string());
                                }
                            }
                            Err(err) => lost(sink, "after", &err.to_string()),
                        }
                    }
                    response
                }
                Err(detail) => {
                    // No after record: the upstream never returned a result,
                    // so there is no result to record. The action has a before
                    // and a during and no after, and that asymmetry is the
                    // fact, not a gap to fill with the guard's own 502.
                    if ctx.is_some() {
                        lost(sink, "after", "the upstream never responded");
                    }
                    json_response(
                        502,
                        &format!(
                            r#"{{"error":"upstream unreachable","detail":{}}}"#,
                            serde_json::to_string(&sanitize(&detail))
                                .unwrap_or_else(|_| "\"\"".into())
                        ),
                    )
                }
            }
        }
```

And add the alerting helper beside `evidence_unavailable`:

```rust
/// C7.6.1: a lost record is alerted, and counted, and never silently dropped.
fn lost(sink: &dyn ClaimSink, phase: &str, why: &str) {
    use std::sync::atomic::Ordering;
    let c = sink.counters();
    match phase {
        "during" => c.lost_during.fetch_add(1, Ordering::SeqCst),
        _ => c.lost_after.fetch_add(1, Ordering::SeqCst),
    };
    eprintln!("EVIDENCE LOSS {phase}-record was not written: {why}");
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --features evidence --test three_records && cargo test && cargo test --features evidence`
Expected: `three_records` PASS, 5 tests. Both whole-suite runs PASS, unedited.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Emit three records per action, with the middle one meaning dispatched and saying so

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: the failure matrix, and the CLI that refuses to start

**Files:**
- Modify: `src/bin/transit.rs`, `tests/stub_ephemeris/mod.rs`
- Test: `tests/evidence_failure_modes.rs`

**Interfaces:**
- Changes: `Cmd::Guard` loads `[evidence]` and builds a `UdsSink`, or refuses to start.

The matrix this task pins, from the design:

| condition | behaviour |
| --- | --- |
| `[evidence]` configured, socket absent at startup | **refuse to start** |
| ack does not arrive within the deadline | `503`, no forward. **Not `502`** |
| `ephemeris` refuses the claim | `503`, no forward, refusal reason logged verbatim |
| socket dies after the before-record was acked | forward proceeds; during and after lost and alerted |
| after-record write fails, effect already performed | relay the response anyway; alerted |
| `[evidence]` absent | claims not emitted; the guard behaves as it does today |

- [ ] **Step 1: Extend the stub**

Append to `tests/stub_ephemeris/mod.rs`:

```rust
/// Acknowledge the first `n` claims, then close every connection without
/// answering. Models `ephemeris` dying mid-action.
pub const ACK_THEN_DIE: &str = "ack_then_die";

/// An upstream that answers, slowly, so a concurrency cap can be tripped.
pub fn slow_upstream(delay_ms: u64, reply: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { return };
            std::thread::spawn(move || {
                let Ok(clone) = s.try_clone() else { return };
                let mut r = BufReader::new(clone);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(delay_ms));
                let _ = s.write_all(reply.as_bytes());
            });
        }
    });
    port
}

/// Like `guard_on`, but with an `Enforcement` a test chose — several of these
/// findings are only observable by actually tripping a bound.
pub fn guard_on_with(
    upstream_port: u16,
    enforce: transit::guard::Enforcement,
    sink: Arc<dyn transit::evidence::ClaimSink>,
) -> u16 {
    for _ in 0..20 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let cfg = transit::guard::GuardConfig {
            listen: format!("127.0.0.1:{port}"),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            enforce: enforce.clone(),
            route: Vec::new(),
        };
        let sink = sink.clone();
        std::thread::spawn(move || {
            let _ = transit::guard::serve_with(&cfg, sink);
        });
        for _ in 0..100 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return port;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    panic!("could not stand a guard up on any probed port");
}
```

Add the `AckN` behaviour. In `Behaviour`, add `AckN(usize)`, and in the accept loop replace the `match behaviour` arms' `Ack` case with a counter-aware one:

```rust
                match behaviour {
                    Behaviour::Ack => reply_ack(&mut s, &mut step),
                    Behaviour::AckN(n) => {
                        if (step as usize) < n {
                            reply_ack(&mut s, &mut step);
                        }
                        // Otherwise close without answering, which is what a
                        // process that died between accept and fsync does.
                    }
                    Behaviour::Refuse => {
                        let _ = s.write_all(
                            b"{\"ok\":false,\"error\":\"claim refused: unknown field\"}\n",
                        );
                    }
                    Behaviour::Silent => {
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
```

with

```rust
fn reply_ack(s: &mut std::os::unix::net::UnixStream, step: &mut u64) {
    let reply = format!(
        "{{\"ok\":true,\"step_index\":{step},\"chain_head\":\"{}\"}}\n",
        "00".repeat(32)
    );
    *step += 1;
    let _ = s.write_all(reply.as_bytes());
}
```

- [ ] **Step 2: Write the failing test**

`tests/evidence_failure_modes.rs`:

```rust
#![cfg(all(unix, feature = "evidence"))]
//! The failure matrix. Every row exists because the fail-open culture across
//! these repositories is strong enough that someone would import it here by
//! reflex.

mod stub_ephemeris;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use stub_ephemeris::{
    guard_on, guard_on_with, recording_upstream, send, slow_upstream, Behaviour, Stub,
};
use transit::evidence::{ClaimSink, EvidenceConfig, EvidenceError, UdsSink};

const OK_REPLY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

const CONFORMING: &str = "POST /v1/transfer HTTP/1.1\r\n\
     Content-Type: application/json\r\n\
     Idempotency-Key: k1\r\n\
     If-Match: 0";

fn ev(socket: String, ms: u64) -> EvidenceConfig {
    EvidenceConfig {
        socket,
        agent_id: "did:web:example.org:agents:guard-1".into(),
        initiating_user: "user:unattended".into(),
        ack_timeout_ms: ms,
    }
}

#[test]
fn an_absent_socket_refuses_to_start() {
    // A guard that starts without its recorder and 503s every request has
    // already failed. Failing at startup is louder and cheaper.
    let missing = std::env::temp_dir().join("tg-does-not-exist/e.sock");
    let e = UdsSink::connect_or_refuse(&ev(missing.display().to_string(), 2000)).unwrap_err();
    assert!(matches!(e, EvidenceError::Unreachable { .. }), "{e}");
}

#[test]
fn a_stale_socket_file_refuses_to_start() {
    // Mutation this kills: checking `Path::exists` instead of connecting. A
    // socket file left behind by a crashed `ephemeris` exists and refuses
    // every connection, and a guard that started against one would 503 every
    // request until somebody noticed.
    let dir = std::env::temp_dir().join("tg-stale");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("e.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    let e = UdsSink::connect_or_refuse(&ev(path.display().to_string(), 2000)).unwrap_err();
    assert!(matches!(e, EvidenceError::Unreachable { .. }), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_zero_ack_timeout_refuses_to_start() {
    let stub = Stub::start("fm-zero", Behaviour::Ack);
    let e = UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 0)).unwrap_err();
    assert!(matches!(e, EvidenceError::Refused(_)), "{e}");
}

#[test]
fn an_evidence_failure_is_503_and_never_502() {
    // Mutation this kills: collapsing two failure domains, so an operator
    // debugging a 502 goes and looks at a ledger that is perfectly healthy.
    let stub = Stub::start("fm-dead", Behaviour::Ack);
    let (up, rx) = recording_upstream(OK_REPLY);
    let sink: Arc<dyn ClaimSink> = Arc::new(
        UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 500)).unwrap(),
    );
    let port = guard_on(up, sink);

    // The store dies after startup. The upstream is entirely healthy.
    stub.kill();
    std::thread::sleep(Duration::from_millis(100));

    let (status, body) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 503, "{body}");
    assert!(
        body.contains("evidence store unavailable"),
        "the 503 must name the component that failed: {body}"
    );
    assert!(
        !body.contains("upstream unreachable"),
        "the 503 blamed the upstream: {body}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(750)).is_err(),
        "the upstream was contacted despite the evidence failure"
    );
}

#[test]
fn a_refusal_reason_is_logged_verbatim_and_does_not_become_a_retry_loop() {
    // A refused claim is a bug in this component. One 503, one log line, no
    // retries: a retry loop against a store that will refuse the same claim
    // forever is a self-inflicted denial of service.
    let stub = Stub::start("fm-refuse", Behaviour::Refuse);
    let (up, _rx) = recording_upstream(OK_REPLY);
    let sink: Arc<dyn ClaimSink> = Arc::new(
        UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 2000)).unwrap(),
    );
    let port = guard_on(up, sink);

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 503);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        stub.count(),
        1,
        "one refused claim produced {} attempts",
        stub.count()
    );
}

#[test]
fn a_lost_after_record_still_relays_the_response_and_is_counted() {
    // The effect has already been performed. Withholding the response would
    // not un-perform it, and the action is in the log with a before, a during
    // and no after — which is exactly what happened.
    let stub = Stub::start("fm-ack2", Behaviour::AckN(2));
    let (up, rx) = recording_upstream(OK_REPLY);
    let sink: Arc<dyn ClaimSink> = Arc::new(
        UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 500)).unwrap(),
    );
    let port = guard_on(up, sink.clone());

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 200, "the response was withheld for a lost after-record");
    rx.recv_timeout(Duration::from_secs(5)).expect("the upstream saw the request");
    std::thread::sleep(Duration::from_millis(400));

    assert_eq!(
        sink.counters().lost_after.load(Ordering::SeqCst),
        1,
        "the lost after-record was not alerted"
    );
    assert_eq!(sink.counters().lost_during.load(Ordering::SeqCst), 0);
}

#[test]
fn a_socket_that_dies_after_the_before_record_still_forwards() {
    // The ack was the precondition and it was met. Refusing the action now
    // would be fail-closed applied to the wrong moment.
    let stub = Stub::start("fm-ack1", Behaviour::AckN(1));
    let (up, rx) = recording_upstream(OK_REPLY);
    let sink: Arc<dyn ClaimSink> = Arc::new(
        UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 500)).unwrap(),
    );
    let port = guard_on(up, sink.clone());

    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 200);
    rx.recv_timeout(Duration::from_secs(5)).expect("the upstream saw the request");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(sink.counters().lost_during.load(Ordering::SeqCst), 1);
    assert_eq!(sink.counters().lost_after.load(Ordering::SeqCst), 1);
}

#[test]
fn admission_shedding_is_counted_because_it_produces_no_record() {
    // Past `max_concurrent_requests`, `serve` responds 503 without reading a
    // byte or spawning a thread, so `decide` never runs and there is no
    // snapshot, no verdict and no record. That is correct — the request was
    // never intercepted — and it means the log undercounts refusals. An
    // auditor computing a refusal rate from the log alone will be wrong, so
    // the number is reported rather than left implicit.
    let stub = Stub::start("fm-shed", Behaviour::Ack);
    let up = slow_upstream(1500, OK_REPLY);
    let sink: Arc<dyn ClaimSink> = Arc::new(
        UdsSink::connect_or_refuse(&ev(stub.socket.display().to_string(), 4000)).unwrap(),
    );
    let mut enforce = transit::guard::Enforcement::default();
    enforce.max_concurrent_requests = 1;
    let port = guard_on_with(up, enforce, sink.clone());

    let handles: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(move || send(port, CONFORMING, r#"{"a":1}"#)))
        .collect();
    for h in handles {
        let _ = h.join();
    }
    assert!(
        sink.counters().shed.load(Ordering::SeqCst) > 0,
        "nothing was shed with a cap of one and eight concurrent slow requests"
    );
}

#[test]
fn without_an_evidence_section_the_guard_behaves_as_it_does_today() {
    // The last row of the matrix, and the one that keeps `transit` a
    // self-contained research tool.
    use transit::evidence::NoEvidence;
    let (up, rx) = recording_upstream(OK_REPLY);
    let port = guard_on(up, Arc::new(NoEvidence::default()));
    let (status, _) = send(port, CONFORMING, r#"{"a":1}"#);
    assert_eq!(status, 200);
    let seen = rx.recv_timeout(Duration::from_secs(5)).expect("forwarded");
    assert!(seen.contains("X-Transit-Digest"), "{seen}");
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --features evidence --test evidence_failure_modes`
Expected: FAIL — `Behaviour::AckN`, `guard_on_with` and `slow_upstream` are new, and `an_absent_socket_refuses_to_start` may already pass.

- [ ] **Step 4: Wire the CLI**

In `src/bin/transit.rs`, replace the `Cmd::Guard` arm:

```rust
        Cmd::Guard { config } => {
            let cfg = transit::guard::load_config(&config)?;
            serve_guard(&config, &cfg)
        }
```

and add, at the bottom of the file:

```rust
/// Stand the guard up, with or without a recorder.
///
/// Two functions rather than one `#[cfg]`-riddled body, because this is the
/// one place where the two builds genuinely differ: one of them can construct
/// a `UdsSink` and the other cannot.
#[cfg(feature = "evidence")]
fn serve_guard(path: &std::path::Path, cfg: &transit::guard::GuardConfig) -> anyhow::Result<()> {
    use std::sync::Arc;
    use transit::evidence::{ClaimSink, NoEvidence, UdsSink};
    let sink: Arc<dyn ClaimSink> = match transit::guard::load_evidence(path)? {
        // `connect_or_refuse` is the refuse-to-start gate: a configured
        // recorder that cannot be reached is a startup failure, not a
        // per-request one.
        Some(ev) => Arc::new(UdsSink::connect_or_refuse(&ev)?),
        None => Arc::new(NoEvidence::default()),
    };
    transit::guard::serve_with(cfg, sink)?;
    Ok(())
}

#[cfg(not(feature = "evidence"))]
fn serve_guard(_path: &std::path::Path, cfg: &transit::guard::GuardConfig) -> anyhow::Result<()> {
    transit::guard::serve(cfg)?;
    Ok(())
}
```

`EvidenceError` needs to reach `anyhow`, which it does through `thiserror`'s `std::error::Error`.

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cargo test --features evidence --test evidence_failure_modes
cargo test && cargo test --features evidence
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features evidence -- -D warnings
cargo fmt --check
```
Expected: 9 tests, both suites green and unedited, clippy clean in both configurations.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Pin the failure matrix: 503 never 502, refuse to start, and count what is not recorded

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: what is real, what is modelled, and what is not claimed

**Files:**
- Modify: `README.md`, `docs/USING.md`, `docs/DEPLOYING.md`, `examples/guard.toml`, `.github/workflows/ci.yml`
- Test: `tests/banner.rs`

**Interfaces:**
- None. This is the task where the tool says out loud what it does not do.

- [ ] **Step 1: Write the failing test**

`tests/banner.rs`:

```rust
//! The startup banner is the one place every operator reads. What it does not
//! say, nobody knows.

use std::sync::Arc;
use transit::evidence::{ClaimSink, NoEvidence};
use transit::guard::{banner, Enforcement, GuardConfig};

fn cfg() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:8080".into(),
        upstream: "http://127.0.0.1:8787".into(),
        enforce: Enforcement::default(),
        route: Vec::new(),
    }
}

#[test]
fn the_banner_says_this_is_not_a_path_aware_authorization_point() {
    // Fork 4's other half. Shipping `path_summary_hash` unfilled is only
    // honest if the omission is visible where somebody will see it, rather
    // than in a footnote of a design document.
    //
    // Mutation this kills: quietly dropping the disclaimer once the records
    // start flowing and the field's absence stops being noticeable.
    let sink: Arc<dyn ClaimSink> = Arc::new(NoEvidence::default());
    let text = banner(&cfg(), sink.as_ref());
    assert!(text.contains("NOT A PATH-AWARE AUTHORIZATION POINT"), "{text}");
    assert!(text.contains("C4.1.7"), "{text}");
    assert!(text.contains("path_summary_hash"), "{text}");
    assert!(text.contains("P04"), "{text}");
}

#[test]
fn the_banner_says_whether_anything_is_being_recorded() {
    let sink: Arc<dyn ClaimSink> = Arc::new(NoEvidence::default());
    let text = banner(&cfg(), sink.as_ref());
    assert!(text.contains("records nothing"), "{text}");
    // And the existing promises survive.
    assert!(text.contains("fail-closed"), "{text}");
    assert!(text.contains("127.0.0.1:8080"), "{text}");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test --test banner`
Expected: PASS, 2 tests — Task 8 already wrote `banner`. If it fails, `banner` dropped a line it must carry.

- [ ] **Step 3: Extend `README.md`'s "What is real and what is modelled"**

That section already exists and leads. Add to it, verbatim:

> **Evidence claims (`--features evidence`) are real and partial.** With an
> `[evidence]` section, `transit guard` emits three claims per intercepted
> action to `ephemeris` over a Unix domain socket and does not forward until
> the first is durably acknowledged. What is real: the action snapshot and its
> digest, the policy bundle hash, the verdict, the target resource, the action
> ID, write-before-forward, and fail-closed behaviour on every evidence
> failure.
>
> What is **not** claimed:
>
> - **`path_summary_hash` is `null`.** This guard is not a path-aware
>   authorization point. `decide` is a pure function of one request; there is
>   no agent identity in the request model, no ordering across the guard's own
>   concurrent threads, and no state that survives a restart. A summary in
>   this process's memory would be cleared by a `SIGTERM`, which is P04's
>   eviction attack with no attack required. C4.1.7 is not claimed.
> - **`agent_id` and `initiating_user` come from static config.** One guard,
>   one agent. That is wrong for any fleet, and it is honest about being
>   wrong. The real answer is a verified RA-TLS peer identity, which needs its
>   own spec. **They are never read from a request header** — the agent
>   asserting its own identity to the component whose job is not to trust it
>   produces a record whose identity fields mean nothing.
> - **The middle of the three records means *dispatched*, not *performed*.**
>   An interception gateway cannot witness an effect. It carries
>   `observed = "request_dispatched"`, and the `interception_point` enum has no
>   value for the middle of C7.1.2's three — see
>   `docs/standard-findings.md` finding 5.
> - **The `nonce` is minted by this guard**, labelled `nonce_source =
>   "guard_minted"`. C7.1.4's challenge comes from the relying party and
>   nothing in this ecosystem issues one; a challenge generated by the party
>   being challenged resists no replay. Finding 8.
> - **A record carries two digests.** `canonical_snapshot_hash` covers the
>   constructed snapshot — method, target, query, body, evaluated headers —
>   and the extension claim `snapshot_body_sha256` covers the canonical body
>   alone, which is what `X-Transit-Digest` carries and what `poc-audit`
>   recomputes. They are not equal and are not meant to be.
> - **Requests shed at admission produce no record.** Past
>   `max_concurrent_requests` the guard refuses without reading a byte, so
>   `decide` never runs. The count is reported; the refusals are not in the
>   log, and a refusal rate computed from the log alone will be low.
> - **Transport framing refusals produce no record.** `Transfer-Encoding`,
>   `Connection: upgrade`, invalid UTF-8 and an over-length body are refused
>   inside `handle_one` before `decide` is called. The line between "not
>   admitted" and "denied" is load-bearing for a compliance number and is
>   drawn here deliberately, not by where the code happens to return.

- [ ] **Step 4: Document the section in `docs/DEPLOYING.md` and `examples/guard.toml`**

Append to `examples/guard.toml`, commented out so the shipped example still runs on a default build:

```toml
# Evidence claims. Requires `cargo build --features evidence`; a default build
# REFUSES a config containing this section rather than ignoring it.
#
# Nothing here is overridable from the environment, the same rule [enforce]
# already follows. If the socket cannot be reached at startup the guard
# refuses to start — it does not start and 503 every request.
#
# [evidence]
# socket = "/run/ephemeris/claims.sock"
# agent_id = "did:web:example.org:agents:transit-guard-1"
# initiating_user = "user:unattended"
# ack_timeout_ms = 2000
```

In `docs/DEPLOYING.md`, add a section stating: the guard is fail-closed on evidence, so `ephemeris` becomes a hard dependency of the request path; an `ephemeris` outage is a full outage of everything behind this guard, by design and per C7.1.3; the mitigation for a garbage flood is `max_concurrent_requests` at admission, not a relaxation at the record.

- [ ] **Step 5: Extend CI to both configurations**

In `.github/workflows/ci.yml`, add to the existing job (or add a second job) so that all of the following run on push and pull request:

```yaml
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo clippy --all-targets --features evidence -- -D warnings
      - run: cargo test
      - run: cargo test --features evidence
```

A default-build-only CI would let the evidence path rot silently, which is the failure this whole plan is written against.

- [ ] **Step 6: Run everything**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features evidence -- -D warnings
cargo test
cargo test --features evidence
```
Expected: all green, and `git status` shows **no modifications to any pre-existing test file**. Verify that last claim explicitly:

```bash
git diff --stat master -- tests/acceptance.rs tests/guard_blocks_the_attacks.rs \
    tests/guard_wire.rs tests/model_fidelity.rs tests/robustness.rs
```
Expected: empty output. If it is not empty, the opt-in constraint was violated somewhere and the violation must be fixed rather than accepted.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Say plainly what these records do not claim, and run CI in both configurations

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## What this plan does not do

**The `poc-audit` cross-check.** The design's build-order step 7: a claim this guard emits, chained by `ephemeris`, driving `poc-audit`'s `field/canonical` off `UNCHECKED` against the same payload. It needs released tags of two other repositories and `ephemeris`'s UDS listener, which is the first task of that tool's Phase 2. It is the test that would catch the one thing every test here cannot: that the definition of `canonical_snapshot_hash` chosen here is not the one the auditor recomputes. Until it exists, the mitigation is that `snapshot_body_sha256` carries the value `poc-audit` *does* recompute, so the seam has a matching pair even if the primary field does not.

**A load-bearing path summary.** Fork 4's option C — a per-agent summary the guard maintains and `decide` consults, bounded by lattice height rather than truncation, durable across restarts. That is the research P04 asks for and belongs in its own spec. It needs agent identity, which needs fork 8's real answer, which needs the `parallax-proxy` composition, which is itself the unresolved fail-open/fail-closed conflict.

**RA-TLS peer identity.** Fork 8's real answer, and the deployable path this programme already has.

**A wire-protocol agreement with `ephemeris`.** Task 8 defines one and `ephemeris` Phase 2 must adopt it. Until then the only implementation of the server side is the stub in `tests/stub_ephemeris/mod.rs`, and that is a fact worth repeating in a commit message rather than discovering at integration.
