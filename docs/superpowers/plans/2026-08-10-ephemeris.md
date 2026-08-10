# ephemeris Implementation Plan — Phase 1

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ephemeris`, an append-only evidence log that accepts claims from an enforcement point, chains them, builds an RFC 6962 tree over them, signs roots, serves inclusion and consistency proofs, and refuses to acknowledge a claim it has not durably written.

**Architecture:** A single Cargo package exposing a library and an `ephemeris` binary. Records are canonicalized through `transit::jcs` rather than a second canonicalizer. A hash chain gives sequential integrity and an RFC 6962 tree gives inclusion and consistency proofs; a `Topology` trait decides which tree a given agent's leaves land in. Storage is append-only segment files with group commit, and acknowledgement happens strictly after `fsync`. Signing is behind a trait whose Phase 1 implementation is a clearly-labelled software key.

**Tech Stack:** Rust 2021, `sha2` 0.10, `serde` + `serde_json` + `toml`, `clap` 4 (derive), `thiserror`, `anyhow`, `hex` 0.4, `ed25519-dalek` 2 (software signer), `hyper` 1 + `hyper-util` + `tokio` (UDS listener), `humantime`.

**Phase 2, deliberately not in this plan:** the TEE signer behind its cargo feature, `bench` (throughput and linkability across topologies), and the `poc-audit` cross-check that requires a released tag of this repo. Phase 1 ends with a working, durable, software-signed log that resists the A9 rewrite.

---

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**.
- **`#![forbid(unsafe_code)]` in `src/lib.rs`.**
- `cargo clippy --all-targets -- -D warnings` must be clean. Warnings are errors.
- Library errors use `thiserror`; the binary uses `anyhow`. Errors print with `{e}`, never `{e:#}`.
- **No panics on malformed input.** Every parse, index, and lookup path on anything read from a file or a socket returns `Result`. No `unwrap`, `expect`, slice indexing, or unchecked integer conversion on such data. Asserted by test in Task 10.
- **Time is always injected, never read from the system clock**, in every function reachable from a test. Follow `parallax`'s existing discipline: pass `now_secs: u64`.
- **Fail-closed. A claim is never acknowledged before its bytes are durable.** This is C7.1.3 and it is the requirement the whole tool exists to satisfy. Any error on the write path refuses the claim. There is no allow-on-error mode, no flag, and no config key. This is the opposite of `occultation-gateway`'s fail-open philosophy, deliberately — the gateway must not take down an API it fronts, whereas this component is a precondition of action release.
- **Any field participating in a value's identity is load-bearing for every comparison downstream.** Wherever this crate derives an identity — a record's canonical digest, a chain head, a leaf hash, a topology's tree key — the derivation is written down explicitly, covers every field that ought to distinguish two values, and is tested **both ways**: semantically identical inputs compare **equal**, and inputs differing in any one contributing field compare **unequal**. Four of `parallax`'s five criticals were failures of exactly this rule; see `docs/parallax-outcomes.md` in the roadmap repository.
- **Every configuration surface rejects unknown keys** via `#[serde(deny_unknown_fields)]`. A silently ignored typo in a security-relevant config is a gate that fails open.
- Exit codes: `0` success, `1` a verification or policy failure, `2` bad input or configuration.
- Licensing: **Apache-2.0 throughout**, in a single `LICENSE` file. Copyright "Advanced AI Society and the Proof-of-Control contributors".
- Upstream tools are pinned by **`rev`**, never by branch, matching `poc-audit`'s `Cargo.toml`.
- Repo is **private** in the `Task-force-for-AI-agents-in-Healthcare` org, cloned to `/Users/jimschwoebel/Desktop/ephemeris`.
- Every test runs **offline**: no network, no credentials, no TEE.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/lib.rs` | crate root, `forbid(unsafe_code)`, module declarations |
| `src/record.rs` | `Claim`, `Record`, canonical form, record digest |
| `src/chain.rs` | `chain_head` derivation and chain verification |
| `src/tree.rs` | RFC 6962 hashing, incremental append, root, proofs |
| `src/verify.rs` | log verification against a **prior published root** |
| `src/store.rs` | append-only segments, group commit, crash recovery |
| `src/topology.rs` | the `Topology` trait and its three implementations |
| `src/sign.rs` | `Signer` trait, software signer, signed roots |
| `src/serve.rs` | the Unix-domain-socket listener and its routes |
| `src/bin/ephemeris.rs` | the CLI |
| `tests/` | integration tests, one file per property |

---

## Task 1: Record, canonical form, and digest

**Files:**
- Create: `Cargo.toml`, `LICENSE`, `.gitignore`, `src/lib.rs`, `src/record.rs`
- Test: `tests/record_identity.rs`

**Interfaces:**
- Produces: `record::Claim`, `record::Record`, `record::canonical(&Record) -> Result<String, RecordError>`, `record::digest(&Record) -> Result<[u8; 32], RecordError>`, `record::RecordError`.

The `Claim` is what an enforcement point sends. The `Record` is what `ephemeris` writes. The split is the T2/T3 boundary from the design: the caller supplies what only it knows, `ephemeris` adds what is a property of the log.

- [ ] **Step 1: Create the package**

```bash
mkdir -p /Users/jimschwoebel/Desktop/ephemeris/src/bin
cd /Users/jimschwoebel/Desktop/ephemeris
git init
```

`Cargo.toml`:

```toml
[package]
name = "ephemeris"
version = "0.1.0"
edition = "2021"
rust-version = "1.90"
license = "Apache-2.0"
description = "An append-only evidence log for Proof-of-Control records"
repository = "https://github.com/Task-force-for-AI-agents-in-Healthcare/ephemeris"

[lib]
name = "ephemeris"
path = "src/lib.rs"

[[bin]]
name = "ephemeris"
path = "src/bin/ephemeris.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
clap = { version = "4", features = ["derive"] }
thiserror = "2"
anyhow = "1"
sha2 = "0.10"
hex = "0.4"
humantime = "2"

transit = { git = "https://github.com/Task-force-for-AI-agents-in-Healthcare/transit.git", rev = "3e10e13" }
```

`.gitignore`:

```
/target
```

- [ ] **Step 2: Write the failing test**

`tests/record_identity.rs`:

```rust
use ephemeris::record::{canonical, digest, Claim, Record};

fn claim() -> Claim {
    Claim {
        action_id: "a-1".into(),
        agent_id: "did:web:example.org:agents:ref-1".into(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: "ALLOW".into(),
    }
}

fn record() -> Record {
    Record::new(claim(), 0, [0u8; 32], 1_700_000_000, "n-1".into())
}

#[test]
fn our_canonical_form_is_rfc_8785_of_the_same_content() {
    // The meaningful version of "order independent". Serializing a Rust
    // struct is trivially ordered by declaration, so comparing two structs
    // proves nothing. This compares our output against the canonical form of
    // the *same content written with its keys shuffled* — which is what a
    // second implementation would hand us.
    let ours = canonical(&record()).unwrap();

    let shuffled = r#"{
        "eat_profile": "https://advancedaisociety.org/poc/v0.1",
        "nonce": "n-1",
        "iat": 1700000000,
        "chain_head": "0000000000000000000000000000000000000000000000000000000000000000",
        "step_index": 0,
        "claim": {
            "verdict": "ALLOW",
            "policy_bundle_hash": "a7713be5",
            "path_summary_hash": null,
            "canonical_snapshot_hash": "54c323d3",
            "target_resource": "/v1/charges",
            "interception_point": "PRE_CALL_TOOL_INVOCATION",
            "initiating_user": "user:alice",
            "agent_id": "did:web:example.org:agents:ref-1",
            "action_id": "a-1"
        }
    }"#;
    let parsed = transit::json::parse_strict(shuffled).unwrap();
    assert_eq!(ours, transit::jcs::canonicalize(&parsed).unwrap());
}

#[test]
fn every_claim_field_contributes_to_the_digest() {
    // The other half of the identity rule: differing in any one field
    // that ought to distinguish two records must change the digest.
    let base = record();
    let base_digest = digest(&base).unwrap();

    let mutators: Vec<(&str, Box<dyn Fn(&mut Claim)>)> = vec![
        ("action_id", Box::new(|c: &mut Claim| c.action_id = "a-2".into())),
        ("agent_id", Box::new(|c: &mut Claim| c.agent_id = "did:web:other".into())),
        ("initiating_user", Box::new(|c: &mut Claim| c.initiating_user = "user:bob".into())),
        ("interception_point", Box::new(|c: &mut Claim| c.interception_point = "TASK_COMPLETION".into())),
        ("target_resource", Box::new(|c: &mut Claim| c.target_resource = "/v1/refunds".into())),
        ("canonical_snapshot_hash", Box::new(|c: &mut Claim| c.canonical_snapshot_hash = "deadbeef".into())),
        ("path_summary_hash", Box::new(|c: &mut Claim| c.path_summary_hash = Some("cafe".into()))),
        ("policy_bundle_hash", Box::new(|c: &mut Claim| c.policy_bundle_hash = "feedface".into())),
        ("verdict", Box::new(|c: &mut Claim| c.verdict = "DENY".into())),
    ];

    for (name, mutate) in mutators {
        let mut c = claim();
        mutate(&mut c);
        let r = Record::new(c, 0, [0u8; 32], 1_700_000_000, "n-1".into());
        assert_ne!(
            digest(&r).unwrap(),
            base_digest,
            "changing {name} did not change the record digest"
        );
    }
}

#[test]
fn log_supplied_fields_also_contribute() {
    let base_digest = digest(&record()).unwrap();
    assert_ne!(digest(&Record::new(claim(), 1, [0u8; 32], 1_700_000_000, "n-1".into())).unwrap(), base_digest);
    assert_ne!(digest(&Record::new(claim(), 0, [1u8; 32], 1_700_000_000, "n-1".into())).unwrap(), base_digest);
    assert_ne!(digest(&Record::new(claim(), 0, [0u8; 32], 1_700_000_001, "n-1".into())).unwrap(), base_digest);
    assert_ne!(digest(&Record::new(claim(), 0, [0u8; 32], 1_700_000_000, "n-2".into())).unwrap(), base_digest);
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --test record_identity`
Expected: FAIL — `ephemeris::record` does not exist.

- [ ] **Step 4: Write the implementation**

`src/lib.rs`:

```rust
#![forbid(unsafe_code)]

pub mod record;
```

`src/record.rs`:

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The EAT profile every record this crate emits declares.
pub const EAT_PROFILE: &str = "https://advancedaisociety.org/poc/v0.1";

/// What an enforcement point sends. Every field here is something only the
/// enforcement point knows: `ephemeris` cannot recompute a verdict it did not
/// make, nor a digest over bytes it never saw.
///
/// `deny_unknown_fields` is not decoration. A claim arriving with a misspelled
/// field must be refused, because accepting it would write a record missing a
/// value the sender believed it had supplied.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub action_id: String,
    pub agent_id: String,
    pub initiating_user: String,
    pub interception_point: String,
    pub target_resource: String,
    pub canonical_snapshot_hash: String,
    /// Optional because no tool computes a bounded path summary yet; see P04.
    /// A record carries `null` rather than a fabricated digest.
    #[serde(default)]
    pub path_summary_hash: Option<String>,
    pub policy_bundle_hash: String,
    pub verdict: String,
}

/// What `ephemeris` writes. The claim, plus the fields that are properties of
/// the log and its trust domain rather than of the action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub claim: Claim,
    pub step_index: u64,
    /// Hex, lowercase. Hex rather than bytes because this is what the evidence
    /// schema's `digest` type is and what a verifier reads.
    pub chain_head: String,
    pub iat: u64,
    pub nonce: String,
    pub eat_profile: String,
}

impl Record {
    pub fn new(
        claim: Claim,
        step_index: u64,
        chain_head: [u8; 32],
        iat: u64,
        nonce: String,
    ) -> Self {
        Self {
            claim,
            step_index,
            chain_head: hex::encode(chain_head),
            iat,
            nonce,
            eat_profile: EAT_PROFILE.to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("could not serialize the record: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("the serialized record was not accepted by the strict decoder: {0}")]
    Decode(#[from] transit::json::JsonError),
    #[error("could not canonicalize the record: {0}")]
    Canonicalize(#[from] transit::jcs::JcsError),
}

/// The RFC 8785 canonical form of a record.
///
/// This routes through `transit`'s canonicalizer rather than a second
/// implementation, and the reason is C7.7's own commentary: two
/// implementations that serialize the same action differently produce
/// different digests, every signature still verifies, nothing looks broken,
/// and the natural next step is to relax the comparison until interoperation
/// works — which silently removes the property the comparison existed to
/// provide.
///
/// Routing through `parse_strict` on the way is a deliberate second benefit:
/// a record that somehow contained a duplicate key or a lone surrogate is
/// refused here rather than written.
pub fn canonical(r: &Record) -> Result<String, RecordError> {
    let text = serde_json::to_string(r)?;
    let parsed = transit::json::parse_strict(&text)?;
    Ok(transit::jcs::canonicalize(&parsed)?)
}

/// SHA-256 over the canonical bytes. This is the leaf datum the tree commits
/// to and the value the chain extends with.
pub fn digest(r: &Record) -> Result<[u8; 32], RecordError> {
    Ok(Sha256::digest(canonical(r)?.as_bytes()).into())
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test record_identity`
Expected: PASS, 3 tests.

- [ ] **Step 6: Add the licence and commit**

Copy `LICENSE` verbatim from `/Users/jimschwoebel/Desktop/transit/LICENSE`.

```bash
git add -A
git commit -m "Add the record type and its canonical form, reusing transit's canonicalizer"
```

---

## Task 2: The hash chain

**Files:**
- Create: `src/chain.rs`
- Modify: `src/lib.rs`
- Test: `tests/chain.rs`

**Interfaces:**
- Consumes: `record::{Record, digest}`.
- Produces: `chain::extend(previous_head: [u8; 32], r: &Record) -> Result<[u8; 32], RecordError>`, `chain::GENESIS: [u8; 32]`, `chain::verify_sequence(records: &[Record]) -> Result<(), ChainError>`, `chain::ChainError`.

The schema defines `chain_head` as `H(previous_head ‖ canonical_snapshot_hash ‖ verdict)`. This crate extends with the **whole record digest** instead, and Step 4's commentary records why and what it means for the standard.

- [ ] **Step 1: Write the failing test**

`tests/chain.rs`:

```rust
use ephemeris::chain::{extend, verify_sequence, ChainError, GENESIS};
use ephemeris::record::{Claim, Record};

fn claim(id: &str) -> Claim {
    Claim {
        action_id: id.into(),
        agent_id: "did:web:example.org:agents:ref-1".into(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: "ALLOW".into(),
    }
}

/// Build a chained run of `n` records the way the store will.
fn run(n: u64) -> Vec<Record> {
    let mut out = Vec::new();
    let mut head = GENESIS;
    for i in 0..n {
        let r = Record::new(claim(&format!("a-{i}")), i, head, 1_700_000_000 + i, format!("n-{i}"));
        head = extend(head, &r).unwrap();
        out.push(r);
    }
    out
}

#[test]
fn a_chain_of_records_verifies() {
    assert!(verify_sequence(&run(8)).is_ok());
}

#[test]
fn altering_a_record_breaks_the_chain() {
    let mut rs = run(8);
    rs[3].claim.verdict = "DENY".into();
    assert!(matches!(
        verify_sequence(&rs),
        Err(ChainError::HeadMismatch { at: 4, .. })
    ));
}

#[test]
fn reordering_two_records_breaks_the_chain() {
    let mut rs = run(8);
    rs.swap(3, 4);
    assert!(verify_sequence(&rs).is_err());
}

#[test]
fn a_gap_in_step_index_is_detected() {
    // C7.3.1 says a gap is an omission. The chain alone would not catch a
    // removed record if the remover also re-linked, so step_index carries
    // its own contiguity check.
    let mut rs = run(8);
    rs.remove(3);
    assert!(matches!(
        verify_sequence(&rs),
        Err(ChainError::StepGap { expected: 3, found: 4 })
    ));
}

#[test]
fn the_first_record_must_chain_from_genesis() {
    let r = Record::new(claim("a-0"), 0, [9u8; 32], 1_700_000_000, "n-0".into());
    assert!(matches!(
        verify_sequence(&[r]),
        Err(ChainError::HeadMismatch { at: 0, .. })
    ));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test chain`
Expected: FAIL — `ephemeris::chain` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod chain;` to `src/lib.rs`.

`src/chain.rs`:

```rust
use crate::record::{digest, Record, RecordError};
use sha2::{Digest, Sha256};

/// The head a chain starts from. All-zero, so a first record's
/// `previous_head` is unambiguous and cannot be confused with a real digest
/// that happened to be produced by an empty input.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// `chain_head_n = H(chain_head_{n-1} ‖ digest(record_n))`.
///
/// **This differs from the schema, deliberately.** The evidence schema defines
/// `chain_head` as `H(previous_head ‖ canonical_snapshot_hash ‖ verdict)` —
/// three fields of the record, not the record. Chaining over only those three
/// leaves every other field unprotected by the chain: `step_index`,
/// `target_resource`, `policy_bundle_hash` and the identity fields could all be
/// altered without breaking a single link.
///
/// Extending with the whole record digest is strictly stronger and costs
/// nothing, since the digest is already computed for the tree leaf. The
/// weaker schema definition is a finding to report upstream rather than a
/// constraint to honour; see the design's "specification gap" section.
pub fn extend(previous_head: [u8; 32], r: &Record) -> Result<[u8; 32], RecordError> {
    let mut h = Sha256::new();
    h.update(previous_head);
    h.update(digest(r)?);
    Ok(h.finalize().into())
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("record {at} declares chain_head {found}, but the chain computes {expected}")]
    HeadMismatch {
        at: usize,
        expected: String,
        found: String,
    },
    #[error("step_index jumps from {expected} to {found}; C7.3.1 treats a gap as an omission")]
    StepGap { expected: u64, found: u64 },
    #[error(transparent)]
    Record(#[from] RecordError),
}

/// Verify that a run of records is internally consistent: each declares the
/// head its predecessor produced, and step indices are contiguous from zero.
///
/// This establishes that **nobody altered the log without re-signing it**. It
/// says nothing about an operator who altered a record and recomputed every
/// subsequent link, which is attack A9 and is `verify::against_root`'s job.
pub fn verify_sequence(records: &[Record]) -> Result<(), ChainError> {
    let mut head = GENESIS;
    for (i, r) in records.iter().enumerate() {
        let want = hex::encode(head);
        if r.chain_head != want {
            return Err(ChainError::HeadMismatch {
                at: i,
                expected: want,
                found: r.chain_head.clone(),
            });
        }
        let expected_step = i as u64;
        if r.step_index != expected_step {
            return Err(ChainError::StepGap {
                expected: expected_step,
                found: r.step_index,
            });
        }
        head = extend(head, r)?;
    }
    Ok(())
}
```

Note the ordering inside the loop: `chain_head` is checked **before** `step_index`, so a record that is both mis-chained and mis-indexed reports the chain failure. The gap test removes a record without touching heads, so it reaches the step check.

Wait — removing `rs[3]` leaves `rs[3]` holding the old record 4, whose `chain_head` is record 3's output, not record 2's. The head check fires first. Fix by checking `step_index` **before** `chain_head`:

```rust
        let expected_step = i as u64;
        if r.step_index != expected_step {
            return Err(ChainError::StepGap { expected: expected_step, found: r.step_index });
        }
        let want = hex::encode(head);
        if r.chain_head != want {
            return Err(ChainError::HeadMismatch { at: i, expected: want, found: r.chain_head.clone() });
        }
```

Use this ordering. A gap is the more specific diagnosis and should win.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test chain`
Expected: PASS, 5 tests. If `altering_a_record_breaks_the_chain` reports `at: 4` rather than `at: 3`, that is correct: record 3's own declared head is still right; it is record 4 whose expectation the alteration broke.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Chain records by whole-record digest, which is stronger than the schema's three fields"
```

---

## Task 3: The RFC 6962 tree

**Files:**
- Create: `src/tree.rs`
- Modify: `src/lib.rs`
- Test: `tests/tree.rs`

**Interfaces:**
- Produces: `tree::leaf_hash(&[u8]) -> [u8; 32]`, `tree::node_hash(&[u8; 32], &[u8; 32]) -> [u8; 32]`, `tree::EMPTY_ROOT`, `tree::Tree` with `append`, `root`, `size`, and `tree::root_of(leaves: &[[u8; 32]]) -> [u8; 32]`.

- [ ] **Step 1: Write the failing test**

`tests/tree.rs`:

```rust
use ephemeris::tree::{leaf_hash, node_hash, root_of, Tree, EMPTY_ROOT};

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| leaf_hash(&[i as u8])).collect()
}

#[test]
fn an_empty_tree_has_the_rfc_6962_empty_root() {
    // RFC 6962 §2.1: MTH({}) = SHA-256().
    use sha2::{Digest, Sha256};
    let want: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(EMPTY_ROOT, want);
    assert_eq!(Tree::new().root(), want);
}

#[test]
fn a_single_leaf_tree_roots_to_that_leaf() {
    let mut t = Tree::new();
    let l = leaf_hash(b"x");
    t.append(l);
    assert_eq!(t.root(), l);
}

#[test]
fn leaf_and_node_prefixes_differ() {
    // RFC 6962 §2.1 prefixes leaves with 0x00 and nodes with 0x01 precisely
    // so a leaf cannot be presented as an interior node. Without the
    // distinction a second-preimage attack rewrites the tree's shape.
    let a = leaf_hash(b"");
    let b = node_hash(&[0u8; 32], &[0u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn incremental_append_agrees_with_recomputation_at_every_size() {
    // The right-fringe incremental root must equal the reference recursive
    // root for every size, not merely for powers of two — the sizes where a
    // fringe bug hides are the ones that are not.
    let ls = leaves(33);
    let mut t = Tree::new();
    for (i, l) in ls.iter().enumerate() {
        t.append(*l);
        assert_eq!(t.size(), (i + 1) as u64);
        assert_eq!(t.root(), root_of(&ls[..=i]), "root diverged at size {}", i + 1);
    }
}

#[test]
fn a_two_leaf_root_is_the_node_hash_of_its_leaves() {
    let ls = leaves(2);
    assert_eq!(root_of(&ls), node_hash(&ls[0], &ls[1]));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test tree`
Expected: FAIL — `ephemeris::tree` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod tree;` to `src/lib.rs`.

`src/tree.rs`:

```rust
use sha2::{Digest, Sha256};

/// RFC 6962 §2.1 domain separation. A leaf and an interior node must hash
/// differently, or a leaf can be presented as a node and the tree's shape
/// rewritten.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// MTH({}) = SHA-256() over the empty string, per RFC 6962 §2.1.
pub const EMPTY_ROOT: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The reference recursive Merkle tree head, written straight from RFC 6962
/// §2.1. Used by `Tree` for proofs and by the tests as the oracle the
/// incremental path must agree with.
pub fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => EMPTY_ROOT,
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// The largest power of two strictly less than `n`, for `n > 1`. RFC 6962
/// splits every interior node at exactly this point, so an off-by-one here
/// produces a tree that is internally consistent and incompatible with every
/// other implementation.
pub(crate) fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// An append-only tree that keeps its right fringe, so appending is O(log n)
/// and the head is available without rescanning.
///
/// The full leaf vector is kept alongside it because inclusion and consistency
/// proofs need arbitrary subtrees, not only the fringe. That makes proof
/// generation O(n); whether proof serving becomes the bottleneck under audit
/// load is P08's open question 5 and is measured in Phase 2, not guessed at
/// here.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    /// Complete subtrees, largest first. `fringe[i]` is the root of a complete
    /// subtree, and the sizes are the set bits of `size` from high to low.
    fringe: Vec<[u8; 32]>,
    leaves: Vec<[u8; 32]>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut carry = leaf;
        let mut n = self.leaves.len();
        // Every set low bit of the current size is a complete subtree of the
        // same height as `carry`, so it merges. The loop stops at the first
        // clear bit, which is where `carry` comes to rest.
        while n & 1 == 1 {
            if let Some(left) = self.fringe.pop() {
                carry = node_hash(&left, &carry);
            }
            n >>= 1;
        }
        self.fringe.push(carry);
        self.leaves.push(leaf);
    }

    /// Fold the fringe right to left: the smallest subtree is the rightmost,
    /// and each larger one sits to its left.
    pub fn root(&self) -> [u8; 32] {
        let mut acc: Option<[u8; 32]> = None;
        for h in self.fringe.iter().rev() {
            acc = Some(match acc {
                None => *h,
                Some(right) => node_hash(h, &right),
            });
        }
        acc.unwrap_or(EMPTY_ROOT)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test tree`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add the RFC 6962 tree, with the incremental root pinned to the recursive one at every size"
```

---

## Task 4: Inclusion and consistency proofs

**Files:**
- Modify: `src/tree.rs`
- Test: `tests/proofs.rs`

**Interfaces:**
- Produces: `tree::inclusion_proof(leaves, m) -> Option<Vec<[u8; 32]>>`, `tree::verify_inclusion(leaf, m, size, proof, root) -> bool`, `tree::consistency_proof(leaves, m) -> Option<Vec<[u8; 32]>>`, `tree::verify_consistency(old_size, old_root, new_size, new_root, proof) -> bool`.

- [ ] **Step 1: Write the failing test**

`tests/proofs.rs`:

```rust
use ephemeris::tree::{
    consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion,
};

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| leaf_hash(&[i as u8])).collect()
}

#[test]
fn every_leaf_of_every_tree_up_to_33_proves_inclusion() {
    for n in 1..=33usize {
        let ls = leaves(n);
        let root = root_of(&ls);
        for m in 0..n {
            let p = inclusion_proof(&ls, m).expect("proof for an in-range leaf");
            assert!(
                verify_inclusion(ls[m], m as u64, n as u64, &p, root),
                "leaf {m} of {n} failed to verify"
            );
        }
    }
}

#[test]
fn an_inclusion_proof_does_not_verify_against_a_different_leaf() {
    let ls = leaves(8);
    let root = root_of(&ls);
    let p = inclusion_proof(&ls, 3).unwrap();
    assert!(!verify_inclusion(ls[4], 3, 8, &p, root));
}

#[test]
fn an_out_of_range_leaf_has_no_proof() {
    assert!(inclusion_proof(&leaves(8), 8).is_none());
}

#[test]
fn proof_size_is_logarithmic_not_linear() {
    // C7.3.4's auditor evidence asks for exactly this check.
    let ls = leaves(1024);
    let p = inclusion_proof(&ls, 500).unwrap();
    assert!(p.len() <= 10, "proof of {} elements for 1024 leaves", p.len());
}

#[test]
fn every_prefix_is_consistent_with_every_extension() {
    for n in 1..=33usize {
        let ls = leaves(n);
        let new_root = root_of(&ls);
        for m in 1..=n {
            let old_root = root_of(&ls[..m]);
            let p = consistency_proof(&ls, m).expect("proof for an in-range prefix");
            assert!(
                verify_consistency(m as u64, old_root, n as u64, new_root, &p),
                "prefix {m} of {n} failed to verify"
            );
        }
    }
}

#[test]
fn a_rewritten_history_fails_consistency() {
    // The whole point. Take an 8-leaf log, publish its root, then rewrite
    // leaf 2 and extend to 12. The new tree is internally perfect and
    // inconsistent with the published root.
    let original = leaves(8);
    let published = root_of(&original);

    let mut rewritten = leaves(12);
    rewritten[2] = leaf_hash(b"tampered");
    let new_root = root_of(&rewritten);

    let p = consistency_proof(&rewritten, 8).unwrap();
    assert!(!verify_consistency(8, published, 12, new_root, &p));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test proofs`
Expected: FAIL — the four functions do not exist.

- [ ] **Step 3: Write the implementation**

Append to `src/tree.rs`:

```rust
/// RFC 6962 §2.1.1 PATH(m, D[n]).
pub fn inclusion_proof(leaves: &[[u8; 32]], m: usize) -> Option<Vec<[u8; 32]>> {
    if m >= leaves.len() {
        return None;
    }
    Some(path(leaves, m))
}

fn path(leaves: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_below(n);
    if m < k {
        let mut p = path(&leaves[..k], m);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = path(&leaves[k..], m - k);
        p.push(root_of(&leaves[..k]));
        p
    }
}

/// Recompute the root from a leaf and its path, and compare. RFC 6962 §2.1.1.
pub fn verify_inclusion(
    leaf: [u8; 32],
    m: u64,
    size: u64,
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    if m >= size || size == 0 {
        return false;
    }
    let mut hash = leaf;
    let mut index = m;
    let mut last = size - 1;
    let mut it = proof.iter();
    while last > 0 {
        let Some(sibling) = it.next() else {
            return false;
        };
        if index % 2 == 1 || index == last {
            hash = node_hash(sibling, &hash);
            // Walk up past any right-edge shortcut.
            while index % 2 == 0 && index > 0 {
                index /= 2;
                last /= 2;
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        index /= 2;
        last /= 2;
    }
    it.next().is_none() && hash == root
}

/// RFC 6962 §2.1.2 PROOF(m, D[n]).
pub fn consistency_proof(leaves: &[[u8; 32]], m: usize) -> Option<Vec<[u8; 32]>> {
    if m == 0 || m > leaves.len() {
        return None;
    }
    Some(subproof(leaves, m, true))
}

fn subproof(leaves: &[[u8; 32]], m: usize, b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        return if b { Vec::new() } else { vec![root_of(leaves)] };
    }
    let k = largest_power_of_two_below(n);
    if m <= k {
        let mut p = subproof(&leaves[..k], m, b);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = subproof(&leaves[k..], m - k, false);
        p.push(root_of(&leaves[..k]));
        p
    }
}

/// Verify that the tree of `new_size` leaves rooted at `new_root` is an
/// append-only extension of the tree of `old_size` leaves rooted at
/// `old_root`.
///
/// **This is the function that stops attack A9.** A rewritten-and-re-signed
/// log is internally flawless and replays perfectly; the only thing that
/// contradicts it is a root published before the rewrite, compared here.
/// C7.3.5 exists because this specification's own reference implementation
/// compared record counts instead, and accepted a rewritten history.
pub fn verify_consistency(
    old_size: u64,
    old_root: [u8; 32],
    new_size: u64,
    new_root: [u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut node = old_size - 1;
    let mut last = new_size - 1;
    while node % 2 == 1 {
        node /= 2;
        last /= 2;
    }

    let mut it = proof.iter();
    // A proof for a prefix that is itself a complete subtree omits that
    // subtree's root, so it is seeded from `old_root`.
    let (mut fr, mut sr) = if node > 0 {
        let Some(first) = it.next() else {
            return false;
        };
        (*first, *first)
    } else {
        (old_root, old_root)
    };

    while node > 0 {
        if node % 2 == 1 {
            let Some(sibling) = it.next() else {
                return false;
            };
            fr = node_hash(sibling, &fr);
            sr = node_hash(sibling, &sr);
        } else if node < last {
            let Some(sibling) = it.next() else {
                return false;
            };
            sr = node_hash(&sr, sibling);
        }
        node /= 2;
        last /= 2;
    }

    while last > 0 {
        let Some(sibling) = it.next() else {
            return false;
        };
        sr = node_hash(&sr, sibling);
        last /= 2;
    }

    it.next().is_none() && fr == old_root && sr == new_root
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test proofs`
Expected: PASS, 6 tests.

These two verifiers are the most error-prone code in the crate, and the two exhaustive tests over sizes 1..=33 and every leaf and prefix are why. If either fails, fix the verifier against RFC 6962 §2.1.1 and §2.1.2 directly — do not relax the test. A relaxed proof check is the exact failure C7.7's commentary describes.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add inclusion and consistency proofs, exhaustively verified to 33 leaves"
```

---

## Task 5: The A9 rewrite test

**Files:**
- Create: `src/verify.rs`
- Modify: `src/lib.rs`
- Test: `tests/a9_rewrite.rs`

**Interfaces:**
- Consumes: `chain::verify_sequence`, `tree::{root_of, consistency_proof, verify_consistency}`, `record::digest`.
- Produces: `verify::against_root(records, prior: Option<PriorRoot>) -> Result<Accepted, VerifyError>`, `verify::PriorRoot { size: u64, root: [u8; 32] }`, `verify::Accepted { size: u64, root: [u8; 32] }`, `verify::VerifyError`.

This task exists to make one attack impossible to reintroduce.

- [ ] **Step 1: Write the failing test**

`tests/a9_rewrite.rs`:

```rust
use ephemeris::chain::{extend, GENESIS};
use ephemeris::record::{digest, Claim, Record};
use ephemeris::tree::{leaf_hash, root_of};
use ephemeris::verify::{against_root, PriorRoot, VerifyError};

fn claim(id: &str, verdict: &str) -> Claim {
    Claim {
        action_id: id.into(),
        agent_id: "did:web:example.org:agents:ref-1".into(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: verdict.into(),
    }
}

/// Build a fully self-consistent log. `tamper_at` rewrites one verdict and
/// re-links everything after it, which is exactly what an operator holding
/// the signing key can do.
fn build(n: u64, tamper_at: Option<u64>) -> Vec<Record> {
    let mut out = Vec::new();
    let mut head = GENESIS;
    for i in 0..n {
        let verdict = if Some(i) == tamper_at { "DENY" } else { "ALLOW" };
        let r = Record::new(claim(&format!("a-{i}"), verdict), i, head, 1_700_000_000 + i, format!("n-{i}"));
        head = extend(head, &r).unwrap();
        out.push(r);
    }
    out
}

fn root(records: &[Record]) -> [u8; 32] {
    let ls: Vec<[u8; 32]> = records
        .iter()
        .map(|r| leaf_hash(&digest(r).unwrap()))
        .collect();
    root_of(&ls)
}

#[test]
fn a_rewritten_and_relinked_log_is_internally_perfect() {
    // The premise of the attack, asserted so nobody mistakes the defence for
    // the chain check. Every link verifies. Nothing looks broken.
    let tampered = build(8, Some(3));
    assert!(ephemeris::chain::verify_sequence(&tampered).is_ok());
}

#[test]
fn without_a_prior_root_the_rewrite_is_accepted() {
    // Stated plainly because it is the tool's honest limitation: with no
    // externally published prior root there is nothing to contradict a
    // rewrite. This is C7.3.3, which Phase 1 does not defend.
    let tampered = build(8, Some(3));
    assert!(against_root(&tampered, None).is_ok());
}

#[test]
fn against_a_prior_root_the_rewrite_is_rejected() {
    let honest = build(8, None);
    let published = PriorRoot { size: 8, root: root(&honest) };

    let mut tampered = build(8, Some(3));
    tampered.extend(build(12, Some(3)).into_iter().skip(8));

    assert!(matches!(
        against_root(&tampered, Some(published)),
        Err(VerifyError::Inconsistent { .. })
    ));
}

#[test]
fn an_honest_extension_is_accepted_against_the_same_prior_root() {
    // The negative control. Without it, a verifier that rejected everything
    // would pass the test above.
    let honest8 = build(8, None);
    let published = PriorRoot { size: 8, root: root(&honest8) };
    let honest12 = build(12, None);
    assert!(against_root(&honest12, Some(published)).is_ok());
}

#[test]
fn a_step_count_comparison_alone_would_have_accepted_the_rewrite() {
    // C7.3.5's own warning, pinned as a test: the rewritten log has the
    // right length. Length is not evidence.
    let honest = build(8, None);
    let mut tampered = build(8, Some(3));
    tampered.extend(build(12, Some(3)).into_iter().skip(8));
    assert_eq!(honest.len(), 8);
    assert_eq!(tampered.len(), 12);
    assert_ne!(root(&honest), root(&tampered[..8].to_vec()));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test a9_rewrite`
Expected: FAIL — `ephemeris::verify` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod verify;` to `src/lib.rs`.

`src/verify.rs`:

```rust
use crate::chain::{verify_sequence, ChainError};
use crate::record::{digest, Record, RecordError};
use crate::tree::{consistency_proof, leaf_hash, root_of, verify_consistency};

/// A root published before now, against which a log claims to be an
/// append-only extension. Obtaining one is outside this crate's scope in
/// Phase 1 — see the design's "what this does not defend against".
#[derive(Clone, Copy, Debug)]
pub struct PriorRoot {
    pub size: u64,
    pub root: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct Accepted {
    pub size: u64,
    pub root: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the log is not internally consistent: {0}")]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(
        "the log is not an append-only extension of the root published at size {prior_size}; \
         a record before that point was altered and the chain relinked"
    )]
    Inconsistent { prior_size: u64 },
    #[error("the prior root claims size {prior_size}, larger than this log's {size}")]
    PriorLarger { prior_size: u64, size: u64 },
}

/// Verify a log, and — when a prior root is supplied — verify that it did not
/// rewrite history.
///
/// **`prior` is `Option` and that is the whole design.** Passing `None` runs
/// only the internal checks, which a rewritten log passes. This is not an
/// oversight to be tightened later; it is the honest shape of a tool that
/// publishes no root outside the operator's control. The caller must decide
/// whether it holds a prior root, and `None` means it does not.
pub fn against_root(records: &[Record], prior: Option<PriorRoot>) -> Result<Accepted, VerifyError> {
    verify_sequence(records)?;

    let mut leaves = Vec::with_capacity(records.len());
    for r in records {
        leaves.push(leaf_hash(&digest(r)?));
    }
    let root = root_of(&leaves);
    let size = leaves.len() as u64;

    if let Some(p) = prior {
        if p.size > size {
            return Err(VerifyError::PriorLarger { prior_size: p.size, size });
        }
        let proof = consistency_proof(&leaves, p.size as usize)
            .ok_or(VerifyError::Inconsistent { prior_size: p.size })?;
        if !verify_consistency(p.size, p.root, size, root, &proof) {
            return Err(VerifyError::Inconsistent { prior_size: p.size });
        }
    }

    Ok(Accepted { size, root })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test a9_rewrite`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Pin attack A9: a relinked rewrite is internally perfect and fails against a prior root"
```

---

## Task 6: Append-only storage and crash recovery

**Files:**
- Create: `src/store.rs`
- Modify: `src/lib.rs`
- Test: `tests/store_recovery.rs`

**Interfaces:**
- Produces: `store::Store` with `open(dir) -> Result<Store, StoreError>`, `append_batch(&mut self, records: &[Record]) -> Result<(), StoreError>`, `records(&self) -> &[Record]`, `head(&self) -> [u8; 32]`, `next_step(&self) -> u64`; and `store::StoreError`.

Framing: each record is written as a 4-byte big-endian length, then the canonical JSON bytes, then a 32-byte SHA-256 of those bytes. The trailing digest is what makes a torn write detectable rather than merely suspicious.

- [ ] **Step 1: Write the failing test**

`tests/store_recovery.rs`:

```rust
use ephemeris::record::{Claim, Record};
use ephemeris::store::Store;
use std::fs::OpenOptions;
use std::io::Write;

fn claim(id: &str) -> Claim {
    Claim {
        action_id: id.into(),
        agent_id: "did:web:example.org:agents:ref-1".into(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: "ALLOW".into(),
    }
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ephemeris-test-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn records_survive_a_reopen() {
    let d = tmpdir("reopen");
    {
        let mut s = Store::open(&d).unwrap();
        for i in 0..5u64 {
            let r = Record::new(claim(&format!("a-{i}")), s.next_step(), s.head(), 1_700_000_000 + i, format!("n-{i}"));
            s.append_batch(&[r]).unwrap();
        }
        assert_eq!(s.records().len(), 5);
    }
    let s = Store::open(&d).unwrap();
    assert_eq!(s.records().len(), 5);
    assert_eq!(s.next_step(), 5);
}

#[test]
fn a_torn_write_is_truncated_not_accepted() {
    let d = tmpdir("torn");
    {
        let mut s = Store::open(&d).unwrap();
        for i in 0..3u64 {
            let r = Record::new(claim(&format!("a-{i}")), s.next_step(), s.head(), 1_700_000_000 + i, format!("n-{i}"));
            s.append_batch(&[r]).unwrap();
        }
    }
    // Simulate a process death mid-write: a length header and a few bytes.
    let mut f = OpenOptions::new().append(true).open(d.join("segment-0.log")).unwrap();
    f.write_all(&[0, 0, 4, 0]).unwrap();
    f.write_all(b"{\"cl").unwrap();
    drop(f);

    let s = Store::open(&d).unwrap();
    assert_eq!(s.records().len(), 3, "the torn record must not be recovered");
    assert_eq!(s.next_step(), 3);
}

#[test]
fn a_corrupted_complete_record_is_refused_not_skipped() {
    // A record whose trailing digest does not match its bytes is not a torn
    // write; it is an alteration. Recovery stops rather than silently
    // dropping it, because silently dropping evidence is the failure this
    // whole tool exists to prevent.
    let d = tmpdir("corrupt");
    {
        let mut s = Store::open(&d).unwrap();
        for i in 0..3u64 {
            let r = Record::new(claim(&format!("a-{i}")), s.next_step(), s.head(), 1_700_000_000 + i, format!("n-{i}"));
            s.append_batch(&[r]).unwrap();
        }
    }
    let p = d.join("segment-0.log");
    let mut bytes = std::fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n - 40] ^= 0xff;
    std::fs::write(&p, &bytes).unwrap();

    assert!(Store::open(&d).is_err());
}

#[test]
fn head_and_next_step_advance_together() {
    let d = tmpdir("advance");
    let mut s = Store::open(&d).unwrap();
    assert_eq!(s.next_step(), 0);
    assert_eq!(s.head(), ephemeris::chain::GENESIS);
    let r = Record::new(claim("a-0"), 0, ephemeris::chain::GENESIS, 1_700_000_000, "n-0".into());
    s.append_batch(&[r]).unwrap();
    assert_eq!(s.next_step(), 1);
    assert_ne!(s.head(), ephemeris::chain::GENESIS);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test store_recovery`
Expected: FAIL — `ephemeris::store` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod store;` to `src/lib.rs`.

`src/store.rs`:

```rust
use crate::chain::{extend, GENESIS};
use crate::record::{canonical, Record, RecordError};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const SEGMENT: &str = "segment-0.log";
const LEN_BYTES: usize = 4;
const DIGEST_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("could not open the log at {path}: {source}")]
    Open { path: String, source: std::io::Error },
    #[error("could not write to the log: {0}")]
    Write(std::io::Error),
    #[error("could not flush the log to disk: {0}")]
    Sync(std::io::Error),
    #[error(
        "the record at byte {at} is complete but its trailing digest does not match its bytes; \
         this is an alteration, not a torn write, and recovery will not skip it"
    )]
    Corrupt { at: u64 },
    #[error("the record at byte {at} could not be parsed: {source}")]
    Parse { at: u64, source: serde_json::Error },
    #[error("a record declares a length of {len} bytes, beyond any plausible record")]
    LengthImplausible { len: u32 },
    #[error(transparent)]
    Record(#[from] RecordError),
}

/// A record longer than this is refused rather than allocated. The bytes come
/// off disk and a corrupted length header would otherwise be a memory
/// exhaustion.
const MAX_RECORD: u32 = 1 << 20;

pub struct Store {
    file: File,
    path: PathBuf,
    records: Vec<Record>,
    head: [u8; 32],
}

impl Store {
    /// Open the log at `dir`, recovering whatever is intact.
    ///
    /// A trailing partial record is truncated: a process died mid-write and
    /// that record was never acknowledged, so no caller believes it exists.
    /// A *complete* record whose digest does not match is a different thing
    /// entirely and is an error — see `StoreError::Corrupt`.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir).map_err(|source| StoreError::Open {
            path: dir.display().to_string(),
            source,
        })?;
        let path = dir.join(SEGMENT);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|source| StoreError::Open {
                path: path.display().to_string(),
                source,
            })?;

        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).map_err(StoreError::Write)?;
        file.read_to_end(&mut bytes).map_err(StoreError::Write)?;

        let mut records = Vec::new();
        let mut head = GENESIS;
        let mut at: u64 = 0;
        let mut cursor: usize = 0;

        loop {
            if cursor + LEN_BYTES > bytes.len() {
                break;
            }
            let len_arr: [u8; LEN_BYTES] = match bytes[cursor..cursor + LEN_BYTES].try_into() {
                Ok(a) => a,
                Err(_) => break,
            };
            let len = u32::from_be_bytes(len_arr);
            if len > MAX_RECORD {
                return Err(StoreError::LengthImplausible { len });
            }
            let body_start = cursor + LEN_BYTES;
            let body_end = body_start + len as usize;
            let frame_end = body_end + DIGEST_BYTES;
            if frame_end > bytes.len() {
                // Torn write. Everything from `at` onward was never acked.
                break;
            }
            let body = &bytes[body_start..body_end];
            let want: [u8; DIGEST_BYTES] = Sha256::digest(body).into();
            let got: [u8; DIGEST_BYTES] = match bytes[body_end..frame_end].try_into() {
                Ok(a) => a,
                Err(_) => return Err(StoreError::Corrupt { at }),
            };
            if want != got {
                return Err(StoreError::Corrupt { at });
            }
            let r: Record = serde_json::from_slice(body)
                .map_err(|source| StoreError::Parse { at, source })?;
            head = extend(head, &r)?;
            records.push(r);
            cursor = frame_end;
            at = cursor as u64;
        }

        if (cursor as u64) < bytes.len() as u64 {
            file.set_len(cursor as u64).map_err(StoreError::Write)?;
        }
        file.seek(SeekFrom::End(0)).map_err(StoreError::Write)?;

        Ok(Self { file, path, records, head })
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn next_step(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a batch and `fsync` **once** for the whole batch.
    ///
    /// The caller must not acknowledge any member of the batch until this
    /// returns `Ok`. That is C7.1.3, and Task 7 is where the acknowledgement
    /// path is built so it cannot be got wrong.
    ///
    /// On any error the in-memory state is left untouched, so a failed batch
    /// cannot advance `head` or `next_step` and be acked by a later caller.
    pub fn append_batch(&mut self, records: &[Record]) -> Result<(), StoreError> {
        let mut buf = Vec::new();
        let mut head = self.head;
        for r in records {
            let body = canonical(r)?.into_bytes();
            let len = u32::try_from(body.len()).map_err(|_| StoreError::LengthImplausible {
                len: u32::MAX,
            })?;
            if len > MAX_RECORD {
                return Err(StoreError::LengthImplausible { len });
            }
            let d: [u8; DIGEST_BYTES] = Sha256::digest(&body).into();
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&body);
            buf.extend_from_slice(&d);
            head = extend(head, r)?;
        }

        self.file.write_all(&buf).map_err(StoreError::Write)?;
        self.file.sync_data().map_err(StoreError::Sync)?;

        self.records.extend_from_slice(records);
        self.head = head;
        Ok(())
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test store_recovery`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add append-only storage: a torn write truncates, a corrupted record refuses"
```

---

## Task 7: Group commit and write-before-forward

**Files:**
- Create: `src/commit.rs`
- Modify: `src/lib.rs`, `Cargo.toml`
- Test: `tests/write_before_forward.rs`

**Interfaces:**
- Consumes: `store::Store`, `record::Claim`.
- Produces: `commit::Committer` with `new(store) -> Committer`, `submit(&mut self, claims: Vec<Claim>, now_secs: u64, nonce_for: impl Fn(usize) -> String) -> Vec<Result<Ack, CommitError>>`; `commit::Ack { step_index: u64, chain_head: String }`; `commit::CommitError`.

The property under test is stated as a negative: **no `Ack` is ever produced for a claim whose bytes are not on disk.** A synchronous batching committer is the simplest shape that makes this checkable, and it is what the benchmark in Phase 2 will drive concurrently.

Add to `Cargo.toml` under `[dev-dependencies]`:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 1: Write the failing test**

`tests/write_before_forward.rs`:

```rust
use ephemeris::commit::{Committer, CommitError};
use ephemeris::record::Claim;
use ephemeris::store::Store;

fn claim(id: &str) -> Claim {
    Claim {
        action_id: id.into(),
        agent_id: "did:web:example.org:agents:ref-1".into(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: "ALLOW".into(),
    }
}

#[test]
fn a_batch_is_acked_only_after_it_is_durable() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let mut c = Committer::new(store);

    let claims = vec![claim("a-0"), claim("a-1"), claim("a-2")];
    let acks = c.submit(claims, 1_700_000_000, |i| format!("n-{i}"));
    assert_eq!(acks.len(), 3);
    for a in &acks {
        assert!(a.is_ok());
    }

    // Everything acked must be readable from a fresh open of the same
    // directory. Anything else means the ack preceded durability.
    let reopened = Store::open(d.path()).unwrap();
    assert_eq!(reopened.records().len(), 3);
}

#[test]
fn acks_carry_contiguous_step_indices_in_submission_order() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Committer::new(Store::open(d.path()).unwrap());
    let acks = c.submit(
        vec![claim("a-0"), claim("a-1"), claim("a-2")],
        1_700_000_000,
        |i| format!("n-{i}"),
    );
    let steps: Vec<u64> = acks.iter().map(|a| a.as_ref().unwrap().step_index).collect();
    assert_eq!(steps, vec![0, 1, 2]);
}

#[test]
fn an_unwritable_store_acks_nothing() {
    // C7.1.3's own auditor test: make the evidence store unavailable and
    // observe that actions do not proceed. Here that means every member of
    // the batch fails; a partial success would let a gateway forward an
    // action whose record was never written.
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let mut c = Committer::new(store);

    // Replace the segment with a directory, so every subsequent write fails.
    let seg = d.path().join("segment-0.log");
    std::fs::remove_file(&seg).unwrap();
    std::fs::create_dir(&seg).unwrap();
    c.force_reopen_for_test(d.path());

    let acks = c.submit(vec![claim("a-0"), claim("a-1")], 1_700_000_000, |i| format!("n-{i}"));
    assert_eq!(acks.len(), 2);
    for a in &acks {
        assert!(matches!(a, Err(CommitError::NotDurable { .. })), "a claim was acked without being durable");
    }
}

#[test]
fn a_failed_batch_does_not_advance_the_chain() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Committer::new(Store::open(d.path()).unwrap());
    let before = c.next_step();
    let seg = d.path().join("segment-0.log");
    std::fs::remove_file(&seg).unwrap();
    std::fs::create_dir(&seg).unwrap();
    c.force_reopen_for_test(d.path());
    let _ = c.submit(vec![claim("a-0")], 1_700_000_000, |i| format!("n-{i}"));
    assert_eq!(c.next_step(), before);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test write_before_forward`
Expected: FAIL — `ephemeris::commit` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod commit;` to `src/lib.rs`.

`src/commit.rs`:

```rust
use crate::record::{Claim, Record};
use crate::store::{Store, StoreError};
use std::path::Path;

/// What a caller receives once, and only once, its record is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub step_index: u64,
    pub chain_head: String,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum CommitError {
    #[error("the claim was not durably written and must not be forwarded: {why}")]
    NotDurable { why: String },
}

/// Batches claims into a single `fsync`.
///
/// **The `Ack` type is the enforcement mechanism.** It is constructed in
/// exactly one place — after `append_batch` returns `Ok` — so there is no
/// code path that produces one for a claim whose bytes are not on disk. A
/// boolean return would have made the mistake expressible; this does not.
pub struct Committer {
    store: Store,
}

impl Committer {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub fn next_step(&self) -> u64 {
        self.store.next_step()
    }

    /// Test-only hook: re-open the store so a test can break the underlying
    /// file and observe the failure path. Not part of the serving API.
    #[doc(hidden)]
    pub fn force_reopen_for_test(&mut self, dir: &Path) {
        if let Ok(s) = Store::open(dir) {
            self.store = s;
        }
    }

    /// Build records for `claims`, write them as one batch, and return one
    /// result per claim in submission order.
    ///
    /// Every member of a failed batch fails. There is no partial success: the
    /// batch shares one `fsync`, so either all of its bytes are durable or
    /// none of them are known to be.
    pub fn submit(
        &mut self,
        claims: Vec<Claim>,
        now_secs: u64,
        nonce_for: impl Fn(usize) -> String,
    ) -> Vec<Result<Ack, CommitError>> {
        let n = claims.len();
        let mut records = Vec::with_capacity(n);
        let mut step = self.store.next_step();
        let mut head = self.store.head();

        for (i, c) in claims.into_iter().enumerate() {
            let r = Record::new(c, step, head, now_secs, nonce_for(i));
            match crate::chain::extend(head, &r) {
                Ok(next) => head = next,
                Err(e) => {
                    return vec![
                        Err(CommitError::NotDurable { why: e.to_string() });
                        n
                    ]
                }
            }
            records.push(r);
            step += 1;
        }

        match self.store.append_batch(&records) {
            Ok(()) => records
                .iter()
                .map(|r| {
                    Ok(Ack {
                        step_index: r.step_index,
                        chain_head: r.chain_head.clone(),
                    })
                })
                .collect(),
            Err(e) => vec![Err(CommitError::NotDurable { why: e.to_string() }); n],
        }
    }
}
```

`StoreError` is imported only for the `e.to_string()` above; if clippy reports it unused after the final shape settles, drop the import rather than adding a wrapper function for it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test write_before_forward`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Group commit, with Ack constructible only after fsync returns"
```

---

## Task 8: The topology trait

**Files:**
- Create: `src/topology.rs`
- Modify: `src/lib.rs`
- Test: `tests/topology.rs`

**Interfaces:**
- Produces: `topology::Topology` trait with `tree_for(&self, agent: &str) -> TreeId` and `anchor_policy(&self) -> AnchorPolicy`; `topology::{Global, PerAgent, Joint}`; `topology::TreeId(String)`; `topology::AnchorPolicy`; `topology::Forest` with `insert(&mut self, agent, leaf)`, `roots(&self)`, `tree_count(&self)`.

`Forest` is why this task is not a trait sitting on its own. A trait nothing consumes is speculative, and the equivalence property the design asks for — the same claims through all three topologies produce the same *records*, differing only in tree placement — is unwritable without something that actually routes leaves.

- [ ] **Step 1: Write the failing test**

`tests/topology.rs`:

```rust
use ephemeris::topology::{AnchorPolicy, Global, Joint, PerAgent, Topology, TreeId};

#[test]
fn global_puts_every_agent_in_one_tree() {
    let t = Global;
    assert_eq!(t.tree_for("agent-a"), t.tree_for("agent-b"));
    assert_eq!(t.anchor_policy(), AnchorPolicy::None);
}

#[test]
fn per_agent_gives_each_agent_its_own_tree() {
    let t = PerAgent;
    assert_ne!(t.tree_for("agent-a"), t.tree_for("agent-b"));
    assert_eq!(t.tree_for("agent-a"), t.tree_for("agent-a"));
}

#[test]
fn joint_partitions_per_agent_and_declares_an_interval() {
    let t = Joint { interval_secs: 60 };
    assert_ne!(t.tree_for("agent-a"), t.tree_for("agent-b"));
    assert_eq!(t.anchor_policy(), AnchorPolicy::Joint { interval_secs: 60 });
}

#[test]
fn the_tree_key_is_derived_from_the_whole_agent_id() {
    // The identity rule. Two agent ids differing anywhere must not collide,
    // and the same id must always map to the same tree.
    let t = PerAgent;
    assert_ne!(t.tree_for("did:web:example.org:agents:a"), t.tree_for("did:web:example.org:agents:b"));
    assert_ne!(t.tree_for("a"), t.tree_for("a "));
    assert_eq!(
        t.tree_for("did:web:example.org:agents:a"),
        t.tree_for("did:web:example.org:agents:a")
    );
}

#[test]
fn a_global_tree_id_does_not_collide_with_any_agent_id() {
    // Global's key must be unambiguous, not merely constant: an agent
    // literally named "global" must not land in the same namespace.
    assert_ne!(Global.tree_for("global"), PerAgent.tree_for("global"));
    assert_ne!(Global.tree_for("x"), PerAgent.tree_for("global"));
}

#[test]
fn a_forest_routes_leaves_by_topology() {
    use ephemeris::topology::Forest;
    let mut g = Forest::new(Global);
    let mut p = Forest::new(PerAgent);
    for (agent, leaf) in [("a", [1u8; 32]), ("b", [2u8; 32]), ("a", [3u8; 32])] {
        g.insert(agent, leaf);
        p.insert(agent, leaf);
    }
    assert_eq!(g.tree_count(), 1);
    assert_eq!(p.tree_count(), 2);
}

#[test]
fn the_same_leaves_produce_the_same_records_under_every_topology() {
    // The design's equivalence property. A topology decides *where* a leaf
    // lands, never *what* it says. If a topology could change a record, the
    // three would not be comparable and the Phase 2 benchmark would be
    // measuring three different systems rather than three placements of one.
    use ephemeris::topology::Forest;
    let leaves = [("a", [1u8; 32]), ("b", [2u8; 32]), ("a", [3u8; 32])];

    let mut g = Forest::new(Global);
    let mut p = Forest::new(PerAgent);
    let mut j = Forest::new(Joint { interval_secs: 60 });
    for (agent, leaf) in leaves {
        g.insert(agent, leaf);
        p.insert(agent, leaf);
        j.insert(agent, leaf);
    }

    // Every topology saw every leaf, exactly once.
    assert_eq!(g.leaf_count(), 3);
    assert_eq!(p.leaf_count(), 3);
    assert_eq!(j.leaf_count(), 3);

    // PerAgent and Joint partition identically; only their anchor policy
    // differs. If this ever fails, Joint has become a third partitioning
    // rather than a per-agent one with anchoring.
    assert_eq!(p.roots(), j.roots());
    assert_ne!(g.roots(), p.roots());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test topology`
Expected: FAIL — `ephemeris::topology` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod topology;` to `src/lib.rs`.

`src/topology.rs`:

```rust
/// Which tree a record's leaf lands in. A newtype rather than a bare `String`
/// so a tree key cannot be confused with an agent id, which is exactly the
/// kind of casual identity that caused four of `parallax`'s five criticals.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreeId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorPolicy {
    None,
    Joint { interval_secs: u64 },
}

/// How the log partitions its leaves.
///
/// The three implementations differ in throughput **and** in what the chain
/// reveals about who acted, and the two axes point in opposite directions.
/// A global tree leaks nothing about identity, because membership
/// distinguishes nobody; a per-agent tree's identity *is* an agent
/// identifier, so every action in it is linked to every other by
/// construction. P08 prefers per-agent for throughput; P05 objects to it for
/// exactly that reason. Measuring both axes is Phase 2's `bench`.
pub trait Topology {
    fn tree_for(&self, agent: &str) -> TreeId;
    fn anchor_policy(&self) -> AnchorPolicy;
}

/// One tree for the whole deployment. Total order; serial ceiling; the tree
/// key reveals nothing about who acted.
#[derive(Clone, Copy, Debug)]
pub struct Global;

/// One tree per agent. Parallel; no ordering across agents; **the tree key is
/// an agent identifier.**
#[derive(Clone, Copy, Debug)]
pub struct PerAgent;

/// One tree per agent, plus a joint root published every `interval_secs`,
/// giving coarse cross-agent ordering at anchor granularity.
#[derive(Clone, Copy, Debug)]
pub struct Joint {
    pub interval_secs: u64,
}

/// Tree keys are namespaced so that no agent id can collide with the global
/// key, whatever the agent is called. The prefix is part of the identity and
/// is why `TreeId` is not simply the agent id.
const GLOBAL_KEY: &str = "tree:global";
const AGENT_PREFIX: &str = "tree:agent:";

impl Topology for Global {
    fn tree_for(&self, _agent: &str) -> TreeId {
        TreeId(GLOBAL_KEY.to_string())
    }
    fn anchor_policy(&self) -> AnchorPolicy {
        AnchorPolicy::None
    }
}

impl Topology for PerAgent {
    fn tree_for(&self, agent: &str) -> TreeId {
        TreeId(format!("{AGENT_PREFIX}{agent}"))
    }
    fn anchor_policy(&self) -> AnchorPolicy {
        AnchorPolicy::None
    }
}

impl Topology for Joint {
    fn tree_for(&self, agent: &str) -> TreeId {
        TreeId(format!("{AGENT_PREFIX}{agent}"))
    }
    fn anchor_policy(&self) -> AnchorPolicy {
        AnchorPolicy::Joint {
            interval_secs: self.interval_secs,
        }
    }
}

/// A set of trees, with a topology deciding which one each leaf lands in.
///
/// This is the trait's consumer, and it exists so the equivalence property
/// can be stated: a topology decides *where* a leaf goes, never *what* the
/// record says. Phase 2's benchmark depends on that being true, because
/// otherwise it is measuring three different systems rather than three
/// placements of one.
pub struct Forest<T: Topology> {
    topology: T,
    trees: std::collections::BTreeMap<TreeId, crate::tree::Tree>,
    leaf_count: u64,
}

impl<T: Topology> Forest<T> {
    pub fn new(topology: T) -> Self {
        Self {
            topology,
            trees: std::collections::BTreeMap::new(),
            leaf_count: 0,
        }
    }

    pub fn insert(&mut self, agent: &str, leaf: [u8; 32]) {
        let id = self.topology.tree_for(agent);
        self.trees.entry(id).or_default().append(leaf);
        self.leaf_count += 1;
    }

    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Every tree's root, keyed by tree. `BTreeMap` so the order is the tree
    /// key's order and never insertion order — two forests holding the same
    /// trees must compare equal regardless of the sequence that built them.
    pub fn roots(&self) -> std::collections::BTreeMap<TreeId, [u8; 32]> {
        self.trees.iter().map(|(k, v)| (k.clone(), v.root())).collect()
    }

    pub fn anchor_policy(&self) -> AnchorPolicy {
        self.topology.anchor_policy()
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test topology`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add the topology trait, whose two axes point in opposite directions"
```

---

## Task 9: Signing, and the label that cannot be removed

**Files:**
- Create: `src/sign.rs`
- Modify: `src/lib.rs`, `Cargo.toml`
- Test: `tests/signing.rs`

**Interfaces:**
- Produces: `sign::Signer` trait with `sign_root(&self, root: &[u8; 32], size: u64) -> SignedRoot` and `custody(&self) -> Custody`; `sign::SoftwareSigner::generate(seed: [u8; 32])`; `sign::{SignedRoot, Custody}`.

Add to `Cargo.toml`:

```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand_chacha = "0.3"
rand_core = "0.6"
```

- [ ] **Step 1: Write the failing test**

`tests/signing.rs`:

```rust
use ephemeris::sign::{Custody, Signer, SoftwareSigner};

#[test]
fn a_software_signer_declares_software_custody() {
    let s = SoftwareSigner::generate([7u8; 32]);
    assert_eq!(s.custody(), Custody::Software);
}

#[test]
fn a_signed_root_carries_its_custody_and_cannot_be_relabelled() {
    // `Custody` is set from the signer that produced the root and there is
    // no setter. A software build must not be able to emit a root claiming
    // hardware custody, and the type system is what enforces it rather than
    // a code review.
    let s = SoftwareSigner::generate([7u8; 32]);
    let signed = s.sign_root(&[0u8; 32], 0);
    assert_eq!(signed.custody, Custody::Software);
}

#[test]
fn the_signature_covers_both_the_root_and_the_size() {
    // A signature over the root alone lets a root be replayed at a different
    // claimed size, which is precisely the confusion C7.3.5 warns about.
    let s = SoftwareSigner::generate([7u8; 32]);
    let a = s.sign_root(&[1u8; 32], 8);
    let b = s.sign_root(&[1u8; 32], 9);
    assert_ne!(a.signature, b.signature);
}

#[test]
fn signing_is_deterministic_for_a_given_seed() {
    let a = SoftwareSigner::generate([7u8; 32]).sign_root(&[1u8; 32], 8);
    let b = SoftwareSigner::generate([7u8; 32]).sign_root(&[1u8; 32], 8);
    assert_eq!(a.signature, b.signature);
    assert_eq!(a.public_key, b.public_key);
}

#[test]
fn a_signed_root_renders_its_custody_and_the_undefended_property() {
    // The design requires that C7.3.3 be printed on every root this tool
    // publishes. A root that renders without saying so is the failure.
    let s = SoftwareSigner::generate([7u8; 32]);
    let text = s.sign_root(&[0u8; 32], 3).render();
    assert!(text.contains("SOFTWARE"));
    assert!(text.contains("C7.3.3"));
    assert!(text.to_lowercase().contains("equivocation"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test signing`
Expected: FAIL — `ephemeris::sign` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod sign;` to `src/lib.rs`.

`src/sign.rs`:

```rust
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::SeedableRng;

/// Where the signing key lives. Set by the signer that produced a root, with
/// no setter anywhere, so a software build cannot emit a root claiming
/// hardware custody. This mirrors `occultation`'s rule that a modelled
/// implementation cannot construct a valid verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custody {
    /// The key is a process-local Ed25519 key. It provides integrity against
    /// anyone who is not the operator, and nothing against the operator.
    Software,
    /// The key was generated inside a TEE and is bound to a quote through
    /// `REPORTDATA`. Phase 2.
    Tee,
}

impl Custody {
    pub fn label(&self) -> &'static str {
        match self {
            Custody::Software => "SOFTWARE",
            Custody::Tee => "TEE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignedRoot {
    pub root: String,
    pub size: u64,
    pub public_key: String,
    pub signature: String,
    pub custody: Custody,
}

impl SignedRoot {
    /// Every root this tool publishes says what it does not defend against.
    ///
    /// C7.3.3 is unmet in Phase 1: nothing is published outside the
    /// operator's control, so an operator holding this key can alter a past
    /// record, recompute every link, re-sign, and produce a log that replays
    /// perfectly. Only a root published before the rewrite contradicts it.
    /// Printing this is the same discipline as `poc-audit` shipping a
    /// permanent `UNCHECKED` row.
    pub fn render(&self) -> String {
        format!(
            "root {} size {} key {} custody {}\n\
             NOT DEFENDED — C7.3.3 equivocation: this root is published only by its own \
             operator. An operator holding the signing key can rewrite history and re-sign it. \
             Compare against a root you obtained earlier and independently, or this signature \
             establishes only that the log is internally consistent.",
            self.root,
            self.size,
            self.public_key,
            self.custody.label()
        )
    }
}

pub trait Signer {
    fn sign_root(&self, root: &[u8; 32], size: u64) -> SignedRoot;
    fn custody(&self) -> Custody;
}

/// The Phase 1 signer. Deterministic from a seed so tests are reproducible
/// and so the same log signed twice is byte-identical.
pub struct SoftwareSigner {
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn generate(seed: [u8; 32]) -> Self {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self {
            key: SigningKey::generate(&mut rng),
        }
    }
}

/// What a root signature covers: the domain tag, the size, and the root.
///
/// The size is inside the signed bytes deliberately. A signature over the
/// root alone would let a valid root be presented at a different claimed
/// size, and a verifier comparing sizes rather than roots is exactly the
/// defect C7.3.5 was written about.
fn signing_bytes(root: &[u8; 32], size: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 8 + 32);
    v.extend_from_slice(b"eph-root");
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(root);
    v
}

impl Signer for SoftwareSigner {
    fn sign_root(&self, root: &[u8; 32], size: u64) -> SignedRoot {
        let sig = self.key.sign(&signing_bytes(root, size));
        SignedRoot {
            root: hex::encode(root),
            size,
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            signature: hex::encode(sig.to_bytes()),
            custody: Custody::Software,
        }
    }

    fn custody(&self) -> Custody {
        Custody::Software
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test signing`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Sign roots over size and root together, and print what C7.3.3 does not cover"
```

---

## Task 10: The CLI, and the no-panic guarantee

**Files:**
- Create: `src/bin/ephemeris.rs`, `README.md`, `.github/workflows/ci.yml`
- Test: `tests/cli.rs`, `tests/no_panics.rs`

**Interfaces:**
- Consumes: everything above.

Phase 1 ships a CLI rather than the UDS listener. The listener is the first task of Phase 2, because it needs `tokio` and `hyper` and because everything it would serve is now testable without a socket. Shipping the CLI first means Phase 1 ends with something a person can run.

- [ ] **Step 1: Write the failing tests**

`tests/cli.rs`:

```rust
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ephemeris")
}

#[test]
fn append_then_root_reports_a_signed_root() {
    let d = tempfile::tempdir().unwrap();
    let claim = r#"{"action_id":"a-0","agent_id":"did:web:x","initiating_user":"user:alice","interception_point":"PRE_CALL_TOOL_INVOCATION","target_resource":"/v1/charges","canonical_snapshot_hash":"54c323d3","policy_bundle_hash":"a7713be5","verdict":"ALLOW"}"#;
    let f = d.path().join("claim.json");
    std::fs::write(&f, claim).unwrap();

    let out = Command::new(bin())
        .args(["append", "--dir", d.path().to_str().unwrap(), "--claim", f.to_str().unwrap(), "--now", "1700000000"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = Command::new(bin())
        .args(["root", "--dir", d.path().to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("C7.3.3"), "the root must print what it does not defend");
    assert!(text.contains("size 1"));
}

#[test]
fn a_claim_with_an_unknown_field_is_refused_with_exit_2() {
    let d = tempfile::tempdir().unwrap();
    let claim = r#"{"action_id":"a-0","agent_id":"did:web:x","initiating_user":"u","interception_point":"TASK_COMPLETION","target_resource":"/x","canonical_snapshot_hash":"aa","policy_bundle_hash":"bb","verdict":"ALLOW","typo_field":1}"#;
    let f = d.path().join("claim.json");
    std::fs::write(&f, claim).unwrap();
    let out = Command::new(bin())
        .args(["append", "--dir", d.path().to_str().unwrap(), "--claim", f.to_str().unwrap(), "--now", "1700000000"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn verify_exits_1_when_the_log_contradicts_a_prior_root() {
    let d = tempfile::tempdir().unwrap();
    let claim = r#"{"action_id":"a-0","agent_id":"did:web:x","initiating_user":"u","interception_point":"TASK_COMPLETION","target_resource":"/x","canonical_snapshot_hash":"aa","policy_bundle_hash":"bb","verdict":"ALLOW"}"#;
    let f = d.path().join("claim.json");
    std::fs::write(&f, claim).unwrap();
    Command::new(bin())
        .args(["append", "--dir", d.path().to_str().unwrap(), "--claim", f.to_str().unwrap(), "--now", "1700000000"])
        .output()
        .unwrap();

    let out = Command::new(bin())
        .args([
            "verify",
            "--dir",
            d.path().to_str().unwrap(),
            "--prior-size",
            "1",
            "--prior-root",
            &"aa".repeat(32),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}
```

`tests/no_panics.rs`:

```rust
use ephemeris::store::Store;

/// This crate reads bytes it did not write. Every one of these must return an
/// error rather than panic.
#[test]
fn malformed_segments_error_rather_than_panic() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0, 0, 0],
        vec![0, 0, 0, 1],
        vec![0, 0, 0, 1, b'{'],
        vec![0xff, 0xff, 0xff, 0xff],
        vec![0, 0, 0, 2, b'{', b'}'],
        b"not a frame at all".to_vec(),
    ];
    for (i, bytes) in cases.into_iter().enumerate() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("segment-0.log"), &bytes).unwrap();
        // Must not panic. Either outcome is acceptable; a panic is not.
        let _ = Store::open(d.path());
        let _ = i;
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test cli --test no_panics`
Expected: FAIL — the binary has no subcommands yet.

- [ ] **Step 3: Write the implementation**

`src/bin/ephemeris.rs`:

```rust
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ephemeris::commit::Committer;
use ephemeris::record::Claim;
use ephemeris::sign::{Signer, SoftwareSigner};
use ephemeris::store::Store;
use ephemeris::verify::{against_root, PriorRoot};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ephemeris", version, about = "An append-only evidence log for Proof-of-Control records")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Append one claim, read from a JSON file.
    Append {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        claim: PathBuf,
        /// Injected, never read from the system clock.
        #[arg(long)]
        now: u64,
        #[arg(long, default_value = "n-0")]
        nonce: String,
    },
    /// Print the signed tree head.
    Root {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Verify the log, optionally against a root published earlier.
    Verify {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, requires = "prior_root")]
        prior_size: Option<u64>,
        #[arg(long, requires = "prior_size")]
        prior_root: Option<String>,
    },
}

/// A fixed seed so Phase 1 output is reproducible. Phase 2 replaces this
/// signer entirely with the TEE one; a persistent software key would imply a
/// custody story this build does not have.
const DEV_SEED: [u8; 32] = [7u8; 32];

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Append { dir, claim, now, nonce } => {
            let text = std::fs::read_to_string(&claim)
                .with_context(|| format!("could not read {}", claim.display()))?;
            let c: Claim = serde_json::from_str(&text)
                .with_context(|| format!("could not parse {}", claim.display()))?;
            let store = Store::open(&dir)?;
            let mut committer = Committer::new(store);
            let acks = committer.submit(vec![c], now, |_| nonce.clone());
            match acks.into_iter().next() {
                Some(Ok(a)) => {
                    println!("acked step {} head {}", a.step_index, a.chain_head);
                    Ok(ExitCode::SUCCESS)
                }
                Some(Err(e)) => {
                    eprintln!("{e}");
                    Ok(ExitCode::from(1))
                }
                None => {
                    eprintln!("no acknowledgement was produced");
                    Ok(ExitCode::from(1))
                }
            }
        }
        Cmd::Root { dir } => {
            let store = Store::open(&dir)?;
            let accepted = against_root(store.records(), None)?;
            let signer = SoftwareSigner::generate(DEV_SEED);
            println!("{}", signer.sign_root(&accepted.root, accepted.size).render());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify { dir, prior_size, prior_root } => {
            let store = Store::open(&dir)?;
            let prior = match (prior_size, prior_root) {
                (Some(size), Some(hexed)) => {
                    let raw = hex::decode(&hexed).context("--prior-root is not hex")?;
                    let root: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("--prior-root must be 32 bytes"))?;
                    Some(PriorRoot { size, root })
                }
                _ => None,
            };
            match against_root(store.records(), prior) {
                Ok(a) => {
                    println!("accepted: size {} root {}", a.size, hex::encode(a.root));
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("{e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run the whole suite**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all tests PASS, clippy clean, formatting clean.

- [ ] **Step 5: Write the README**

`README.md` must contain, at minimum, a section titled **"What is real and what is modelled"** stating:

- The chain, the RFC 6962 tree, inclusion proofs, consistency proofs, durability and group commit are **real**.
- The signer is a **process-local software key**. It provides no defence against the operator. The TEE signer is Phase 2.
- **C7.3.3 equivocation is not defended.** No root is published outside the operator's control, so attack A9 stands. Every root printed says so.
- `path_summary_hash` is carried as `null` because no tool computes a bounded path summary; see P04.
- `agbom_digest` is absent because no AgBOM tooling exists; see P10 and `spectrum`.

- [ ] **Step 6: Add CI**

`.github/workflows/ci.yml` running, on push and pull request: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`. Model it on `/Users/jimschwoebel/Desktop/poc-audit/.github/workflows/ci.yml`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Add the CLI, the no-panic guarantee, the README and CI"
```

---

## Phase 1 done

At this point `ephemeris` is a working, durable, software-signed evidence log that resists the rewrite its own specification's reference implementation did not, and says plainly what it does not defend against.

**Phase 2, in its own plan:**

1. The UDS listener and its routes, so `transit guard` can write to it.
2. The TEE signer behind a cargo feature, with `Custody::Tee` reachable only from it and a test that a default build cannot claim hardware custody.
3. `bench` — throughput and tail latency against 1–1,000 agents, and linkability per topology via `occultation::anonymity`.
4. The `poc-audit` cross-check, which needs a released tag of this repo and moves the first number in `TOOLING.md` because a tool produced something.
