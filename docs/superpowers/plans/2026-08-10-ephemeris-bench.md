# ephemeris bench Implementation Plan — Phase 2, item 3

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure both axes of the `ephemeris` topology trade-off — throughput and tail latency on one side, linkability on the other — and replace the "we measured nothing" passages in the README and the paper with what was actually measured.

**Architecture:** A concurrent commit front-end (`CommitQueue`) is added to the crate as production code, because per-claim tail latency across a fleet is not measurable against a synchronous `&mut self` API. A `bench` module behind a cargo feature drives that queue at 1/10/100/1000 agents across all three topologies, and reuses `occultation::anonymity::partition` for the linkability metric, projecting its TCB-shaped report into ephemeris vocabulary. Results land in `results/*.json` with the host that produced them.

**Tech Stack:** Rust 2021, `std::sync::mpsc` (no async runtime — the log is blocking and adding tokio would measure the runtime), `occultation` for the anonymity metric, `serde_json` for results.

**Design spec:** `../specs/2026-08-10-ephemeris-bench-design.md`. Read it if a task's intent is unclear; the plan governs.

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**.
- **`#![forbid(unsafe_code)]` stays in `src/lib.rs`.**
- `cargo clippy --all-targets -- -D warnings` must be clean, **and** `cargo clippy --all-targets --features bench -- -D warnings`. Warnings are errors.
- `cargo fmt --check` must be clean.
- Library errors use `thiserror`; binaries use `anyhow`. Errors print with `{e}`, never `{e:#}`.
- **No panics on malformed input.** No `unwrap`, `expect`, slice indexing, or unchecked conversion on anything read from a file or a socket. Bench code may `expect` on values it constructed itself in the same function, and nowhere else.
- **Time is always injected, never read from the system clock**, in every function reachable from a test. `Instant` is permitted **only** for measuring elapsed durations inside `bench`, never for populating a record field.
- **Fail-closed. A claim is never acknowledged before its bytes are durable.** This now has to hold across a thread boundary. `Ack` remains constructible in **exactly one place**. If a task appears to need a second construction site, **stop and report** rather than adding one.
- **Nothing in `results/` may read as a measurement of something it is not.** No `occultation` type appears in any committed artefact; the linkability report is projected into ephemeris vocabulary first.
- **Latency is measured, never modelled.** No arrival-process simulation, no extrapolating per-claim latency from batch timings.
- Every results file records the host: OS, arch, CPU model, logical cores, the sync call used, the **measured** cost of that call, and the crate commit.
- Upstream tools are pinned by **`rev`**, never by branch.
- **This plan measures; it does not tune.** When a number disappoints, the temptation is to optimize and re-measure, and then the report has no before. Optimization is separate work. The only production change here is `CommitQueue`, which exists because the measurement is otherwise impossible, not because it is faster.
- Everything runs **offline**: no network, no credentials, no TEE.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/store.rs` | **modify** — count `fsync` calls so throughput can be checked against the physical quantity |
| `src/commit.rs` | **modify** — `submit_at`, and `CommitQueue` + `QueueHandle` + `QueueStats` |
| `src/bench/mod.rs` | feature-gated module root; `TopologyKind` |
| `src/bench/host.rs` | host provenance, including a measured sync cost |
| `src/bench/run.rs` | throughput and latency for one topology at one agent count |
| `src/bench/linkability.rs` | the `occultation` mapping and its projection |
| `src/bin/ephemeris-bench.rs` | the matrix, writing `results/*.json` |
| `tests/commit_queue.rs` | queue correctness, fail-closed across threads, ordering |
| `tests/bench_linkability.rs` | the projection, pinned both directions |
| `results/` | committed measurements + `results/README.md` |

---

## Task 1: The concurrent commit path

**Files:**
- Modify: `src/store.rs`, `src/commit.rs`
- Test: `tests/commit_queue.rs`

**Interfaces:**
- Consumes: `store::Store`, `commit::{Committer, Ack, CommitError}`, `record::Claim`.
- Produces: `store::Store::sync_count(&self) -> u64`; `commit::Committer::submit_at(&mut self, claims: Vec<(Claim, u64)>) -> Vec<Result<Ack, CommitError>>`; `commit::CommitQueue` with `new(Committer) -> CommitQueue`, `handle(&self) -> QueueHandle`, `shutdown(self) -> QueueStats`; `commit::QueueHandle` (`Clone`) with `submit(&self, claim: Claim, now_secs: u64) -> Result<Ack, CommitError>`; `commit::QueueStats { batches: u64, claims: u64, fsyncs: u64, batch_sizes: Vec<usize> }`.

This is the only task that changes production behaviour, and it is the one that has to keep Phase 1's central guarantee intact while an `Ack` crosses a thread boundary.

- [ ] **Step 1: Add the sync counter to `Store`**

The spec lists `fsync` count as a measured quantity, on the grounds that a throughput number that does not track it is measuring the page cache. So it is counted, not inferred.

In `src/store.rs`, add the field to the struct:

```rust
pub struct Store {
    file: File,
    path: PathBuf,
    records: Vec<Record>,
    head: [u8; 32],
    /// Successful `fsync` calls. The physical quantity throughput follows
    /// from; `bench` reports it so a claims/second figure can be checked
    /// against the number of times the disk was actually made to commit.
    syncs: u64,
}
```

In `Store::open`, the constructor at the end of the function becomes:

```rust
        Ok(Self {
            file,
            path,
            records,
            head,
            syncs: 0,
        })
```

Add the accessor next to `next_step`:

```rust
    /// Successful `fsync` calls since this `Store` was opened.
    pub fn sync_count(&self) -> u64 {
        self.syncs
    }
```

And in `append_batch`, increment **after** the sync returns, never before:

```rust
        self.file.write_all(&buf).map_err(StoreError::Write)?;
        self.file.sync_data().map_err(StoreError::Sync)?;
        self.syncs += 1;
```

- [ ] **Step 2: Write the failing test**

`tests/commit_queue.rs`:

```rust
use ephemeris::commit::{CommitError, CommitQueue, Committer};
use ephemeris::record::Claim;
use ephemeris::store::Store;
use std::collections::BTreeSet;

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
        nonce: "n-1".into(),
    }
}

#[test]
fn every_claim_gets_exactly_one_ack_and_all_are_durable() {
    let d = tempfile::tempdir().unwrap();
    let q = CommitQueue::new(Committer::new(Store::open(d.path()).unwrap()));

    let mut threads = Vec::new();
    for a in 0..8 {
        let h = q.handle();
        threads.push(std::thread::spawn(move || {
            let mut acks = Vec::new();
            for i in 0..25 {
                acks.push(h.submit(claim(&format!("a-{a}-{i}")), 1_700_000_000));
            }
            acks
        }));
    }
    let acks: Vec<_> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();

    assert_eq!(acks.len(), 200);
    assert!(acks.iter().all(|a| a.is_ok()), "a claim was refused");

    // Exactly one ack per claim means the step indices are a permutation of
    // 0..200 with no duplicate and no gap. A duplicate would mean two claims
    // were told they occupy the same position in history.
    let steps: BTreeSet<u64> = acks.iter().map(|a| a.as_ref().unwrap().step_index).collect();
    assert_eq!(steps.len(), 200, "two claims were given the same step index");
    assert_eq!(steps.iter().next(), Some(&0));
    assert_eq!(steps.iter().next_back(), Some(&199));

    let stats = q.shutdown();
    assert_eq!(stats.claims, 200);
    assert_eq!(stats.fsyncs, stats.batches, "one fsync per batch, exactly");
    assert!(stats.batches <= 200);

    // Everything acked must survive a reopen. Anything else means an ack
    // preceded durability.
    let reopened = Store::open(d.path()).unwrap();
    assert_eq!(reopened.records().len(), 200);
    ephemeris::chain::verify_sequence(reopened.records()).expect("chain must verify");
}

#[test]
fn group_commit_actually_batches_under_concurrent_load() {
    // If every claim got its own fsync the queue would be pointless. This does
    // not assert a batch size — that is load- and machine-dependent — only
    // that batching happened at all under 8 concurrent submitters.
    let d = tempfile::tempdir().unwrap();
    let q = CommitQueue::new(Committer::new(Store::open(d.path()).unwrap()));
    let mut threads = Vec::new();
    for a in 0..8 {
        let h = q.handle();
        threads.push(std::thread::spawn(move || {
            for i in 0..25 {
                let _ = h.submit(claim(&format!("a-{a}-{i}")), 1_700_000_000);
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    let stats = q.shutdown();
    assert!(
        stats.batches < stats.claims,
        "no batching occurred: {} batches for {} claims",
        stats.batches,
        stats.claims
    );
}

#[test]
fn an_unwritable_store_acks_nothing_from_any_submitter() {
    // Phase 1's fail-closed rule, now across a thread boundary. Every
    // submitter must be refused, not merely the one that happened to be
    // first.
    let d = tempfile::tempdir().unwrap();
    let mut c = Committer::new(Store::open(d.path()).unwrap());
    let seg = d.path().join("segment-0.log");
    std::fs::remove_file(&seg).unwrap();
    std::fs::create_dir(&seg).unwrap();
    c.force_reopen_for_test(d.path());

    let q = CommitQueue::new(c);
    let mut threads = Vec::new();
    for a in 0..4 {
        let h = q.handle();
        threads.push(std::thread::spawn(move || {
            (0..5)
                .map(|i| h.submit(claim(&format!("a-{a}-{i}")), 1_700_000_000))
                .collect::<Vec<_>>()
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();

    assert_eq!(results.len(), 20);
    for r in &results {
        assert!(
            matches!(r, Err(CommitError::NotDurable { .. })),
            "a claim was acked without being durable"
        );
    }
    let stats = q.shutdown();
    assert_eq!(stats.fsyncs, 0, "an unwritable store performed a sync");
}

#[test]
fn a_submitter_whose_queue_is_gone_is_refused_not_hung() {
    // If the commit loop dies, a submitter must get an error rather than
    // block forever. A gateway waiting on an ack that never arrives is the
    // same outage as a wrong answer, and harder to diagnose.
    let d = tempfile::tempdir().unwrap();
    let q = CommitQueue::new(Committer::new(Store::open(d.path()).unwrap()));
    let h = q.handle();
    let _ = q.shutdown();
    assert!(matches!(
        h.submit(claim("a-0"), 1_700_000_000),
        Err(CommitError::NotDurable { .. })
    ));
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --test commit_queue`
Expected: FAIL — `CommitQueue` does not exist.

- [ ] **Step 4: Add `submit_at` to `Committer`**

The batch arriving at the commit loop carries a timestamp per claim, not one for the whole batch. Rather than build records in the loop — which would be a second place records are made, and a second place an `Ack` could be constructed — `Committer` grows a method that takes claims with their own times, and the existing `submit` becomes a thin wrapper.

In `src/commit.rs`, replace the body of `submit` with a delegation and add `submit_at` above it:

```rust
    /// Build records for `claims`, write them as one batch, and return one
    /// result per claim in submission order. Each claim carries its own
    /// `now_secs`, because a batch is assembled from submissions that arrived
    /// at different times.
    ///
    /// Every member of a failed batch fails. There is no partial success: the
    /// batch shares one `fsync`, so either all of its bytes are durable or
    /// none of them are known to be.
    ///
    /// **This is the only place an `Ack` is constructed in this crate.** The
    /// concurrent path in `CommitQueue` routes results from here back to
    /// submitters; it does not build them.
    pub fn submit_at(&mut self, claims: Vec<(Claim, u64)>) -> Vec<Result<Ack, CommitError>> {
        let n = claims.len();
        if self.unavailable {
            return vec![
                Err(CommitError::NotDurable {
                    why: "the evidence store could not be opened".to_string()
                });
                n
            ];
        }
        let mut records = Vec::with_capacity(n);
        let first_step = self.store.next_step();
        let mut head = self.store.head();

        for (i, (c, now_secs)) in claims.into_iter().enumerate() {
            let r = Record::new(c, first_step + i as u64, head, now_secs);
            match crate::chain::extend(head, &r) {
                Ok(next) => head = next,
                Err(e) => return vec![Err(CommitError::NotDurable { why: e.to_string() }); n],
            }
            records.push(r);
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

    /// One timestamp for the whole batch. Kept because the CLI and the Phase 1
    /// tests submit a batch that was assembled at a single instant.
    pub fn submit(&mut self, claims: Vec<Claim>, now_secs: u64) -> Vec<Result<Ack, CommitError>> {
        self.submit_at(claims.into_iter().map(|c| (c, now_secs)).collect())
    }
```

- [ ] **Step 5: Add `CommitQueue`**

First extend the imports at the **top** of `src/commit.rs`, beside the existing
`use std::path::Path;` — rustfmt keeps imports grouped at the head of the file:

```rust
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
```

Then append the rest to the end of `src/commit.rs`:

```rust
/// One claim on its way to the log, with somewhere to send the answer.
struct Submission {
    claim: Claim,
    now_secs: u64,
    reply: SyncSender<Result<Ack, CommitError>>,
}

/// Work, or the instruction to stop.
///
/// Stopping is an explicit message rather than "the last sender was dropped".
/// Handles are cloneable and outlive the queue value, so waiting for every
/// sender to drop would let one forgotten handle hang `shutdown` forever. The
/// message travels the same channel as the work, so FIFO ordering guarantees
/// everything submitted before the stop is committed before the loop exits.
enum Msg {
    Submit(Submission),
    Stop,
}

/// What a completed run of the queue observed. Reported by `bench` so that a
/// claims/second figure can be checked against the number of times the disk
/// was actually made to commit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub batches: u64,
    pub claims: u64,
    pub fsyncs: u64,
    pub batch_sizes: Vec<usize>,
}

/// A commit loop fed by a channel: many submitters, one batching thread, one
/// `fsync` per batch.
///
/// **The `Ack` guarantee crosses a thread boundary here and does not change.**
/// The loop calls `Committer::submit_at`, which is the single place an `Ack`
/// is constructed, and forwards the results to the submitters that are waiting
/// for them. A submitter *receives* an `Ack` and has no way to build one, so
/// "acknowledge before durable" remains inexpressible rather than merely
/// discouraged.
///
/// Batching policy is "take whatever is queued when the loop wakes". There is
/// no timer and no target batch size: a timer would trade latency for
/// throughput according to a constant we chose, which would make the benchmark
/// a measurement of that constant. Taking whatever has arrived makes batch size
/// an observable of the offered load instead.
pub struct CommitQueue {
    tx: Option<Sender<Msg>>,
    worker: Option<JoinHandle<QueueStats>>,
}

/// A cloneable submission handle. One per agent thread.
#[derive(Clone)]
pub struct QueueHandle {
    tx: Sender<Msg>,
}

impl QueueHandle {
    /// Submit one claim and block until the log has answered.
    ///
    /// Returns `NotDurable` rather than blocking forever if the commit loop is
    /// gone. A caller waiting on an acknowledgement that will never arrive is
    /// the same outage as a wrong answer and harder to diagnose.
    pub fn submit(&self, claim: Claim, now_secs: u64) -> Result<Ack, CommitError> {
        let (reply, answer) = sync_channel(1);
        let gone = |_| CommitError::NotDurable {
            why: "the commit loop is not running".to_string(),
        };
        self.tx
            .send(Msg::Submit(Submission {
                claim,
                now_secs,
                reply,
            }))
            .map_err(gone)?;
        answer.recv().map_err(gone)?
    }
}

impl CommitQueue {
    pub fn new(committer: Committer) -> Self {
        let (tx, rx) = channel::<Msg>();
        let worker = std::thread::spawn(move || run_loop(committer, rx));
        Self {
            tx: Some(tx),
            worker: Some(worker),
        }
    }

    pub fn handle(&self) -> QueueHandle {
        QueueHandle {
            tx: self.tx.clone().unwrap_or_else(dead_sender),
        }
    }

    /// Stop accepting work, commit what is already queued, and report what
    /// happened.
    pub fn shutdown(mut self) -> QueueStats {
        self.stop()
    }

    fn stop(&mut self) -> QueueStats {
        if let Some(tx) = self.tx.take() {
            // A closed channel means the loop already exited; nothing to stop.
            let _ = tx.send(Msg::Stop);
        }
        match self.worker.take() {
            Some(w) => w.join().unwrap_or_default(),
            None => QueueStats::default(),
        }
    }
}

impl Drop for CommitQueue {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// A sender whose receiver is already gone, handed out if `handle()` is somehow
/// called after the queue stopped. Every submission on it is refused rather
/// than panicking, so even a refactor that breaks the invariant fails closed.
fn dead_sender() -> Sender<Msg> {
    let (tx, rx) = channel();
    drop(rx);
    tx
}

fn run_loop(mut committer: Committer, rx: Receiver<Msg>) -> QueueStats {
    let mut stats = QueueStats::default();
    loop {
        // Block for the first message. `Err` means every handle is gone.
        let first = match rx.recv() {
            Ok(Msg::Submit(s)) => s,
            Ok(Msg::Stop) | Err(_) => break,
        };
        let mut batch = vec![first];
        // Take whatever else has already arrived. No timer: see the type docs.
        // A `Stop` found while draining ends the loop *after* this batch
        // commits, so nothing already submitted is dropped on the floor.
        let mut stopping = false;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Submit(s) => batch.push(s),
                Msg::Stop => {
                    stopping = true;
                    break;
                }
            }
        }

        let pairs: Vec<(Claim, u64)> = batch
            .iter()
            .map(|s| (s.claim.clone(), s.now_secs))
            .collect();
        let results = committer.submit_at(pairs);

        stats.batches += 1;
        stats.claims += batch.len() as u64;
        stats.batch_sizes.push(batch.len());
        stats.fsyncs = committer.sync_count();

        for (s, r) in batch.into_iter().zip(results) {
            // A submitter that has given up is not an error worth stopping
            // for; its record is durable either way.
            let _ = s.reply.send(r);
        }

        if stopping {
            break;
        }
    }
    stats
}
```

Add the accessor `run_loop` needs, next to `next_step` in `impl Committer`:

```rust
    /// Successful `fsync` calls made by the underlying store.
    pub fn sync_count(&self) -> u64 {
        self.store.sync_count()
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test commit_queue`
Expected: PASS, 4 tests.

If `group_commit_actually_batches_under_concurrent_load` fails, the loop is committing one claim per batch. Check that `try_recv` draining is present. **Do not weaken the assertion to `<=`** — a queue that never batches has no reason to exist.

- [ ] **Step 7: Run the whole suite and commit**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all PASS — Phase 1's 49 tests plus 4 new ones.

```bash
git add -A
git commit -m "Add the concurrent commit path, with Ack still built in exactly one place"
```

---

## Task 2: Host provenance, with the sync cost measured

**Files:**
- Modify: `Cargo.toml`, `src/lib.rs`
- Create: `src/bench/mod.rs`, `src/bench/host.rs`

**Interfaces:**
- Produces: `bench::TopologyKind` with `ALL: [TopologyKind; 3]`, `name(&self) -> &'static str`, `tree_for(&self, agent: &str) -> topology::TreeId`; `bench::host::Host` with `detect(dir: &Path) -> Host` and public fields `os`, `arch`, `cpu_model`, `logical_cores`, `sync_call`, `sync_us`, `crate_commit`.

A measurement with no record of the machine is not a measurement, so this lands before anything that produces a number.

- [ ] **Step 1: Add the feature and the dependency**

In `Cargo.toml`, add after `[dependencies]`:

```toml
occultation = { git = "https://github.com/Task-force-for-AI-agents-in-Healthcare/occultation.git", rev = "3f50bdd", optional = true }
```

and add, after the `[dependencies]` block:

```toml
[features]
# `bench` pulls occultation, which pulls blstrs and the BLS12-381 stack. The
# default build and the whole default test suite stay free of it.
bench = ["dep:occultation"]

[[bin]]
name = "ephemeris-bench"
path = "src/bin/ephemeris-bench.rs"
required-features = ["bench"]
```

- [ ] **Step 2: Declare the module**

In `src/lib.rs`, add in alphabetical position:

```rust
#[cfg(feature = "bench")]
pub mod bench;
```

- [ ] **Step 3: Write `src/bench/mod.rs`**

```rust
//! The measurement harness. Behind the `bench` feature, because it pulls
//! `occultation` and the BLS12-381 stack that comes with it.
//!
//! Nothing in here is on the write path. `CommitQueue`, which the harness
//! drives, is deliberately *not* feature-gated: measuring something other than
//! what ships would defeat the point.

pub mod host;
pub mod linkability;
pub mod run;

use crate::topology::{Global, Joint, PerAgent, Topology, TreeId};

/// The three topologies, as a value so the matrix can iterate them.
///
/// `Topology` is a trait with three unit implementations; this enum dispatches
/// to those same implementations rather than restating their rules, so a
/// change to how a topology assigns trees cannot silently fail to reach the
/// benchmark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyKind {
    Global,
    PerAgent,
    Joint,
}

impl TopologyKind {
    pub const ALL: [TopologyKind; 3] =
        [TopologyKind::Global, TopologyKind::PerAgent, TopologyKind::Joint];

    pub fn name(&self) -> &'static str {
        match self {
            TopologyKind::Global => "global",
            TopologyKind::PerAgent => "per-agent",
            TopologyKind::Joint => "joint",
        }
    }

    pub fn tree_for(&self, agent: &str) -> TreeId {
        match self {
            TopologyKind::Global => Global.tree_for(agent),
            TopologyKind::PerAgent => PerAgent.tree_for(agent),
            // The interval does not affect partitioning, only anchoring.
            TopologyKind::Joint => Joint { interval_secs: 60 }.tree_for(agent),
        }
    }
}
```

- [ ] **Step 4: Write `src/bench/host.rs`**

The sync cost is **measured on the machine doing the benchmarking**, not asserted from a table. The design spec's own figure was wrong on its first pass and was corrected by measuring; this makes that correction impossible to skip.

```rust
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

/// The machine a measurement came from. Committed alongside every result,
/// because a laptop number is not a production number and the file should say
/// so rather than the README saying it once.
#[derive(Clone, Debug, Serialize)]
pub struct Host {
    pub os: String,
    pub arch: String,
    pub cpu_model: String,
    pub logical_cores: usize,
    /// The call `store::append_batch` makes.
    pub sync_call: String,
    /// **Measured**, not assumed. On macOS `File::sync_data` is
    /// `F_FULLFSYNC` and costs milliseconds; on Linux it is `fdatasync` and
    /// typically does not force a drive cache flush at all. A throughput
    /// number is meaningless without this figure next to it, and the two
    /// platforms are not comparable.
    pub sync_us: f64,
    pub crate_commit: String,
}

impl Host {
    pub fn detect(dir: &Path) -> Host {
        Host {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_model: cpu_model(),
            logical_cores: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            sync_call: "std::fs::File::sync_data".to_string(),
            sync_us: measure_sync_us(dir),
            crate_commit: crate_commit(),
        }
    }
}

/// Time one `write` + `sync_data` pair, the same sequence `append_batch`
/// performs. Returns the mean over `N` iterations in microseconds, or `f64::NAN`
/// if the probe could not run — a NaN in the results file is a visible absence
/// rather than a plausible zero.
fn measure_sync_us(dir: &Path) -> f64 {
    const N: u32 = 50;
    let path = dir.join(".sync-probe");
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return f64::NAN,
    };
    let start = Instant::now();
    for _ in 0..N {
        if f.write_all(b"sync-probe\n").is_err() || f.sync_data().is_err() {
            let _ = std::fs::remove_file(&path);
            return f64::NAN;
        }
    }
    let per = start.elapsed().as_secs_f64() / f64::from(N) * 1e6;
    let _ = std::fs::remove_file(&path);
    per
}

fn cpu_model() -> String {
    #[cfg(target_os = "macos")]
    let probe = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output();
    #[cfg(not(target_os = "macos"))]
    let probe = std::process::Command::new("sh")
        .args([
            "-c",
            "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'",
        ])
        .output();

    match probe {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                "unknown".to_string()
            } else {
                s
            }
        }
        _ => "unknown".to_string(),
    }
}

fn crate_commit() -> String {
    match std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}
```

- [ ] **Step 5: Check it compiles under the feature**

Run: `cargo check --features bench`
Expected: FAIL — `bench::linkability` and `bench::run` do not exist yet. That is expected; they arrive in Tasks 3 and 4. Confirm the only errors are the two missing modules.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add the bench feature, the topology matrix, and host provenance with a measured sync cost"
```

---

## Task 3: Throughput and latency

**Files:**
- Create: `src/bench/run.rs`

**Interfaces:**
- Consumes: `commit::{CommitQueue, Committer, QueueStats}`, `store::Store`, `record::Claim`, `bench::TopologyKind`.
- Produces: `bench::run::{RunConfig, RunReport, Latency, Batches, run}`. `run(cfg: &RunConfig, dir: &Path) -> Result<RunReport, RunError>`.

- [ ] **Step 1: Write `src/bench/run.rs`**

```rust
use crate::commit::{CommitQueue, Committer};
use crate::record::Claim;
use crate::store::{Store, StoreError};
use crate::bench::TopologyKind;
use serde::Serialize;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("could not open the store for the run: {0}")]
    Store(#[from] StoreError),
    #[error("an agent thread panicked, so this run measured nothing")]
    AgentPanicked,
}

#[derive(Clone, Copy, Debug)]
pub struct RunConfig {
    pub topology: TopologyKind,
    pub agents: usize,
    pub claims_per_agent: usize,
}

/// Latency in microseconds, submit to `Ack`.
///
/// Percentiles rather than a mean: the mean hides exactly the tail a gateway
/// waits on, and the tail is the number that decides whether fail-closed
/// logging is deployable.
#[derive(Clone, Debug, Serialize)]
pub struct Latency {
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Batches {
    pub count: u64,
    pub mean_size: f64,
    pub max_size: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunReport {
    pub topology: String,
    pub agents: usize,
    pub claims: usize,
    pub wall_secs: f64,
    pub claims_per_sec: f64,
    pub latency: Latency,
    pub batches: Batches,
    /// The physical quantity the throughput figure follows from.
    pub fsyncs: u64,
}

/// Drive the queue with `agents` threads and measure what comes back.
///
/// Every latency here is measured around a real submit-to-`Ack` round trip.
/// Nothing is modelled, extrapolated, or inferred from batch timings.
pub fn run(cfg: &RunConfig, dir: &Path) -> Result<RunReport, RunError> {
    let queue = CommitQueue::new(Committer::new(Store::open(dir)?));

    let started = Instant::now();
    let mut threads = Vec::with_capacity(cfg.agents);
    for a in 0..cfg.agents {
        let h = queue.handle();
        let per = cfg.claims_per_agent;
        threads.push(std::thread::spawn(move || {
            let agent = format!("agent-{a}");
            let mut samples = Vec::with_capacity(per);
            for i in 0..per {
                let c = claim(&agent, i);
                let t = Instant::now();
                let ack = h.submit(c, 1_700_000_000);
                let us = t.elapsed().as_secs_f64() * 1e6;
                if ack.is_ok() {
                    samples.push(us);
                }
            }
            samples
        }));
    }

    let mut samples = Vec::new();
    for t in threads {
        samples.extend(t.join().map_err(|_| RunError::AgentPanicked)?);
    }
    let wall = started.elapsed().as_secs_f64();
    let stats = queue.shutdown();

    let mean_size = if stats.batches == 0 {
        0.0
    } else {
        stats.claims as f64 / stats.batches as f64
    };

    Ok(RunReport {
        topology: cfg.topology.name().to_string(),
        agents: cfg.agents,
        claims: samples.len(),
        wall_secs: wall,
        claims_per_sec: if wall > 0.0 {
            samples.len() as f64 / wall
        } else {
            0.0
        },
        latency: percentiles(&mut samples),
        batches: Batches {
            count: stats.batches,
            mean_size,
            max_size: stats.batch_sizes.iter().copied().max().unwrap_or(0),
        },
        fsyncs: stats.fsyncs,
    })
}

/// The claim an agent submits. Every field is fixed except the identity ones,
/// so the measurement is of the log rather than of varying record sizes.
pub fn claim(agent: &str, i: usize) -> Claim {
    Claim {
        action_id: format!("{agent}-{i}"),
        agent_id: agent.to_string(),
        initiating_user: "user:alice".into(),
        interception_point: "PRE_CALL_TOOL_INVOCATION".into(),
        target_resource: "/v1/charges".into(),
        canonical_snapshot_hash: "54c323d3".into(),
        path_summary_hash: None,
        policy_bundle_hash: "a7713be5".into(),
        verdict: "ALLOW".into(),
        nonce: format!("n-{agent}-{i}"),
    }
}

/// Nearest-rank percentiles over the sorted samples.
fn percentiles(samples: &mut [f64]) -> Latency {
    if samples.is_empty() {
        return Latency {
            p50_us: f64::NAN,
            p95_us: f64::NAN,
            p99_us: f64::NAN,
            max_us: f64::NAN,
        };
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let at = |q: f64| -> f64 {
        let rank = (q * samples.len() as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(samples.len() - 1);
        samples[idx]
    };
    Latency {
        p50_us: at(0.50),
        p95_us: at(0.95),
        p99_us: at(0.99),
        max_us: at(1.0),
    }
}
```

- [ ] **Step 2: Check it compiles**

Run: `cargo check --features bench`
Expected: FAIL only on the missing `bench::linkability`.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "Add the throughput and latency harness, with percentiles rather than a mean"
```

---

## Task 4: Linkability, and the mapping that must not leak

**Files:**
- Create: `src/bench/linkability.rs`
- Test: `tests/bench_linkability.rs`

**Interfaces:**
- Consumes: `occultation::anonymity::{Fleet, Host as OccHost, partition}`, `bench::TopologyKind`.
- Produces: `bench::linkability::{LinkabilityReport, LinkabilityError, measure}`. `measure(kind: TopologyKind, actions_per_agent: &[(String, usize)]) -> Result<LinkabilityReport, LinkabilityError>`.

- [ ] **Step 1: Write the failing test**

`tests/bench_linkability.rs`:

```rust
#![cfg(feature = "bench")]

use ephemeris::bench::linkability::measure;
use ephemeris::bench::TopologyKind;

fn fleet(agents: usize, each: usize) -> Vec<(String, usize)> {
    (0..agents).map(|a| (format!("agent-{a}"), each)).collect()
}

#[test]
fn a_global_tree_makes_every_action_indistinguishable() {
    // The P05 answer. One tree, so membership distinguishes nobody and the
    // effective anonymity set is the whole population.
    let r = measure(TopologyKind::Global, &fleet(10, 20)).unwrap();
    assert_eq!(r.trees, 1);
    assert_eq!(r.actions, 200);
    assert!((r.effective_anonymity_set - 200.0).abs() < 1e-9);
    assert!(r.entropy_bits.abs() < 1e-9, "one tree cannot carry entropy");
    assert_eq!(r.singleton_trees, 0);
}

#[test]
fn a_per_agent_tree_narrows_an_action_to_its_agent() {
    // The same run, the other topology. Each tree holds exactly one agent's
    // actions, so observing a tree names the agent.
    let r = measure(TopologyKind::PerAgent, &fleet(10, 20)).unwrap();
    assert_eq!(r.trees, 10);
    assert_eq!(r.actions, 200);
    assert!((r.effective_anonymity_set - 20.0).abs() < 1e-9);
    assert!(r.entropy_bits > 3.32, "10 equal trees carry log2(10) bits");
}

#[test]
fn joint_partitions_exactly_as_per_agent_does() {
    // Phase 1's topology test already pins that Joint and PerAgent partition
    // identically; anchoring changes ordering, not partitioning. If this ever
    // fails, Joint has become a third partitioning and that is a bug rather
    // than a finding.
    let f = fleet(7, 13);
    let p = measure(TopologyKind::PerAgent, &f).unwrap();
    let j = measure(TopologyKind::Joint, &f).unwrap();
    assert_eq!(p.trees, j.trees);
    assert_eq!(p.singleton_trees, j.singleton_trees);
    assert!((p.effective_anonymity_set - j.effective_anonymity_set).abs() < 1e-9);
    assert!((p.entropy_bits - j.entropy_bits).abs() < 1e-9);
}

#[test]
fn a_lone_agent_is_a_singleton_under_per_agent_and_not_under_global() {
    // The asymmetry stated as a test: the same fleet, two topologies, and a
    // one-action agent is either hidden or exposed depending only on the
    // topology.
    let f = vec![("busy".to_string(), 100), ("lonely".to_string(), 1)];
    let g = measure(TopologyKind::Global, &f).unwrap();
    let p = measure(TopologyKind::PerAgent, &f).unwrap();
    assert_eq!(g.singleton_trees, 0);
    assert_eq!(p.singleton_trees, 1);
    assert!(p.min_tree == 1 && g.min_tree == 101);
}

#[test]
fn an_empty_fleet_is_refused_rather_than_reported_as_perfect_anonymity() {
    // Zero actions must not report an effective set of zero and read as a
    // measurement. It is an absence.
    assert!(measure(TopologyKind::Global, &[]).is_err());
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --features bench --test bench_linkability`
Expected: FAIL — `bench::linkability` does not exist.

- [ ] **Step 3: Write `src/bench/linkability.rs`**

```rust
use crate::bench::TopologyKind;
use occultation::anonymity::{partition, AnonymityError, Fleet, Host as OccHost};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum LinkabilityError {
    #[error("a run with no actions has no anonymity to report")]
    NoActions,
    #[error("the anonymity partition failed: {0}")]
    Partition(#[from] AnonymityError),
}

/// What a topology gives away, in ephemeris vocabulary.
///
/// The arithmetic comes from `occultation::anonymity::partition` — one
/// implementation of the metric, so the two tools stay comparable, which is the
/// same reason this crate reuses `transit::jcs` rather than writing a second
/// canonicalizer.
///
/// **The vocabulary does not come from there.** An `AnonymityReport` speaks of
/// fleets, hosts and TCB attributes; a reader finding one of those in
/// `results/` could reasonably take it for a hardware-attestation measurement.
/// Nothing in a committed artefact may read as a measurement of something it is
/// not, so the report is projected into these names and no `occultation` type
/// escapes this module.
#[derive(Clone, Debug, Serialize)]
pub struct LinkabilityReport {
    pub topology: String,
    /// Total actions in the run — the population.
    pub actions: usize,
    pub agents: usize,
    /// Distinct trees the topology assigned — the observable partition.
    pub trees: usize,
    /// Expected number of actions an observed action is indistinguishable
    /// from: `sum(n_i^2) / N`. Equal to `actions` when one tree holds
    /// everything, and to the per-agent action count when each agent has its
    /// own tree.
    pub effective_anonymity_set: f64,
    /// Shannon entropy over the tree-size distribution, in bits. Zero when a
    /// single tree holds every action.
    pub entropy_bits: f64,
    /// Trees holding exactly one action. That action's anonymity set is
    /// itself.
    pub singleton_trees: usize,
    pub min_tree: usize,
    pub median_tree: usize,
    pub max_tree: usize,
}

/// Measure what a topology reveals, given how many actions each agent
/// performed.
///
/// The mapping onto `occultation`'s API, stated explicitly because it is a
/// different population than that crate was written for:
///
/// | occultation | here |
/// | --- | --- |
/// | a `Host` | an agent |
/// | `Host::count` | that agent's action count |
/// | the TCB fingerprint | the `TreeId` the topology assigned |
/// | a partition | the actions sharing one tree |
///
/// The question is identical in shape — a population, an observable
/// fingerprint, and how far the fingerprint narrows the population — which is
/// why the arithmetic transfers unchanged.
pub fn measure(
    kind: TopologyKind,
    actions_per_agent: &[(String, usize)],
) -> Result<LinkabilityReport, LinkabilityError> {
    let total: usize = actions_per_agent.iter().map(|(_, n)| *n).sum();
    if actions_per_agent.is_empty() || total == 0 {
        return Err(LinkabilityError::NoActions);
    }

    let host = |(agent, count): &(String, usize)| {
        let mut tcb = BTreeMap::new();
        // The single "attribute" is the tree the topology assigned. This is
        // the fingerprint an observer of an inclusion proof learns.
        tcb.insert("tree".to_string(), kind.tree_for(agent).0);
        OccHost {
            id: agent.clone(),
            count: *count,
            tcb,
        }
    };

    let fleet = Fleet {
        name: kind.name().to_string(),
        host: actions_per_agent.iter().map(host).collect(),
    };
    let report = partition(&fleet)?;

    Ok(LinkabilityReport {
        topology: kind.name().to_string(),
        actions: report.fleet_size,
        agents: actions_per_agent.len(),
        trees: report.partitions.len(),
        effective_anonymity_set: report.effective_set,
        entropy_bits: report.entropy_bits,
        singleton_trees: report.singletons,
        min_tree: report.min_set,
        median_tree: report.median_set,
        max_tree: report.max_set,
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features bench --test bench_linkability`
Expected: PASS, 5 tests.

If `a_per_agent_tree_narrows_an_action_to_its_agent` reports an effective set other than 20, check the mapping puts the **action count** in `Host::count` rather than 1 per agent. The population is actions, not agents.

- [ ] **Step 5: Verify no occultation type escapes**

Run: `grep -rn "occultation" src/ --include=*.rs | grep -v "^src/bench/linkability.rs"`
Expected: no output. The dependency is confined to one module by design; if it has spread, the vocabulary will leak into results.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Measure linkability by reusing occultation's metric and renaming its output"
```

---

## Task 5: The matrix, and the results files

**Files:**
- Create: `src/bin/ephemeris-bench.rs`, `results/README.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write `src/bin/ephemeris-bench.rs`**

```rust
//! Runs the measurement matrix and writes `results/<topology>.json`.
//!
//!     cargo run --release --features bench --bin ephemeris-bench
//!
//! `--release` matters: a debug build measures rustc's bounds checks as much
//! as the log.

use anyhow::{Context, Result};
use clap::Parser;
use ephemeris::bench::host::Host;
use ephemeris::bench::linkability::measure;
use ephemeris::bench::run::{run, RunConfig, RunReport};
use ephemeris::bench::TopologyKind;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ephemeris-bench", about = "Measure both axes of the topology trade-off")]
struct Cli {
    /// Where to write results.
    #[arg(long, default_value = "results")]
    out: PathBuf,
    /// Agent counts to sweep.
    #[arg(long, value_delimiter = ',', default_value = "1,10,100,1000")]
    agents: Vec<usize>,
    /// Claims each agent submits.
    #[arg(long, default_value_t = 20)]
    claims_per_agent: usize,
}

#[derive(Serialize)]
struct TopologyResults {
    topology: String,
    host: Host,
    /// Recorded before any number was measured, so a contradicting run reads
    /// as a contradiction rather than quietly becoming the new expectation.
    prediction: &'static str,
    throughput: Vec<RunReport>,
    linkability: Vec<serde_json::Value>,
}

const PREDICTION: &str = "All three topologies share one store and one fsync per batch, \
so throughput is expected to be mean_batch_size * (1e6 / sync_us) claims/second for every \
topology, and the topology axis is expected to barely move it. Linkability is expected to \
rank global best, per-agent worst, and joint exactly equal to per-agent.";

fn main() -> Result<()> {
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.out)
        .with_context(|| format!("could not create {}", cli.out.display()))?;

    let scratch = tempfile::tempdir().context("could not create a scratch directory")?;
    let host = Host::detect(scratch.path());
    println!(
        "host: {} {} · {} · {} cores · {} = {:.0} us",
        host.os, host.arch, host.cpu_model, host.logical_cores, host.sync_call, host.sync_us
    );

    for kind in TopologyKind::ALL {
        let mut throughput = Vec::new();
        let mut links = Vec::new();

        for &agents in &cli.agents {
            let dir = tempfile::tempdir().context("could not create a run directory")?;
            let cfg = RunConfig {
                topology: kind,
                agents,
                claims_per_agent: cli.claims_per_agent,
            };
            let report = run(&cfg, dir.path()).context("the run failed")?;
            println!(
                "  {:9} agents={:<5} {:>9.1} claims/s  p99={:>9.1}us  batch={:.1}  fsyncs={}",
                kind.name(),
                agents,
                report.claims_per_sec,
                report.latency.p99_us,
                report.batches.mean_size,
                report.fsyncs
            );
            throughput.push(report);

            let per_agent: Vec<(String, usize)> = (0..agents)
                .map(|a| (format!("agent-{a}"), cli.claims_per_agent))
                .collect();
            let l = measure(kind, &per_agent).context("linkability measurement failed")?;
            links.push(serde_json::to_value(l)?);
        }

        let out = TopologyResults {
            topology: kind.name().to_string(),
            host: host.clone(),
            prediction: PREDICTION,
            throughput,
            linkability: links,
        };
        let path = cli.out.join(format!("{}.json", kind.name()));
        let text = serde_json::to_string_pretty(&out)?;
        std::fs::write(&path, text)
            .with_context(|| format!("could not write {}", path.display()))?;
        println!("  wrote {}", path.display());
    }

    Ok(())
}
```

- [ ] **Step 2: Move `tempfile` so the binary can use it**

`tempfile` is currently a dev-dependency and the binary needs it. In `Cargo.toml`, remove it from `[dev-dependencies]` and add it to `[dependencies]` as optional, then include it in the feature:

```toml
tempfile = { version = "3", optional = true }
```

```toml
[features]
bench = ["dep:occultation", "dep:tempfile"]
```

Because integration tests also use `tempfile`, add it back for tests only:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Run the matrix**

Run: `cargo run --release --features bench --bin ephemeris-bench`
Expected: three files in `results/`, and console output showing claims/second, p99 latency, mean batch size and fsync count for each topology at each agent count.

**Sanity-check the output before committing it.** `fsyncs` must be greater than zero and no greater than the number of claims. `claims_per_sec` should land near `mean_batch_size * (1e6 / host.sync_us)`. If throughput vastly exceeds that, the store is not syncing what it claims to and that is a finding to report, not a number to publish.

- [ ] **Step 4: Write `results/README.md`**

```markdown
# Measurements

Produced by `cargo run --release --features bench --bin ephemeris-bench`.

**These are measurements of one machine at one moment, not properties of
`ephemeris`.** Every file records the host that produced it — CPU, core count,
OS, the sync call used, and the measured cost of that call. Read those fields
before reading any throughput number.

**Do not compare across platforms without checking `sync_call` and `sync_us`.**
On macOS `File::sync_data` is `F_FULLFSYNC` and forces a drive cache flush,
costing milliseconds. On Linux it is `fdatasync`, which on typical hardware does
not. A Linux run may look an order of magnitude faster while providing *weaker*
durability, so the comparison is meaningless unless both figures are quoted.

`prediction` in each file is what the design expected **before** anything was
measured. It is recorded so a contradicting result reads as a contradiction
rather than quietly becoming the new expectation.
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add the bench binary and the first measurements, with their host recorded"
```

---

## Task 6: CI

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the feature build and a tiny end-to-end run**

Feature-gated code that CI does not build stops compiling quietly.

`occultation` is a **second** private-repo dependency, but it needs no new CI
step: the existing authentication step rewrites `https://github.com/` wholesale,
so one `DEPS_READ_TOKEN` with org read access covers both it and `transit`. The
shape of that blocker does not change; only the number of repos behind it does.

Add to the `rust` job, after the existing `cargo test --all-targets` step:

```yaml
      - run: cargo clippy --all-targets --features bench -- -D warnings
      - run: cargo test --features bench

      # A benchmark that cannot run is not a benchmark. This asserts the
      # harness produces a well-formed result for every topology; it asserts
      # NO threshold, because a performance assertion on a shared runner is a
      # test of that runner's hardware and will flake.
      - name: the harness still produces a result for every topology
        shell: bash
        run: |
          set -euo pipefail
          out="$(mktemp -d)"
          cargo run --release --features bench --bin ephemeris-bench -- \
            --out "$out" --agents 2 --claims-per-agent 10
          for t in global per-agent joint; do
            f="$out/$t.json"
            [ -s "$f" ] || { echo "::error::no results file for $t"; exit 1; }
            python3 - "$f" <<'PY'
          import json, sys
          d = json.load(open(sys.argv[1]))
          assert d["throughput"], "no throughput runs recorded"
          assert d["linkability"], "no linkability runs recorded"
          for r in d["throughput"]:
              assert r["fsyncs"] > 0, "a run reported zero fsyncs"
              assert r["claims"] > 0, "a run recorded no claims"
          assert d["host"]["logical_cores"] > 0, "host provenance missing"
          print(f"{sys.argv[1]}: ok")
          PY
          done
```

- [ ] **Step 2: Validate the YAML locally**

Run: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "YAML OK"'`
Expected: `YAML OK`.

- [ ] **Step 3: Run the same commands locally**

Run the tiny end-to-end exactly as CI will, into a temporary directory, and confirm it exits 0 without touching the committed `results/`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Build and exercise the bench feature in CI, asserting shape rather than speed"
```

---

## Task 7: The write-up

**Files:**
- Modify: `README.md`, `paper/main.tex`, `paper/README.md`, `paper/main.pdf`

The measurement is not finished until the documents that said "we measured nothing" stop saying it.

- [ ] **Step 1: Replace the README's "Not measured" paragraph**

The current text reads:

> **Not measured.** There is no throughput number here, and no linkability
> number. Phase 1 ships no benchmark at all, so any claim about what this costs
> at agent action rates would be invented. That is Phase 2's `bench`, across all
> three topologies.

Replace it with a **Measured** paragraph giving the headline figures from `results/`, the host they came from, and — stated plainly — whether the prediction held. Add the sync-cost caveat and a pointer to `results/README.md`. Update the badge if the test count changed.

- [ ] **Step 2: Replace the paper's no-numbers passages**

In `paper/main.tex`, §7 currently contains:

> We have no performance numbers. None. The log batches claims into a single
> sync and we have not measured what that costs, so we do not know whether the
> durability requirement is compatible with the action rates people want from
> agents, and we are not going to guess.

and

> We have not measured the linkability cost of the tree topology. [...] Those
> two facts point in opposite directions and we have implemented all three
> arrangements without measuring either axis.

Both must go. Add a new section before §7 reporting what was measured: the sync ceiling, throughput against it, the tail latency, and both axes side by side. **Report whichever prediction failed as prominently as the ones that held** — the design recorded them precisely so a contradiction is visible.

- [ ] **Step 3: Update `paper/README.md`**

Its status note currently says the paper "deliberately reports **no measurements**". That is no longer true. Update it, and update the "No fabricated numbers" note to say where the figures come from and that they are one machine's.

- [ ] **Step 4: Rebuild the PDF**

Run: `cd paper && tectonic main.tex`
Expected: `main.pdf` written, no undefined citations.

- [ ] **Step 5: Full verification**

Run: `cargo test && cargo test --features bench && cargo clippy --all-targets --features bench -- -D warnings && cargo fmt --check`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Report what was measured, in the README and the paper"
```

---

## Done

`ephemeris` now measures both axes of its own central trade-off, and says which machine the numbers came from.

**Still Phase 2, still not here:** the UDS listener (blocked on the `path_summary_hash` fork in the transit-guard spec), the TEE signer, and the `poc-audit` cross-check.
