# Design — `ephemeris bench`, measuring both axes

**Date:** 2026-08-10 · **Status:** approved, ready for implementation planning ·
**Repo:** existing — [`ephemeris`](https://github.com/AAI-Society/ephemeris),
adding a dependency on
[`occultation`](https://github.com/AAI-Society/occultation)

**Supersedes nothing.** This is item 3 of the four listed as "Phase 2, in its own
plan" at the end of `2026-08-10-ephemeris.md`. The other three — the UDS listener,
the TEE signer, and the `poc-audit` cross-check — are out of scope here and are
discussed only where they constrain this work.

---

## Why

`ephemeris` Phase 1 shipped a durable, software-signed evidence log with exhaustively
verified proofs, and **no numbers at all**. Its README and paper both say so in those
terms: "Phase 1 ships no benchmark, so any claim about what this costs at agent action
rates would be invented."

That silence is honest but it leaves the design's central finding unmeasured. The
`ephemeris` design states that P08 and P05 rank the three topologies in opposite orders
— per-agent trees parallelize and therefore win on throughput, and a per-agent tree key
*is* an agent identifier and therefore loses on linkability — and records the conflict
as unresolved with no path to resolving it. It then says: "Measuring both axes over one
trait is the path."

This is that measurement.

## Scope

**In:**

- A concurrent commit front-end (`CommitQueue`), because per-claim tail latency across a
  fleet is not measurable against a synchronous `&mut self` API.
- A throughput and latency harness across agent counts 1, 10, 100, 1000 and all three
  topologies.
- A linkability harness reusing `occultation::anonymity::partition`.
- `results/*.json`, committed, each recording the host that produced it.
- Rewriting the paper's §7 passages that say no measurement exists, and the README's
  "Not measured" paragraph.

**Out:**

- The UDS listener, the TEE signer, the `poc-audit` cross-check.
- Any claim about production hardware. Every number here is a laptop number until
  somebody runs it elsewhere, and the results files say which machine they came from.
- Tuning. This measures the three topologies as built; it does not optimize them. A
  benchmark that also changes the thing it measures cannot report a before and after.

## The boundary

`bench` sits behind a `bench` cargo feature. The default build does not pull
`occultation` or the threading harness, and `cargo test` continues to run fully offline
with no network and no credentials. The binary is declared with
`required-features = ["bench"]`, so a default `cargo build` does not attempt it and
cannot fail on a dependency it was not asked to fetch.

Committed measurements live in `results/` at the repository root, one JSON file per
topology, alongside a `results/README.md` naming the machine and the crate commit they
came from.

`CommitQueue` is the exception and is **not** feature-gated. It is production code: a
real deployment fronting a log with many agents needs exactly this shape, and putting it
behind a benchmark feature would mean the thing we measure is not the thing we ship.

## Architecture

| module | purpose | reuses |
| --- | --- | --- |
| `commit` (extended) | `CommitQueue` — channel-fed commit loop, one `fsync` per batch | `store` |
| `bench::run` | drives the queue at a given agent count; records per-claim latency | `commit` |
| `bench::linkability` | maps a run's records onto an anonymity partition | `occultation::anonymity` |
| `bench::host` | records the machine a measurement came from | — |
| `bin/ephemeris-bench` | runs the matrix, writes `results/*.json` | all of the above |

### `CommitQueue`, and the guarantee that has to survive it

Phase 1's central mechanism is that `Ack` is constructible in exactly one place, after
`fsync` returns, so "acknowledge before durable" is not an expressible program. This is
the first time an `Ack` crosses a thread boundary, and the guarantee has to survive the
crossing unchanged.

```
agent thread ──┐
agent thread ──┼──▶ [ mpsc queue ] ──▶ commit loop ──▶ store::append_batch ──▶ fsync
agent thread ──┘                            │                                    │
      ▲                                     │            Ack constructed here ◀──┘
      └──────────── oneshot per claim ◀──────┘                (still one site)
```

Each submission carries a oneshot sender. The commit loop drains whatever has arrived,
writes it as one batch, and — only after `append_batch` returns `Ok` — constructs one
`Ack` per record and sends each back to its own submitter. On error every member of the
batch receives `CommitError::NotDurable`, matching the existing rule that a batch has no
partial success.

A submitter therefore *receives* an `Ack` and cannot construct one. The single
construction site moves from `Committer::submit` into the loop; it does not multiply.
**If the implementation appears to need a second construction site, that is a signal to
stop and report rather than to add one.**

Batching policy is "take everything queued when the loop wakes", with no timer and no
target batch size. A timer would trade latency for throughput and make the measurement a
function of a tuning constant we chose; taking whatever has arrived makes batch size an
*observable* of the offered load, which is the thing worth reporting.

### Linkability, and the mapping that must be stated

`occultation::anonymity::partition` computes exactly the metrics wanted — effective
anonymity set `Σn²/N`, Shannon entropy over the partition distribution, singleton count,
min/median/max set size. It computes them over a `Fleet` of hosts partitioned by TCB
fingerprint.

Our population is not hosts. The mapping is:

| occultation | ephemeris |
| --- | --- |
| a `Host` | an agent |
| `Host::count` | that agent's action count in the run |
| `Host::tcb` fingerprint | the `TreeId` the topology assigned |
| a `Partition` | the set of actions sharing one tree |
| effective set `Σn²/N` | expected number of actions an observed action is indistinguishable from |

The math is identical because the question is identical in shape: a population, an
observable fingerprint, and how much the fingerprint narrows the population. Reusing it
is the same discipline that makes this crate reuse `transit::jcs` rather than write a
second canonicalizer — two implementations of one metric diverge silently and destroy
comparability between the two tools.

**But the vocabulary must not leak.** An `AnonymityReport` rendered as-is is TCB-shaped
prose: it names `distinguishing_attributes`, it speaks of fleets and hosts, and a reader
finding one in `results/` could reasonably take it for a hardware-attestation
measurement. So `bench::linkability` projects the report into an ephemeris-side type
that names actions, agents, and trees, and no `occultation` type appears in any
committed artefact. Nothing in `results/` may read as a measurement of something it is
not.

The projection is pinned by test in both directions: a global topology yields exactly
one partition whose effective set is the full action count; a per-agent topology yields
one partition per agent; and no field of the source report is dropped in translation
without that being deliberate.

## The prediction, recorded before the measurement

The `ephemeris` design says the two-axes finding "should be stated before any number is
measured, so that the measurement can contradict it." Recorded here, so that a
contradicting run reads as a contradiction rather than quietly becoming the new
expectation:

| | expected throughput rank | expected linkability rank |
| --- | --- | --- |
| **global** | worst — one tree, one serial append point | best — every action in one tree, so membership distinguishes nobody |
| **per-agent** | best — independent trees, no cross-agent ordering | worst — the tree key *is* an agent identifier |
| **joint** | close to per-agent, plus anchor cost | same as per-agent; anchoring changes ordering, not partitioning |

Two predictions we expect to be *wrong*, and want the measurement to settle:

1. **Topology may not move throughput much at all.** All three share one store, one
   segment file, and one `fsync` per batch, so the physical bottleneck is identical
   across them; the tree work is in-memory hashing. If that dominates, the honest
   finding is that P08's preference is not purchased by the topology at these rates,
   which would be a more interesting result than confirming it. The `fsync` measurement
   under **Failure modes** turns this into a falsifiable number: sustained
   claims/second should land near `mean_batch_size × 310` on the development machine,
   within a small constant, for **all three** topologies. If the topologies differ by
   more than that, something other than durability is dominating and the write-up must
   say what.
2. **Joint should equal per-agent on linkability exactly**, since Phase 1's topology
   test already pins that they partition identically. If they differ, the anchoring
   implementation has become a third partitioning and that is a bug, not a finding.

## What is measured

Per topology, per agent count in {1, 10, 100, 1000}:

| quantity | why it is here |
| --- | --- |
| claims/second sustained | P08's question |
| latency p50 / p95 / p99 / max, submit → `Ack` | a mean hides exactly the tail a gateway waits on |
| batch size distribution | how much group commit actually amortized under this load |
| `fsync` count | the physical quantity the rest follows from; a throughput number that does not track it is measuring the page cache |
| effective anonymity set, entropy bits, singletons | P05's question |

Latency is measured, never modelled. No arrival-process simulation, no extrapolation
from batch timings to per-claim timings — a modelled number that reads as a measured one
is the failure this programme keeps finding in other people's work.

## Failure modes

**`fsync` that does not sync — measured, and it is the opposite way round.** The
concern was that macOS `fsync(2)` does not flush the drive's write cache and only
`F_FULLFSYNC` does, so our numbers might be an optimistic upper bound. Measured on the
development machine, that is not what `ephemeris` does:

| call | µs/op |
| --- | --- |
| `fsync(2)` via libc | 26 |
| `fcntl(F_FULLFSYNC)` via libc | 3,174 |
| `File::sync_data()` — **what `store.rs` calls** | 3,223 |
| `File::sync_all()` | 3,555 |

Rust's `File::sync_data` on macOS is the strong call, within noise of `F_FULLFSYNC` and
122× the cost of plain `fsync`. So the durability numbers are honest rather than
optimistic, and the real consequence is a hard ceiling: **at ~3.2 ms per sync this
machine cannot exceed roughly 310 batches/second, whatever the topology does.**

Two things follow, and both belong in the plan rather than being discovered during it:

1. **Throughput is batch size times ~310/second, and almost nothing else.** All three
   topologies share one store and one sync per batch, so if this holds, the topology
   axis will barely move throughput and the interesting variable is how much load
   arrives while a sync is in flight. See the second "expected to be wrong" prediction
   above, which this measurement sharpens into a number.
2. **A Linux number and a macOS number are not comparable.** On Linux `sync_data` is
   `fdatasync`, which on typical hardware does not force a drive cache flush. A CI run
   may look an order of magnitude faster than the laptop while being *weaker*. Results
   files record the platform and the call, and no cross-platform comparison is drawn
   without saying which was which.

**Threads are not agents.** 1,000 OS threads on a laptop measures the scheduler at least
as much as the log. Thread count is reported as a parameter, and the write-up says where
contention rather than durability is the limit.

**A benchmark that weakens what it measures.** A queue that dropped, coalesced, or
reordered claims to look fast would be measuring a different system. `CommitQueue` runs
under the same fail-closed rule as `Committer`, and the concurrent equivalent of
`an_unwritable_store_acks_nothing` is part of this work rather than deferred.

**Numbers outliving their host.** Committed results are a measurement of one machine at
one time. Every file records CPU, core count, filesystem, OS, the sync call used, and
the commit of the crate that produced it.

## Testing

The harness is tested like production code, because a broken benchmark emits numbers
rather than errors — which is Phase 1's own lesson restated. That phase found a
fail-closed test whose fault injection injected no fault, and it was caught only because
an unrelated bug in the same test failed loudly first.

- **Queue correctness.** Every submitted claim receives exactly one `Ack` or one error —
  never both, never neither — and every acked record is present after a reopen.
- **Fail-closed across the thread boundary.** A queue whose store cannot be opened acks
  nothing, from any submitter, matching Phase 1's rule.
- **Ordering.** Records land with contiguous `step_index` and a chain that
  `verify_sequence` accepts, under concurrent submission. Concurrency may reorder which
  claim gets which index; it may not produce a gap.
- **The linkability projection**, pinned both directions as described above.
- **A tiny end-to-end run in CI** — 2 agents, 20 claims — asserting the results file
  parses and covers every topology. It asserts **no threshold**: a performance assertion
  on a shared runner is a test of that runner's hardware and will flake.

## Risks

**`occultation` is a second private-repo dependency.** CI already fails without
`DEPS_READ_TOKEN` for `transit`; this adds a second repo behind the same secret and does
not change the shape of that blocker.

**The `bench` feature is a place for rot.** Feature-gated code that CI does not build
stops compiling quietly. CI builds `--features bench` and runs its tests, or the feature
is not worth having.

**Scope creep into tuning.** The moment a number is disappointing, the temptation is to
optimize and re-measure. That is a different piece of work; this one reports what the
three topologies as built actually do.

## Build order

1. `CommitQueue` and its tests — production code, fail-closed, `Ack` still unforgeable.
2. `bench::host` — host provenance, so no measurement can be recorded without it.
3. `bench::run` — throughput and latency for one topology at one agent count.
4. `bench::linkability` — the projection and its both-directions test.
5. `bin/ephemeris-bench` — the matrix, and `results/*.json`.
6. CI: build `--features bench`, run the tiny end-to-end.
7. The write-up — README's "Not measured" paragraph and the paper's §7, replaced by what
   was actually measured, including any prediction the run contradicted.

Step 1 is useful on its own and is the only step that changes production behaviour. Each
later step adds a measurement rather than reworking one.
