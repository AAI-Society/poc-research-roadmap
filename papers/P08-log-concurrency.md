# P08 — What a Serial Log Costs a Fleet

**Domain:** C7 Evidence · **Kind:** Empirical · **Impact:** Medium-high · **Effort:** Small

---

## The question

A hash chain is inherently serial: each link depends on the one before. What does that cost a
fleet of concurrent agents, and does per-agent logging break the cross-agent ordering that
delegation and composition analysis need?

## Why it matters

**For the standard.** Every number in the paper is single-core, single-log. The chain is serial by
construction, so a single global log caps throughput regardless of cores. Per-agent logs
parallelize but produce no total order across agents — and cross-agent ordering is exactly what
[P06](P06-delegation-attenuation.md) needs to detect two delegates composing an effect neither
could achieve alone.

**The standard is silent on log granularity**, which means implementers will pick per-agent for
performance and discover the ordering problem later, or pick global and discover the throughput
ceiling. Both discoveries are expensive after deployment.

The paper's own limitations section names this and the reviewers asked for it directly:
*"concurrent multi-agent durability/scalability evaluation with durable logs, root publishing,
proof serving, verifier load, failures, and recovery."*

**For the field.** The same tension appears in distributed tracing, event sourcing, and any
append-only log with ordering semantics. The Merkle-tree work already in the implementation
provides a middle path worth evaluating: per-agent trees with periodic joint roots.

## What is already known

* **Certificate Transparency at scale** — sharding, multiple logs, and the operational literature
  on running them. The closest real-world instance of this exact trade.
* **Distributed logs** — Kafka partitioning, and the standard result that per-partition order is
  cheap while total order is not.
* **Logical and hybrid clocks** — Lamport; vector clocks; HLC (Kulkarni et al.). Give partial
  order without serialization and are the obvious first answer.
* **Verifiable data structures at scale** — Trillian, Merkle² , and aggregation across logs.
* **Consensus cost** — the throughput ceilings of ordered broadcast, which bound the global-log
  option.
* **Streaming durability** — group commit and batching, which the paper already measured for
  signing (64× at batch 128) and which applies again here.

## What is genuinely open

1. **The actual ceiling.** Where does a single global chain saturate with N concurrent agents?
   Unmeasured, and the answer determines whether it is a real constraint or a theoretical one.
2. **Per-agent trees with joint anchoring.** Each agent gets a tree; a periodic joint root commits
   to all of them. Preserves parallelism, gives inclusion proofs, and provides *coarse* cross-agent
   ordering at anchor granularity. Is that enough for delegation analysis?
3. **What ordering the security arguments actually need.** Possibly much less than total order —
   perhaps only causal order along delegation edges. If so, the expensive option is unnecessary
   and that is the paper's main result.
4. **Crash and recovery.** What is in flight when a process dies mid-batch, and how long to
   re-establish? Unmeasured, and relevant to the fail-closed requirement C7.6.3.
5. **Verifier-side load.** Serving inclusion proofs for a fleet under audit: throughput, caching,
   and whether proof serving becomes the bottleneck instead of logging.

## Method

1. Implement three designs on the existing pipeline: single global chain; per-agent chains; and
   per-agent Merkle trees with joint periodic anchoring.
2. Measure throughput and tail latency against 1…1,000 concurrent agents, with durable storage
   rather than in-memory.
3. Determine what ordering guarantee each provides, and check each against the cross-delegate
   composition detection that P06 requires.
4. Crash-recovery: kill mid-batch, measure loss and recovery time, confirm fail-closed holds.
5. Measure proof-serving throughput under audit load.

## What would settle it

Throughput curves for the three designs with a clear statement of which security properties each
preserves. The valuable outcome is a recommendation the standard can adopt: *use per-agent trees
with joint anchoring at interval Δ, which preserves the properties that matter and scales.*

## Consequence for the standard

* New requirement on **log granularity**, currently absent.
* **C7.6.6** may need extending: joint anchoring across agents is a different obligation from
  anchoring one chain.
* **C7.6.3** fail-closed gains measured recovery semantics.

## Venue

A systems venue — ATC, EuroSys, Middleware — or a measurement workshop. Straightforward
engineering with a clear result.

## Effort and dependencies

Small. All three designs are modest changes to code that exists. Should be done **before**
[P06](P06-delegation-attenuation.md), since P06's cross-agent reasoning depends on what ordering
is affordable.
