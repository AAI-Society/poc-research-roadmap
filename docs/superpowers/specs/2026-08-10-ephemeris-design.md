# Design — `ephemeris`, the evidence log

**Date:** 2026-08-10 · **Status:** approved, ready for implementation planning ·
**Repo:** new — `ephemeris`, depending on
[`parallax`](https://github.com/AAI-Society/parallax),
[`transit`](https://github.com/AAI-Society/transit) and
[`occultation`](https://github.com/AAI-Society/occultation)

---

## Why

Seven tools have shipped and none of them emits a Proof-of-Control evidence record.
[`TOOLING.md`](../../../TOOLING.md) counts twenty-one required fields and finds two
produced. `poc-audit`, run against the standard's own strongest positive vector with
every optional input supplied, establishes two rows out of twenty-two — and both are
identity rows whose finding is a privacy cost.

The reason is structural. Every tool in the programme was built to answer a research
question, research questions are about whether a claim holds, and so the programme built
verifiers. Verifying is the half that assumes the record already exists.

`ephemeris` is the half that produces one. It closes thirteen of the twenty-one fields,
and it is the T2 of the tooling roadmap.

## Scope

**In:** an append-only evidence log that accepts claims from an enforcement point, chains
them, builds an RFC 6962 tree over them, signs roots with a key held inside a TEE, and
serves inclusion and consistency proofs. Plus a benchmark that measures three log
topologies on two axes.

**Out, deliberately:**

- **Interception.** C7.1 requires an Action Interception Gateway running as a separate
  process from the agent, and `transit guard` already is one — it sits in the request
  path, canonicalizes the body, decides, and forwards. `ephemeris` never sees a socket
  the agent talks to. See [Boundary](#the-boundary).
- **Policy.** It records verdicts. It does not produce them.
- **Equivocation resistance (C7.3.3).** Shipped as a visible gap, printed on every root.
  See [What this does not defend against](#what-this-does-not-defend-against).
- **Cross-host logging.** A Unix domain socket is the transport, so writer and log share
  a host. See [Risks](#risks).
- **An aggregate verdict.** It emits records. Judging them is `poc-audit`'s job, and the
  programme's rule against a single summary word holds here too.

## The boundary

```
transit guard ──claim──▶ ephemeris                  poc-audit
  decides       (UDS)      1. build record             │
  forwards ◀────ack───     2. append + fsync           │
   (C7.1)                  3. leaf → tree              │
                           4. sign root                │
                           5. serve proofs ◀───────────┘
                             (C7.2, C7.3)
```

`transit guard` satisfies C7.1. `ephemeris` satisfies C7.2 and C7.3. Neither reimplements
the other, and each is testable alone.

This split is a correctness decision rather than a convenience one. C7.1.1 requires the
gateway to hold the only path from agent to tools; C7.3.2 requires the signing key to be
inaccessible to the operator *and* the agent. Putting both in one process means the
component holding the agent's traffic also holds the evidence key. Separating them makes
the key custody claim checkable by looking at which process has it.

## Architecture

| module | purpose | reuses |
| --- | --- | --- |
| `record` | typed evidence record, canonical form, digest | `transit::jcs` |
| `chain` | `chain_head = H(previous_head ‖ canonical_snapshot_hash ‖ verdict)` | — |
| `tree` | RFC 6962 tree, incremental right fringe | — |
| `topology` | global / per-agent / joint-anchored partitioning | — |
| `store` | append-only segments, group commit, crash recovery | — |
| `sign` | TEE-held key, `REPORTDATA` binding | `parallax::attest::tsm` |
| `proof` | inclusion, consistency, published roots | — |
| `serve` | the UDS listener and its four routes | `hyper` |
| `bench` | throughput and linkability across topologies | `occultation::anonymity` |

Canonicalization is `transit::jcs`, not a second implementation. C7.7's own commentary
explains why: two implementations that serialize the same action differently produce
different digests, every signature still verifies, nothing looks broken, and the natural
next step is to relax the comparison until interoperation works — which silently removes
the property the comparison existed to provide. One canonicalizer, reused.

### The topology trait

The core abstraction, and the reason the tool answers a research question rather than
merely storing records.

```rust
trait Topology {
    /// Which tree this agent's leaves land in.
    fn tree_for(&self, agent: &AgentId) -> TreeId;
    fn anchor_policy(&self) -> AnchorPolicy;   // None | Joint(Duration)
}
```

Three implementations over one Merkle core:

| | Trees | Ordering | Throughput | What the chain reveals |
| --- | :--: | --- | --- | --- |
| `Global` | 1 | total | serial ceiling | membership distinguishes nobody |
| `PerAgent` | N | none across agents | parallel | **tree identity is an agent identifier** |
| `Joint(Δ)` | N + joint root | coarse, at Δ | parallel | agent, plus Δ-cohort |

The difference between them is partitioning and anchor cadence. It is a trait boundary,
not three logs.

## The two axes point in opposite directions

This is the design's central finding and it should be stated before any number is
measured, so that the measurement can contradict it.

[P08](../../../papers/P08-log-concurrency.md) asks what a serial log costs a fleet, and
expects per-agent trees with joint anchoring to win: they parallelize, they still give
inclusion proofs, and they provide coarse cross-agent ordering at anchor granularity.

[P05](../../../papers/P05-unlinkable-identity.md) asks what identity evidence gives away.
Against that question the ranking inverts. **A global chain leaks nothing about who acted
— every action is in the same chain, so membership distinguishes nobody. A per-agent
chain's identity is an agent identifier, so every action in it is linked to every other
by construction.**

So the option P08 prefers is the option P05 objects to, and Δ is a two-sided knob rather
than a performance tuning parameter. `TOOLING.md` records this conflict as unresolved
with no path to resolving it. Measuring both axes over one trait is the path.

Neither topology is clean, and the design should not pretend otherwise:

- A global tree still leaks through **inclusion proofs**. A proof reveals a leaf's
  position, and adjacent leaves across agents reveal temporal adjacency — a timing
  channel, not an identity one.
- A per-agent tree leaks **identity directly**, which is the stronger leak.

Both are reported. Neither is described as private.

## Data flow

```
claim ──▶ record::build ──▶ chain::extend ──▶ store::append ──┐
                                                              │ group commit
                              ack ◀── fsync ◀─────────────────┘
                                │
                                └──▶ tree::insert ──▶ sign::root
```

**Acknowledgement happens after `fsync` and never before.** C7.1.3 requires that the
gateway not forward until the *before* record is durably written, so the ack is the
mechanism by which `transit guard` learns it may proceed. An ack that precedes durability
is not an optimization; it removes the requirement.

### What the claim carries, and what `ephemeris` adds

The split is the roadmap's T2/T3 boundary made concrete, and getting it wrong means two
components both believing the other computes a field.

| | Fields | Why there |
| --- | --- | --- |
| **The caller supplies** | `agent_id`, `initiating_user`, `interception_point`, `target_resource`, `canonical_snapshot_hash`, `path_summary_hash`, `policy_bundle_hash`, `verdict`, `nonce`, and an action ID | Only the enforcement point knows what it decided and over which bytes. `ephemeris` cannot recompute a verdict it did not make |
| **`ephemeris` adds** | `iss`, `iat`, `eat_profile`, `step_index`, `chain_head`, `merkle_root`, `tree_size`, `alg`, `signature`, and `submods.attestation` | These are properties of the log and its trust domain, not of the action |
| **Neither supplies** | `agbom_digest` | No AgBOM tooling exists. It is `spectrum`, roadmap T4. The record carries whatever the caller passes and `ephemeris` asserts nothing about it |

Two consequences worth stating. `interception_point` is a *caller-supplied value* even
though the roadmap counts it under T2 — T2 closes it in the sense that a record now carries
it, not in the sense that `ephemeris` derives it. And `agent_id` and `initiating_user` are
recorded as given: verifying that a delegation chain attenuates rather than amplifies is
[P06](../../../papers/P06-delegation-attenuation.md) and roadmap T6, and `ephemeris` must
not be read as checking them.

A claim missing a required caller-supplied field is refused, not defaulted. A defaulted
field is a record that looks complete and is not, which is the failure mode this whole
programme exists to attack.

### `nonce` is caller-supplied, and this is a finding

An earlier draft of this design listed `nonce` among the fields `ephemeris` adds. That was
wrong, and the error is worth recording rather than quietly fixing.

C7.1.4 calls the nonce a **relying-party challenge**: it binds the token to one request and
defeats replay. A challenge minted by the party being challenged defeats nothing. If
`ephemeris` generates its own nonce, the field is present, the record validates, and the
replay property it exists to provide is absent — the exact shape of failure this programme
was founded to attack.

So the caller supplies it, and **a claim without one is refused.** Which surfaces the
finding: the schema marks `nonce` **required**, and nothing in this ecosystem issues one.
No relying party challenges an agent action today. Every record anyone emits is therefore
either schema-invalid or carries a self-minted value that provides no replay resistance.

`ephemeris` refuses rather than papering over it, and the practical path is T5's: a relying
party publishes an **epoch challenge**, and the enforcement point passes it through. That
makes the declared refresh interval observable and is the only variant whose cost is
budgetable against the 39.5 ms quote. Resolving it belongs to
[P03](../../../papers/P03-attestation-freshness.md) and T5, not here — but `ephemeris` must
not make the problem invisible by generating a value.

### Records per action

C7.1.2 requires **three** records per intercepted action — request received, effect
performed, result returned — each independently signed and linkable by one action ID.
This is a different axis from the eight `interception_point` values, and it means record
volume is three times action volume. The benchmark reports actions per second, not records
per second, because the former is what an operator budgets against.

### Group commit

Concurrent claims batch into one `fsync`; every caller waits for that `fsync`; all are
acked together. An `fsync` per record cannot meet the 15 ms per-action budget once three
records per action is accounted for, and group commit is already established in this
programme — the P08 brief records 64× at batch 128 for signing.

Batching does not weaken C7.1.3. Each caller still blocks until its own record is durable;
it merely shares the disk flush with whoever else was waiting.

## Key custody

The signing key is generated inside the TEE and never leaves it. Its binding is
`report_data = SHA-256(SPKI(signing_key))`, requested through
`parallax::attest::tsm::request_quote` — the same call `parallax-attest` already makes for
its TLS key.

This satisfies C7.2.4 (the attestation binds the evidence signing key, so a verifier
establishes *this key ran inside this measured environment* rather than receiving a
measurement and a key that merely arrived together) and C7.3.2 (keys held by the
generating mechanism, inaccessible to operator and agent identities).

Everything TEE-touching sits behind a cargo feature, as `parallax-attest`'s paths already
do, so the default build and the whole test suite run on a developer laptop. A build
without the feature signs with a clearly-labelled software key and **cannot** produce a
root that claims hardware custody — asserted by test, following `occultation`'s
`ModelledPermit` pattern where a modelled implementation cannot construct a valid verdict.

## What this does not defend against

**C7.3.3 equivocation, and this is printed on every root `ephemeris` publishes.**

C7.3.5's own commentary describes the attack, and notes it was present in this
specification's reference implementation and found by building the inclusion-proof
experiment (attack A9): an operator holding the signing key alters a past record,
recomputes every subsequent link, and re-signs the whole log. The result has the right
length and replays perfectly, because nothing about it is internally inconsistent. The
only thing that contradicts it is a root published *before* the rewrite.

`ephemeris` publishes no root outside the operator's control, so the attack stands. Saying
so in the output is the same discipline as `poc-audit` shipping `field/chain` as a
permanent `UNCHECKED` row: a gap you can see is worth more than a table implying coverage
it does not have.

The upgrade is clean and deliberately left for its own design. The root is already
computed; anchoring is publishing it somewhere the operator does not control, and choosing
that somewhere — an RFC 3161 authority, a witness quorum, a ledger — is
[P07](../../../papers/P07-evidence-continuity.md) and
[P12](../../../papers/P12-conformance-credibility.md) territory rather than a paragraph
here.

## A specification gap this will surface

The schema defines `step_index` as **monotonic per agent, starting at 0, with no gaps**,
and defines `chain_head` as `H(previous_head ‖ canonical_snapshot_hash ‖ verdict)`
**without saying which chain `previous_head` belongs to.**

Under `PerAgent` the two agree. Under `Global` they disagree: the chain's predecessor is
some other agent's record, so `step_index` and chain position are different sequences over
the same records. The standard does not say which is meant, and an implementer choosing
`Global` for the privacy reason above has no guidance.

This is expected output, not an obstacle. Three of the standard's existing requirements
exist because writing the code forced a precision the prose never did, and this is the same
shape. The finding belongs in `docs/` in this repository when it lands, alongside
[what building `parallax` established](../../parallax-outcomes.md).

## Failure modes

**Fail-closed, and deliberately opposite to `occultation-gateway`.** The gateway sits in a
revenue path and must never be the reason an API is down, so it fails open. `ephemeris` is
the thing C7.1.3 makes a precondition of action release: if it cannot durably record, the
action must not proceed. Recorded explicitly because the fail-open culture across these
repositories is strong enough that someone would import it here by reflex — `poc-audit`'s
design had to say the same thing for the same reason.

| condition | behaviour |
| --- | --- |
| store unavailable or full | refuse the claim, never ack |
| `fsync` fails | refuse the whole batch, never ack a member |
| TEE unavailable with the feature on | refuse to start, never fall back to software |
| partial record found at startup | truncate to the last complete record, log it |
| tree state inconsistent with the log | refuse to serve proofs, rebuild from the log |

Exit codes follow the suite's convention: `0` clean, `1` a policy or verification failure,
`2` bad input or configuration.

## Testing

Fully offline. No network, no credentials, no TEE in the default configuration.

| test | must fail when |
| --- | --- |
| **A9 rewrite** — rebuild a log with one historical record altered *and re-signed*; reject against a prior root, and confirm a step-count comparison alone would have accepted it | the verifier compares length rather than roots, reintroducing the reference implementation's own defect |
| **Identity derivation, both directions** — every digest gets semantically-identical-compares-equal *and* differs-in-one-contributing-field-compares-unequal | a field feeding `Eq`/`Hash` is specified casually, which was the root cause of four of `parallax`'s five criticals |
| **Crash mid-batch** — kill during group commit | an acked record is lost, or a partial record survives recovery |
| **Write-before-forward** — make the store unavailable | a claim is acked without being durable, removing C7.1.3 |
| **Inclusion and consistency** — proofs verify against published roots; proof size grows logarithmically | a proof is served that does not reconstruct the root |
| **Topology equivalence** — the same claims through all three topologies produce the same *records*, differing only in chaining and tree placement | a topology silently changes what a record says |
| **Software key cannot claim hardware** — a non-TEE build cannot emit a root asserting hardware custody | the feature flag becomes cosmetic |
| **Cross-check into `poc-audit`** — a record `ephemeris` emits drives `field/chain` off `UNCHECKED` | the seam between producer and auditor drifts |

The cross-check is load-bearing. Every other row tests our own code; that one tests whether
the record this tool produces is the record the auditor expects, and it is the first time a
number in `TOOLING.md` moves because a tool produced something rather than because someone
counted schema fields.

## Risks

**The UDS transport rules out cross-host logging**, which a real fleet wants and which P08's
1–1,000 agent measurement will want to span. Accepted for v1: same-host is what C7.2.1's
"within the executing transaction" implies, filesystem permissions are a stronger auth
boundary than a bearer token on loopback, and there is no open port to forge claims at.
Revisit when a measurement actually needs more than one host.

**Anything that can write to the socket can insert records.** Filesystem permissions are the
entire authorization model. Stated in the README rather than mitigated, because a second
authorization layer inside the log would be security theatre over a boundary the OS already
enforces.

**Reusing `occultation::anonymity` for linkability is an adaptation, not a drop-in.** That
engine partitions hosts by TCB fingerprint; `ephemeris` partitions actions by what the chain
links. The mathematics is the same — partition into equivalence classes, report set sizes,
entropy and singletons — and the fingerprint map is free-form by design, so the reuse is
sound. But the domains differ and the README must say so, or a reader will assume the
anonymity-set numbers mean what they mean in `occultation`.

**Version pinning across four repositories.** Git dependencies on three moving tools.
Mitigated as `poc-audit` mitigates it: pin tags rather than branches, and let the cross-check
tests fail loudly when a pinned version's behaviour moves.

## Build order

1. `record` + `chain` + `tree`, in memory, no signing. End state: records chain, a tree head
   is computable, and the A9 test already passes.
2. `store` — segments, group commit, recovery. End state: write-before-forward holds and
   crash-mid-batch is pinned.
3. `topology` — all three behind the trait, with the equivalence test.
4. `serve` — the UDS listener; `transit guard` can write to it.
5. `proof` — inclusion and consistency, served and verified.
6. `sign` — the TEE key behind its feature, with the software-cannot-claim-hardware test.
7. `bench` — throughput and linkability across topologies.
8. The `poc-audit` cross-check, which requires a released tag of this repo.

Step 1 is a complete, honest, in-memory log that resists the attack the reference
implementation did not. Each later step adds a property rather than reworking one.
