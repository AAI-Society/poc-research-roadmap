# Proof-of-Control — Compliance Tooling

What an operator can run today, what it gives them, and what has to be built before
"we comply with Proof-of-Control" is a statement anyone can check.

This is the companion to [README.md](README.md). That document ranks research by what
the standard gets wrong. This one ranks tools by what an operator cannot yet do. They
are the same programme read from opposite ends, and the [coverage table](#what-the-record-requires)
is where they meet.

---

## The state of it

**No tool in this programme emits a Proof-of-Control evidence record.** Not one.

The record is what compliance means. `poc-evidence.schema.json` requires twenty
fields, and a twenty-first — the signature — that the schema marks optional and
without which nothing is verifiable at all. Seven tools have shipped. Between them
they compute the value of five of those twenty-one fields: `parallax-attest` mints
a real TDX measurement, `transit guard` computes a canonical digest, a normalized
target and a decision for every request it forwards. **No tool assembles those into
a record, signs it, or chains it to the previous one. The values exist and are
thrown away.**

Ten of the twenty-one fields have nothing behind them at all — no tool computes
them, no tool checks them, and no design exists for the tool that would.

Since [T1](#t1--poc-audit--the-map-it-drew) shipped, this is no longer an assertion.
Run against the standard's own strongest positive vector, with every optional input
supplied, `poc-audit` establishes **two rows out of twenty-two** — and both are
identity fields, established in the sense that they are *linkable*. The finding is a
privacy cost, not a security property. [What it reports](#what-poc-audit-actually-reports)
is below the table.

That is the gap this document exists to close, and it is worth being blunt about
why it opened. Every tool in the programme was built to answer a research question,
and research questions are about whether a claim holds. So the programme built five
verifiers and one attester. Verifying is the half that assumes the record already
exists.

---

## What the record requires

Twenty-one fields. **Computed** means a shipped tool derives the value, whether or
not it keeps it. **Checked** means a shipped tool says something substantive about
it — not that a schema validator confirmed its type.

| # | Field | Computed by | Checked by | Closed by | Paper |
| :--: | --- | --- | --- | :--: | :--: |
| 1 | `iss` | — | — | T2 | — |
| 2 | `iat` | — | *structural only* | T2 · T5 | [P03](papers/P03-attestation-freshness.md) |
| 3 | `nonce` | — | — | T2 · T5 | — |
| 4 | `eat_profile` | — | *structural only* | T2 | — |
| 5 | `agent_id` | — | `poc-audit` → `occultation` | T6 | [P05](papers/P05-unlinkable-identity.md) ✓ · [P06](papers/P06-delegation-attenuation.md) |
| 6 | `initiating_user` | — | `poc-audit` → `occultation` | T6 | [P06](papers/P06-delegation-attenuation.md) |
| 7 | `agbom_digest` | — | — | T4 | [P10](papers/P10-agbom.md) |
| 8 | `interception_point` | — | — | T2 | — |
| 9 | `step_index` | — | — | T2 | [P08](papers/P08-log-concurrency.md) |
| 10 | `chain_head` | — | — | T2 | [P08](papers/P08-log-concurrency.md) |
| 11 | `merkle_root` | — | — | T2 | [P08](papers/P08-log-concurrency.md) · [P07](papers/P07-evidence-continuity.md) |
| 12 | `tree_size` | — | — | T2 | [P08](papers/P08-log-concurrency.md) · [P07](papers/P07-evidence-continuity.md) |
| 13 | `policy_bundle_hash` | — | — | T3 | — |
| 14 | `target_resource` | `transit guard` | — | T3 | — |
| 15 | `canonical_snapshot_hash` | `transit guard` | `poc-audit` → `transit` | T3 | [P02](papers/P02-effect-binding.md) ✓ |
| 16 | `path_summary_hash` | — | — | T3 | [P04](papers/P04-bounded-summaries.md) |
| 17 | `verdict` | `transit guard` | — | T3 | [P02](papers/P02-effect-binding.md) ✓ |
| 18 | `alg` | — | *structural only* | T2 | — |
| 19 | `platform` | `parallax-attest` | *live only* † | T2 · T5 | [P01](papers/P01-trust-calculus.md) ✓ |
| 20 | `measurement` | `parallax-attest` | *live only* † | T2 · T5 | [P01](papers/P01-trust-calculus.md) ✓ |
| 21 | `signature` | — | *structural only* | T2 | — |

✓ marks research already done. *Structural only* means the standard's own
`schema/validate.py` confirms the field's shape and nothing confirms its meaning.

† **`parallax-proxy` verifies a live quote inside a TLS handshake. Nothing verifies
the `measurement` field of a record against reference values.** These are different
acts and the roadmap originally conflated them. A record is a claim that a
verification happened; re-checking that claim offline is unbuilt work, and it is why
`poc-audit` returns `ASSERTED` on both rows even when handed the deployment that
names the reference values. This gap was found by running the tool, not by writing
the table.

Three things this table says that are worth reading twice.

**The verified fields are the attestation fields, and only those.** `platform` and
`measurement` are the two rows with a tool on both sides, which is exactly where
three of the six shipped tools point. The record has nineteen other fields.

**The log fields are a solid block of nothing.** Rows 8–12 — `interception_point`
through `tree_size` — have no tool on either side, and they are not five independent
gaps. They are one missing component, described five times.

**`transit guard` computes three fields and writes down none of them.** It already
sits in the request path, already canonicalizes the body, already decides. Row 14, 15
and 17 are a serialization problem, not a research problem.

### What `poc-audit` actually reports

The table above is one person's reading of the schema. This is a tool's, on
`schema/vectors/positive/hardware-attested.json` — the standard's own strongest
positive vector — with `--deployment` and `--fleet` supplied:

| verdict | rows | which |
| --- | :--: | --- |
| `ESTABLISHED` | 2 | `agent_id`, `initiating_user` |
| `ASSERTED` | 2 | `platform`, `measurement` |
| `UNCHECKED` | 18 | everything else |

`DIVERGES` and `CANNOT HOLD` are reachable but need an input this vector does not
carry: a payload two decoders disagree about drives `canonical_snapshot_hash` to
`DIVERGES` and exits 1, and `--profile unlinkable` drives both identity rows to
`CANNOT HOLD` and exits 1.

Three things to take from it.

**The only two established rows are the identity fields, and what they establish is a
cost.** `agent_id` passes C5.1.1 *because* it is a persistent identifier, and the tool
says so in the same breath as saying that every action carrying it is linkable to one
subject. Against `fleet-drifted.toml`: 120 hosts, smallest anonymity set 1, effective
set 52.7, one singleton. On the standard's best vector, the strongest thing a tool can
say is a privacy finding.

**`poc-audit` reports twenty-two rows to this table's twenty-one.** It adds
`poc_claims` and `submods` as container rows and omits the optional `signature`. Both
counts are right about different things; the tool's is the one wired to a test that
reads the schema's `required` array, so when the standard adds a field the build
breaks rather than the report narrowing.

**Eighteen `UNCHECKED` is the honest state of compliance tooling**, and the reasons
split three ways: out of scope by design (`iss`, `iat`, `nonce`), already covered by
`validate.py` (`eat_profile`, `interception_point`, `verdict`, `alg`, `tree_size`), and
*nothing exists* (`chain_head`, `merkle_root`, `step_index`, `agbom_digest`,
`policy_bundle_hash`, `path_summary_hash`). Only the third group is this roadmap's
problem, and it is exactly T2, T3 and T4.

---

## What you can run today

Seven tools have shipped. This is what each actually gives an operator, stated as
narrowly as it deserves.

| Tool | What it gives you | What it does not |
| --- | --- | --- |
| [`parallax`](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax) | The set of parties whose dishonesty would change your answer, from a deployment file you wrote | Nothing is verified. It computes over your description, not your deployment |
| `parallax-proxy` | Verifies a real Intel TDX quote — chain, TCB, revocation, key binding — and refuses the connection when the residual trust set violates policy | Egress only. TDX only. RA-TLS only |
| `parallax-attest` | Puts an **unmodified** application behind RA-TLS on a GCP C3 Confidential VM, extending RTMR3 with the workload digest so the quote covers your code and not just the firmware | GCP only. Emits a certificate, not an evidence record |
| [`transit`](https://github.com/Task-force-for-AI-agents-in-Healthcare/transit) | Whether an endpoint satisfies the four effect-binding conditions, and a reproduction of what goes wrong when it does not — offline, no credentials | Classification is advisory. `probe` against third-party endpoints is gated and stays gated |
| `transit guard` *(subcommand)* | An enforcing reverse proxy that refuses requests failing those conditions, with a generated config from `classify --emit-guard-config` | Emits no evidence. It decides and forgets |
| [`occultation`](https://github.com/Task-force-for-AI-agents-in-Healthcare/occultation) + `occultation-gateway` | What unlinkability costs at agent action rates, and a **fail-open** meter that tells a relying party what each live request gave away | Provides no unlinkability. Two of five priced layers are modelled stubs with no security. The gateway never rejects |
| [`poc-audit`](https://github.com/Task-force-for-AI-agents-in-Healthcare/poc-audit) | Reads an evidence record and reports, per field, what actually backs the claim — the only tool that answers "where do I stand" | Fills no field, signs nothing, prints no aggregate verdict, and on today's records reports mostly `UNCHECKED` |

**The pairing worth knowing about:** `parallax-attest` on the workload and
`parallax-proxy` in front of the client is a deployable attestation path today, with
no application changes on either side. It is the one place in this programme where an
operator gets a real, end-to-end, verified property.

---

## What gets built, in order

Six steps. Each row states the number of the twenty-one fields a signed record
carries after it, because a roadmap whose steps do not move a number is a wish list.

| | Tool | Status | Closes | Fields in a record, after |
| :--: | --- | --- | --- | :--: |
| **T1** | [`poc-audit`](https://github.com/Task-force-for-AI-agents-in-Healthcare/poc-audit) | **shipped** | nothing | 0 |
| **T2** | `ephemeris` — new repo | **not designed** | 1–4, 8–12, 18, 19–21 | **13** |
| **T3** | `transit guard` — extension | guard shipped | 13–17 | **18** |
| **T4** | `spectrum` — new repo | **not designed** | 7 | **19** |
| **T5** | `parallax-proxy` — extension | shipped | *checks* 2, 3 | 19 |
| **T6** | delegation chain — unnamed | **not designed** | 5, 6 | **21** |

### T1 · `poc-audit` — the map it drew

**Shipped.** It is the only tool here that fills no field. It reads an evidence record
and reports, per field, what actually backs the claim — `ESTABLISHED`, `ASSERTED`,
`DIVERGES`, `CANNOT HOLD`, or `UNCHECKED` — against the
[design](docs/superpowers/specs/2026-08-09-poc-audit-design.md) written the day before
it was built.

It went first because every coverage claim in this document was otherwise an assertion
by the person who wrote it, and a roadmap that cannot be checked against a tool is the
failure mode this programme was founded to attack. That earned its cost immediately:
running it **corrected a row in the table above**. `platform` and `measurement` were
marked as having no tooling gap left, on the grounds that `parallax-proxy` verifies
them. It verifies a live quote in a handshake. Nothing re-checks a record's claim that
this happened, so both rows come back `ASSERTED`, and closing them moved into T5.

What it does not do is fill a field, and no amount of auditing will produce a record to
audit. That is T2.

### T2 · `ephemeris` — the missing producer

A new repository. The recorder that sits at the eight `interception_point` hooks of
C7.1 — `TASK_INITIALIZATION` through `TASK_COMPLETION` — and emits signed evidence
records with a real `step_index`, `chain_head`, `merkle_root` and `tree_size`, serving
inclusion and consistency proofs over them.

It is the largest single commitment in the programme and it closes thirteen of
twenty-one fields, because it is the thing that turns computed values into a record.
It carries `platform` and `measurement` across from `parallax-attest` rather than
recomputing them.

An ephemeris is a table giving an object's position at a sequence of times, which is a
step-indexed append-only log stated in the vocabulary the other three tools already
use.

**Its research is [P08](papers/P08-log-concurrency.md) and
[P07](papers/P07-evidence-continuity.md), and building it is how those get answered
rather than argued.** `step_index` is specified as monotonic per agent with no gaps —
a gap is an omission under C7.3.1 — which is precisely P08's question about what a
serial log costs a fleet, asked in a form that has to be answered before the code
compiles. An inclusion proof that survives an organizational boundary is P07.

It has no natural parent repository. It is not about attestation, canonicalization or
unlinkability, which is why it is a new repo rather than a fourth binary somewhere.

### T3 · `transit guard` — write down what it already knows

An extension, not a repository. The guard computes the canonical digest, the normalized
target and the decision, then discards all three. Teaching it to emit a partial record
for `ephemeris` to chain closes five fields and is mostly serialization.

Four of the five are. `path_summary_hash` is not: nothing computes a bounded path
summary anywhere, which is [P04](papers/P04-bounded-summaries.md)'s subject. P04's
reported null result was caused by nothing reading the structure under test, and the
guard would be the first thing that reads it. `policy_bundle_hash` needs the guard's
config to have a stable identity, which is the defect class
[`parallax` learned the hard way](docs/parallax-outcomes.md#the-defect-pattern-worth-carrying-to-transit-and-occultation):
anything feeding a digest must have its derivation written down and tested in both
directions.

### T4 · `spectrum` — one field, and nobody knows what goes in it

A new repository that decomposes an agent deployment into its constituent parts and
digests the result, filling `agbom_digest`.

One field, ranked fourth, because [P10](papers/P10-agbom.md) is genuinely open: the
question is not how to digest a bill of materials but what belongs in one for a system
whose composition changes at runtime. A tool built before that is answered would digest
the wrong thing convincingly. It is placed after T3 for that reason and not because the
engineering is hard.

### T5 · Freshness, the challenge, and re-checking the claim

An extension to `parallax-proxy`. It emits no new field. It makes four existing ones
mean something.

Two are the replay pair: a staleness bound on `iat`, and actually issuing the `nonce`
that C7.1.4 says defeats replay. A record with an unchecked `iat` and a `nonce` nobody
chose is a record that replays. Its research is
[P03](papers/P03-attestation-freshness.md), and the measurement that motivated P03 — a
hardware quote costs 39.5 ms — is the reason a staleness bound is a policy decision
rather than a constant.

The other two arrived from running T1. `platform` and `measurement` are `ASSERTED`
because verifying a live quote and re-checking a record's claim that a quote was
verified are different acts, and only the first is built. Closing them means comparing
a record's `measurement` against the reference values a `parallax` deployment names,
offline, with no handshake to observe. That is the same comparison `parallax-proxy`
already performs in step 5 of its pipeline, reached from a file instead of a socket.

### T6 · The delegation chain

Unnamed, undesigned, and left that way deliberately.

`initiating_user`'s own schema description says delegation chains are represented by a
chain of tokens rather than a list. Nothing in this programme issues such a chain or
verifies one, and [P06](papers/P06-delegation-attenuation.md) — delegation without
amplification — is the paper that says what the chain must guarantee. Naming a tool for
work nobody has designed would put a box on this roadmap that means nothing.

---

## Two conflicts we have not resolved

Both are real, both are load-bearing, and both get worse the moment T2 exists. Neither
has an answer here.

**The chain links everything.** `chain_head` and `merkle_root` link every action by an
agent to every other one, by construction. That is precisely the property
[`occultation`](https://github.com/Task-force-for-AI-agents-in-Healthcare/occultation)
exists to measure the loss of, and [P05](papers/P05-unlinkable-identity.md) is the paper
arguing it should not be assumed. Building `ephemeris` means this programme ships the
thing its own research argues against. `poc-audit`'s design already flags the tension;
building the recorder converts it from a footnote into a decision somebody has to make.

**Fail-open against fail-closed.** `parallax-proxy` and `transit guard` refuse requests.
`occultation-gateway` never does, and that guarantee was defended across eight tasks of
review on the grounds that a meter must not be able to take down the API it fronts.
Composing all three in one request path has no agreed answer.
[`poc-audit`'s design](docs/superpowers/specs/2026-08-09-poc-audit-design.md) explicitly
deferred it to its own spec, and it is still deferred.

---

## What this does not cover

**Three papers have no field to fill.** [P09](papers/P09-zk-evidence.md) would *replace*
the evidence record with something that reveals nothing, rather than populate it — it is
an alternative to this table, not a row in it.
[P11](papers/P11-verification-economics.md) and
[P12](papers/P12-conformance-credibility.md) are institutional, and
[PRIORITIZATION.md](PRIORITIZATION.md) already argues they may be the most determinative
work in the programme and ranks them last anyway. Nothing here changes that assessment;
it only notes they produce no tool.

**No aggregate verdict, and not the word "compliant."** This document counts fields in a
coverage table. It does not define a threshold at which a deployment passes, for the same
reason [`poc-audit`](docs/superpowers/specs/2026-08-09-poc-audit-design.md) prints no
overall result: a single summary word is what lets a deployment claim a tier it has not
earned, which is [P01](papers/P01-trust-calculus.md)'s documented finding.

**Nothing here is described as existing until it does.** `ephemeris`, `spectrum` and T6
are not designed. Seven tools have shipped and are linked above, and the one row in the
coverage table that turned out to be wrong was found by running one of them.

---

*Proof-of-Control is stewarded by the [Advanced AI Society](https://advancedaisociety.org/) —
**[join a working group at advancedaisociety.org](https://advancedaisociety.org/)**.*
