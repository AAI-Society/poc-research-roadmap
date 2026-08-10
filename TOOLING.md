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
them and no tool checks them. Nine of the ten now have a design; `path_summary_hash`
has neither, and cannot until [P04](papers/P04-bounded-summaries.md) is answered.

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
| 16 | `path_summary_hash` | — | — | **none** | [P04](papers/P04-bounded-summaries.md) |
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

**`transit guard` computes three fields and writes down none of them — but only one of
them is free.** An earlier version of this row called T3 "a serialization problem, not a
research problem." Reading `guard.rs` to design the extension refuted that, and the
correction is worth keeping visible:

- `jcs::digest` digests the request **body**, not a snapshot, so two requests posting the
  same body to different endpoints collide today.
- It is `""` for every bodiless request, where the schema requires a `sha-256:…` value.
- **Nothing at all is computed on a rejection.** Every `reject(…)` returns early, so
  `DENY` records — the ones an auditor most wants — carry no snapshot hash.
- `policy_bundle_hash` over the config alone cannot re-derive a verdict: `transit`'s own
  fix rounds prove the same TOML with different code produces different verdicts.

Only `verdict` is a pure serialization problem. The rest is work.

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

**The arc ends at 20, not 21.** `path_summary_hash` has no tool and no step, because
[P04](papers/P04-bounded-summaries.md) has to be answered before anything can fill it
honestly — see T3. An earlier version of this table ended at 21 by assigning that field
to T3, which reading the guard's source refuted. A roadmap that reaches 100% by
allocating an unsolved problem to a step is the failure this document was written
against.

| | Tool | Status | Closes | Fields in a record, after |
| :--: | --- | --- | --- | :--: |
| **T1** | [`poc-audit`](https://github.com/Task-force-for-AI-agents-in-Healthcare/poc-audit) | **shipped** | nothing | 0 |
| **T2** | [`ephemeris`](docs/superpowers/specs/2026-08-10-ephemeris-design.md) — new repo | designed, phase 1 planned | 1–4, 8–12, 18, 19–21 | **13** |
| **T3** | [`transit guard`](docs/superpowers/specs/2026-08-10-transit-guard-claims-design.md) — extension | designed, forks resolved | 13, 14, 15, 17 | **17** |
| **T4** | [`spectrum`](docs/superpowers/specs/2026-08-10-spectrum-design.md) — new repo | designed, steps 1–4 planned | 7 | **18** |
| **T5** | [`parallax-proxy`](docs/superpowers/specs/2026-08-10-parallax-freshness-design.md) — extension | designed, forks resolved | *checks* 2, 3, 19, 20 | 18 |
| **T6** | delegation chain — unnamed | **not designed** | 5, 6 | **20** |

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

An extension, not a repository — [designed](docs/superpowers/specs/2026-08-10-transit-guard-claims-design.md),
all eight forks resolved. The guard sits in the request path, canonicalizes, decides, and discards all
of it. Teaching it to emit a claim for `ephemeris` to chain closes **four** fields.

It was four rather than five, and the roadmap said five, because
`path_summary_hash` cannot be filled here. That is not a scheduling choice.
[P04](papers/P04-bounded-summaries.md)'s subject is bounded path summaries, and the guard
is structurally the wrong place for one: `decide` is pure, `serve` runs 256 concurrent
threads with no ordering, and nothing carries agent identity — so even a correct fold
would be process-local, and **a guard restart would clear every path.** That is P04's own
eviction attack, available without an attacker. The field ships unfilled and the row above
says `none`, because a fabricated summary digest is worse than an absent one.

`policy_bundle_hash` carries the other trap. Hashing the config alone cannot re-derive a
verdict — `transit`'s own fix rounds proved the same TOML with different code produces
different verdicts, when `/v1/search/../transfer` and `/v1/tra%6Esfer` both used to get
through. The design answers it with a `decide_semantics` version pinned by a golden
corpus, which is the defect class
[`parallax` learned the hard way](docs/parallax-outcomes.md#the-defect-pattern-worth-carrying-to-transit-and-occultation):
anything feeding a digest must have its derivation written down and tested in both
directions.

### T4 · `spectrum` — one field, and nobody knows what goes in it

A new repository — [designed](docs/superpowers/specs/2026-08-10-spectrum-design.md),
and the only spec here marked *draft, forks unresolved* rather than approved.

One field, ranked fourth, because [P10](papers/P10-agbom.md) is genuinely open: the
question is not how to digest a bill of materials but what belongs in one for a system
whose composition changes at runtime. A tool built before that is answered would digest
the wrong thing convincingly.

The design's answer is that **`spectrum` does not define an AgBOM.** It defines a digest
over a *declared* component set, ships several sets as named falsifiable hypotheses, puts
the profile id inside the digest so two theories of composition cannot be compared, and
refuses to load a profile claiming full capture. Its build order splits at the point where
a fork becomes an assertion: everything up to the detection harness holds under every
resolution of the eight open forks, and wiring a profile into a signed record does not.

Designing it also found four problems in the standard's own artifacts, before any tool
exists. The sharpest: **C1.2.2 requires a link nobody can compute** — input records
hash-linked to the actions *"they influenced."* Influence is why-provenance. Everyone
meeting that requirement today is meeting *was present in the context* and calling it
influence.

Expect a **negative** result. If the design's prediction holds, an AgBOM is a
change-detection control over the capability surface and an inventory control over
content — which upgrades tool substitution rather than the context-poisoning rows P10 was
aiming at. Worth building for the mechanism behind the finding, but anyone approving it
should expect that field graded down, not up.

### T5 · Freshness, the challenge, and re-checking the claim

An extension to `parallax` — [designed](docs/superpowers/specs/2026-08-10-parallax-freshness-design.md),
all ten forks resolved. It emits no new field. It makes four existing ones mean something.

Two are the replay pair: a staleness bound on `iat`, and actually issuing the `nonce`
that C7.1.4 says defeats replay. A record with an unchecked `iat` and a `nonce` nobody
chose is a record that replays. Its research is
[P03](papers/P03-attestation-freshness.md), and the measurement that motivated P03 — a
hardware quote costs 39.5 ms — is the reason a staleness bound is a policy decision
rather than a constant.

Resolving its forks added a **prerequisite correction to `parallax` itself**, which lands
before the offline path. `parallax-attest` extends RTMR3 with the workload digest and
nothing reads it — `derive.rs` says so in a comment — so the shipped pair attests the
workload and the shipped gate checks only MRTD. Building the offline re-verifier first
would enshrine that defect in a second place.

It also decided that `measurement` **is the MRTD**, `sha-384` and 96 hex. That makes the
standard's own `hardware-attested.json` invalid, since its value is 32 bytes and a TDX
MRTD is 48 — filed upstream as a finding rather than treated as a reason to weaken the
check. A second defect rides with it: the schema's `digest` pattern does not tie the tag
to the length, so `sha-384:` followed by 64 hex validates.

And `poc-audit` will grow two verdicts where it has one: `ESTABLISHED (compared)` and
`ESTABLISHED (re-verified)`. Comparing two strings and re-verifying a quote chain are
different acts, and collapsing them is the conflation that produced the † correction
above.

Designing it produced the fact that makes freshness hard: **a TDX quote carries no
timestamp.** `VerificationOutcome`'s date fields date the collateral, not the quote. And
`parallax-attest` quotes once at process start, so an attestation's real age is the
sidecar's uptime — invisible to any verifier. Freshness therefore cannot be *read*, only
*challenged*, which is why the nonce and the staleness bound are one piece of work rather
than two.

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

**Nothing here is described as existing until it does.** Seven tools have shipped and are
linked above. `ephemeris` is designed with Phase 1 planned; `transit guard`'s extension,
`spectrum` is designed with steps 1–4 planned and its eight forks deliberately open;
`transit guard`'s extension and T5 are designed with every fork resolved; T6 is not
designed and `path_summary_hash`
has no step at all.

**Building the tools has produced eight findings against the standard itself**, recorded
in [`docs/standard-findings.md`](docs/standard-findings.md). Six are invisible to
`validate.py`, because they are defects in what a field *means* and a schema checks
shape. Five of them produce a record that validates cleanly while failing to carry the
property the field exists to provide.

**Three rows in this table were wrong, and each was corrected by doing the work rather
than re-reading the schema.** `platform` and `measurement` were found by running
`poc-audit`. T3's field count was found by reading `guard.rs` to design its extension.
The arc's endpoint was found by discovering that `path_summary_hash` has nowhere to live.
That is the method this programme claims for itself — three of the standard's own
requirements exist because building forced a precision the prose never did — and it
applies to the roadmap as much as to the specification.

---

*Proof-of-Control is stewarded by the [Advanced AI Society](https://advancedaisociety.org/) —
**[join a working group at advancedaisociety.org](https://advancedaisociety.org/)**.*
