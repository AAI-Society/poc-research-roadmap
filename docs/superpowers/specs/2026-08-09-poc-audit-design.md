# Design — `poc-audit`, the fourth layer

**Date:** 2026-08-09 · **Status:** approved, ready for implementation planning ·
**Repo:** new — `poc-audit`, depending on
[`parallax`](https://github.com/AAI-Society/parallax),
[`transit`](https://github.com/AAI-Society/transit) and
[`occultation`](https://github.com/AAI-Society/occultation)

---

## Why

Three research tools have shipped. Each answers a real question, and a developer
who finds one of them has no way to see that the other two exist, let alone that
they are about the same object.

They are about the same object. The Proof-of-Control Evidence Token
(`ov-poc-standard/schema/poc-evidence.schema.json`) requires fourteen
`poc_claims` fields plus a `submods.attestation`, and **each tool independently
found that one of those required fields is weaker than the standard assumes**:

| record field | tool | the finding |
| --- | --- | --- |
| `submods.attestation` → `reference_values_uri` | parallax | the schema makes it **optional**; absent it, the quote authenticates silicon and not code identity |
| `canonical_snapshot_hash` | transit | two parties compute different digests over the same wire bytes — one field name hiding a divergence |
| `agent_id`, `initiating_user` | occultation | C5.1.1 requires both; an unlinkable profile cannot supply them |
| `chain_head`, `merkle_root` | *(occultation flags the tension)* | a global chain links every action by construction |

So the pairing is not "three tools that go together." It is sharper: **the
evidence record is the shared object, and each tool says whether one of its
required fields means what the standard says it means.**

`poc-audit` is the tool that asks all three at once.

## Scope

**In:** a CLI that reads a PoC evidence record, optionally plus each tool's
existing configuration, and reports per-field what actually backs each claim.

**Out, deliberately:**

- **Signing, keys, `--emit`.** The tool reads records and reports. It never
  produces a signed artifact. Signing a "you passed" token is the overclaim the
  whole research programme exists to attack, and nothing needs it yet.
- **Re-implementing layers 1–3.** See Architecture.
- **The composed runtime path.** Chaining `parallax-proxy`, `transit guard` and
  `occultation-gateway` in one request path is deferred to its own spec. It
  carries an unresolved conflict: the first two refuse requests, and
  occultation's central guarantee — defended across eight tasks of review — is
  that it never does. That decision deserves its own design, not a paragraph
  here.
- **An aggregate pass/fail.** No overall verdict and never the word
  "compliant". The C8 tier is printed but subordinated and attributed — see
  [No aggregate verdict](#no-aggregate-verdict).

## Architecture

The standard already ships a validator with three layers. `poc-audit` adds a
fourth and does not duplicate the others.

```
validate.py                     poc-audit
  1 STRUCTURE   the JSON Schema      ─┐
  2 CANONICAL   RFC 8785 + profile    ├─ assumed to have passed
  3 SEMANTIC    tier / signature      ─┘
                                          4 RESIDUAL
                                            what the fields do not tell you
```

A record missing a required field exits 2 and points at `validate.py`.
`poc-audit` does not re-check schema, canonicalization or tier rules. Two
implementations of one rule drift, and drift between them is precisely the
defect class these repositories hunt.

This is a deliberate dependency inversion: **the standard does not depend on the
research tools.** A normative specification that required three research
findings to validate a record would be the wrong shape. The dependency runs one
way, from `poc-audit` outward.

### Components

| module | purpose | reuses |
| --- | --- | --- |
| `record` | typed parse of the evidence record | `serde` |
| `field/attestation` | is `submods.attestation` code identity, or only silicon? | `parallax::{derive, trust, verify}` |
| `field/canonical` | do both sides compute the same `canonical_snapshot_hash`? | `transit::{jcs, decoder, differential}` |
| `field/identity` | what do `agent_id`/`initiating_user` cost, and can they hold? | `occultation::{anonymity, gateway::meter}` |
| `field/chain` | `chain_head`, `merkle_root`, `step_index` | **nothing — always `UNCHECKED`** |
| `verdict` | the ladder, and the residual trust set behind each finding | — |
| `report` | table, JSON, `--explain <field>` | — |

Every field auditor implements one interface, so adding one later touches
nothing else:

```rust
trait FieldAuditor {
    /// Dotted path into the record, e.g. "submods.attestation".
    fn field(&self) -> &'static str;
    fn audit(&self, rec: &Record, ctx: &Context) -> Finding;
}
```

Each auditor receives the whole record and the whole context and returns one
`Finding`. **No auditor can observe another's result**, so there is no ordering
dependency and no hidden coupling between them.

### Two structural decisions

**`field/chain` ships and always returns `UNCHECKED`.** Nothing audits
hash-chain continuity today. The temptation is to omit the row, and omitting it
produces a report that looks complete. A gap you can see is worth more than a
table implying coverage it does not have.

**The schema's `required` array is the source of truth for the report's rows.**
A test reads the vendored `poc-evidence.schema.json` and asserts every required
field has a registry entry. When the standard adds a field, the build fails
rather than the report silently narrowing.

The schema is vendored at `schema/poc-evidence.schema.json` in this repository,
copied from `ov-poc-standard`, with the upstream commit recorded beside it in
`schema/PROVENANCE.md`. This is the one place coupling to the standard repo is
accepted, because the alternative is a report that quietly stops covering the
record. Refreshing it is a documented manual step, not a build-time fetch — a
network dependency in the build would break the offline constraint the whole
suite holds.

## Data flow

```
evidence.json ────> record::parse ──┐
                                     ├──> [FieldAuditor] ──> Finding ──> report
optional inputs ──> Context ────────┘      one per field
  --deployment   parallax's existing format
  --payload      the request bytes, and nothing else
  --fleet        occultation's existing format
```

`--payload` needs no decoder configuration: `transit::differential::run_payload`
takes the bytes alone, runs every in-crate decoder model against them, and
returns a `CaseReport` naming the divergences. Requiring the operator to declare
which decoders their policy engine and backend use would also be asking them for
the answer — the finding is that they are frequently wrong about it.

The record alone always produces a report, marking what it cannot establish as
`UNCHECKED` rather than guessing. Supplying a tool's **existing** configuration
upgrades those fields to a real verdict.

Reusing the three upstream config formats rather than inventing a fourth is a
correctness decision, not a convenience one. A combined `poc-audit.toml`
mirroring three schemas by hand would drift the moment any of them changed, and
the drift would be silent.

## Verdicts

Five, and the distinctions between them are the entire value of the tool.

| verdict | means | example |
| --- | --- | --- |
| `ESTABLISHED` | something outside the record checked it, and it holds | measurement compared against a named reference value |
| `ASSERTED` | we looked, and found **nothing behind it** | `submods.attestation` present, `reference_values_uri` absent |
| `DIVERGES` | two parties who must agree produce different values | `canonical_snapshot_hash`: policy `54c323d3…`, backend `a7713be5…` |
| `CANNOT HOLD` | structurally unsatisfiable here, not merely unverified | `agent_id` under an unlinkable profile |
| `UNCHECKED` | we did not look — no auditor, or its input was missing | `chain_head`; `canonical_snapshot_hash` with no `--payload` |

`ASSERTED` versus `UNCHECKED` is the split that matters most. **"I checked and
there is nothing behind this" is a different statement from "I did not check."**
Collapsing them is how a report ends up implying coverage it does not have.

A verdict is a verdict; a reason is prose. "Silicon only, reference values never
compared" is the *reason* attached to an `ASSERTED` finding on
`submods.attestation` — not a sixth rung. The ladder stays at five.

`--explain <field>` prints the residual trust set behind a finding: which
principals must be honest, what each could do, and how long before you would
know. That is parallax's model, used as the drill-down rather than as the
headline, because "five principals, four undetectable" does not tell a developer
whether they passed.

### No aggregate verdict

The report prints no overall result and never the word "compliant". A single
summary word is what lets a deployment claim a tier it has not earned, which is
P01's documented finding.

The C8 tier **is** printed, as one secondary line below the table, explicitly
attributed to the standard rather than to this tool — `per C8 (see P01: the
ladder is contested): Tier 2`. It is reported because a conformance process asks
for it and refusing to print it helps nobody; it is subordinated and attributed
because P01 holds the ladder is wrong as written, and making it the headline
would bake in the thing the programme is trying to fix.

The exit code is the machine-readable summary. The table is the human one.

### Exit codes

Following occultation's existing convention.

| code | condition |
| :--: | --- |
| `0` | report produced; nothing `DIVERGES` or `CANNOT HOLD` |
| `1` | at least one `DIVERGES` or `CANNOT HOLD` |
| `2` | bad input, an unreadable optional input, or a failed auditor |

`--require-checked` promotes any `UNCHECKED` finding to a failure, exiting `1`
rather than `0`. It is the CI gate for "no unaudited fields". It does not change
what any auditor does, only how the exit code is computed — so a report is
byte-identical with and without it.

## Behaviour and failure modes

**This tool fails loud, and that is the opposite of occultation's philosophy on
purpose.** The gateway sits in someone's revenue path and must never be the
reason an API is down, so it fails open. `poc-audit` sits in a review or a CI
gate, where silent degradation is the entire danger. Recorded explicitly because
the fail-open culture across these repositories is strong enough that someone
would otherwise import it here by reflex.

**1. A misconfigured input is an error, never a downgrade.** `--deployment`
pointing at a missing or unparseable file exits 2. It must not fall through to
`UNCHECKED`, because `UNCHECKED` looks benign: a typo in a path would quietly
turn a real audit into a clean-looking report with fewer rows. This is the
failure mode most likely to actually occur.

**2. A failed auditor is distinguished from one that had no input.** Both render
`UNCHECKED`; they carry different reasons and different consequences.

| reason | renders | exit |
| --- | --- | :--: |
| `MissingInput` | `UNCHECKED — no --payload given` | unaffected |
| `AuditorFailed` | `UNCHECKED — transit::differential panicked` | **2** |

Without the split, a panicking auditor yields `UNCHECKED`, `UNCHECKED` does not
trigger a failure, and a crash reads as a pass.

**3. `ESTABLISHED` cannot be returned bare.** The `Finding` type gives it a
mandatory non-empty `backed_by`, so the compiler refuses a pass that names
nothing.

Panics from the three upstream libraries are caught at the auditor boundary with
`catch_unwind` and converted to `AuditorFailed` — not because a panic is
expected, but because a third-party parser over attacker-supplied bytes is
exactly where one would originate, and losing three findings to one of them
would be a poor trade.

## Testing

Seven groups, each with the mutation it must kill.

| test | must fail when |
| --- | --- |
| **Vector conformance** — every positive vector in the standard audits without `AuditorFailed`; every negative vector exits 2 | a parse regression makes valid records unreadable |
| **Registry coverage** — read the vendored schema's `required`, assert each has a registry entry | the standard adds a required field and the report silently narrows |
| **Both directions per field** — each auditor has a case producing its verdict and a case producing a different one | a verdict is hardcoded |
| **`ASSERTED` ≠ `UNCHECKED`** — input present, nothing behind it → `ASSERTED`; input absent → `UNCHECKED` | the two variants are collapsed |
| **Exit matrix** — one case pinning each of 0/1/2 and `--require-checked` | `AuditorFailed` stops setting 2, and a crash reads as a pass |
| **Upstream cross-check** — transit's shipped `duplicate_key` example must drive `field/canonical` to `DIVERGES` carrying *those two digests*; equivalents for parallax and occultation | an upstream changes behaviour and we keep reporting the old answer |
| **Misconfigured input** — `--deployment /nonexistent` exits 2 and emits **no** `UNCHECKED` row | a bad path degrades into a benign-looking report |

Two constraints on the suite:

**Fully offline.** Every test runs against committed fixtures — parallax's
committed quote, transit's hostile endpoint, occultation's fleet examples. No
network, no credentials, no third party. All three repositories hold this line
already.

**The upstream cross-check is load-bearing.** Every other row tests our own
code. That one tests the *seam* — that reusing three libraries yields the same
answers those tools give on their own. It is the test that checks the bet this
design makes, which is why it is wanted for all three tools rather than only for
the one with the most convenient example.

`field/chain` is explicitly untested beyond appearing in the table, since it
returns `UNCHECKED` unconditionally. Its test arrives with its implementation.

## Risks

**Version pinning across four repositories.** Git dependencies on three tools
that are themselves moving. Mitigated by pinning tags rather than branches and
by the upstream cross-check tests, which fail loudly when a pinned version's
behaviour has moved rather than silently reporting a stale answer.

**The vendored schema goes stale.** The registry-coverage test catches a schema
that has *gained* a required field only after someone refreshes the vendored
copy. Nothing detects that the copy itself is old. Accepted: the alternative is
a build-time network fetch, which breaks the offline constraint. The refresh
should be a documented step, not an assumed one.

**Most field auditors depend on optional context**, so the default invocation —
record alone — reports largely `UNCHECKED`. That is honest but could read as the
tool not working. Every `UNCHECKED` row must therefore name the flag that would
deepen it, not merely report that it is unchecked.

`field/identity` is the exception and should be built to exploit it: a
`poc_claims.agent_id` that is a stable identifier — a DID, per the schema's own
description — is linkable on its face, so the auditor returns a real verdict
from the record alone. `--fleet` deepens that from "linkable" to an
anonymity-set size. It is the one auditor that gives a first-time user a
non-`UNCHECKED` row with no extra arguments, which matters for whether the tool
reads as working at all.

## Build order

1. `record` + the five-verdict `Finding` type + `report`, with `field/chain` as
   the only registered auditor. End state: a working CLI that honestly reports
   everything as `UNCHECKED`, and the registry-coverage test passing.
2. `field/attestation` on parallax, with its upstream cross-check.
3. `field/canonical` on transit, with the `duplicate_key` cross-check.
4. `field/identity` on occultation, with its cross-check.
5. `--explain`, the residual trust drill-down.
6. `--require-checked` and the exit matrix.
7. The attributed C8 tier line.

Step 1 is deliberately a complete, shippable, honest tool that establishes
nothing. Each later step converts `UNCHECKED` rows into real verdicts.
