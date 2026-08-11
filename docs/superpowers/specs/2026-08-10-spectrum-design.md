# Design — `spectrum`, the composition commitment

**Date:** 2026-08-10 · **Status:** draft, forks unresolved · **Repo:** new — `spectrum`,
depending on [`transit`](https://github.com/AAI-Society/transit)
and, for its cross-check only, [`poc-audit`](https://github.com/AAI-Society/poc-audit)

A spectrum decomposes light into its constituent components. That is what a bill of
materials does to a system, and it is the only claim this name makes.

---

## Why this design is not "approved, ready for implementation planning"

Every other spec in this directory carries that status. This one does not, and the
reason is the design's defining fact.

[P10](../../../papers/P10-agbom.md) is open. The question it asks is not how to digest a
bill of materials — that is a `SHA-256` call — but **what belongs in one for a system
whose composition changes at runtime**. Nobody has answered it. CycloneDX has not,
SPDX has not, MITRE ATLAS's AML.M0023 has not, and the standard this programme serves
has not.

A tool that ships an AgBOM schema before that question is answered does not fill
`agbom_digest`. It fills it with a confident wrong answer, which is worse than the
`UNCHECKED` row `poc-audit` reports today, because an `UNCHECKED` row is visible and a
wrong digest is not. This is the exact defect class
[`parallax` documented across five criticals](../../parallax-outcomes.md#the-defect-pattern-worth-carrying-to-transit-and-occultation):
correct code implementing a subtly wrong specification, producing a confident wrong
answer rather than an error.

So the first design decision is what `spectrum` refuses to do:

**`spectrum` does not define an Agent Bill of Materials.** It defines a digest
derivation over a *declared* component set, ships several such sets as named,
falsifiable hypotheses, and reports what each one could not capture. The question of
which set is right is P10's, and this tool is built to be the instrument that answers
it rather than the artifact that presumes it.

The forks below are the places where a decision would presume an answer. They are
marked, not taken.

---

## What is already wrong, before any tool exists

Four findings from reading the standard's own shipped artifacts. They are inputs to
the design, and three of them belong in `docs/` in this repository when it lands,
alongside [what building `parallax` established](../../parallax-outcomes.md).

**1. The schema and the reference implementation already disagree.**
`poc-evidence.schema.json` describes the field as *"Digest of the agent bill of
materials **in force for this step** (C1.2)."* The reference implementation
(`impl/poc/core.py`) computes it once in `AttestingEnvironment.__init__` and never
changes it, with the comment *"a fixed value here, since the reference agent's
composition does not change at runtime."* The schema already specifies the runtime
reading. Nothing implements it. This is not a gap `spectrum` opens; it is one already
present in the standard's two normative artifacts.

**2. `TASK_INITIALIZATION` has no runtime composition to digest.** The field is
required at all eight `interception_point` values. At the first of them, by
definition, nothing has been retrieved, no memory read, no sub-agent spawned. Either
the field carries the static root there — in which case the field means two different
things at two hooks — or it is meaningless there. The schema does not say.

**3. C1.2.1 already requires the runtime half, at Level 1.** The roadmap's
[C1 assessment](../../../domains/C1-provenance.md) reads C1 as covering build time well
and runtime barely. Read C1.2.1 directly: *"each input that steers agent behavior
(prompts, retrieved documents, memory reads, tool outputs) is recorded at ingestion
with a source identifier and timestamp"* — Level 1. The requirement is already
written. It is the *mechanism* that is missing, and `agbom_digest` is the only field in
the record where it could land.

**4. C1.2.2 requires a link nobody can compute.** *"input records are hash-linked to
the execution records of the actions **they influenced**"* — Level 2. Influence is
why-provenance. No production system can compute which retrieved chunk steered a
decision; RAG attribution is an open research area, and the closest tractable relation
is *was present in the context*, which is an over-approximation that includes every
document the model ignored. Any implementer meeting C1.2.2 today is meeting a weaker
requirement and calling it that one. `spectrum` must record presence and must never
name it influence.

Finding 4 is the reason the honest scope of this tool is narrower than P10's ambition,
and it is stated here rather than in a risks section because it bounds everything
below.

## Scope

**In:** a library and CLI that (a) projects existing SBOM documents and a deployment
description into a normalized component set under a named profile, (b) commits to that
set with a digest whose derivation is written down and tested in both directions, (c)
extends a running commitment as composition changes at runtime, (d) reports what the
profile did not capture, and (e) runs a detection harness against composition attacks
and reports honestly which it does and does not catch.

**Out, deliberately:**

- **Inventing a BOM document format.** `spectrum` consumes and emits CycloneDX. See
  [Relationship to CycloneDX](#relationship-to-cyclonedx-and-spdx).
- **Emitting an evidence record.** `spectrum` produces a digest and an event stream.
  Assembling, chaining and signing records is `ephemeris`, roadmap T2.
- **Influence.** `spectrum` records what entered the composition. It never claims to
  record what steered the output. See finding 4.
- **Reference-value distribution.** P10's fifth open question. Given a digest, a
  verifier today has nothing to compare it against, because no infrastructure
  publishes expected AgBOMs for models, prompts or tools. `spectrum verify` compares
  against a locally supplied expected manifest and nothing else, and says so.
- **Training-data lineage (C1.2.4).** Level 3, obtainable-by-an-external-verifier, and
  no mechanism in this programme moves it. Permanently `Opaque`.
- **An aggregate verdict.** The programme's rule holds. No summary word, and never
  "complete".

## Relationship to CycloneDX and SPDX

The instruction not to reinvent CycloneDX is right, and the precise form of the
relationship matters more than the intent.

**`spectrum` consumes CycloneDX as input and emits CycloneDX as output. It does not
digest CycloneDX.** A byte digest of a CycloneDX document is not an identity of the
system that document describes: `serialNumber` is a fresh UUID per generation and
`metadata.timestamp` is the generation time, so two BOMs of a byte-identical system,
produced a second apart, hash differently. Digesting the document would reproduce
`parallax`'s `12h`-versus-`720m` defect at the top of the pipeline — a tool reporting
total divergence between a system and itself.

So there is a **projection**: CycloneDX (and SPDX, read-only) in, a normalized ordered
component set out, and the digest is over the projection. The projection is the
identity derivation, which makes it load-bearing, which means it is written down and
tested in both directions like every other derivation here.

What CycloneDX gives us and we do not rebuild: component identity conventions
(`purl`, `bom-ref`), the hash structure, `externalReferences`, the ML-BOM component
kinds and `modelCard`, and the dependency graph. What it does not give us, and is the
entire subject of this tool: **a component kind whose value changes between two
actions of the same process.** ML-BOM describes a model as a build artifact. It has no
vocabulary for "the tool schema this MCP server returned at 14:02 differs from the one
it returned at 14:01."

`spectrum`'s emitted CycloneDX therefore carries the runtime components in the
extension namespace rather than pretending they are standard component types, and a
consumer that only understands standard CycloneDX gets a correct, incomplete document
rather than a subtly wrong one.

> **OPEN FORK 1 — SPDX support.**
> **(a)** Read CycloneDX only. **(b)** Read both, emit CycloneDX. **(c)** Read and emit
> both. Cost rises steeply with (c) because a second emitter is a second identity
> derivation to keep in agreement, and disagreement between two emitters of the same
> system is precisely the `transit` finding.
> **Recommendation: (b).** Reading SPDX costs one projection and buys the operators
> who already have SPDX; emitting it buys a second thing to keep true.

## Profiles, and how the design stays honest

A **profile** is a declarative statement of which component kinds are in scope. It is
the mechanism by which `spectrum` avoids asserting an AgBOM schema.

```
profile = { id, component kinds included, identity derivation per kind, coverage }
```

Three rules make the profile carry the honesty rather than the prose.

**The profile identity is inside the digest.** `agbom_digest = H(profile_id ‖ …)`. Two
deployments under different profiles produce digests that cannot be compared, and
`spectrum diff` refuses to compare them rather than reporting a difference. This is
`parallax`'s rule that trust sets for different claims are not ranked, applied to
composition: a digest is a commitment *under a stated theory of what composition
means*, and comparing digests across theories is a category error.

**Every profile must enumerate what it does not capture, and the build fails if it
does not.** `coverage` is a required, non-empty field. A profile claiming to capture
everything does not compile. This follows `poc-audit`'s `ESTABLISHED`-cannot-be-bare
rule and `ephemeris`'s printed C7.3.3 gap: a gap you can see is worth more than a
manifest implying coverage it does not have.

**No profile is named `default`, and there is no default.** `--profile` is required.
Profiles are named after their claim — `build-manifest`, `runtime-tools`,
`runtime-with-context` — so that no invocation of this tool can produce an unmarked
"the AgBOM." A reader of a digest can always ask which theory produced it, and the
answer is in the digest.

The profiles shipped are hypotheses, and the README says so:

| profile | includes | the claim it makes | what it cannot capture |
| --- | --- | --- | --- |
| `build-manifest` | model identity, system prompt, tool definitions, code and dependency SBOM | composition is fixed at task start | everything that changes after |
| `runtime-tools` | the above, plus MCP server tool-list re-measurement and sub-agent roster | the *capability surface* changes at runtime and is small enough to re-measure | retrieved context, memory |
| `runtime-with-context` | the above, plus retrieved-chunk and memory-read references | everything that enters the context is part of composition | which of it mattered; see finding 4 |

`build-manifest` reproduces the reference implementation's behaviour. It is shipped so
that the cost and the detection power of the other two are measured *against* it
rather than asserted over it — P10's method step 3.

## The witness class, and the identity trap

[`parallax`'s outcomes document](../../parallax-outcomes.md) records that four of five
criticals traced to one root cause: **a field participating in a value's identity was
specified casually.** Everything below feeds a digest, so everything below is
load-bearing.

The trap here is sharper than `parallax`'s, because for several component kinds *there
is no measurement available at all* and the honest derivation is a string the operator
typed. A digest that renders those identically to measured ones is a confident wrong
answer by construction.

So every component reference carries a **witness class**, and the class is inside the
digest:

| class | means | example |
| --- | --- | --- |
| `Measured` | we read the bytes and hashed them | a system prompt file; a tool JSON Schema |
| `Attested` | a third party signed a statement about it | a SLSA provenance attestation over a container image |
| `Declared` | the operator asserted it and nothing checked | `gpt-x-2026-05` behind a hosted API |
| `Opaque` | we know a component of this kind is present and cannot name it | training data behind a hosted model |

`Opaque` is not the absence of a component. It is a positive statement that something
is there and unmeasurable, and it must appear in the manifest for the same reason
`poc-audit` ships a permanently-`UNCHECKED` `field/chain`.

Per-kind derivations, each of which is a place a casual specification produces a wrong
answer:

| kind | derivation | the trap |
| --- | --- | --- |
| model, self-hosted | digest of weights + serving config, per C1.1.1 | serving config is a moving target; quantization changes behaviour and not the weight file |
| model, hosted API | provider ‖ model string ‖ declared snapshot, `Declared` | the same string names different weights over time and the operator cannot tell |
| system prompt | JCS-canonical bytes of the rendered instance | template-versus-rendered is [fork 4](#open-fork-4--prompt-identity); trailing whitespace and line endings must be normalized or the same prompt from two checkouts differs |
| tool definition | JCS over the JSON Schema | a schema with duplicate keys is exactly `transit`'s finding; two decoders disagree about what the tool is |
| MCP server | JCS over the tool list *as returned*, re-measured | see [fork 5](#open-fork-5--mcp-server-identity); a URL is not an identity |
| retrieved chunk | digest of chunk bytes ‖ retriever's own chunk id | granularity is [fork 6](#open-fork-6--retrieved-context-granularity); linkability is [fork 7](#open-fork-7--context-digests-are-a-cross-session-fingerprint) |
| memory read | as retrieved chunk | a memory write is a composition change for every *future* step, not this one |
| sub-agent | the delegate's own manifest root at delegation time | [fork 8](#open-fork-8--cross-agent-composition) |

Canonicalization is `transit::jcs`, not a second implementation, for the reason C7.7's
own commentary gives and `ephemeris` restates: two canonicalizers that serialize the
same object differently produce different digests, every signature still verifies, and
the natural repair is to relax the comparison until it works.

> **OPEN FORK 2 — does the witness class contribute to the digest?**
> **(a) Inside.** Upgrading a component from `Declared` to `Measured` changes the
> digest even though the system did not change, so improving instrumentation looks
> like a composition change.
> **(b) Outside**, carried in a separate coverage digest. Then a `Declared` model and a
> `Measured` model with the same claimed identity hash identically, which is a lie by
> omission and exactly the failure this tool exists to avoid.
> **Recommendation: (a), inside.** The evidence genuinely did change, and a digest that
> cannot distinguish "we hashed the weights" from "the operator typed a version
> string" is the confident wrong answer. The cost — instrumentation changes read as
> composition changes — is real and belongs in the README, mitigated by
> `spectrum diff`, which reports *witness class changed* as a distinct kind of
> difference from *component changed*.

## The running commitment

P10's second open question asks whether the AgBOM can be a running commitment,
extended per composition change like a TPM PCR, and notes the model appears
unexplored. It is the right model and this tool is how it gets tested.

```
C₀ = H(profile_id ‖ static_manifest_digest)          genesis
Cₙ = H(Cₙ₋₁ ‖ H(event))                              extension, one-way
```

`event` is a typed composition-change record: kind, component reference, witness
class, and the hook it occurred at. The register value is 32 bytes regardless of how
much composition has changed, which is what makes a per-step field affordable.

Three properties, each of which is a test below:

- **One-way.** No API lowers the register. A "reset composition" call is a rewrite of
  history and there is none.
- **Replayable.** The register value is reproducible from the event log and the
  genesis value alone. A register that cannot be replayed is a number, not a
  commitment.
- **Small in the record, large in the log.** This is the honest half of P10's
  question 1. The extension solves the *record size* problem completely and the
  *verification* problem not at all: checking a register requires the events, so
  somebody must store them. That somebody is `ephemeris`. **The digest is small; the
  evidence that makes it checkable is not.**

The division with `ephemeris` follows its own stated rule — the caller supplies what
only the caller knows. `ephemeris`'s design records `agbom_digest` as supplied by
neither party and asserts nothing about it; under this design the enforcement point
links `spectrum` as a library, holds the register, supplies the current value in the
claim, and emits composition events into the same log.

Three of the eight `interception_point` values are composition-change hooks —
`CONTEXT_ASSEMBLY`, `MEMORY_WRITE`, `SUBAGENT_DELEGATION`. The standard's hook list
already names the points where composition moves, which is a good sign the runtime
reading is the intended one and further evidence for finding 1.

> **OPEN FORK 3 — what value goes in `agbom_digest`.**
> **(a) Static root only.** Matches the reference implementation and finding 1 says it
> is wrong.
> **(b) The register value**, with the static root as genesis.
> **(c) `H(static_root ‖ register)`**, carrying both explicitly.
> **Recommendation: (b).** A static agent's register never advances, so (b) degenerates
> exactly to (a) and the field's meaning does not change between a static and a dynamic
> deployment. (c) carries the same information and makes every consumer parse a
> structure the schema's `digest` pattern does not admit. The cost of (b) is that a
> reader cannot tell from the field alone whether composition ever moved — resolved by
> `spectrum diff` against the genesis, not by widening the field.

> **OPEN FORK 4 — prompt identity.**
> **(a) The rendered instance** — the bytes the model saw. Changes whenever a variable
> changes, so a per-user greeting makes every session's AgBOM unique and links the
> digest to the user.
> **(b) The template plus a digest of the variable *names***. Stable across sessions,
> and blind to a variable whose *value* is an injection.
> **(c) Both, as two components.**
> **Recommendation: (c).** They answer different questions — (b) is "is this the prompt
> we shipped", (a) is "is this the prompt that ran" — and a verifier needs both. The
> cost is two components where an implementer expects one, and the linkability of (a)
> is real and belongs in the same paragraph as [fork 7](#open-fork-7--context-digests-are-a-cross-session-fingerprint).

> **OPEN FORK 5 — MCP server identity.**
> **(a) Endpoint URL plus declared server version**, `Declared`. Cheap, and a URL is
> not an identity: the server behind it can change its tool list between two calls
> with no local signal.
> **(b) JCS digest of the tool list as returned**, re-measured at each
> `PRE_CALL_TOOL_INVOCATION`, `Measured`. Costs a round trip or a cache with an
> explicit staleness bound.
> **(c) Refuse — `Opaque`.**
> **Recommendation: (b), and this is the design's central bet.** See
> [What this is actually for](#what-this-is-actually-for). The staleness bound is the
> same shape as C7.2.3's attestation refresh interval and should be declared the same
> way rather than left to whatever the implementation does.

## What this is actually for

P10's method step 4 is the real test: construct memory-poisoning and RAG-poisoning
attacks and determine whether the design lets a verifier detect them from evidence
alone. P10 states the honest fallback plainly — if it detects none, AgBOM is an
inventory control rather than a security control and the standard should grade it
accordingly.

**This design predicts it detects one class and not the other, and says so before the
measurement so the measurement can contradict it.**

*Detected:* **the tool-definition rug-pull.** A tool or MCP server presents schema *S*
when the operator reviews and approves it, and schema *S′* — a widened parameter, an
added field, a changed target — at the moment of the call. Under `build-manifest` the
digest is identical before and after, because the manifest was taken at task start.
Under `runtime-tools` the register diverges at the call, and the event names the
component. This is detectable because a tool definition is **small, local, and
re-readable**: re-measuring it costs a JCS hash of a few kilobytes.

*Not detected:* **content poisoning.** A retrieved document that is validly sourced,
correctly digested, faithfully recorded, and malicious. The register commits to the
fact that this chunk entered the context. It says nothing about whether the chunk was
adversarial, and nothing about whether it steered the decision — that is finding 4, and
the threat model's own boundary column already says the same thing about C1.2's
coverage of memory poisoning ("a validly sourced but misleading note").

If that prediction holds, the honest finding for P10 is narrower and more useful than
"AgBOM is inventory": **a running composition commitment is a change-detection control
over the capability surface, and an inventory control over content.** That would still
be a threat-model movement, but on tool-and-plugin substitution rather than on the
memory- and context-poisoning rows P10 hopes for.

The detection harness is a shipped component, not a paper appendix, following
`transit`'s hostile-server pattern: a local MCP server whose failure modes are
individually toggleable, so every scenario runs offline with no network and no
credentials.

## Architecture

| module | purpose | reuses |
| --- | --- | --- |
| `profile` | the declared included-set, its identity, its required coverage statement | `serde` |
| `component` | kinds, per-kind identity derivation, witness class | — |
| `project` | CycloneDX/SPDX → normalized component set | `transit::jcs` |
| `manifest` | the static composition manifest and its digest | — |
| `register` | genesis, extend, replay | — |
| `collect/*` | per-kind collectors: model, prompt, tool, mcp, context, memory, subagent | — |
| `diff` | component-level difference; refuses across profiles | — |
| `export` | CycloneDX emission | — |
| `hostile-mcp` | the toggleable adversarial MCP server | — |
| `detect` | the attack scenarios and what each profile catches | — |
| `bench` | cost per event; evidence size against the flat baseline | — |

| command | purpose |
| --- | --- |
| `spectrum compose --profile <p> --deployment <d>` | static manifest and its digest |
| `spectrum extend --register <r> --event <e>` | one composition-change extension |
| `spectrum replay --genesis <g> --log <events>` | recompute a register and compare |
| `spectrum diff <a> <b>` | component-level difference, including witness-class change |
| `spectrum coverage --profile <p>` | what this profile does not capture |
| `spectrum export --format cyclonedx <manifest>` | round-trippable document |
| `spectrum detect --scenario <name>` | run one attack against every profile, report detected / not detected |

The repository follows the
[shared skeleton](2026-08-07-poc-research-tools-design.md#shared-skeleton) without
deviation: workspace with library plus binary, `results/` regenerated by CI so a stale
number cannot outlive a code change, `paper/main.tex` for P10, Apache-2.0 throughout,
`deny_unknown_fields` on every configuration surface — which is `parallax`'s fifth
critical and applies to profiles with particular force, since a typo'd component kind
in a profile is a silently narrowed manifest.

## What is real and what is modelled

Following `occultation`'s convention and `ov-poc-standard/impl/README.md`.

**Real.** Blob and file digests. JCS canonicalization. The projection from CycloneDX.
The extension register, its one-way property and its replay. CycloneDX import/export
round-trip. The coverage report. The MCP tool-list re-measurement, against the local
hostile MCP server. The detection harness, which executes real substitutions against
real profiles.

**Modelled.** Hosted-model weight identity: no measurement exists from outside the
provider, so the collector emits `Declared` and **cannot** emit `Measured` — a type
that carries the class, following `occultation`'s `ModelledPermit` and `ephemeris`'s
software-key-cannot-claim-hardware pattern, asserted by test. Training-data lineage:
permanently `Opaque`. Influence: not modelled, not stubbed, absent — there is no
`influence` field and no API that could produce one, because a stub here would be
mistaken for the C1.2.2 link that nobody can compute. Reference-value distribution:
`verify` compares against a locally supplied expected manifest, and the absence of any
publishing infrastructure is P10's fifth open question, not a missing feature.

**Consequence for the numbers.** The benchmark measures the *commitment* — extension
cost, replay cost, evidence size against the flat baseline. It does not measure
*collection*, because collecting a retrieved-chunk digest requires a hook inside
someone's retriever and `spectrum` ships a reference retriever rather than an
integration. Reported costs are therefore a lower bound on end-to-end overhead, stated
rather than extrapolated, exactly as the reference implementation states it for TEE
transitions.

## The privacy conflict this creates

`occultation` exists to measure what identity evidence gives away, and
[`TOOLING.md`](../../../TOOLING.md) records the chain-links-everything conflict as
unresolved. `spectrum` adds a second one, and it is not a variant of the first.

**A per-step composition digest is a fingerprint of what the agent read.** If retrieved
chunk digests are content-derived and stable, two evidence records from two different
agents carrying the same chunk digest prove both agents read the same document. That is
a cross-session, cross-agent linkage over *content*, and it flows from the field C1.4
exists to protect — C1.4.1 requires digests rather than raw payloads, and a digest of a
rare document is an identifier of that document.

The static manifest is not exempt. A `runtime-with-context` digest over an unusual tool
set is a fleet fingerprint of exactly the shape `occultation::anonymity` partitions on.

> **OPEN FORK 6 — retrieved-context granularity.**
> **(a) Per-document.** Small, and blind to a poisoned chunk inside a large document.
> **(b) Per-chunk-as-retrieved** — the unit the retriever returned.
> **(c) Per-token-span**, which requires instrumenting the model and is not available
> from outside it.
> **Recommendation: (b).** It is the finest unit that exists without model
> instrumentation, and it is the unit a retriever can already name. (c) is what
> C1.2.2 would need and is not obtainable.

> **OPEN FORK 7 — context digests are a cross-session fingerprint.**
> **(a) Unlinkable by default**: salt chunk digests per session, commit the salt in the
> log. Kills cross-session `diff`, which is the primary use of a digest.
> **(b) Linkable by default**, with the leak documented and a `--profile unlinkable`
> that salts — mirroring `poc-audit`'s existing flag and `occultation`'s stance of
> metering the cost rather than assuming the property.
> **(c) Reference-only**: corpus id and document version instead of content, which
> leaks less and detects no tampering.
> **Recommendation: (b).** It is consistent with the rest of the programme, which
> measures privacy cost rather than silently choosing a point on the curve, and it
> keeps `diff` — the only thing a verifier can currently do with a digest — working by
> default. The leak must be printed by `spectrum coverage`, not buried in a README.

> **OPEN FORK 8 — cross-agent composition.** P10's fourth open question: in a
> multi-agent system, what is the AgBOM of the *system*?
> **(a) Link.** The delegator's manifest carries the delegate's manifest root as of
> the delegation, and nothing more.
> **(b) Recursive inclusion.** The delegator's digest covers the delegate's full
> composition transitively.
> **Recommendation: (a).** (b) requires the delegate's composition to be frozen at
> delegation time and it is not — the delegate retrieves and spawns after it is
> handed the task, so a transitive digest is stale the moment it is computed, which is
> finding 1 recreated one level down. (a) inherits the chain-links-everything tension:
> committing to a delegate's root links the two agents by construction, which is
> `occultation`'s objection and `ephemeris`'s per-agent-tree problem in a third
> costume. It is also T6 territory — the delegation chain is undesigned and this fork
> should not be closed before it exists.

## Failure modes

**Fail loud.** `spectrum` sits where `poc-audit` sits — in review, in CI, and in a
build step — not in a revenue path. The fail-open culture across these repositories is
strong enough that `poc-audit` and `ephemeris` both had to say this explicitly, and so
does this.

| condition | behaviour |
| --- | --- |
| a component kind in the profile has no collector | refuse to compose; never omit the component |
| a collector fails | refuse to compose; never downgrade the component to `Opaque` |
| an MCP re-measurement times out | refuse the extension, and the caller must refuse the action |
| a profile with an empty `coverage` | refuse to load |
| `diff` across two profiles | refuse, with both profile ids named |
| replay disagrees with the register | exit 1; the register is not a summary of the log |

The second row is the one most likely to actually occur and the most dangerous.
`Opaque` is a legitimate value for a component that is *known* to be unmeasurable; it
must never be reachable from a collector that merely *failed*, because that converts an
outage into a manifest that looks deliberate. This is `poc-audit`'s
`MissingInput`-versus-`AuditorFailed` split, and it has the same root.

Exit codes follow the suite: `0` clean, `1` a policy or verification failure, `2` bad
input or configuration.

## Testing

Fully offline. No network, no credentials, no third-party endpoint. Each row names the
mutation it must kill.

| test | must fail when |
| --- | --- |
| **CycloneDX projection stability** — two BOMs of the same system with different `serialNumber` and `metadata.timestamp` project to the same digest | someone digests the document bytes, reproducing `parallax`'s `12h`/`720m` defect at the input |
| **Identity derivation, both directions, per kind** — semantically identical compares equal (key order, whitespace, line endings, version spelling); one contributing field differs compares unequal | a derivation is specified casually, which was the root cause of four of `parallax`'s five criticals |
| **Witness class is load-bearing** — the same claimed component as `Declared` and as `Measured` produce different digests | fork 2 is silently resolved the other way and a typed version string hashes like a measured one |
| **`Declared` cannot become `Measured`** — a hosted-model collector cannot construct a `Measured` witness | the class becomes cosmetic, following `occultation`'s stub pattern |
| **Register replay** — replaying the event log from genesis reproduces the record's value | the register drifts from its log and remains a plausible-looking number |
| **Register is one-way** — no API sequence produces a lower or repeated register value | a "reset composition" convenience appears |
| **Coverage is non-empty** — a profile with an empty `coverage` fails to load, asserted at load and at build | a profile ships implying complete capture |
| **Profile identity in the digest** — the same components under two profiles produce different digests, and `diff` refuses across them | digests from different theories of composition are silently compared |
| **Rug-pull detection** — schema *S* at approval, *S′* at call: `build-manifest` digest unchanged, `runtime-tools` register diverges and the event names the component | the re-measurement is dropped or cached without a staleness bound, which is the design's central bet failing quietly |
| **Poisoning negative control** — a poisoned retrieved document is reported **not detected** under every profile | someone claims detection the mechanism does not provide; this test asserts a negative on purpose |
| **Unknown keys rejected** — a typo'd kind in a profile or deployment file is an error | `parallax`'s fifth critical, where a one-letter typo silently disabled a gate |
| **Collector failure is not `Opaque`** — a failing collector exits 2 and emits no component | an outage renders as a deliberate unmeasurable |
| **Cross-check into `poc-audit`** — a digest `spectrum` produces drives a `field/agbom` auditor off `UNCHECKED` | the seam between producer and auditor drifts |

The last row is load-bearing for the same reason it is in `ephemeris`'s suite: every
other row tests our own code, and that one tests whether what this tool produces is
what the auditor expects. It requires `poc-audit` to grow a `field/agbom` auditor,
which today is one of the six rows where *nothing exists*, and it is the only way a
number in `TOOLING.md` moves because a tool produced something.

The negative control is the row most likely to be deleted by someone tidying the
suite, and it is the row that keeps this tool honest about P10's fallback finding.

## Risks

**The forks are the risk.** Eight open forks in a design whose subject is an open
research question is the correct number, and every one of them resolved wrongly
produces a digest that is precise, stable, testable and about the wrong object. There
is no mitigation other than resolving them in the open and recording the reasoning,
which is what `results/` and the paper are for.

**Fork 5 is the load-bearing one.** If MCP tool-list re-measurement turns out to be
unaffordable — a round trip per tool call against a remote server, inside the same 15 ms
budget C7.2.3 already blows on a hardware quote — then the design's one predicted
detection disappears, and P10's fallback finding is the whole result. The benchmark
must therefore measure re-measurement latency *first*, not last, in the same way
`parallax-attest`'s spike gated everything.

**`build-manifest` is a supported profile and it is the wrong answer.** Shipping the
reference implementation's behaviour as a named, comparable baseline is what makes the
measurement possible, and it also gives an operator a supported way to keep doing the
wrong thing. Mitigated by naming — `build-manifest`, not `default` — and by
`spectrum coverage` printing what it misses on every run. Not eliminated.

**The `runtime-with-context` profile is a privacy regression shipped by this
programme**, in the same way `ephemeris` ships the chain its own research argues
against. Fork 7 is the decision point and it is not resolved here.

**Nothing verifies a digest.** P10's fifth open question is unaddressed by this design
and by anything else. `diff` against a prior digest of the same deployment is the only
operation a verifier can perform, which makes `agbom_digest` a change detector between
two records rather than a checkable claim about one. That is a real limit on the
field's value and it should be said in the paper's abstract, not its future work.

## Build order

Ordered so that the P10-neutral parts land first and the profile committed to
`agbom_digest` lands last. Steps 1–4 are needed under *any* resolution of the forks;
step 5 is where a fork becomes a shipped answer.

1. `component`, `profile`, `project`, `manifest` — CycloneDX in, normalized set out,
   digest, with the projection-stability and both-directions tests. End state: a tool
   that reproduces the reference implementation's static behaviour, honestly, and
   prints what it does not capture.
2. `register` — genesis, extend, replay, one-way. In memory, no integration.
3. `hostile-mcp` and `collect/mcp` — the re-measurement, and the latency benchmark that
   gates fork 5.
4. `detect` — the rug-pull scenario and the poisoning negative control, across all three
   profiles. **This step is P10's method step 4 and its output is the paper's headline,
   whichever way it comes out.**
5. The remaining collectors, the `ephemeris` integration, and the `poc-audit`
   cross-check — which is where a profile becomes the value of a field in a signed
   record, and should not begin until steps 1–4 have been read by whoever resolves the
   forks.

Step 1 is a complete, shippable tool that fills `agbom_digest` no better than the
reference implementation does and says so on every run. That is not a placeholder. It
is the honest state of the art, made measurable.
