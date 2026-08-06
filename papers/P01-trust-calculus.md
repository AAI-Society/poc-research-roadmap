# P01 — A Trust Calculus for Attestation Tiers

**Domain:** C8 Verifiability Tiers · **Kind:** Corrective, Foundational · **Impact:** Very high ·
**Effort:** Medium

---

## The question

When a system claims that evidence is "independently verifiable," exactly which parties must a
verifier still trust — and can that residual set be computed from a system description rather
than argued about?

## Why it matters

**For the standard.** C8 defines four Verifiability Tiers, and says of Tier 3 that *"there is
nobody left to trust; anyone can check the evidence with published tools."* That sentence is
false, and we can now show it is false rather than suspect it. Deploying the reference
implementation on Intel TDX forced us to enumerate what a verifier must accept to believe a
single measurement:

| Party | What you must assume |
| --- | --- |
| Intel | the TDX module and CPU behave as specified; the provisioning key is not misissued |
| Intel's certification service | the collateral fetched to check a quote is authentic |
| The quoting enclave | it signs TD reports honestly |
| The cloud operator | the host does not extract domain memory outside the TDX threat model; the firmware measured into RTMRs is what it claims |
| Whoever publishes reference values | the MRTD compared against belongs to the code you believe it does |

Anchoring the evidence log removes **none** of these. It makes the *history* publicly auditable
— a real and valuable property — while the *measurement* still rests on that chain. The tier
ladder conflates two things a careful reader will separate: **public verifiability** (anyone may
check, with published tools) and **trust independence** (no party's honesty is load-bearing).
Hardware attestation buys the first and leaves the second largely intact.

This is the binary threshold the whole standard is organized around. If the threshold is
mis-drawn, every conformance claim above it says less than its definition promises.

**For the field.** This is not a Proof-of-Control problem. Confidential computing marketing,
zero-knowledge systems, transparency logs, and remote attestation generally all reach for
"trustless" or "verifiable" without a vocabulary that distinguishes *who checks* from *whose
honesty matters*. A calculus that takes a system description and returns the residual trust set
would be reusable well beyond this standard, and would give reviewers a mechanical way to
contest a claim rather than a rhetorical one.

## What is already known

Engage this literature specifically:

* **RATS architecture** ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)) — already separates
  Attester, Verifier, Relying Party, Endorser, and Reference Value Provider. This is the closest
  existing vocabulary and the natural foundation; the roles exist but the *trust obligations
  attached to each role* are not formalized.
* **Trust management / authorization logics** — Abadi, Burrows, Lampson and Plotkin, *A Calculus
  for Access Control in Distributed Systems* (1993); Lampson et al., *Authentication in
  Distributed Systems* (1992). The "says" and "speaks-for" primitives are exactly the right shape
  for expressing "Intel says this measurement."
* **Nexus authorization logic** (Schneider, Walsh, Sirer) — an authorization logic built for
  attestation-based systems; the closest prior art to what this paper proposes.
* **Byzantine and threshold assumptions** — for expressing "any *k* of these *n* endorsers."
* **Transparency systems** — Certificate Transparency ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)),
  CONIKS, gossip protocols. These are the canonical examples of converting trust into detection
  rather than eliminating it, which is the distinction the tiers need.
* **Attestation critiques** — the SGX/TDX attack literature (Foreshadow, SGAxe, Plundervolt,
  ÆPIC Leak) establishes that hardware roots are assumptions, not axioms.
* **DAA (Direct Anonymous Attestation)** — Brickell, Camenisch, Chen (2004) — relevant because it
  shows how much of the trust structure can be restructured cryptographically.

## What is genuinely open

Nobody has produced a *computable* residual-trust set. The RATS roles are descriptive; the
authorization logics can express trust relationships but were not built to answer "given this
deployment, list every party whose dishonesty changes the answer, and say what each could do."

Specific unanswered pieces:

1. **A type system or logic** whose judgments are of the form *"proposition P holds provided
   parties {A, B, C} are honest"*, where composition of mechanisms composes the trust sets.
2. **A distinction, made formally, between removal and conversion of trust.** Anchoring does not
   remove trust in the log operator; it converts undetectable misbehaviour into detectable
   misbehaviour. Those are different and the tiers treat them the same.
3. **Detection latency as a first-class term.** "Detectable eventually" and "detectable within
   Δ" are different guarantees. The standard's anchoring interval and attestation refresh
   interval are both instances of this and are currently unrelated concepts.
4. **What a tier boundary should be.** If trust cannot be eliminated, tiers must be ordered by
   something else — cardinality of the trust set? Independence of the parties? Cost of
   collusion? Each gives a different and defensible ladder.

## Method

1. **Formalize.** Define a judgment `Γ ⊢ P` where Γ is a set of trust assumptions, each naming a
   party and a capability. Give composition rules for the mechanisms the standard admits:
   signing, hash chaining, anchoring, gossip, witness quorums, TEE attestation, ZK proofs.
2. **Mechanize.** Encode in Coq/Lean or a Datalog-style solver so residual trust is computed,
   not argued. A small checker that takes a deployment description and emits the trust set is
   the artifact that makes this paper land.
3. **Validate against reality.** Run it on the TDX deployment already built and confirm it
   produces the five-party list we derived by hand. Then run it on: a Tier-2 software-only
   deployment; a witness-quorum design; a hypothetical ZK design. The tool should reproduce
   known answers before it is trusted on unknown ones.
4. **Re-derive the tiers.** Propose a tier ladder ordered by a defensible property of the trust
   set, and check it against the deployments above.

## What would settle it

**Supporting:** the checker reproduces hand-derived trust sets for at least four deployment
classes, and produces at least one non-obvious result — for example, that two mechanisms
believed independent share a party.

**Refuting:** if residual trust sets turn out to be incomparable across realistic designs — no
partial order that respects intuition — then *tiers are the wrong abstraction entirely*, and the
finding is that conformance should publish a trust set rather than a tier. **That is a publishable
result and it would be a bigger contribution than confirming the ladder.** The paper should be
designed so this outcome is reachable.

## Consequence for the standard

* **C8.1–C8.3 rewritten.** Tiers defined by residual trust rather than by mechanism.
* **C7.4 / C10.2 strengthened.** Trust-assumption disclosure becomes a computed artifact with a
  schema, not prose.
* **A new conformance obligation:** publish the trust set alongside the tier claim.
* The paper's §4.2 and §10 both need revision; §10 currently concedes the problem without
  solving it.

## Venue

IEEE S&P / USENIX Security for the full treatment; NDSS or a CCS short paper for the calculus
alone. Alternatively an IETF RATS-adjacent draft, which would carry further with implementers
than a paper would.

## Effort and dependencies

Medium. The formalism is a few months; the checker is small; validation reuses the TDX
deployment already built. **No dependencies** — this is the natural first paper, and P02 and P03
both read more cleanly once the vocabulary exists.
