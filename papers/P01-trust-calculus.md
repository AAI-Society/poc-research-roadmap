# P01 — A Trust Calculus for Attestation Tiers

**Domain:** C8 Verifiability Tiers · **Kind:** Corrective, Foundational · **Impact:** Very high ·
**Effort:** Medium

---

## The question

When a system claims that evidence is "independently verifiable," exactly which parties must a
verifier still trust — and can that residual set be computed from a system description rather
than argued about?

A desk study has since sharpened the second half of the question into a different one. If residual
trust sets across realistic deployments turn out to be *incomparable* — not merely unequal — then
no ordinal tier ladder can be sound, and the question becomes what replaces it.

## Why it matters

**For the standard.** C8 defines four Verifiability Tiers, and says of Tier 3 that *"there is
nobody left to trust; anyone can check the evidence with published tools."* That sentence is
false, and we can now show it is false rather than suspect it. Deploying the reference
implementation on Intel TDX forced us to enumerate what a verifier must accept to believe a
single measurement:

| Party | What you must assume | What a breach buys the adversary | Detectable in |
| --- | --- | --- | --- |
| Intel | the TDX module, microcode and CPU behave as specified; the provisioning key is not misissued | arbitrary quote forgery, state extraction, memory manipulation inside the hardware boundary | never |
| Intel's certification service (PCS) | the collateral fetched to check a quote is authentic (TCB recovery info, CRLs, QE certs) | revoked, vulnerable or emulated hardware presented as a valid target | collateral refresh interval (~12 h) |
| The quoting enclave | it measures TD reports accurately and signs without key leakage | forged execution claims on a compromised host | never |
| The cloud operator | the host does not extract domain memory outside the TDX threat model; the firmware measured into RTMRs is what it claims | deceptive measurement injection at boot; side-channel extraction | never |
| Whoever publishes reference values | the MRTD compared against belongs to the code you believe it does | valid attestation of subverted software inside a genuine TD | never |

The fourth column is new and is the point. **Four of the five** assumptions have **no detection
mechanism at all** — their violation is silent and permanent. Only the certification service's
collateral is checked on a schedule, and that schedule is the one thing in the table an operator
can shorten. Anchoring the evidence log removes **none** of
these. It makes the *history* publicly auditable — a real and valuable property — while the
*measurement* still rests on that chain. The tier ladder conflates two things a careful reader will
separate: **public verifiability** (anyone may check, with published tools) and **trust
independence** (no party's honesty is load-bearing). Hardware attestation buys the first and leaves
the second largely intact.

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
  attached to each role* are not formalized. RFC 9334 is descriptive: it says who plays what part,
  not what breaks when a part is played dishonestly.
* **Trust management / authorization logics** — Abadi, Burrows, Lampson and Plotkin, *A Calculus
  for Access Control in Distributed Systems* (1993); Lampson et al., *Authentication in
  Distributed Systems* (1992). The "says" and "speaks-for" primitives are exactly the right shape
  for expressing "Intel says this measurement."
* **Nexus authorization logic** (Schneider, Walsh, Sirer) — an authorization logic built for
  attestation-based systems, and the closest prior art. NAL's division of authorization bases into
  **axiomatic** (trusted by policy fiat), **analytic** (derived from mechanical analysis of code)
  and **synthetic** (produced by a trusted transformation or isolated environment) is directly
  reusable: it is already a taxonomy of *why* a claim is believed, which is one axis of what this
  paper needs to compute.
* **Declarative policy languages** — SecPAL, DKAL, Binder. These evaluate authorization queries
  against a fixed trust root. **None of them inverts the question**: given a query that succeeds,
  emit the minimal set of principals whose honesty the success depended on. That inversion is the
  paper's technical core.
* **Byzantine and threshold assumptions** — for expressing "any *k* of these *n* endorsers," and
  for the non-collusion predicate that a quorum rule reduces to.
* **Transparency systems** — Certificate Transparency ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)),
  CONIKS, gossip protocols. These are the canonical examples of converting trust into detection
  rather than eliminating it, which is the distinction the tiers need.
* **Attestation critiques** — the SGX/TDX attack literature (Foreshadow, SGAxe, Plundervolt,
  ÆPIC Leak) establishes that hardware roots are assumptions, not axioms. Note the specific shape
  of these attacks: they break isolation *without* invalidating the signing key, so the quote
  remains cryptographically valid while the claim it makes is false.
* **DAA (Direct Anonymous Attestation)** — Brickell, Camenisch, Chen (2004) — relevant because it
  shows how much of the trust structure can be restructured cryptographically rather than merely
  documented. See [P05](P05-unlinkable-identity.md).
* **Tabled logic-program evaluation** — SLG resolution and the XSB engine. Relevant to
  mechanization: plain SLD resolution does not terminate on mutual or circular attestation, which
  real deployments contain.

## What the desk study already found

A preliminary analysis encoded four deployment paradigms and computed residual trust sets by hand
and by a prototype rule set. **These are desk results, not validated tool output** — reproducing
them mechanically is the paper's first job, not its conclusion. They are recorded here because they
make the paper's predictions concrete enough to be wrong.

| Deployment | Mechanism | Residual trust set (principal, capability, detection latency) | Catastrophic failure |
| --- | --- | --- | --- |
| **Σ₁** software-only host | signed measurement logs | (Host OS, kernel integrity, ∞), (Admin, key custody, ∞), (Verifier, policy sync, ∞) | silent log modification |
| **Σ₂** Intel TDX | ECDSA quotes + PCS collateral | (Intel, silicon logic, ∞), (Intel PCS, collateral honesty, 12 h), (QE, quote signing, ∞), (Cloud op, measurement injection, ∞), (RVP, golden values, ∞) | microcode breach → undetectable forgery |
| **Σ₃** witness quorum (5-of-7) | threshold signatures + transparency log | (Witnesses, non-collusion at *k*=5, ∞), (Log operator, monotonicity, 15 min), (Gossip peers, view sync, 15 s) | 5-way collusion validates false state |
| **Σ₄** ZK rollup | Groth16 + on-chain verifier | (Ceremony, toxic-waste destruction, ∞), (Compiler, sound arithmetization, ∞), (Auditor, constraint completeness, ∞), (L1 consensus, execution fidelity, 12 s) | under-constrained circuit accepts false proofs |

Two findings matter more than the table:

**1. The sets are incomparable, not merely different.** T(Σ₂) ⊄ T(Σ₄) and T(Σ₄) ⊄ T(Σ₂) — they
intersect only in the reference-value/compiler role. Under set inclusion there is no partial order,
so neither architecture is "more verifiable." Every candidate total ordering fails for an
independent reason: **cardinality** treats one opaque silicon vendor as equivalent to ten
transparent witnesses; **collusion cost** is adversary-relative (a domestic enterprise and a
cross-border protocol rank the same two designs oppositely); **set inclusion** does not hold. If
this survives mechanization, *the refuting branch below is the actual result*.

**2. Two non-obvious structural findings**, which is the bar the method sets for the tool being
worth building:

* **Hidden shared dependency.** A hybrid design combining a TEE with ZK proofs — marketed as
  defence in depth — was found to share an upstream compiler toolchain and reference-value
  provider across both layers. One build-pipeline compromise corrupts the MRTD baseline *and* the
  circuit constraints simultaneously. The two layers are not independent, and no party had noticed.
* **Settlement-layer dependency ingestion.** Anchoring to a public ledger converts log-operator
  trust into a bounded detection latency, which is the intended win. It also silently *ingests* a
  new assumption — consensus-layer execution fidelity. A deep reorganization rolls back published
  attestation evidence. Anchoring is usually described as pure gain; it is a trade.

## What is genuinely open

Nobody has produced a *computable* residual-trust set. The RATS roles are descriptive; the
authorization logics can express trust relationships but were not built to answer "given this
deployment, list every party whose dishonesty changes the answer, and say what each could do."

The desk study designs a calculus but validates nothing. What remains genuinely open:

1. **A type system or logic** whose judgments have the form `Γ ⊢ P : T, Δ` — *"proposition P holds
   provided the parties in T are honest, with violations detectable within Δ"* — where composing
   mechanisms composes the trust sets. Composition rules are drafted for signing, hash chaining,
   anchoring, gossip, witness quorums, TEE attestation and ZK verification; **none is proved
   sound**, and soundness is the whole value of the artifact.
2. **Removal versus conversion, made formal.** Anchoring does not remove trust in the log
   operator; it converts undetectable misbehaviour into detectable misbehaviour. The drafted
   treatment introduces a monitoring operator mapping an assumption to a detection-bounded one.
   Whether that operator composes correctly across chained mechanisms is unresolved.
3. **Detection latency as a first-class term.** Δ is proposed as a function of attestation refresh
   interval, anchoring periodicity, and gossip propagation delay — three parameters the standard
   currently treats as unrelated. Open: whether Δ composes as a max, a sum, or neither, and what
   happens to a judgment evaluated outside its validity window. The draft degenerates the judgment
   to the unmonitored case; that is a choice, not a derivation.
4. **The completeness problem — the hardest and least-addressed.** A solver computes over
   dependencies that were *encoded*. It cannot discover an unmodelled one. A tool that confidently
   emits a five-element trust set while a sixth dependency exists off-model is worse than no tool,
   because it converts an open question into a false answer. The paper needs an honest story here:
   differential encoding by independent authors, adversarial review of system descriptions, or an
   explicit soundness caveat printed with every manifest. **This is the most likely reviewer
   objection and the proposal should meet it head-on rather than in a limitations paragraph.**
5. **What replaces the ladder.** If the incomparability result holds, conformance publishes a
   *manifest* rather than a *tier*. That raises new questions the desk study does not answer: how
   does a relying party with a local policy evaluate an unfamiliar manifest, how are principals
   named stably enough to compare across manifests, and what stops manifest inflation (listing
   many trivial assumptions to look rigorous)?
6. **Principal independence.** Quorum rules reduce to a non-collusion predicate over named parties.
   Nothing in the calculus prevents five of seven "independent" witnesses from sharing a
   jurisdiction, a cloud region, or a corporate parent. Whether independence can be *computed* from
   a description, or must be asserted, is open and consequential.

## Method

1. **Formalize.** Define the judgment `Γ ⊢ P : T, Δ` where Γ is the observed context (credentials,
   quotes, log heads, keys), T is the residual trust set of (principal, capability, latency)
   triples, and Δ the composed detection bound. Give composition rules for every mechanism the
   standard admits and **prove them sound** against an operational model in which a named principal
   may deviate arbitrarily.
2. **Mechanize.** Encode as Datalog with tabled (SLG) resolution — XSB or a Souffle equivalent —
   so that circular delegation and mutual attestation terminate rather than diverge. Establish
   decidability and the data-complexity bound for computing T(Σ) on a finite system description.
   The drafted claim is polynomial in principals × credentials; verify it rather than assert it.
   A small checker that takes a deployment description and emits the trust set is the artifact
   that makes this paper land.
3. **Validate against reality.** Run it on Σ₁–Σ₄ above. Success criterion: it reproduces the
   five-party TDX set we derived by hand *from the deployment description alone*, without those
   parties being named in the encoding.
4. **Attack the encoding.** Have a second author independently encode Σ₂ and diff the trust sets.
   Any divergence is a finding about the calculus, not a bug to be quietly fixed. This is the
   completeness problem from §4 above and deserves its own experiment.
5. **Re-derive or abolish the tiers.** Test each candidate ordering (cardinality, collusion cost,
   set inclusion, detection-latency bound) against Σ₁–Σ₄ and report which survive. Current
   expectation: none, and the contribution becomes the manifest schema plus a policy-evaluation
   procedure.

## What would settle it

**Supporting:** the checker reproduces hand-derived trust sets for at least four deployment
classes, and produces at least one non-obvious result — for example, that two mechanisms believed
independent share a party. *The desk study predicts two such results (shared compiler toolchain;
settlement-layer ingestion); mechanically rediscovering them is a concrete, falsifiable target.*

**Refuting — and now the expected outcome:** if residual trust sets are incomparable across
realistic designs — no partial order that respects intuition — then *tiers are the wrong
abstraction entirely*, and the finding is that conformance should publish a trust set rather than
a tier. **That is a publishable result and it would be a bigger contribution than confirming the
ladder.** The desk analysis already points this way; the paper should be built so this outcome is
the headline rather than a footnote.

**Genuinely negative:** if independent encodings of the same deployment produce materially
different trust sets, the calculus is under-determined and the honest report is that residual trust
is not mechanically computable from descriptions at the fidelity available. That would be worth
publishing too, and it is the outcome step 4 is designed to detect.

## Consequence for the standard

* **C8.1–C8.3 rewritten**, along the lines the desk study proposes:
  * **C8.1 (Tiers 1–2)** → *Unmonitored / Unbounded-Latency Attestation*: signed statements with
    no detection mechanism, Δ = ∞.
  * **C8.2 (Tier 3)** → *Publicly Verifiable, Hardware-Anchored Attestation*. The claim that there
    is "nobody left to trust" is **deleted**, replaced by an explicit enumeration of silicon,
    provisioning and reference-value dependencies with their detection bounds.
  * **C8.3 (Tier 4)** → *Multi-Domain Bounded-Detection Attestation*: single-party assumptions
    converted, via transparency logs, gossip or threshold quorums, into a bounded system-wide Δ.
  * The reframing is worth noting on its own: tiers become ordered by **detection latency and
    domain diversity**, not by mechanism — which is defensible even if the full manifest proposal
    is rejected.
* **C7.4 / C10.2 strengthened.** Trust-assumption disclosure becomes a computed artifact with a
  schema, not prose: a machine-readable **Residual Trust Manifest** listing each principal (as a
  DID or stable identifier), its assumed capability, detection latency, and failure impact, plus
  any structural thresholds (*k*-of-*n* quorums).
* **A new conformance obligation C10.3 (automated trust evaluation).** Verifier software accepts a
  local trust policy and mechanically rejects an attestation whose manifest exceeds the policy's
  admissible principal set or detection-latency bound. This is what makes the manifest load-bearing
  rather than decorative — without it, publishing a trust set is documentation, not enforcement.
* The paper's §4.2 and §10 both need revision; §10 currently concedes the problem without
  solving it.

## Venue

IEEE S&P / USENIX Security for the full treatment; NDSS or a CCS short paper for the calculus
alone. Alternatively an IETF RATS-adjacent draft, which would carry further with implementers
than a paper would — and the manifest schema is exactly the kind of artifact the RATS working
group is equipped to absorb.

## Effort and dependencies

Medium, and now lower-risk than when this was drafted: the formalism is sketched, the four
validation deployments are chosen, and the expected result is identified. The remaining work is
the soundness proofs, the tabled encoding, and the independent-encoding experiment — a few months.
Validation reuses the TDX deployment already built. **No dependencies** — this is the natural first
paper, and P02 and P03 both read more cleanly once the vocabulary exists.
