# P05 — Accountable but Unlinkable Agent Identity

**Domain:** C5 Identity · **Kind:** Generative · **Impact:** High · **Effort:** Large

---

## The question

Can an autonomous agent's actions be independently verifiable and attributable *when it matters*,
while being unlinkable across relying parties the rest of the time — and what does the mechanism
cost at agent action rates?

## Why it matters

**For the standard.** This is [open issue 2](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md),
raised by working-group member Bob Blessing-Hartley, and it is stated as a live design choice
rather than a settled one:

> "I strongly advocate for verifiable unlinkability so enterprises can deploy agents without
> disclosing customer PII or corporate identities to third-party vendors. The best way to secure
> information is to not hand it out unnecessarily."

C5 has **six requirements** — the thinnest of the six domains — and carries two of the three
substantive open issues. The specification is least developed exactly where the design questions
are hardest, which is the usual signature of a topic nobody has worked out.

The tension is real and structural. Every other part of this standard pushes toward *more*
identifiable evidence: `agent_id`, `initiating_user`, hash chains that link every action to every
prior action, anchors published where anyone can see them. A hash-chained, publicly anchored log
of an agent's actions is close to the worst case for unlinkability — it is a permanent, ordered,
cryptographically-bound dossier. Making that unlinkable is not a matter of omitting a field.

**For the field.** Agent deployments are about to collide with this at scale. An enterprise that
sends an agent to transact with a third-party vendor currently reveals, with every action, which
enterprise it is, which user it acts for, and how much it has done. Under GDPR data minimization
and comparable regimes, that is difficult to defend when the vendor needs to know only that the
agent is authorized. The cryptography to fix it has existed for twenty years and has never been
applied to this setting.

## What is already known

The mechanisms are mature. The application is not.

* **Direct Anonymous Attestation** — Brickell, Camenisch, Chen (CCS 2004); adopted in TPM 2.0 and
  standardized in ISO/IEC 20008. **This is the closest existing answer**: it lets a TPM attest
  that *some* valid TPM produced a statement without revealing which. The elliptic-curve variant
  (ECDAA, as used in FIDO) is the practical form and maps onto our TEE evidence directly. The fact
  that it is already in shipping hardware makes it the obvious starting point.
* **Anonymous credentials** — Camenisch–Lysyanskaya; Idemix; U-Prove; BBS+ signatures over
  BLS12-381 (now with a maturing IETF/W3C track for selective disclosure). Also SPSEQ-UC
  (structure-preserving signatures on equivalence classes over updatable commitments), which is
  less well known and directly relevant because re-randomization is the property the log layer
  needs.
* **Group and ring signatures** — Chaum–van Heyst; Rivest–Shamir–Tauman. Group signatures include
  an opening authority, which is the escrow mechanism the issue asks about.
* **Verifiable credentials and DIDs** — W3C VC 2.0, SD-JWT, BBS+ selective disclosure. The
  standard already recommends DIDs for `agent_id`, so this is the natural integration surface.
* **Privacy Pass / rate-limited anonymous tokens** — [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578)
  and the VOPRF construction beneath it. The closest deployed analogue to "unlinkable but bounded,"
  directly relevant to abuse prevention, and — per the cost analysis below — probably the mechanism
  that makes the whole design practical rather than merely possible.
* **Threshold cryptography** — distributed key generation, threshold ElGamal, and DLEQ proofs for
  verifiable partial decryption. This is the machinery that turns "escrow" from a backdoor into a
  quorum action.
* **Escrow and accountability** — fair exchange, threshold escrow, key-escrow critiques
  (Abelson et al., *Keys Under Doormats*, 2015), and the Clipper Chip's specific failure modes:
  centralized depository, fragile operational control, no transparency. The escrow design is where
  this gets politically as well as technically hard, and the paper should engage that literature
  rather than assume escrow is unproblematic.
* **Transport-layer linkability** — Oblivious HTTP, relays, padding. Easy to forget and fatal if
  omitted: unlinkable credentials presented over a directly-attributable TCP connection are not
  unlinkable.
* **Privacy-preserving transparency** — how to keep a log auditable while its entries are
  unlinkable; less settled than the credential side and probably where the novelty is.

## The candidate construction

A desk study has assembled a concrete four-layer construction. It is a credible starting point and
it is **unimplemented and unproven** — recording it here makes the paper's work specific rather
than exploratory.

| Layer | Mechanism | Defeats |
| --- | --- | --- |
| Hardware attestation | **ECDAA** — prove membership in a valid TEE group without emitting a platform identifier | RP or auditor fingerprinting the silicon |
| Agent credential | **BBS+ / SPSEQ-UC** — fresh blinding per presentation, selective attribute disclosure | colluding relying parties correlating sessions |
| Evidence log | **ephemeral per-session chains**, roots posted as re-randomizable Pedersen commitments | log operator reconstructing a global action sequence |
| Accountability | ***k*-of-*n* threshold ElGamal escrow tag** + NIZK that the tag encrypts the credential-bound identity; opening produces DLEQ proofs | a rogue escrow node unmasking unilaterally |
| Transport | OHTTP relay + padding | network observer linking by IP and timing |

The escrow design is the part most likely to survive review intact, because it takes the political
objection seriously: no assembled master key ever exists, shares live in non-exportable HSMs across
independent jurisdictions, every opening emits a public receipt naming the warrant and the target
session commitment, and — the property that actually matters — **opening one session gives zero
leverage on any other session by the same agent.** That last point converts escrow from a
surveillance capability into a per-incident one, which is the distinction *Keys Under Doormats*
argues is usually absent.

## What the desk study found about cost — and the arithmetic problem it exposes

Indicative figures, drawn from published primitive benchmarks rather than from our pipeline. **None
of this has been measured on our stack; treat every number as a hypothesis with a named test.**

| Operation | Cost | Notes |
| --- | --- | --- |
| Ed25519 sign / verify (baseline) | 97 µs / 162 µs | what the standard assumes today |
| BBS+ presentation (proof generation) | ~13.8 ms | of which ZK proof construction ~8.3 ms and escrow tag + DLEQ ~4.6 ms |
| BBS+ verification | ~4.2 ms | ~1.1 ms with cached pairing pre-computation |
| Privacy Pass token (VOPRF) | ~850 µs | sub-ms amortized when pre-fetched in batches |
| zk-STARK proof | ~238 ms generate / ~12 ms verify | not viable at action rates |

**The important finding is one the source did not draw.** Presentation and verification are each
assessed separately against the 15 ms budget and each looks acceptable. Add them: 13.8 + 4.2 =
**18 ms, which exceeds the budget outright.** With cached pairings it is 14.9 ms — under the limit
with a 100 µs margin, meaning zero headroom for the actual application work, network time, or
evidence writing.

So the honest headline is:

> **The naive construction does not fit the latency budget. Pre-computation is not an optimization;
> it is load-bearing.** With pre-computed proof pools (~2.8 ms presentation) and cached pairings
> (~1.1 ms verification) the per-action cost is ~3.9 ms — feasible, but still roughly **15× the
> Ed25519 baseline**, against ~70× unoptimized.

That reframing matters because it relocates the risk. The open question is no longer "is BBS+ fast
enough" but "**is the pre-computation pool sound?**" — which is a security question, not a
performance one, and nobody has asked it:

* A pool of pre-computed blinding factors and commitments sits in TEE memory for an unknown
  interval. What is the exposure if that memory is compromised, and does it retroactively link
  past presentations?
* What happens when the pool is exhausted under burst load? The two available behaviours are
  **stall** (a latency spike precisely when the agent is busiest — an observable side channel that
  itself leaks) or **reuse** (which breaks unlinkability outright). Neither is acceptable and the
  design must specify a third option.
* Pool refill is idle-time work inside the TEE. Does refill activity correlate with agent activity
  in a way an observer of the host can exploit?

## What is genuinely open

1. **Unlinkability against a hash-chained, anchored log.** The credential literature makes
   *credentials* unlinkable. It does not address a public, ordered, tamper-evident record of
   every action the credential holder took. Two actions in the same chain are linked *by the
   chain*, whatever signature scheme wraps them. The proposed answer — per-session ephemeral chains
   with roots posted as re-randomizable commitments — is plausible and **unproven**. The specific
   thing to prove: that a log operator seeing a stream of Pedersen commitments cannot correlate
   them, given that it also sees posting times, sizes and frequencies. Cryptographic hiding does
   not defeat traffic analysis, and the desk study does not address the gap.
2. **Whether tamper-evidence survives decoupling.** If the global chain is replaced by per-session
   chains, what exactly is still guaranteed? A global chain proves *no action was deleted*.
   Independent session chains prove no action was deleted *from a session you already know about* —
   an agent could suppress an entire session and the log would not show a gap. **This may be the
   real result of the paper**: unlinkability and completeness-of-record are in genuine tension, and
   naming precisely what is surrendered is a contribution whichever way it resolves.
3. **What "when it matters" means, mechanically.** Threshold escrow answers who holds the key and
   how opening is proved. It does not answer who decides a warrant is valid, what stops *k* nodes
   in one jurisdiction from being compelled together, how a verifier confirms the escrow exists and
   is live without exercising it, or what happens when a node is unreachable at opening time.
4. **Composition with hardware attestation.** ECDAA gives an anonymous *platform* attestation; we
   need the evidence key bound to a measured environment (requirement C7.2.4) *and* unlinkable.
   Whether those compose without leaking a platform identifier is open. The concrete hazard: TDX
   quote collateral (TCB levels, PCS certificate chains) is itself a fingerprint. Two agents on
   distinct TCB versions are distinguishable even under perfect ECDAA, and TCB diversity across a
   fleet may reduce the anonymity set to something small. **This deserves measurement — how many
   distinct TCB configurations exist in a realistic fleet? — and it is cheap to do.**
5. **Selective disclosure over evidence, not just credentials.** An auditor may need the full
   chain while a vendor sees one action. That is a disclosure policy over a tamper-evident
   structure, not selective disclosure over a credential. Note this pulls directly against the
   escrow's anti-scope-creep property: opening one session must give no leverage on others, yet an
   auditor must sometimes reconstruct the whole sequence. Both cannot hold unconditionally, and the
   design must say which authority gets which power.
6. **Revocation.** Barely touched by the desk study and historically the hardest part of anonymous
   credential deployment. Revoking a compromised agent's credential without linking its past
   actions, and without an accumulator update cost that scales badly, is an open problem in its own
   right.
7. **The anonymity set.** Unlinkability is meaningless without one. If an enterprise deploys twelve
   agents and a vendor sees traffic from twelve unlinkable credentials in a pattern only that
   enterprise produces, the cryptography has not helped. **What is the anonymity set actually made
   of** — agents within a firm, firms within an issuer, or hardware within a TEE group? — is the
   first question a PETS reviewer will ask, and neither the standard nor the desk study answers it.

## Method

1. **Threat and requirements model.** Enumerate who should be able to link what: relying party,
   colluding relying parties, log operator, auditor, escrow holder, network observer. State the
   three target properties formally — session unlinkability, cross-RP unlinkability under
   collusion, and verifiable tracing under *k*-of-*n* authorization — and state the anonymity set
   each is defined over. Most "anonymity" designs fail against colluding relying parties; make that
   the explicit target.
2. **Construct.** Assemble the four layers above and prove the unlinkability properties against the
   stated adversary. The novel proof obligation is the log layer, not the credential layer.
3. **Implement** on top of the existing reference implementation, which already has the chain,
   the anchoring, the tree, and a real TDX deployment to build on.
4. **Measure** — and note this is the step to do *first*, before any construction work.
   Signature and verification cost, evidence record size, effect on inclusion-proof size, and
   end-to-end per-action latency against the 15 ms budget, compared to the published Ed25519
   baseline. Specifically test the composed path (present **and** verify), which is where the
   desk figures break, and characterize the pre-computation pool: refill rate, memory footprint,
   exhaustion behaviour under burst.
5. **Measure the anonymity set**, not just the cryptography: TCB configuration diversity across a
   realistic fleet, and whether posting times and sizes permit correlation of commitments. A
   negative result here would invalidate the construction regardless of how good the proofs are,
   which is a reason to do it early.
6. **Evaluate the escrow** as a governance mechanism, not only a cryptographic one — including
   the case against it, and including the compulsion-correlation question in §3.

## What would settle it

**Supporting:** a construction that is unlinkable against colluding relying parties, retains
tamper-evidence and inclusion proofs, supports threshold opening with public receipts, and fits the
latency budget *on the composed present-and-verify path* — which, per the arithmetic above, requires
the pre-computation pool to be proved sound, not just fast.

**Refuting — and worth publishing:** a proof that unlinkability is incompatible with the
standard's tamper-evidence requirements as written. If a publicly anchored chain necessarily
links an agent's actions, then unlinkability requires giving something up, and *naming precisely
what* would be a real contribution. It would also settle open issue 2 in the negative, which the
working group needs either way. **The suppression gap in §2 above is the most likely form this
takes**, and it is a sharper version of the refutation than the original framing anticipated.

**A third outcome now visible:** unlinkability is achievable but only above a minimum fleet size,
because below it the anonymity set is too small for the cryptography to matter. That would be an
unusually useful result for implementers — a deployment threshold rather than a yes/no — and it
falls directly out of step 5.

## Consequence for the standard

* **C5 gains an unlinkability profile** as an implementer-selectable option, closing open issue 2.
  The desk study's shape is right: a default **C5-Identified** profile (Ed25519, explicit
  `agent_id`, global linear chain) alongside a **C5-Unlinkability** profile (ECDAA attestation,
  BBS+ credentials, ephemeral session chains with re-randomizable commitments, threshold escrow).
  Two profiles rather than a spectrum keeps conformance checkable.
* **C2 Privacy** gains a mechanism it currently gestures at: under the unlinkability profile,
  persistent identifiers — `initiating_user`, static `agent_id`, hardware serials — are omitted
  from third-party interactions and replaced by selectively-disclosed claims.
* **C7.3 may need amendment**, and this is the load-bearing change: the chain structure that
  provides tamper-evidence is the thing that prevents unlinkability. Permitting decoupled ephemeral
  chains requires saying explicitly what tamper-evidence still means once the global order is gone
  — see §2 of the open questions, which is why this amendment cannot be drafted before the research
  is done.
* **C10** — the conformance claim must state which identity profile is in force, since a verifier's
  capabilities differ, and a relying party needs to decide by policy whether an anonymous
  presentation is acceptable at all.
* **Governance requirements are new surface for the standard**: escrow shares in non-exportable
  HSMs across independent jurisdictions, mandatory public receipts for every opening, and
  cryptographic scoping of an opening to a single named session.

## Venue

PETS (Privacy Enhancing Technologies Symposium) is the natural home; CCS or S&P if the
construction is strong. The measurement alone — *what anonymous credentials cost at agent action
rates*, including the composed-path result that the obvious construction misses the budget —
would make a solid workshop paper and could ship first.

## Effort and dependencies

Large. Real cryptographic construction and proof. **Highest-value place to start:** the
measurement in steps 4 and 5, which needs no new cryptography, answers questions nobody has asked,
and would tell you quickly whether the whole direction is viable. The desk study has made that
first step much more specific — there is now a concrete number to confirm or refute (~18 ms
composed, ~3.9 ms with pre-computation) and a named soundness question about the pre-computation
pool that has to be answered before the construction is worth building.
