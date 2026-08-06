# P05 — Accountable but Unlinkable Agent Identity

**Domain:** C5 Identity · **Kind:** Generative · **Impact:** High · **Effort:** Large

---

## The question

Can an autonomous agent's actions be independently verifiable and attributable *when it matters*,
while being unlinkable across relying parties the rest of the time — and what does the mechanism
cost at agent action rates?

## Why it matters

**For the standard.** This is [open issue 2](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md),
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
  that *some* valid TPM produced a statement without revealing which. It maps almost directly
  onto our TEE-based evidence, and the fact that it is already in shipping hardware makes it the
  obvious starting point.
* **Anonymous credentials** — Camenisch–Lysyanskaya; Idemix; U-Prove; BBS+ signatures (now with
  a maturing IETF/W3C track for selective disclosure).
* **Group and ring signatures** — Chaum–van Heyst; Rivest–Shamir–Tauman. Group signatures include
  an opening authority, which is the escrow mechanism the issue asks about.
* **Verifiable credentials and DIDs** — W3C VC 2.0, SD-JWT, BBS+ selective disclosure. The
  standard already recommends DIDs for `agent_id`, so this is the natural integration surface.
* **Privacy Pass / rate-limited anonymous tokens** — the closest deployed analogue to
  "unlinkable but bounded" and directly relevant to abuse prevention.
* **Escrow and accountability** — fair exchange, threshold escrow, key-escrow critiques
  (Abelson et al., *Keys Under Doormats*, 2015). The escrow design is where this gets politically
  as well as technically hard, and the paper should engage that literature rather than assume
  escrow is unproblematic.
* **Privacy-preserving transparency** — how to keep a log auditable while its entries are
  unlinkable; less settled than the credential side and probably where the novelty is.

## What is genuinely open

1. **Unlinkability against a hash-chained, anchored log.** The credential literature makes
   *credentials* unlinkable. It does not address a public, ordered, tamper-evident record of
   every action the credential holder took. Two actions in the same chain are linked *by the
   chain*, whatever signature scheme wraps them. Resolving this may require per-session chains,
   re-randomizable commitments, or abandoning a single global chain — and each has consequences
   for the evidence properties the standard requires.
2. **What "when it matters" means, mechanically.** Piercing pseudonymity under subpoena is easy
   to say and hard to specify: who holds the opening key, under what process, with what
   transparency, and how does a verifier confirm the escrow exists without exercising it?
3. **Cost at agent rates.** BBS+ and DAA are orders of magnitude more expensive than Ed25519.
   Our measured pipeline is ~162 µs per action with a 15 ms budget; pairing-based signatures may
   or may not fit. **Nobody has measured this for agent workloads** and it is a cheap, concrete
   contribution.
4. **Composition with hardware attestation.** DAA gives an anonymous *platform* attestation; we
   need the evidence key bound to a measured environment (requirement C7.2.4) *and* unlinkable.
   Whether those compose without leaking a platform identifier is an open question with a
   concrete answer.
5. **Selective disclosure over evidence, not just credentials.** An auditor may need the full
   chain while a vendor sees one action. That is a disclosure policy over a tamper-evident
   structure, and it is not the same problem as selective disclosure over a credential.

## Method

1. **Threat and requirements model.** Enumerate who should be able to link what: relying party,
   colluding relying parties, log operator, auditor, escrow holder, network observer. Most
   "anonymity" designs fail against colluding relying parties; state the target explicitly.
2. **Construct.** Combine (a) DAA or BBS+ for the agent's credential, (b) a per-session or
   re-randomizable chain structure that preserves tamper-evidence without linking sessions,
   (c) threshold escrow for opening. Prove the unlinkability property against the stated
   adversary.
3. **Implement** on top of the existing reference implementation, which already has the chain,
   the anchoring, the tree, and a real TDX deployment to build on.
4. **Measure**: signature and verification cost, evidence record size, effect on inclusion-proof
   size, and end-to-end per-action latency against the 15 ms budget. Compare to the Ed25519
   baseline already published.
5. **Evaluate the escrow** as a governance mechanism, not only a cryptographic one — including
   the case against it.

## What would settle it

**Supporting:** a construction that is unlinkable against colluding relying parties, retains
tamper-evidence and inclusion proofs, supports threshold opening, and fits the latency budget.

**Refuting — and worth publishing:** a proof that unlinkability is incompatible with the
standard's tamper-evidence requirements as written. If a publicly anchored chain necessarily
links an agent's actions, then unlinkability requires giving something up, and *naming precisely
what* would be a real contribution. It would also settle open issue 2 in the negative, which the
working group needs either way.

## Consequence for the standard

* **C5 gains an unlinkability profile** as an implementer-selectable option, closing open issue 2.
* **C2 Privacy** gains a mechanism it currently gestures at.
* **C7.3** may need amendment: the chain structure that provides tamper-evidence may be the
  thing that prevents unlinkability.
* **C10** — the conformance claim must state which identity profile is in force, since a verifier's
  capabilities differ.

## Venue

PETS (Privacy Enhancing Technologies Symposium) is the natural home; CCS or S&P if the
construction is strong. The measurement alone — *what anonymous credentials cost at agent action
rates* — would make a solid workshop paper and could ship first.

## Effort and dependencies

Large. Real cryptographic construction and proof. **Highest-value place to start:** the
measurement in step 4, which needs no new cryptography, answers a question nobody has asked, and
would tell you quickly whether the whole direction is viable.
