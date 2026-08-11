# P07 — Evidence Continuity Across Trust Domains

**Domain:** C3 Portability · **Kind:** Generative · **Impact:** Medium-high · **Effort:** Medium

---

## The question

When an agent moves between attestation domains — clouds, vendors, jurisdictions — each side can
be internally tamper-evident while no cryptographic link joins them. What construction makes the
seam verifiable, and what does crossing a jurisdiction do to the *disclosure* the evidence carries?

## Why it matters

**For the standard.** This is [open issue 3](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md),
raised by Bob Blessing-Hartley and separately by Advait Patel, and it is unresolved to the point
that the working group has not decided *where it lives* — Portability, a fifth evidence property,
or a domain of its own.

C3 Portability has **five requirements**, the fewest of any domain. It is simultaneously the least
developed and the place an evidence chain most obviously breaks. A migration from one cloud to
another produces two chains, each perfect, with a gap between them that no verifier can see
across — and the gap is exactly where an operator would hide something.

The second half is subtler and comes from the same contribution: **disclosure continuity**. A
zero-knowledge proof or a redacted record that is adequate in one jurisdiction may reveal more
than permitted when surfaced in another. Evidence is not disclosure-neutral when it travels.

**For the field.** Cross-cloud and cross-vendor agent execution is arriving faster than the
verification story for it. The general problem — composing tamper-evident logs across
independent roots of trust — also appears in supply-chain attestation (in-toto layouts spanning
organizations), federated learning, and multi-party audit.

## What is already known

* **in-toto** — Torres-Arias et al. (USENIX Sec 2019). Supply-chain layouts spanning
  organizational boundaries; the closest existing framework for multi-party attested chains.
* **Certificate Transparency** cross-log gossip and the general problem of reconciling
  independent logs.
* **Cross-chain / bridge protocols** — light-client proofs, notary schemes, and their extensive
  failure literature. The failure modes are directly instructive: bridges are where value gets
  stolen, and for structurally similar reasons.
* **Handoff and migration attestation** — TPM key migration, SEV-SNP migration agents, and live
  VM migration for confidential VMs. This is the hardware-level version of the same problem and
  is actively being standardized.
* **Nested / composite attestation** — RATS composite device model
  ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) §3.3) is the vocabulary for an attester
  made of sub-attesters, and is the natural formalism.
* **Data-residency and transfer law** — GDPR Chapter V, Schrems II. The disclosure half is a legal
  as much as technical question and should be engaged as such.

## What is genuinely open

1. **The handoff construction.** What does domain A sign, and what does domain B include, such
   that a verifier can confirm continuity without trusting either? Candidates: B's genesis commits
   to A's final root and A attests the handoff; a shared witness quorum spanning both; anchoring
   both to a common log.
2. **What continuity even asserts.** That no actions occurred between chains? That the same agent
   identity carried over? That state was transferred without modification? These are different
   claims needing different mechanisms, and the standard conflates them.
3. **Asymmetric tiers.** If domain A is Tier 3 and domain B is Tier 1, what is the tier of the
   joined evidence? Almost certainly the minimum, but that is worth stating and possibly wrong —
   an anchored handoff might preserve more than the weaker side alone.
4. **Disclosure continuity.** A formal model of what evidence *reveals*, and how a redaction or
   proof valid under one policy behaves under another. This appears to be genuinely new.
5. **Where it belongs.** The working group's structural question is real: continuity may be a
   fifth evidence property alongside binary, contemporaneous, tamper-evident, and transparent.

## Method

1. Model two domains with independent roots; state continuity properties precisely, separating
   the three claims in (2).
2. Design a handoff protocol; prove continuity against an adversary controlling the gap.
3. Implement across two *actually different* attestation roots — the TDX deployment already built
   plus an AMD SEV-SNP instance — so the cross-root claim is demonstrated, not simulated.
4. Measure handoff cost and the verifier's cost of checking a multi-domain chain.
5. Develop the disclosure model and work at least one concrete jurisdictional example end to end.

## What would settle it

A handoff protocol with a proof and a working cross-root implementation, plus a recommendation on
the structural question the working group asked. If continuity turns out to require a trusted
third party spanning both domains, that is a negative result worth having explicitly.

## Consequence for the standard

* **C3 expands substantially** — likely from 5 requirements to a proper domain.
* Possible **fifth evidence property**, which would touch C7 throughout.
* **C8** gains rules for tier composition across domains.
* **C2 / C10** gain disclosure-continuity obligations.

## Venue

CCS/NDSS for the protocol; a policy-adjacent venue for the disclosure half, which may be better
served as a separate paper.

## Effort and dependencies

Medium. Reads better after [P01](P01-trust-calculus.md), since "tier of joined evidence" is a
trust-composition question and the calculus would answer it directly.
