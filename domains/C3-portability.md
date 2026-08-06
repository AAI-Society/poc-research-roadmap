# C3 — Portability

**5 requirements** · *Boundary crossings: organizational, jurisdictional, compute* ·
[Chapter](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x10-C03-Portability.md)

## State of the domain

The least developed domain in the standard, with five requirements, and the one where the
evidence chain most obviously breaks. That combination is a problem rather than a coincidence: the
domain is thin because the question is hard, not because it is small.

## What is settled

* Boundary crossings are recorded as events — which boundary, when, under what authority.
* Residency constraints are expressible and enforceable through the grant.

## What is open

Essentially the whole domain.

**The cryptographic seam.** When an agent migrates between attestation domains, each side can be
internally tamper-evident with no link joining them. Two perfect chains and a gap between them,
and the gap is exactly where an operator would hide something. No construction is specified.
→ **[P07](../papers/P07-evidence-continuity.md)**

**Where continuity belongs.** The working group has not decided whether cross-domain continuity is
a Portability requirement, a **fifth evidence property** alongside binary, contemporaneous,
tamper-evident and transparent, or a domain of its own
([open issue 3](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md),
raised by Bob Blessing-Hartley and separately by Advait Patel). The structural question is
unresolved and blocks the requirements.

**Tier composition.** If domain A is Tier 3 and domain B is Tier 1, what tier is the joined
evidence? Presumably the minimum, but that deserves an argument, and an anchored handoff might
preserve more than the weaker side alone.

**Disclosure continuity.** Evidence is not disclosure-neutral when it travels between
jurisdictions. This appears to be genuinely unexplored.

## Why this domain matters

Multi-cloud and multi-vendor agent execution is where enterprises actually are, not where they
are heading. An evidence standard that works within one trust domain and breaks at the boundary
describes a deployment pattern that is already unusual.

There is also a structural argument for taking it seriously: the seam is the natural place to
attack. Both sides can pass every check they define while the transition passes none, because
nobody owns the transition.

## Papers

* **[P07 — Evidence Continuity Across Trust Domains](../papers/P07-evidence-continuity.md)** ·
  Medium-high impact, medium effort. Would likely expand this domain substantially.

## Where to start a deep-research pass

in-toto layouts spanning organizations, then the RATS composite-device model
([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) §3.3) for the vocabulary of an attester made
of sub-attesters. Then — and this is the most instructive material — **the cross-chain bridge
failure literature**. Bridges are where value gets stolen in practice, for reasons structurally
identical to this seam, and the postmortems are unusually detailed.
