# P11 — Who Pays for Verification

**Domain:** Cross-cutting · **Kind:** Generative · **Impact:** Medium · **Effort:** Medium

---

## The question

The standard makes evidence checkable by anyone. Who actually checks, what does it cost them, and
what makes an independent verification market exist rather than remain theoretically possible?

## Why it matters

**For the standard.** The paper's opening argument, following Catalini, Hui and Wu, is that the
cost of *doing* falls toward zero while the cost of *verifying* stays pinned to human attention —
so verification becomes the scarce resource. The standard then produces machine-checkable
evidence and, in effect, assumes verifiers will appear.

They may not. Every requirement above Tier 2 depends on someone independent actually running the
check. Anchoring is worthless if nobody compares anchors. Gossip requires at least two verifiers
who talk. Equivocation detection has no value if every verifier is paid by the operator. The
standard's security properties have an *economic* precondition it never states.

**For the field.** This generalizes: Certificate Transparency works because browsers enforce it,
and browsers exist and have leverage. Audit markets exist because regulation requires them.
Bug-bounty markets work because the payoff is concrete. Which of these shapes fits AI agent
verification is genuinely unclear, and the answer determines whether any of this gets adopted.

## What is already known

* **Catalini, Hui, Wu (2026)** on verification cost as the binding constraint — already cited by
  the paper and the natural foundation.
* **Certificate Transparency's political economy** — how CT actually got adopted (browser
  mandate, not voluntary uptake) is the most instructive case study available.
* **Audit market failures** — the accounting literature on auditor independence, Enron/Arthur
  Andersen, and the structural conflict where the audited party pays. SOC 2's known weaknesses
  are directly relevant since the standard positions itself as SOC-2-grade in role.
* **Security economics** — Anderson's *Why Information Security is Hard*; Akerlof's market for
  lemons, which is arguably the exact failure the standard is trying to prevent.
* **Bug bounties and crowdsourced verification** — what makes distributed checking work.
* **Cyber-insurance** — the literature on insurance as a mechanism for pricing security, and the
  standard explicitly names insurers as an intended consumer.

## What is genuinely open

1. **Cost of verification, measured.** The paper measures verification at ~193 µs per record and
   inclusion proofs at 7 µs. Extrapolate: what does continuous verification of a 1,000-agent fleet
   actually cost per year, in compute and in human attention on the exceptions? Nobody has priced
   this and it is straightforward to do.
2. **Who has the incentive.** Insurers pricing risk, regulators sampling, enterprises checking
   vendors, competitors checking each other, or a public-good verifier. Each yields a different
   ecosystem, and some yield none.
3. **The independence problem.** If the operator pays the verifier, is the evidence still
   operator-independent? This is the same structural failure as paid audit, and the standard's
   Tier framing does not currently notice it — a verifier's *independence* is as load-bearing as
   the cryptography.
4. **Minimum viable verifier count.** Equivocation detection needs ≥2 non-colluding verifiers.
   What is the equilibrium number, and does it arise without mandate?
5. **What triggers adoption.** Regulation, procurement, insurance discount, or incident. CT
   suggests mandate by a powerful intermediary; there is no equivalent intermediary here yet.

## Method

1. Cost model from the existing measurements: full replay, sampled inclusion proofs, and
   continuous monitoring, priced at cloud rates for realistic fleets.
2. Model the incentives of each candidate verifier and identify which are self-sustaining.
3. Case-study comparison: CT, SOC 2, FedRAMP, financial audit, cyber-insurance — what made
   verification happen or fail in each.
4. Analyze the independence problem formally, and propose funding structures that preserve it.
5. Propose an adoption path with the mechanism that triggers it named.

## What would settle it

A cost model grounded in measured numbers, plus a defensible argument about which verifier class
is viable. **A negative finding is plausible and important**: if no party has sufficient incentive
absent mandate, the standard should be explicit that its higher tiers require a regulatory or
procurement trigger, rather than implying they are self-executing.

## Consequence for the standard

* **C10 Conformance** gains verifier-independence requirements — who may verify, and how
  independence is established and disclosed.
* **C8** — tier definitions may need an economic precondition stated alongside the technical one.
* The roadmap in the paper's Appendix B likely needs an adoption-mechanism step it currently lacks.

## Venue

WEIS (Workshop on the Economics of Information Security) is the natural home. Also fits a policy
venue, and would strengthen the standard's regulatory engagement more than a technical paper
would.

## Effort and dependencies

Medium; heavily literature- and modelling-based, so a good candidate for a deep-research pass to
carry most of the load.
