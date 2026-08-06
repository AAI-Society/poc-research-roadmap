# P09 — Evidence That Reveals Nothing

**Domain:** C2 Privacy · **Kind:** Generative · **Impact:** Medium · **Effort:** Large

---

## The question

Can an agent prove its actions satisfied a policy without revealing the actions, the policy, or
the data touched — at a cost that fits an action budget rather than a batch job?

## Why it matters

**For the standard.** C2.3 specifies privacy-preserving evidence options. The reference
implementation does not include them, and the paper says so plainly: *"we did not implement the
privacy-preserving evidence options at all."* A specified-but-unbuilt path is the weakest kind
of requirement — it may be infeasible and nobody would know.

The tension is structural. The standard's evidence design deliberately commits to digests rather
than content precisely so the evidence store does not become a second copy of the customer
database. That is good hygiene but it is not privacy: a digest still reveals *that* an action
occurred, its target resource, its timing, and its position in an ordered chain. For an agent
operating on health records, the metadata alone is disclosive.

**For the field.** ZK proofs of policy compliance are an active area with real momentum and very
little empirical grounding at *runtime* rates. Most work proves properties of computations
offline. Nobody has established whether a per-action compliance proof is affordable, and the
answer determines whether an entire branch of the design space exists.

## What is already known

* **zkSNARKs / zkSTARKs** — Groth16, PLONK, Halo2, STARKs. Proving costs have fallen by orders
  of magnitude; verification is cheap and roughly constant, which is the right shape here.
* **zkVMs** — RISC Zero, SP1, Jolt. Prove execution of arbitrary programs, which is exactly the
  "prove the policy engine ran and returned ALLOW" shape.
* **Policy compliance proofs** — zero-knowledge middleboxes (Grubbs et al.), zk proofs for
  regulatory compliance, and privacy-preserving audit literature.
* **The setup problem** — trusted setup ceremonies and their critiques. Directly relevant: the
  paper already warns that a setup run by one party reintroduces the trusted party the scheme
  exists to remove.
* **Recursive proofs / proof aggregation** — Nova, folding schemes. The natural answer to
  per-action cost is aggregating many actions into one proof, and folding is the current best
  technique.
* **Differential privacy** for the metadata-leakage half, which ZK does not address at all.

## What is genuinely open

1. **Cost at action rates.** Our budget is 15 ms per action and the measured pipeline is ~162 µs.
   Proving costs are typically 10²–10⁴ ms. **The gap is several orders of magnitude**, and
   quantifying it precisely is the first and most useful contribution — it may simply close the
   question.
2. **What to prove.** Proving the whole policy engine ran is expensive and probably wrong. Proving
   a narrow statement — *"the action's classification was within the grant"* — may be cheap. The
   right decomposition is open.
3. **Amortization.** Prove a *session* rather than an action, in the same shape as batch signing
   and attestation refresh. Introduces the same staleness exposure and the same need to declare an
   interval.
4. **Composition with attestation.** If a TEE already attests the policy engine ran, what does ZK
   add? Plausibly: it removes the hardware vendor from the trust set — which is precisely the
   Tier-3 problem [P01](P01-trust-calculus.md) formalizes. **That framing makes this paper much
   more interesting than "add privacy."**
5. **Metadata.** ZK hides the statement, not the fact that a proof was produced at a time about a
   resource. The chain structure itself leaks. This may be the harder half.

## Method

1. **Measure the gap first.** Implement the narrowest useful statement in a zkVM, measure proving
   and verification cost against the 15 ms budget. This is a week of work and may settle the
   feasibility question outright.
2. Explore decompositions: full engine, policy predicate only, and a hybrid where a TEE attests
   the engine and ZK covers only the sensitive predicate.
3. Evaluate session-level amortization and folding.
4. Analyze what the trust set becomes under each design, using P01's calculus — *this* is the
   contribution, not the privacy per se.
5. Address metadata leakage: what the chain reveals even with perfect proofs.

## What would settle it

A cost table across decompositions with a clear verdict on which, if any, fit an action budget.
**A negative result is valuable and likely**: if per-action ZK is infeasible by orders of
magnitude, the standard should say so and reposition C2.3 as a session- or audit-time mechanism
rather than a runtime one.

## Consequence for the standard

* **C2.3** either gains a concrete mechanism with measured cost or is repositioned honestly.
* **C8** — if ZK removes the hardware vendor from the trust set, it may define a tier that
  attestation cannot reach, which would be a significant structural finding.
* **C7.4** trust disclosure gains a ZK-specific obligation: name the setup and who ran it.

## Venue

CCS/S&P for the construction; a measurement workshop for the feasibility study, which should
ship first regardless.

## Effort and dependencies

Large overall, but **step 1 is small and decisive** — do it before committing. Depends on
[P01](P01-trust-calculus.md) for the trust-set framing that makes it compelling.
