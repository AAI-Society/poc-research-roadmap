# C4 — Authorization

**12 requirements** · *Authority granted, decisions within or against it, delegation validity* ·
[Chapter](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x10-C04-Authorization.md)

## State of the domain

The best-developed domain, and the one whose central claim is weaker than it appears. C4 covers
the grant, per-action evaluation against it, blocking at the interception point, tool-parameter
schema validation, per-task credentials, human approval records, path-aware evaluation, and
delegation.

Two requirements were added during security review and are the most interesting in the chapter:
**C4.1.7** (authorization must be path-aware — a composed sequence of individually permitted
actions can be refused) and **C4.1.8** (outputs of diagnostic and advisory tools cannot raise
trust state).

## What is settled

* Grants are explicit, scoped, and time-bounded.
* Every action is evaluated and the decision is evidenced with the policy bundle hash, so a
  verdict can be re-derived rather than taken on trust.
* Path composition is a real escalation vector, demonstrated as attack A6, and path-aware
  evaluation blocks it.
* The utility cost of path-awareness is measured: 42% false rejections without a declassification
  point, and unverified declassification trades 1.6 points of detection for every point of relief.

## What is open

**Effect binding.** Theorem 1 binds the bytes of a request, not the effect an endpoint performs.
No snapshot-to-effect relation is defined anywhere in the specification, and real endpoints have
defaults, redirects, retries, aliases, and server-side state that break the correspondence. This
is the standard's central theorem and everything above Tier 2 inherits the gap.
→ **[P02](../papers/P02-effect-binding.md)**

**Soundness of the bounded path summary.** C4.1.7 requires a bounded summary so cost does not grow
with path length. Bounded means lossy, and lossy against an adversary who knows the bound means
evictable. The reference implementation truncates a label set to 8 in iteration order — and never
reads it, which means the paper's reported null result on the bound is uninformative rather than
reassuring. → **[P04](../papers/P04-bounded-summaries.md)**

**Delegation attenuation.** C4.2.3 requires that delegation "structurally prevents" a delegate
exceeding its delegator. No construction is named, and the composition case — two attenuated
delegates achieving what neither could alone — is not addressed at all.
→ **[P06](../papers/P06-delegation-attenuation.md)**

## Why this domain matters

Authorization is where the standard stops describing and starts refusing. Everything else
produces evidence; C4 produces denials. It is therefore the domain where a wrong answer has an
immediate operational cost — a false rejection is a blocked business process — and where the
adversary's incentive is highest.

It is also the domain with the most transferable results. Path-aware authorization, effect
binding, and delegation attenuation are problems for every agent platform being built right now,
whether or not they adopt this standard.

## Papers

* **[P02 — From Message Authorization to Effect Binding](../papers/P02-effect-binding.md)** ·
  Very high impact. Corrective.
* **[P04 — Are Bounded Path Summaries Soundly Bounded?](../papers/P04-bounded-summaries.md)** ·
  High impact, small effort. Corrective.
* **[P06 — Delegation Without Amplification](../papers/P06-delegation-attenuation.md)** ·
  High impact. Shared with C5.

## Where to start a deep-research pass

For P02: Saltzer and Schroeder on complete mediation, then macaroons, then the confused-deputy
and request-smuggling literature — the last is the same failure in a different domain and is
where the concrete attacks live. For P04: abstract interpretation and widening, then adversarially
robust streaming. For P06: macaroons, SPKI/SDSI reduction rules, and object-capability
composition.
