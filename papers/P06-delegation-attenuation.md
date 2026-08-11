# P06 — Delegation Without Amplification

**Domain:** C4 Authorization / C5 Identity · **Kind:** Generative, Foundational ·
**Impact:** High · **Effort:** Medium

---

## The question

When an agent delegates to a sub-agent, what mechanism guarantees the delegate's authority is a
strict subset of the delegator's — and that a chain of delegations cannot reassemble authority
nobody held?

## Why it matters

**For the standard.** This is [open issue 1](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md):
whether identity-binding belongs to Identity (C5) or Authorization (C4). The working group leans
toward Authorization owning it with Identity as an input, but the deeper question is untouched.

C4.2.3 requires that "the delegation mechanism structurally prevents a delegate's authority from
exceeding the delegator's." *Structurally* is doing a great deal of work in that sentence, and the
standard does not say by what construction. Sub-agent delegation is one of the eight interception
points, so this is not a corner case — it is a primary flow.

The composition risk is specific and nasty: two delegates each holding a legitimate subset may
combine to achieve an effect neither could alone, and the path-aware monitor sees two separate
paths. Our own C4.1.7 work shows path composition is where authority escalates; delegation
multiplies paths.

**For the field.** Multi-agent systems are being deployed now with delegation implemented as
"pass the credential down." That is authority amplification by construction. The cryptographic
answers exist and are not being used, largely because nobody has written down what the property
should be for this setting.

## What is already known

* **Macaroons** — Birgisson et al. (NDSS 2014). Caveats attenuate monotonically; the canonical
  answer and directly applicable.
* **Biscuit tokens** — Datalog-based attenuation, a modern engineering realization.
* **SPKI/SDSI** — Ellison et al.; authorization certificates and delegation chains, with the
  5-tuple reduction rules that formalize chain composition.
* **Capability attenuation** — the object-capability literature (Miller's *Robust Composition*),
  and the confused-deputy problem as the failure mode.
* **Proof-carrying authorization** — Appel and Felten; Bauer's work on PCA for access control.
* **OAuth token exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) and its downscoping
  semantics — the deployed-but-weak baseline worth comparing against.
* **ZCAP / UCAN** — capability delegation in the decentralized-identity world, closest to the DID
  model the standard recommends.

## What is genuinely open

1. **Attenuation under path-aware policy.** Macaroon caveats attenuate a *static* permission set.
   Our authority is a function of accumulated path state. What does attenuation mean when the
   grant depends on history — does the delegate inherit the delegator's path, start fresh, or
   something between? **Each choice is exploitable in a different way**, and this is the core
   research question.
2. **Cross-delegate composition.** Two delegates, individually attenuated, combining. Detecting
   this requires reasoning across paths, which the bounded per-agent summary cannot do.
3. **Evidence for a delegation chain.** How does a verifier check, from the evidence alone, that
   an action taken by a depth-3 sub-agent was within the original principal's grant? Chain of
   tokens, aggregate signature, or recursive proof — each with different verifier cost.
4. **Revocation.** Revoking mid-task authority through a delegation tree, with bounded
   propagation delay — the same exposure-window shape as anchoring and attestation refresh.
5. **Termination.** Can delegation depth be unbounded? What stops an agent delegating to itself
   in a loop to launder path state?

## Method

1. Formalize agent delegation with path-dependent authority; define non-amplification precisely,
   including the cross-delegate composition case.
2. Construct the attack: two attenuated delegates achieving an effect neither could alone.
   Demonstrate it against a macaroon-style baseline to show the classical mechanism is
   insufficient here.
3. Design and implement attenuation that composes with path-aware policy. Extend the reference
   implementation, which already models sub-agent delegation as an interception point.
4. Measure: verifier cost against delegation depth, evidence size, revocation propagation.
5. Prove non-amplification for the construction, and mechanize.

## What would settle it

A demonstrated composition attack against the natural baseline, plus a construction that provably
prevents it with measured cost. The attack is the part that will change what people build.

## Consequence for the standard

* **C4.2.3** gains a named construction instead of the word "structurally."
* **C5** gains delegation-chain identity semantics, closing open issue 1 with a technical answer
  rather than an ownership decision.
* New requirements likely: delegation depth bound; cross-delegate composition check; revocation
  propagation interval declared in the conformance claim.

## Venue

CSF, ESORICS, or CCS. Strong candidate for a workshop paper first on the composition attack alone.

## Effort and dependencies

Medium. Benefits from [P04](P04-bounded-summaries.md), since cross-delegate composition and
bounded-summary soundness are the same difficulty seen from two directions.
