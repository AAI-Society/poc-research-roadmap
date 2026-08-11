# C6 — Security

**12 requirements** · *Execution-environment integrity; controls held; tools invoked; key
lifecycle* ·
[Chapter](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md)

## State of the domain

The domain that leans hardest on hardware, and therefore the domain where the standard's trust
story is most exposed.

C6 covers control enumeration, runtime environment attestation, hardware-rooted attestation of
the execution substrate, sandboxing of generated code and untrusted tools, and evidence key
lifecycle. It is where the specification cashes its claim that evidence is operator-independent —
and where deploying on real hardware showed that claim needs qualification.

## What is settled

* Controls are enumerated in the conformance claim and mapped to the evidence that shows they held.
* Attestation reports the measured environment, and — since C7.2.4 — binds the evidence signing
  key into the measurement. This is now demonstrated on real Intel TDX rather than asserted.
* Signing keys are held by the generating mechanism, inaccessible to operator identities.
* Signature algorithms are identified per record with a declared migration path, and post-quantum
  or hybrid signing is required where retention outlives the scheme.

## What is open

**What attestation actually establishes.** Deploying on TDX forced the list of parties a verifier
must still trust: Intel, Intel's certification service, the quoting enclave, the cloud operator,
and whoever publishes reference values. The standard says Tier 3 means "nobody left to trust."
It does not. → **[P01](../papers/P01-trust-calculus.md)**

**Attestation freshness.** A hardware quote costs 39.5 ms — 2.6× the entire per-action budget —
so every deployment amortizes, and amortization means actions rest on measurements taken before
them. Requirement C7.2.3 now demands the interval be declared; the theory for choosing it does not
exist. → **[P03](../papers/P03-attestation-freshness.md)**

**Runtime rather than load-time measurement.** MRTD attests the *initial* TD contents. What
attests that the environment has not changed since? Continuous measurement is the open question
inside P03 and the most valuable technical piece of it.

**Key lifecycle across attestation refresh.** If the environment is re-measured, is it the same
key? Rotation, sealing, and continuity of evidence across a refresh are unaddressed.

## Why this domain matters

Every tier above 2 depends on C6. If hardware attestation establishes less than claimed, the tier
ladder compresses and a large part of the standard's value proposition compresses with it. That
is not a reason to avoid the question — it is the reason [P01](../papers/P01-trust-calculus.md) is
ranked first.

## Papers

* **[P01 — A Trust Calculus for Attestation Tiers](../papers/P01-trust-calculus.md)** · Very high
  impact. Corrective and foundational.
* **[P03 — The Cost of Knowing What Ran](../papers/P03-attestation-freshness.md)** · High impact,
  small effort. **Best effort-to-result ratio in the roadmap** — the apparatus already exists.

## Where to start a deep-research pass

For P01: RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)) roles, then the authorization
logics — Abadi–Burrows–Lampson–Plotkin, and Nexus authorization logic, which is the closest prior
art. For P03: RFC 9334 §10 on freshness, then IMA and DRTM for continuous measurement, then the
certificate-revocation literature, which is the same "statement made once, relied on later"
problem in a mature domain.
