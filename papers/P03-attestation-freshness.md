# P03 — The Cost of Knowing What Ran

**Domain:** C7 Evidence · **Kind:** Empirical, Corrective · **Impact:** High · **Effort:** Small

---

## The question

Hardware attestation is expensive enough that no deployment can afford it per action. What is the
right refresh policy, and what exactly is exposed in the window between quotes?

## Why it matters

**For the standard.** We measured this and it was the surprise of the TDX deployment:

| | Measured (Intel TDX, GCP c3-standard-4) |
| --- | ---: |
| Trust-domain overhead on the pipeline | 9.45 µs (+6.2%) |
| One hardware quote | **39.5 ms** |

A quote costs 4,180× the per-step overhead and **2.6× the entire 15 ms per-action budget on its
own**. Per-action attestation is not expensive, it is impossible. Every deployment amortizes —
and amortization means actions rest on a measurement taken before them. If the measured code
changed in between, their evidence attests an environment that is no longer the one that ran, and
nothing in the record says so.

That became requirement C7.2.3 (declare a maximum attestation refresh interval). The requirement
exists; the *theory* behind choosing the interval does not. It is currently in the same position
the anchoring interval Δ was before we measured it: real, load-bearing, and set by guesswork.

**For the field.** Everyone building on confidential computing hits this and mostly does not
publish it. The measurement is useful on its own; the policy question — how to detect that a
measured environment changed mid-session, and how to bound the damage — is unanswered and applies
to every attested service, not only agents.

## What is already known

* **Attestation freshness** — the RATS architecture ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334))
  discusses nonce-based and epoch-based freshness; RFC 9334 §10 is the direct antecedent.
* **TCG / TPM attestation** and the long-standing TOCTOU critique of load-time measurement.
* **Runtime integrity measurement** — IMA, Linux integrity subsystem; DRTM. These attempt
  continuous rather than point-in-time measurement and are the natural comparison.
* **CT gossip and detection latency** — the pattern of converting an undetectable window into a
  bounded one, already used for the anchoring interval in this standard.
* **Certificate revocation** — OCSP, CRLs, short-lived certificates. This is *the same problem*
  in a mature domain: a statement made once, relied on later, and how long it stays good.
  Short-lived certificates are the direct analogue of frequent re-attestation, and the operational
  lessons transfer.

## What is genuinely open

1. **A model of the staleness window.** Exposure = (actions per interval) × (probability the
   environment changed) × (damage per unattested action). Only the first factor is measured.
2. **Cheap continuous attestation.** Can RTMR extension, a sealed monotonic counter, or a
   TEE-held heartbeat give continuous evidence that the environment has not changed, at a cost
   far below a full quote? This is the highest-value technical question.
3. **Adaptive refresh.** Should the interval depend on action sensitivity — quote before an
   irreversible action, amortize across reads? The standard already reasons this way about Δ.
4. **Detection rather than prevention.** If the environment changes mid-session, can a verifier
   learn it *after the fact* from the evidence alone? That converts a prevention problem into a
   detection problem, which is the move that worked for equivocation.
5. **Cross-platform comparison.** Is 39.5 ms typical? SEV-SNP, ARM CCA, AWS Nitro, and Confidential
   Space all differ, and the number determines every deployment's design.

## Method

1. **Measure across platforms.** TDX (done), SEV-SNP, ARM CCA if available, Nitro. Same pipeline,
   same control methodology (identical non-confidential instance) already built.
2. **Decompose the 39.5 ms.** How much is the quoting enclave, the TDX module call, collateral
   fetching, the host round trip? Determines what could be optimized.
3. **Measure verification cost** at the relying party, including DCAP collateral fetch and
   caching — currently unmeasured and a separate deployment constraint.
4. **Build and evaluate a lightweight freshness beacon**: RTMR extension or sealed counter,
   measure its cost, and analyze what it does and does not attest compared to a full quote.
5. **Formalize the exposure window** and produce the same style of guidance the anchoring
   interval got: decide how many actions you could tolerate resting on a stale measurement,
   divide by your action rate.

## What would settle it

A cross-platform table of attestation costs, a decomposition showing where the time goes, and a
demonstrated cheap freshness mechanism with a stated security difference from a full quote. If no
cheap mechanism exists, the finding is that attestation-based evidence has an irreducible
staleness window, and the standard should require it be published rather than minimized.

## Consequence for the standard

* **C7.2.3** gains guidance for choosing the interval instead of only requiring one.
* Possible new requirement: continuous or beacon-based freshness at Tier 4.
* **C8** — tier placement may depend on refresh interval, since a stale measurement weakens the
  claim a tier is meant to encode.

## Venue

A measurement or systems venue: ATC, EuroSys, or a confidential-computing workshop (SysTEX,
CCSW). This is the most publishable-quickly paper in the roadmap.

## Effort and dependencies

Small. The apparatus exists — `impl/tdx/run_on_gcp.sh` already deploys, measures, and tears down.
Mostly a matter of running it on more platforms and decomposing the number. **Best
effort-to-result ratio in this roadmap.**
