# Proof-of-Control — Research Roadmap

A prioritized research agenda following from
[**Proof-of-Control: An Open Standard for Runtime Verifiability and Cryptographic Oversight in
Autonomous AI Execution**](https://github.com/AAI-Society/ov-poc-standard)
(working draft v0.1, August 2026).

The standard defines 127 requirements across six verification domains and four cross-cutting
chapters. Writing it, building the reference implementation, and putting the paper through
review surfaced a set of questions the specification currently answers by assertion, by
convention, or not at all. **This repository turns those into a research program.**

Each paper below is scoped so it can be handed to a deep-research pass and come back with
something worth building on: a specific question, the prior art it must engage, the experiment
that would settle it, and the change it would make to the standard if the answer came out either
way.

> **Looking for what to deploy rather than what to research?**
> [**TOOLING.md**](TOOLING.md) is the companion roadmap. It maps every required field of
> the Proof-of-Control evidence record to the tool that produces it, the tool that checks
> it, and the paper that blocks it — and reports that no tool in this programme emits a
> record at all yet.

---

## The short version

If you only do three, do these.

| # | Paper | Domain | Why first |
| :--: | --- | --- | --- |
| **[P01](papers/P01-trust-calculus.md)** | A Trust Calculus for Attestation Tiers | Cross-cutting (C8) | The standard's central taxonomy is provably wrong as written. We found this with a hardware measurement, not an argument. |
| **[P02](papers/P02-effect-binding.md)** | From Message Authorization to Effect Binding | C4 / C7 | The paper's main theorem proves less than the paper claims. Everything downstream inherits the gap. |
| **[P05](papers/P05-unlinkable-identity.md)** | Accountable but Unlinkable Agent Identity | C5 Identity | The largest genuinely open design question in the standard, with mature cryptography waiting to be applied. |

P01 and P02 are *corrective* — the standard overclaims without them. P05 is *generative* — it
opens a design space rather than closing a hole.

---

## All papers, by priority

Impact scoring is explained in [PRIORITIZATION.md](PRIORITIZATION.md). Briefly: **Corrective**
means the standard currently says something untrue or unproven without it; **Foundational**
means other work depends on it; **Generative** means it opens design space; **Empirical** means
it measures something asserted but unmeasured.

| # | Paper | Domain | Kind | Impact | Effort |
| :--: | --- | --- | --- | :--: | :--: |
| [P01](papers/P01-trust-calculus.md) | A Trust Calculus for Attestation Tiers | C8 Tiers | Corrective · Foundational | **Very high** | Medium |
| [P02](papers/P02-effect-binding.md) | From Message Authorization to Effect Binding | C4 / C7 | Corrective · Foundational | **Very high** | Medium |
| [P03](papers/P03-attestation-freshness.md) | The Cost of Knowing What Ran | C7 Evidence | Empirical · Corrective | **High** | Small |
| [P04](papers/P04-bounded-summaries.md) | Are Bounded Path Summaries Soundly Bounded? | C4 Authorization | Corrective · Foundational | **High** | Small |
| [P05](papers/P05-unlinkable-identity.md) | Accountable but Unlinkable Agent Identity | C5 Identity | Generative | **High** | Large |
| [P06](papers/P06-delegation-attenuation.md) | Delegation Without Amplification | C4 / C5 | Generative · Foundational | **High** | Medium |
| [P07](papers/P07-evidence-continuity.md) | Evidence Continuity Across Trust Domains | C3 Portability | Generative | **Medium-high** | Medium |
| [P08](papers/P08-log-concurrency.md) | What a Serial Log Costs a Fleet | C7 Evidence | Empirical | **Medium-high** | Small |
| [P09](papers/P09-zk-evidence.md) | Evidence That Reveals Nothing | C2 Privacy | Generative | **Medium** | Large |
| [P10](papers/P10-agbom.md) | What Belongs in an Agent Bill of Materials | C1 Provenance | Generative | **Medium** | Medium |
| [P11](papers/P11-verification-economics.md) | Who Pays for Verification | Cross-cutting | Generative | **Medium** | Medium |
| [P12](papers/P12-conformance-credibility.md) | Why Assurance Regimes Fail | C10 Conformance | Empirical | **Medium** | Medium |

---

## By domain

The standard's six verification domains, and what each still needs. Full detail in
[`domains/`](domains).

| Domain | Reqs | State of the theory | Papers |
| --- | :--: | --- | --- |
| [C1 Provenance](domains/C1-provenance.md) | 13 | Solid mechanisms (signing, SBOM), weak on *runtime* composition | P10 |
| [C2 Privacy](domains/C2-privacy.md) | 13 | Specified a ZK path and never built it | P09 |
| [C3 Portability](domains/C3-portability.md) | 5 | Thinnest domain; the cross-boundary chain is genuinely unsolved | P07 |
| [C4 Authorization](domains/C4-authorization.md) | 12 | Best-developed, but the central theorem is weaker than claimed | P02, P04, P06 |
| [C5 Identity](domains/C5-identity.md) | 6 | Underspecified, and the open questions are the most interesting | P05, P06 |
| [C6 Security](domains/C6-security.md) | 12 | Leans hardest on hardware, which is where the trust story breaks | P01, P03 |
| [Cross-cutting](domains/cross-cutting.md) | 66 | C7 evidence is deepest; C8 tiers are the weakest link | P01, P03, P08, P11, P12 |

Two observations worth noting. **C3 Portability has five requirements** — it is the least
developed domain and the one where an evidence chain most obviously breaks, which is a poor
combination. And **C5 Identity has six requirements** but carries two of the three open issues
the working group flagged, meaning the specification is thin exactly where the design questions
are hardest.

---

## Where this comes from

Nothing here is invented. Each paper traces to one of:

* **Open working-group issues** — [Appendix D](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md)
  records 13, several contributed by working-group members.
* **Threat-model gaps** — [Appendix C](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x92-Appendix-C_Threat-Model.md)
  grades 32 threats; most are *Partial*.
* **Review findings** — three independent reviews of the paper returned weak reject with
  blocking objections; two are unaddressed and become P01 and P02.
* **Measurements that surprised us** — the TDX deployment showed a hardware quote costs 39.5 ms,
  which forced a new requirement and becomes P03.
* **Defects found by building** — three requirements exist because the implementation was wrong
  in a way the prose could not reveal.

The last category is the one worth dwelling on. Three of this standard's requirements exist
because writing the code forced a precision that reading the specification never did. That is a
methodological claim as much as an engineering one, and it shapes how these papers are scoped:
**every one of them has something to build, not only something to argue.**

---

## How to use this

Each paper file is written to be handed directly to a deep-research pass. The sections are:

1. **The question** — one sentence, falsifiable
2. **Why it matters** — impact on the standard and on the field, stated separately
3. **What is already known** — the literature to engage, with specific anchors
4. **What is genuinely open** — the part nobody has answered
5. **Method** — what to build and what to measure
6. **What would settle it** — the result that would change minds, in both directions
7. **Consequence for the standard** — which requirements change, and how
8. **Venue and effort**

Start a deep-research pass from sections 3 and 4. Section 5 is the part that needs a human.

---

## Status

**P01, P02 and P05 are done.** Each has a drafted paper and a shipped Rust tool —
`parallax`, `transit` and `occultation` — and [what building `parallax` established, and
what P01 must change](docs/parallax-outcomes.md) records the amendments the implementation
forced. Four further tools followed that this roadmap did not anticipate:
`parallax-proxy`, `parallax-attest`, `occultation-gateway`, and
[`poc-audit`](https://github.com/AAI-Society/poc-audit),
which reads an evidence record and reports what actually backs each claim.

The nine remaining papers are unwritten. Priorities reflect one assessment and should be
argued with — see [PRIORITIZATION.md](PRIORITIZATION.md) for the scoring, including where
it is most likely to be wrong.

Those seven shipped tools do not yet let anyone comply with the standard —
`poc-audit` establishes two rows out of twenty-two on the standard's own strongest
positive vector — and [TOOLING.md](TOOLING.md) is the roadmap for what would.

---

*Proof-of-Control is stewarded by the [Advanced AI Society](https://advancedaisociety.org/) —
**[join a working group at advancedaisociety.org](https://advancedaisociety.org/)**.*
