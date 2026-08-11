# Cross-Cutting — C7 Evidence, C8 Tiers, C9 System Surface, C10 Conformance

**66 requirements across four chapters** — over half the standard.

| Chapter | Reqs | What it covers |
| --- | :--: | --- |
| [C7 Evidence Generation & Properties](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md) | 28 | Interception, the evidence properties, custody, interoperability |
| [C8 Verifiability Tiers](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | 15 | Tier placement, the binary threshold, self-enforcing execution |
| [C9 System Surface (MAESTRO)](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C09-System-Surface-MAESTRO.md) | 6 | Locating evidence on the 7-layer agent stack |
| [C10 Conformance & Disclosure](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md) | 17 | Stages, scope declaration, trust-assumption disclosure |

## C7 — Evidence: the deepest chapter

The most developed part of the standard, and the one that has changed most under review. Recent
additions came from building rather than writing: complete mediation of the effect channel
(C7.1.4), non-equivocation (C7.3.3), inclusion and consistency proofs (C7.3.4/7.3.5), the
Interoperable Property (C7.7), and attestation freshness and key binding (C7.2.3/7.2.4).

**Open:** log granularity is unspecified — a serial chain caps fleet throughput while per-agent
logs lose cross-agent ordering, and the standard says nothing about which to build.
→ **[P08](../papers/P08-log-concurrency.md)**

## C8 — Tiers: the weakest link

Fifteen requirements resting on a taxonomy that is wrong as written. The standard says Tier 3
means "nobody left to trust"; the TDX deployment produced a five-party list that anchoring does
not shorten. The chapter conflates **public verifiability** with **trust independence**, and the
binary threshold — the organizing idea of the whole standard — sits exactly on that confusion.
→ **[P01](../papers/P01-trust-calculus.md)**

This is why P01 is first. Every conformance claim above the threshold currently promises more
than it delivers, and no amount of work in the other domains fixes that.

## C9 — System surface: adopted, not researched

Six requirements locating evidence on CSA's MAESTRO 7-layer stack. This chapter deliberately
adopts an external framework as an axis rather than proposing one, and there is no open research
question here. It is included for completeness.

## C10 — Conformance: inherited weaknesses

Seventeen requirements defining three stages and what a claim must contain. The design is
inherited from SOC 2, ISO certification and FedRAMP — regimes with documented pathologies the
standard has not systematically absorbed. Cryptographic evidence prevents log forgery. It does
nothing about **scope gaming**, and a cryptographically perfect claim over a narrow scope may
mislead more effectively than a weak claim over a broad one.
→ **[P12](../papers/P12-conformance-credibility.md)**

The economic precondition is also unstated: every property above Tier 2 requires somebody
independent to actually run the check, and the standard does not ask who that is or why they
would. → **[P11](../papers/P11-verification-economics.md)**

## Papers

* **[P01 — A Trust Calculus for Attestation Tiers](../papers/P01-trust-calculus.md)** · C8 ·
  Very high impact
* **[P03 — The Cost of Knowing What Ran](../papers/P03-attestation-freshness.md)** · C7 · High
  impact, small effort
* **[P08 — What a Serial Log Costs a Fleet](../papers/P08-log-concurrency.md)** · C7 ·
  Medium-high impact, small effort
* **[P11 — Who Pays for Verification](../papers/P11-verification-economics.md)** · C10 · Medium
  impact — **possibly underrated**, see [PRIORITIZATION](../PRIORITIZATION.md)
* **[P12 — Why Assurance Regimes Fail](../papers/P12-conformance-credibility.md)** · C10 · Medium
  impact
