# How These Were Prioritized

One person's assessment, written down so it can be argued with rather than absorbed.

## The criteria

Four things, in this order.

**1. Does the standard currently say something untrue without it?** A specification that
overclaims is worse than one with a gap, because readers act on it. Two papers exist because the
standard makes claims we have shown to be wrong — [P01](papers/P01-trust-calculus.md) (Tier 3
does not eliminate trust) and [P04](papers/P04-bounded-summaries.md) (a reported null result whose
cause is that nothing reads the structure under test) — and one because a central theorem proves
less than the prose around it — [P02](papers/P02-effect-binding.md). These outrank everything.

**2. Does other work depend on it?** [P01](papers/P01-trust-calculus.md) gives a vocabulary that
[P03](papers/P03-attestation-freshness.md), [P07](papers/P07-evidence-continuity.md) and
[P09](papers/P09-zk-evidence.md) all need. [P08](papers/P08-log-concurrency.md) determines what
ordering [P06](papers/P06-delegation-attenuation.md) can afford. Foundational work compounds.

**3. Would it change what people build?** Not just what they cite. [P02](papers/P02-effect-binding.md)'s
API survey would immediately affect anyone shipping agent authorization. [P05](papers/P05-unlinkable-identity.md)
opens a design space that is currently closed by default.

**4. Can it be done?** [P03](papers/P03-attestation-freshness.md) and [P04](papers/P04-bounded-summaries.md)
reuse apparatus that already exists and could be finished in weeks.
[P05](papers/P05-unlinkable-identity.md) and [P09](papers/P09-zk-evidence.md) need real
cryptographic work.

## The resulting order

| Tier | Papers | Rationale |
| --- | --- | --- |
| **Do first** | P01, P02 | Corrective and foundational. The standard is wrong without them. |
| **Do cheaply, soon** | P03, P04, P08 | Small effort, existing apparatus, and P04 corrects a published claim. |
| **The real research** | P05, P06, P07 | Genuine open design space; where the interesting results are. |
| **Longer horizon** | P09, P10 | Large effort or dependent on the foundational work. |
| **Institutional** | P11, P12 | Not technical, and possibly more determinative of adoption than any of the above. |

## Where this is most likely wrong

Four places I would push back on if someone else had written this.

**P11 and P12 may be underrated.** They are placed last because they are not technical, but the
history of assurance standards suggests adoption is decided by institutions and incentives, not by
proofs. Certificate Transparency succeeded because browsers mandated it, not because the Merkle
tree was elegant. If that pattern holds, [P11](papers/P11-verification-economics.md) is the most
important paper here and it is ranked tenth.

**P05 may be overrated for impact-per-effort.** Identity unlinkability is intellectually the most
interesting problem in the set and it is a large cryptographic undertaking with a real chance of a
negative result. The measurement half — *what anonymous credentials cost at agent action rates* —
is small, decisive, and should be done first regardless of whether the full paper proceeds.

**P04 may be too small to be a paper.** It might be a section of a stronger paper on bounded
runtime monitors, or simply a correction to the existing one. It is ranked fourth on importance,
not on publishability, and those come apart here.

**The corrective bias.** Three of the top four are fixes to our own errors. That is defensible —
they were found by review and measurement, so they are the best-evidenced items — but it means
the roadmap is shaped by what we happened to get wrong rather than by what the field most needs.
Somebody without our history would likely rank [P05](papers/P05-unlinkable-identity.md) and
[P06](papers/P06-delegation-attenuation.md) higher and the corrections lower, on the grounds that
a specification's errors matter to its authors more than to anyone else.

## What is deliberately not here

* **Better agent benchmarks.** Real and needed, but a different research programme.
* **Model-level safety.** Explicitly outside the standard's determinism boundary — this standard
  verifies execution facts, not output quality, and the roadmap should not blur that.
* **Hardware attacks on TEEs.** An active field with its own community; we consume its results
  rather than contributing to them.
* **A formal verification of the whole standard.** Appealing and probably premature while the tier
  definitions are still wrong.

## A note on sequencing

The dependencies that actually bind:

```
P01 (trust calculus) ─┬─> P03 (attestation freshness)
                      ├─> P07 (evidence continuity)
                      └─> P09 (ZK evidence)

P08 (log concurrency) ──> P06 (delegation)

P04 (bounded summaries) ──> P06 (delegation)
```

Everything else is parallel. If two tracks were run at once, the natural split is **P01 → P02**
on one and **P03 → P04 → P08** on the other, since the second is mostly measurement on apparatus
that already exists.
