# P12 — Why Assurance Regimes Fail

**Domain:** C10 Conformance · **Kind:** Empirical · **Impact:** Medium · **Effort:** Medium

---

## The question

Existing assurance regimes — SOC 2, ISO certification, FedRAMP, CE marking — routinely certify
systems that then fail. What are their failure modes, and which of them does this standard
reproduce?

## Why it matters

**For the standard.** C10 defines three conformance stages (Self-Declared, Third-Party Assessed,
Continuously Monitored) and 17 requirements for what a claim must contain. That design is
inherited from regimes with known and well-documented pathologies: scope gaming, point-in-time
snapshots that say nothing about the period, auditor shopping, and the structural conflict of the
audited party choosing and paying the assessor.

The standard's answer is that cryptographic evidence resists these because it is
mechanism-generated. That is partly true and worth testing rather than asserting. **Scope is
still declared by the operator** — C10.1.6 requires a boundary declaration, and an operator who
scopes their agent fleet narrowly produces perfectly valid evidence about an uninteresting
subset. Cryptography does not fix scope gaming; it may make it easier to hide behind a strong
technical claim.

The coverage mapping already found that 40–70% of what this standard requires is absent from
existing frameworks. The inverse question is unasked: **what do those frameworks know about
assurance failure that this standard has not absorbed?**

**For the field.** AI assurance regimes are being designed right now — the EU AI Act's conformity
assessment, NIST's work, sectoral schemes. Most are repeating structures whose failure modes are
documented in other industries. A clear cross-domain analysis would be timely and useful well
beyond this standard.

## What is already known

* **Audit failure literature** — accounting research on auditor independence, opinion shopping,
  and expectation gaps; Enron/Andersen, Wirecard.
* **SOC 2 critiques** — the practitioner literature on scope manipulation, the difference between
  Type I and Type II, and what a clean report does not mean.
* **FedRAMP** — authorization timelines, the reciprocity problem, and continuous-monitoring
  practice versus intent. The closest existing analogue to a "Continuously Monitored" stage.
* **Common Criteria** — the canonical example of an assurance regime with high cost and contested
  value; the EAL-level critique literature is directly instructive for a tier ladder.
* **CE marking and self-declaration** — what happens when self-declaration dominates, which
  matters because Self-Declared is this standard's entry stage.
* **Safety cases** — the assurance-case literature (GSN, Toulmin arguments), and confirmation bias
  in safety-case construction. A conformance claim *is* a safety case and could borrow the
  vocabulary.
* **Certification in ML** — the emerging critique of AI audit as currently practised (Raji et al.
  on algorithmic auditing, and the accountability-gap literature).

## What is genuinely open

1. **A failure taxonomy across regimes** — the same categories keep recurring but nobody has
   assembled them into a checklist a new standard can be tested against.
2. **Which failures cryptographic evidence actually prevents.** Log forgery: yes. Scope gaming:
   no. Point-in-time snapshot: partly, via continuous monitoring. **Assessor independence: not at
   all.** Working this out honestly is the core contribution.
3. **Whether strong technical evidence makes scope gaming worse.** A cryptographically perfect
   claim over a narrow scope may be *more* misleading than a weak claim over a broad one, because
   it reads as rigorous. This is a genuinely uncomfortable hypothesis and worth testing.
4. **What "Continuously Monitored" must mean** to avoid becoming FedRAMP-style continuous
   monitoring in name only.
5. **Detecting scope gaming from evidence.** C10.1.8 requires inventory reconciliation against
   automated discovery — the one control aimed at this. Is it sufficient?

## Method

1. Assemble the failure taxonomy from the literature across at least five regimes.
2. Map each failure mode against this standard's 17 conformance requirements: prevented,
   mitigated, or untouched. Publish the untouched list.
3. **Red-team the conformance regime**: construct a conforming claim that is technically perfect
   and substantively misleading. If this is easy, that is the paper's headline.
4. Propose amendments for the failure modes that survive.
5. Compare against the EU AI Act conformity-assessment design, since that is the regime this will
   have to interoperate with.

## What would settle it

A completed mapping with an honest untouched column, plus at least one demonstrated
technically-conforming-but-misleading claim. That artifact would do more for the standard's
credibility than another technical requirement.

## Consequence for the standard

* **C10 gains anti-gaming requirements**, particularly around scope declaration.
* Possible new requirement on **assessor independence** — currently absent and the most obvious
  inherited weakness.
* The Continuously Monitored stage likely needs sharper definition.

## Venue

A policy or governance venue — FAccT, AIES, or a law-and-technology journal. Would also make a
strong working-group document, which may matter more than publication.

## Effort and dependencies

Medium; mostly literature and analysis, well suited to a deep-research pass. Pairs naturally with
[P11](P11-verification-economics.md) — one covers the economics of verification, the other its
institutional form.
