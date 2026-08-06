# P04 — Are Bounded Path Summaries Soundly Bounded?

**Domain:** C4 Authorization · **Kind:** Corrective, Foundational · **Impact:** High ·
**Effort:** Small

---

## The question

Path-aware authorization keeps a bounded summary of everything an agent has done, so evaluation
cost does not grow with path length. A bounded summary of an unbounded history is lossy. Can an
adversary exploit the loss?

## Why it matters

**For the standard.** C4.1.7 requires path-aware authorization over a bounded summary, and the
paper proves evaluation is O(|Π| + B) and measures it flat from 10 to 50,000 steps. Both are
true. Neither addresses soundness.

The reference implementation's summary keeps a label set truncated to a hard bound of 8:

```python
frozenset(list(labels)[:8])   # hard size bound B
```

Two problems, and the second is worse. **First**, which labels survive truncation depends on set
iteration order — arbitrary, not policy-determined. **Second**, and this is the real finding:
`labels` is never read by any policy decision. The engine consults only accumulated sensitivity
and cumulative spend.

That means the paper's reported null result — *"sweeping the bounded-summary label bound B from
1 to 16 made no difference on these workloads — a null result, reported as one"* — has a trivial
explanation the paper does not give. B cannot matter, because nothing consults the bounded
structure. The experiment tested nothing, and it is currently presented as evidence that the
bound is harmless.

**For the field.** Every runtime monitor over unbounded histories faces this: static analysis
abstractions, IFC label systems with widening, streaming anomaly detection, sliding-window rate
limiters. The general question — *when is a bounded abstraction of an unbounded history sound
against an adversary who knows the abstraction* — is well posed and, for this class of monitor,
unanswered. An attack construction plus a soundness condition would be broadly reusable.

## What is already known

* **Abstract interpretation** — Cousot and Cousot (1977). Widening operators are exactly bounded
  abstractions of unbounded structures, and soundness there means over-approximation: the
  abstraction never says "safe" when the concrete is unsafe. **That is the property to import.**
* **Information-flow control** — Denning's lattice; Sabelfeld and Myers; label creep in Jif,
  HiStar, Flume. Label creep is the *consequence* of monotone accumulation; truncation is the
  usual fix and its soundness is rarely analyzed.
* **Runtime verification** — monitorability of LTL properties, and which properties are
  monitorable with bounded state. Directly on point and underused in security.
* **Streaming algorithms** — count-min sketch, HyperLogLog, sliding-window. These have precise
  error bounds; adversarial rather than random inputs are the relevant regime, and there is an
  adversarially-robust streaming literature to draw on.
* **Cardinality-bound evasion** — the general pattern of flooding a bounded structure to evict an
  incriminating entry appears in cache attacks and IDS evasion; the analogy is close.

## What is genuinely open

1. **Is truncation sound?** Under abstract-interpretation soundness, dropping a label is
   under-approximation — the monitor may now permit what it should refuse. That is unsound by
   construction unless truncation is compensated by something conservative, such as raising a
   summary flag when the bound is exceeded.
2. **The eviction attack.** If labels were consulted, an adversary who knows B could touch B+1
   compartments to evict the incriminating one, then egress. **This attack should be constructed
   and demonstrated** — it is the concrete deliverable.
3. **Sound bounded designs.** Candidates: monotone lattice join (bounded height, no truncation);
   a "overflowed" flag that fails closed; Bloom-filter membership with one-sided error in the
   safe direction. Each has a different utility cost.
4. **The real trade.** Bound size versus false-rejection rate versus evasion probability — the
   three-way frontier, of which the paper measured one two-way slice.

## Method

1. **Make labels load-bearing.** Implement compartment tags: reading a resource tags the path,
   and egress to an endpoint not cleared for a compartment is refused. This is a natural IFC
   design and distinct from the existing sensitivity lattice.
2. **Construct the eviction adversary** — an agent that touches B+1 compartments specifically to
   evict, then exfiltrates. Measure success against B.
3. **Re-run the B sweep** with the adversary present. The paper's null result should become a
   curve; if it does not, that is itself informative.
4. **Implement and evaluate the sound alternatives** above, measuring utility cost against the
   existing declassification-frontier methodology.
5. **State the soundness condition** for a bounded path summary, and prove the chosen design
   meets it.

## What would settle it

A working eviction attack with success rising as B falls, plus a design that is provably sound
with quantified utility cost. If truncation turns out to be unexploitable for a principled
reason, that reason is the contribution — but it must be a reason, not the current absence of
evidence.

## Consequence for the standard

* **C4.1.7 amended** to require that the bounded summary be sound: either the abstraction
  over-approximates, or exceeding the bound is itself recorded and fails closed.
* The paper's §9.5 B-sweep result must be **corrected or withdrawn** — it currently reports a
  null result whose cause is that nothing reads the structure under test.

## Venue

CSF or ESORICS for the formal treatment; PLDI/POPL if the abstract-interpretation framing leads.
The attack alone would fit a workshop.

## Effort and dependencies

Small — days to weeks. The frontier harness, the workload generator, and the policy engine all
exist. **This is the cheapest correction in the roadmap and it fixes a claim currently in print.**
