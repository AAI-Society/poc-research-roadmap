# C2 — Privacy

**13 requirements** · *What data was read and written — evidenced without re-leaking it* ·
[Chapter](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x10-C02-Privacy.md)

## State of the domain

Well specified in intent, and the domain with the largest gap between what is written and what
has been built.

C2 carries an elegant central idea: evidence commits to a *digest* of what was read, never the
content, so the evidence store does not quietly become a second copy of the customer database.
That is genuinely good design and it is implemented.

It is also not privacy. A digest still reveals that an action occurred, against which resource,
at what time, in what order relative to every other action. For an agent working on health
records, the metadata is disclosive even when the content is not.

## What is settled

* Data reads and writes are evidenced by commitment, not content.
* Classification is carried through the path summary and constrains egress.
* Purpose and residency constraints are expressible in the grant.

## What is open

**The zero-knowledge path.** C2.3 specifies privacy-preserving evidence options. None are
implemented, and the paper says so directly. A specified-but-unbuilt requirement may be
infeasible and nobody would know — proving costs are currently several orders of magnitude above
the standard's own 15 ms action budget. → **[P09](../papers/P09-zk-evidence.md)**

**Metadata leakage.** Even with perfect content privacy, the chain structure reveals timing,
volume, ordering, and target resources. This is the same structural problem
**[P05](../papers/P05-unlinkable-identity.md)** hits from the identity side, and the two should be
solved together or not at all.

**Disclosure across jurisdictions.** A proof or redaction adequate under one regime may reveal
too much under another. Raised in [open issue 3](https://github.com/Task-force-for-AI-agents-in-Healthcare/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md)
and handled in **[P07](../papers/P07-evidence-continuity.md)**.

## Why this domain matters

Privacy is where the standard's core mechanism works against its core purpose. Verifiability
wants more evidence, retained longer, checkable by more parties. Privacy wants less, retained
briefly, disclosed narrowly. Every other domain benefits from more evidence; C2 is where the
standard has to decide what it will not record — and where a regulator will look first.

## Papers

* **[P09 — Evidence That Reveals Nothing](../papers/P09-zk-evidence.md)** · Medium impact, large
  effort. **Step 1 is a one-week feasibility measurement that may settle the question outright**
  — do that before committing to anything larger.

## Where to start a deep-research pass

zkVM proving costs (RISC Zero, SP1, Jolt) benchmarked against a 15 ms budget — this is the
decisive number and it is obtainable quickly. Then zero-knowledge middleboxes (Grubbs et al.) for
the closest existing "prove compliance without revealing traffic" construction. Then folding
schemes (Nova) for amortization. The framing that makes this interesting is not privacy but trust:
**does ZK remove the hardware vendor from the trust set that [P01](../papers/P01-trust-calculus.md)
enumerates?**
