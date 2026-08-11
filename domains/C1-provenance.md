# C1 — Provenance

**13 requirements** · *Which model ran; lineage, artifact and supply-chain origin* ·
[Chapter](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md)

## State of the domain

Mechanically the most mature domain, because it borrows from a solved problem. Artifact signing,
digest comparison at load time, and bills of materials are well understood in software supply
chain, and C1 largely applies them to models and agents.

The maturity is deceptive. Software supply chain solves provenance for artifacts that **do not
change while they run**. An agent's effective composition changes continuously: context is
retrieved, memory is written, tools are loaded, sub-agents are spawned. C1 covers the build-time
half well and the runtime half barely.

## What is settled

* Model and artifact identity by digest, verified at load.
* Signed manifests and supply-chain verification, following SLSA and in-toto.
* An AgBOM digest carried in every evidence record.
* Substrate identification — which compute environment the execution ran on.

## What is open

**Runtime composition.** The AgBOM digest in the reference implementation is computed once and
never changes, which is honest for a static agent and wrong for a real one. A digest that commits
to "the manifest at task start" tells a verifier nothing about the document retrieved three steps
later that actually steered the decision. → **[P10](../papers/P10-agbom.md)**

**Provenance for the threat model.** Memory and context poisoning, and RAG weakness, are all
graded *Partial* in the threat model. Provenance is the mechanism that should upgrade them, and
it currently cannot, because it does not record what it would need to.

**Privacy-preserving provenance.** C1.4 requires retaining digests or redacted commitments where
full lineage cannot be disclosed. Specified, not built. Overlaps
**[P09](../papers/P09-zk-evidence.md)**.

## Why this domain matters

Provenance answers the first question anyone asks after an incident: *what was actually running?*
If the answer is a build manifest from three hours before the incident, it is the wrong answer to
a slightly different question.

There is also a timing argument. AI BOM is being standardized right now — MITRE ATLAS added
AML.M0023, M0024 and M0025; CycloneDX has an ML-BOM; the EU AI Act's technical documentation
requirements point the same way. Almost all of it addresses build and training time. Runtime
composition is the part that distinguishes agents from models, and it is the part nobody has
specified.

## Papers

* **[P10 — What Belongs in an Agent Bill of Materials](../papers/P10-agbom.md)** · Medium impact,
  medium effort, independent of the rest — a good parallel track.

## Where to start a deep-research pass

CycloneDX ML-BOM and the MITRE ATLAS mitigations M0023/M0025 for what the field currently
believes belongs in an AI BOM. Then — and this is the underused part — the **database provenance
literature** (why-, how-, and where-provenance), which has a far more precise vocabulary for
"which input influenced this output" than the AI BOM discussion currently uses. Then TPM PCR
extension as the model for an incremental composition commitment.
