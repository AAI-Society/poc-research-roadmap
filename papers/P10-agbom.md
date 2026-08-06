# P10 — What Belongs in an Agent Bill of Materials

**Domain:** C1 Provenance · **Kind:** Generative · **Impact:** Medium · **Effort:** Medium

---

## The question

An SBOM describes software that does not change while it runs. An agent's effective composition —
model version, system prompt, tool set, retrieved context, memory — changes continuously. What
must an Agent Bill of Materials record, and how does it stay true at runtime?

## Why it matters

**For the standard.** C1 requires an AgBOM digest in every evidence record (`agbom_digest`), and
the reference implementation computes it once at construction and never changes it. That is
honest for a static reference agent and wrong for any real one. If an agent loads a tool at
runtime, retrieves a document into context, or writes to memory, its effective composition has
changed and the digest has not.

The interesting failure is not a stale digest — it is that **the digest can be accurate and
useless**. Committing to "the manifest at task start" tells a verifier nothing about the
retrieved document that actually steered the decision three steps later.

**For the field.** AI BOM is being standardized right now — MITRE ATLAS added AML.M0023 (AI Bill
of Materials) and AML.M0025 (Maintain AI Dataset Provenance), CISA and CycloneDX have AI/ML
extensions, and the EU AI Act's technical documentation requirements point the same way. Almost
all of it is oriented to *training-time and build-time* composition. The runtime composition
problem is barely addressed and is where agents actually differ from models.

## What is already known

* **SBOM** — SPDX, CycloneDX (which now has ML-BOM), and the SBOM-in-practice literature on
  accuracy and drift.
* **in-toto and SLSA** — build-integrity attestation; the provenance model to extend rather than
  reinvent.
* **MITRE ATLAS** — AML.M0023, M0024 (AI Telemetry Logging), M0025 (Dataset Provenance). Newly
  added and directly on point.
* **Model cards / datasheets** — Mitchell et al.; Gebru et al. Documentation rather than
  attestation, but they establish what people believe belongs in the description.
* **Data provenance systems** — PROV-O, and the database provenance literature (why-, how-, and
  where-provenance), which is a far more precise vocabulary than the AI BOM discussion currently
  uses and is underexploited here.
* **RAG attribution / context tracing** — the emerging work on tracing which retrieved chunk
  influenced an output; the technical core of runtime composition.

## What is genuinely open

1. **Static versus dynamic boundary.** What belongs in a build-time manifest versus what must be
   recorded per action? A digest of the whole context window per action is enormous; a digest of
   nothing is useless.
2. **Incremental composition commitment.** Can the AgBOM be a *running* commitment — extended per
   context change like a TPM PCR — so a verifier can confirm composition at any step without
   storing every context? RTMR-style extension is the obvious model and appears unexplored here.
3. **Granularity that supports the security argument.** The threat model includes memory and
   context poisoning and RAG weakness. An AgBOM only earns its place if it lets a verifier detect
   those after the fact. That is the test to design against, and it is more demanding than
   inventory.
4. **Cross-agent composition.** In a multi-agent system, what is the AgBOM of the *system*? Does
   the delegator's record commit to the delegate's composition?
5. **Verification.** Given an AgBOM digest, what does a verifier do with it? Reference values for
   models, prompts, and tools imply a distribution infrastructure nobody has built.

## Method

1. Taxonomize what changes and at what rate: model, weights, system prompt, tool schemas,
   retrieved context, memory, sub-agent roster.
2. Design an incremental composition commitment; implement as a PCR-style extension in the
   reference pipeline.
3. Measure cost per action and evidence size against the flat-digest baseline.
4. **Evaluate against the threat model**: construct memory-poisoning and RAG-poisoning attacks and
   determine whether the AgBOM design lets a verifier detect them from evidence alone. This is the
   real test.
5. Map onto CycloneDX ML-BOM and ATLAS mitigations so the output is adoptable rather than parallel.

## What would settle it

A composition-commitment design with measured cost, plus a demonstration that it detects at least
one threat-model attack a static AgBOM misses. If it detects none, the honest finding is that
AgBOM is an inventory control rather than a security control, and the standard should grade it
accordingly.

## Consequence for the standard

* **C1.2 substantially expanded** — runtime composition rather than a build manifest.
* **C7** evidence schema gains composition-commitment fields.
* Threat-model coverage grades for memory and context poisoning could move from Partial toward
  Full, which would be one of the few such upgrades available.

## Venue

A software-supply-chain venue (SCORED workshop, or CCS), or an SE venue such as ICSE/FSE for the
measurement.

## Effort and dependencies

Medium. Independent of the other papers; a good parallel track.
