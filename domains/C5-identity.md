# C5 — Identity

**6 requirements** · *Which agent and which principal ran* ·
[Chapter](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md)

## State of the domain

The thinnest of the six domains, and the one carrying the most unresolved design questions. Six
requirements cover agent instance identity, binding to an initiating principal, credential
binding to an attested environment, and delegation identity. Two of the working group's three
substantive open issues live here.

That combination — fewest requirements, most open questions — is the usual signature of a topic
nobody has worked out rather than one that is simple. Identity is where the standard is least
prescriptive because the right answer is genuinely unknown, not because there is little to say.

## What is settled

* An agent instance has a stable identifier; DIDs are recommended.
* Evidence names the principal on whose authority the agent acts (`initiating_user`).
* The credential should be bound to an attested execution environment (C5.1.4) — and with
  requirement C7.2.4 this is now demonstrated on real hardware, with the evidence key digest
  carried in the TDX quote's `REPORTDATA`.

## What is open

**Unlinkability versus accountability** ([open issue 2](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md)).
Whether the standard supports verifiable-but-unlinkable identity as a selectable option, and how
escrow works if it does. The tension is structural rather than incidental: every other part of
the standard pushes toward evidence that links actions together, and a hash-chained publicly
anchored log is close to the worst case for unlinkability. → **[P05](../papers/P05-unlinkable-identity.md)**

**Where identity binding lives** ([open issue 1](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x93-Appendix-D_Open-Issues.md)).
Whether C5 or C4 owns it. The working group leans toward Authorization owning it with Identity as
an input, which is probably right — but the ownership question is downstream of a technical one
nobody has answered: what identity semantics does a delegation chain need?
→ **[P06](../papers/P06-delegation-attenuation.md)**

**Identity across trust domains.** When an agent migrates, does its identity survive, and what
attests the continuity? → **[P07](../papers/P07-evidence-continuity.md)**

## Why this domain matters more than its size suggests

Every other domain's evidence is *about* something the identity names. Provenance says which
model ran — for whom? Authorization says an action was within a grant — granted to whom, by whom?
If identity is weak, the rest is evidence about an unnamed party, which is most of the way to no
evidence at all.

There is a second reason. Identity is where this standard will collide with data-protection law
first. An agent that reveals its enterprise, its user, and its activity volume to every vendor it
transacts with is difficult to defend under data minimization, and that collision is arriving
faster than the specification is.

## Papers

* **[P05 — Accountable but Unlinkable Agent Identity](../papers/P05-unlinkable-identity.md)** ·
  High impact, large effort. The measurement half is small and should be done first.
* **[P06 — Delegation Without Amplification](../papers/P06-delegation-attenuation.md)** ·
  High impact, medium effort. Shared with C4.

## Where to start a deep-research pass

Direct Anonymous Attestation (Brickell–Camenisch–Chen 2004, ISO/IEC 20008) is the closest existing
answer and is already in shipping TPM hardware. Start there, then BBS+ selective disclosure and
the W3C verifiable-credentials track, then the group-signature opening-authority literature for
the escrow question. The gap to look for: **none of it addresses unlinkability against a
tamper-evident ordered log of the credential holder's own actions.**
