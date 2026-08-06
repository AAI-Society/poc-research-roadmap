# P02 — From Message Authorization to Effect Binding

**Domain:** C4 Authorization / C7 Evidence · **Kind:** Corrective, Foundational ·
**Impact:** Very high · **Effort:** Medium

---

## The question

A signed capability can bind the *bytes of a request*. Under what conditions does that bind the
*effect a real endpoint performs* — and what must an API guarantee for the two to coincide?

## Why it matters

**For the standard.** Theorem 1 of the paper claims execution fidelity: an adversary cannot make
a relying party perform an action other than the one the policy evaluated. The proof works by
digest comparison — the relying party recomputes a digest over the request it was asked to
perform and refuses on mismatch.

An independent review identified the gap, and it is real. Definition 1 says the snapshot
"describes exactly" the effect, but **no snapshot-to-effect relation is ever defined**. Canonical
byte equality binds an agreed *request representation*. It does not bind what an endpoint does
with that representation, and real endpoints have: parameter defaults, server-side state,
redirects, retries, content negotiation, resource aliases, idempotency semantics, and concurrent
requests that interact.

Two concrete failures the current theorem does not exclude:

* The same signed request performed twice produces two effects. The nonce check prevents replay
  *by the adversary*, but a network retry at a non-idempotent endpoint is not a replay.
* `POST /v1/transfer?to=acct-9` and `POST /v1/transfer` with `to` defaulting to `acct-9`
  canonicalize differently and mean the same thing; two implementations legitimately disagree
  about which the agent requested.

This is the paper's central theorem and everything downstream inherits the gap: C7.1.4 complete
mediation, C8.3 self-enforcing execution, and the Tier-3/4 claims all rest on it.

**For the field.** Capability systems, macaroons, OAuth token binding, and every "signed intent"
scheme in agent tooling share this hole. The industry is currently shipping agent authorization
protocols that bind messages while their marketing describes binding actions. A clear statement
of the conditions under which message binding implies effect binding — and a taxonomy of the APIs
where it cannot — would be widely reusable and immediately actionable.

## What is already known

* **Complete mediation** — Saltzer and Schroeder (1975); Anderson's reference monitor (1972).
  The classical formulation assumes the monitor and the resource share a machine, which is
  exactly the assumption that fails here.
* **Capability systems** — Dennis and Van Horn (1966); Levy, *Capability-Based Computer Systems*;
  macaroons (Birgisson et al., NDSS 2014) for caveats and attenuation.
* **Protocol verification** — Dolev-Yao; ProVerif, Tamarin. These verify message-level properties
  and are the right tools for the message half of the argument.
* **API formalization** — REST semantics ([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)) on
  idempotency and safety; OpenAPI as a machine-readable surface description.
* **Semantic gap / TOCTOU** — the confused-deputy problem (Hardy, 1988) is the ancestor of this
  bug. Also the substantial literature on parser differentials and request smuggling, which is
  the same failure in a different suit.
* **Financial-messaging binding** — ISO 20022 and payment-initiation authorization solve a
  restricted version of this by fixing the message semantics, which is one of the escape routes
  below.

## What is genuinely open

The honest position is that **effect binding is not achievable in general** — an arbitrary
endpoint can do anything. So the research question is not "how do we bind effects" but "what is
the weakest condition on an API under which binding a message binds an effect?"

Open pieces:

1. **A formal effect model.** Endpoint as a state transformer; a request representation induces
   an effect *relative to server state*. Effect binding then means the induced transformation is
   determined by the signed representation.
2. **The condition itself.** Candidates: canonical request form is a function of the effect
   (injectivity); the endpoint is idempotent; the endpoint publishes a normalization it commits
   to; all state the effect depends on is named in the request.
3. **A taxonomy of real APIs** by which condition they satisfy. This is the empirical half and is
   probably the most valuable output.
4. **What to do about the rest.** For endpoints that cannot satisfy any condition — the majority,
   probably — the honest answer may be that only Tier 1–2 claims are available. That is a
   consequential result and the standard should say it.

## Method

1. Define the effect model and state the binding property precisely, separating **message
   authorization** (provable now) from **effect binding** (conditional).
2. Prove the conditional theorem: given condition X on endpoint E, message binding implies
   effect binding. Mechanize in Tamarin or ProVerif.
3. **Survey real APIs.** Take 20–30 endpoints agents actually call — payments, email, calendar,
   cloud provisioning, database writes, code hosting — and classify each against the conditions.
   Report how many qualify. Expect the answer to be discouraging and report it anyway.
4. **Build the adversarial test suite the reviewers asked for**: ambiguous JSON/CBOR, duplicate
   keys, Unicode and URL normalization, defaults, redirects, retries, aliases, concurrency. Run
   the reference implementation against a deliberately hostile endpoint and see what gets
   through.
5. Propose a profile: what an API must publish to be *bindable*, so this becomes something an API
   designer can conform to rather than a property researchers wish for.

## What would settle it

**Supporting:** a conditional theorem with a mechanized proof, plus a survey showing a
non-trivial fraction of real endpoints satisfy the condition or can cheaply be made to.

**Refuting — and equally valuable:** the survey shows almost no real API qualifies. Then the
finding is that effect binding requires an *attested enforcement point* (option (c) of C7.1.4)
rather than a capability at the endpoint, and the standard should stop offering option (b) as
equivalent. That would be a significant correction and a stronger paper than a comfortable
confirmation.

## Consequence for the standard

* **Theorem 1 restated** as message authorization, with effect binding conditional and the
  condition named.
* **C7.1.4** — the three mediation options are currently presented as alternatives. They are not
  equally strong, and this paper would establish the ordering.
* **C7.1.5** — the "may claim Tier 1–2 only" rule likely applies far more often than currently
  implied.
* A new requirement: the conformance claim names the endpoint condition relied on.

## Venue

USENIX Security or CCS. The API survey alone would make a strong measurement paper for IMC or a
workshop, and could be published first as a standalone result.

## Effort and dependencies

Medium; the survey is the long pole and is parallelizable. Reads more cleanly after
[P01](P01-trust-calculus.md) but does not depend on it.
