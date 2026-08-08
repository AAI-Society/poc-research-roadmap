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

**For the field.** Capability systems, macaroons, Biscuit, OAuth Rich Authorization Requests, token
binding, and every "signed intent" scheme in agent tooling share this hole. The industry is
currently shipping agent authorization protocols that bind messages while their marketing describes
binding actions. A clear statement of the conditions under which message binding implies effect
binding — and a taxonomy of the APIs where it cannot — would be widely reusable and immediately
actionable.

## What is already known

* **Complete mediation** — Saltzer and Schroeder (1975); Anderson's reference monitor (1972).
  The classical formulation assumes the monitor and the resource share a machine, which is
  exactly the assumption that fails here. Naming that assumption explicitly is the paper's
  cleanest framing device: capability protocols distribute the reference monitor and inherit a gap
  the original model defined away.
* **Capability systems** — Dennis and Van Horn (1966); Levy, *Capability-Based Computer Systems*;
  macaroons (Birgisson et al., NDSS 2014) for caveats and attenuation.
* **Protocol verification** — Dolev-Yao; ProVerif, Tamarin. These verify message-level properties
  and are the right tools for the message half of the argument — and, importantly, *only* that
  half. A Tamarin proof of the message layer is not evidence about effects, and the paper should
  say so rather than let a mechanized proof imply more than it covers.
* **API formalization** — REST semantics ([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)) on
  idempotency and safety; OpenAPI as a machine-readable surface description; JSON Canonicalization
  Scheme ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) and I-JSON
  ([RFC 7493](https://www.rfc-editor.org/rfc/rfc7493)) for the canonical form.
* **Semantic gap / TOCTOU** — the confused-deputy problem (Hardy, 1988) is the ancestor of this
  bug. Also the substantial literature on parser differentials and request smuggling, which is
  the same failure in a different suit.
* **Financial-messaging binding** — ISO 20022 and payment-initiation authorization solve a
  restricted version of this by fixing the message semantics, which is one of the escape routes
  below. This turns out to be the single strongest existing answer and deserves close reading
  rather than a citation.

## The four conditions

A desk study has converted the vague "what is the weakest condition" question into four named,
separately checkable conditions. This is the paper's likely technical spine, and each is falsifiable
against a real endpoint:

**C1 — Parameter completeness / default invariance.** The effect depends only on state named in the
request and state named in the pinned server state; there is no un-signed server-side defaulting.
Where optional parameters exist, the endpoint must publish a normalization function and the
signature must cover the *normalized* form, not the wire form.

**C2 — Representation injectivity.** Parsing followed by canonicalization is injective from
semantic intent to canonical bytes: two wire forms with the same canonical digest must induce the
same state transformation. This fails under URI aliasing (`/v1/users/me` vs `/v1/users/usr_99812`)
and under any parser differential between the policy engine and the backend.

**C3 — Strict idempotency with nonce-decoupled retries.** Repeated execution of the same canonical
request yields the same final state. Critically, the *authorization* nonce must be decoupled from
the *business* idempotency key, because they solve different problems and conflating them is what
produces the retry failure below.

**C4 — Contextual state pinning.** Every piece of server state the effect depends on is pinned in
the signed request via ETags, version vectors or state digests, so that a concurrent mutation
between check and use causes an atomic abort rather than a different effect.

The conditions are **sufficient, and the paper must be careful not to claim they are necessary.**
The desk study states the restated theorem as an "if and only if" while proving only one direction;
an endpoint could achieve effect binding by other means (a co-located monitor, a total function
over a fixed state space). Getting this right is a small point of rigor that a reviewer will
absolutely test.

## What the desk survey already found

A preliminary desk survey classified 24 production endpoints across six sectors against C1–C4.
**These are documentation-derived classifications, not live measurements** — verifying them against
running endpoints is a substantial part of the paper's work, and the numbers should be treated as a
hypothesis to be tested rather than a result to be cited.

| Outcome | Share | Examples |
| --- | --- | --- |
| **Qualified** — satisfies C1–C4 as specified | 4 / 24 (17%) | ISO 20022 `pain.001`; AWS S3 `PUT` with `If-Match`; GitHub contents API with parent SHA; Vault check-and-set |
| **Conditional** — qualifies only if the client volunteers explicit idempotency keys, fully-qualified identifiers and complete parameter structs | 6 / 24 (25%) | Stripe charges, AWS `RunInstances`, GCP `instances.insert`, Azure ARM, Docker create, Pinecone upsert |
| **Non-qualifying** — fails both idempotency and parameter completeness | 14 / 24 (58%) | GitHub repo create, Google Calendar events, Gmail send, MS Graph `sendMail`, Slack `chat.postMessage`, Jira, Salesforce, HubSpot, Okta, Auth0, GitLab, Cloudflare DNS, Plaid |

If this survives live verification, the conclusion is stark and directly actionable: **the majority
of endpoints agents actually call cannot support an effect-binding claim at all**, and the four
that can share a specific design signature — mandatory schema validation, content-addressed version
pinning, and unambiguous primary-key resolution rather than aliases. That signature is the paper's
recommendation, derived rather than asserted.

Note the sampling caveat honestly: 24 endpoints chosen for sector coverage is a convenience sample,
and "SaaS productivity APIs are worse than financial messaging" is close to a foregone conclusion.
The paper should either enlarge and randomize the sample or reframe the survey as a structured
taxonomy with illustrative cases, and not present 58% as a population estimate.

## The adversarial surface

The desk study also produced the concrete attack material the reviewers asked for. The strongest
example, and the one to lead with:

**Duplicate-key parser differential.** RFC 8785 prohibits duplicate JSON object keys. Real decoders
disagree about what to do anyway — Go's `encoding/json` takes the *last* key, Elixir's `:json`
retains the *first*, Node's `JSON.parse` takes the last, Jackson varies by mode. An adversary
submits a payload with duplicate `to` keys. The policy engine (first-key-wins) authorizes a
transfer to the legitimate recipient; the backend (last-key-wins) transfers to the attacker. The
signature verifies over bytes both sides agree on. **Every step is individually correct and the
composition is exploitable** — which is precisely why message-level proofs miss it.

Supporting cases: lone surrogates silently replaced with U+FFFD by lenient decoders; NFC/NFD
normalization mismatch between the signing engine and the resource resolver; numeric handling where
the policy engine uses arbitrary precision and the endpoint rounds to IEEE-754 double; negative zero
and underflow tokens.

**The retry ambiguity, stated precisely.** Client sends a non-idempotent `POST` with nonce *n*. The
endpoint commits state and returns 200. A TCP reset drops the response. The proxy retries with the
same capability. The endpoint's nonce cache rejects it as a replay — so the client believes the
operation failed while the state change happened. If instead the proxy obtains a fresh signature
over a new nonce, the operation executes twice. **Neither branch is correct, and no message-level
mechanism can distinguish an adversarial replay from an infrastructure retry** — the distinction
does not exist at the message layer. This is the cleanest possible demonstration that the gap is
structural rather than an implementation defect, and it should probably open the paper.

**Parameter defaulting as a policy bypass.** An agent omits `fee_tier`. The policy engine sees no
fee tier, applies a rule that auto-approves ordinary transfers, and signs. The endpoint loads the
user profile default, which resolves to `priority`. The executed action is one the policy would
have rejected had it been explicit. The signature is valid throughout.

## What is genuinely open

The honest position remains that **effect binding is not achievable in general** — an arbitrary
endpoint can do anything. The desk study proposes conditions but validates none of them. What is
open:

1. **Soundness of the conditional theorem.** The restated theorem — message binding plus C1–C4
   implies effect binding — has a proof sketch that leans on EUF-CMA unforgeability, collision
   resistance, and each condition in turn. It has not been mechanized, and the necessity direction
   is claimed without proof (see above).
2. **Whether the conditions are checkable rather than merely definable.** C1 and C4 are properties
   of endpoint *implementations*, not of published interfaces. An OpenAPI document does not reveal
   server-side defaulting. Absent source access, classification is inference from documentation and
   black-box probing — and the survey's credibility depends entirely on how that is done. This is
   the methodological crux of the empirical half.
3. **Verification without cooperation.** If an endpoint must *publish* a normalization commitment
   to be bindable, what does a relying party do about the endpoints that never will? Options are
   the attested enforcement point, a trusted intermediary that normalizes, or accepting a lower
   tier. Their relative strength is unanalysed.
4. **What replaces binding for the 58%.** If most endpoints cannot qualify, the standard's honest
   position is that only Tier 1–2 claims are available for them. That is a consequential result and
   the standard should say it plainly rather than let implementers assume otherwise.
5. **Composition across multi-step agent workflows.** Every condition above is stated for a single
   request. An agent performing a five-call workflow has effects that depend on intermediate
   results. Whether per-request effect binding composes into workflow-level binding is untouched by
   the desk study and is arguably the question the agent setting actually poses.

## Method

1. Define the effect model — endpoint as a state transformer `E : Σ × W → Σ × O`, with parsing and
   canonicalization made explicit — and state the binding property precisely, separating **message
   authorization** (provable now) from **effect binding** (conditional on C1–C4).
2. Prove the conditional theorem. Mechanize the message layer in Tamarin or ProVerif; be explicit
   that the effect layer is proved by hand against the state-transformer model, since the protocol
   verifiers cannot express it. Settle the necessity question rather than eliding it.
3. **Verify the survey against live endpoints.** Take the 24 classifications above and test them:
   send requests with omitted optional parameters and observe the materialized resource; send
   aliased identifiers and compare effects; send duplicate keys and observe which wins; retry
   under induced connection failure and count side effects. **Documentation-derived classification
   is the weakest link in the current draft and live probing is what turns it into evidence.**
   Expect the answer to be discouraging and report it anyway.
4. **Build the adversarial test suite the reviewers asked for**: duplicate keys, lone surrogates,
   NFC/NFD drift, numeric precision and negative zero, parameter defaults, redirects, aliases,
   retries, concurrency. Run the reference implementation against a deliberately hostile endpoint
   and see what gets through. Ship it as a reusable conformance harness — that artifact may outlive
   the paper.
5. Propose the **Boundable API Profile**: strict canonical ingestion (reject non-I-JSON, duplicate
   keys, lone surrogates, unbounded numerics *before* signature verification); a published
   normalization function with signatures covering the normalized form; a mandatory explicit
   idempotency key distinct from the authorization nonce; and mandatory state preconditions. State
   it as an OpenAPI extension so it is something an API designer can conform to rather than a
   property researchers wish for.

## What would settle it

**Supporting:** a conditional theorem with a mechanized message layer and a hand-proved effect
layer, plus live verification showing a non-trivial fraction of real endpoints satisfy the
conditions or can cheaply be made to — for instance, that most of the "conditional" 25% become
qualified with client-side discipline alone, which would make the profile adoptable incrementally.

**Refuting — and equally valuable:** live probing confirms almost no real API qualifies. Then the
finding is that effect binding requires an *attested enforcement point* (option (c) of C7.1.4)
rather than a capability at the endpoint, and the standard should stop offering option (b) as
equivalent. That would be a significant correction and a stronger paper than a comfortable
confirmation. **The desk survey points this way**, so the paper should be structured to carry that
conclusion.

**A concrete falsifiable prediction to publish up front:** at least one widely-deployed agent
authorization stack is exploitable today via the duplicate-key differential between its policy
engine and its backend, because they are written in different languages with different decoders.
Demonstrating that on a real (responsibly disclosed) stack would make the paper unignorable.

## Consequence for the standard

* **Theorem 1 restated** as *conditional* execution fidelity: message authorization holds
  unconditionally; effect binding holds given C1–C4, with the conditions named in the claim.
* **C7.1.4 reordered.** The three mediation options are currently presented as alternatives. They
  are not equally strong and the paper establishes the ordering:
  1. **(c) attested enforcement point** — monitor co-located inside the execution boundary,
     mediating the fully-expanded operation immediately before mutation. Strongest.
  2. **(a) direct endpoint enforcement** — acceptable *only* where the endpoint conforms to the
     Boundable API Profile.
  3. **(b) endpoint capability with un-attested local normalization** — cannot guarantee effect
     binding and should be **demoted**, not listed as an equal alternative.
* **C7.1.5** — the "may claim Tier 1–2 only" rule likely applies to the majority of endpoints, not
  the exceptions. Tier 3/4 claims restricted to endpoints proving Boundable-Profile conformance or
  using an attested enforcement point.
* **A new requirement:** the conformance claim names the endpoint condition relied on, so a
  verifier can tell which of C1–C4 is load-bearing for a given deployment.
* **A parser mandate.** Authorization pipelines must use strict RFC 8785 decoders that reject
  duplicate keys, lone surrogates and unbounded numerics. Language-default decoders must not be
  used to parse anything a signature will cover. This is the cheapest fix in the paper and probably
  the one with the largest immediate effect.

## Venue

USENIX Security or CCS. The API survey alone would make a strong measurement paper for IMC or a
workshop, and could be published first as a standalone result — the live-probing methodology is the
part that makes it a measurement contribution rather than a taxonomy.

## Effort and dependencies

Medium; the survey is the long pole and is parallelizable, and converting it from desk
classification to live probing is now the bulk of that work. The conditions and adversarial cases
are drafted, which de-risks the theory half considerably. Reads more cleanly after
[P01](P01-trust-calculus.md) but does not depend on it.
