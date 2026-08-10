# Design — `transit guard` claims, the enforcement point that writes down what it decided

**Date:** 2026-08-10 · **Status:** draft, forks unresolved ·
**Repo:** extension to [`transit`](https://github.com/Task-force-for-AI-agents-in-Healthcare/transit),
writing to [`ephemeris`](2026-08-10-ephemeris-design.md) over a Unix domain socket

---

## Why

`transit guard` is already the Action Interception Gateway of C7.1. It sits in the
request path, canonicalizes the body, decides, and forwards. Then it throws the
decision away.

[`TOOLING.md`](../../../TOOLING.md) counts this as roadmap T3 and says it is "mostly
serialization" — three of five fields already computed, two genuinely new. **Reading the
code, that is optimistic.** One of the three is computed exactly as the roadmap says. One
is computed over the wrong object and only for a subset of requests. One requires choosing
between three defensible definitions. Of the two "new" fields, one needs an identity
derivation of the kind that caused four of `parallax`'s five criticals, and one may not be
computable by this component at all.

This spec is the audit of that claim, and the design that follows from it.

## Scope

**In:** the guard emits an evidence claim per intercepted action to `ephemeris`, over the
UDS transport that spec defines, supplying exactly the caller-supplied column of
[its contract table](2026-08-10-ephemeris-design.md#what-the-claim-carries-and-what-ephemeris-adds).
Write-before-forward per C7.1.3. Three records per action per C7.1.2.

**Out, deliberately:**

- **Signing, chaining, `step_index`, `merkle_root`, `tree_size`, `iat`, `nonce`.** These
  are `ephemeris`'s column. The guard computes none of them and must not be read as
  checking them.
- **Log storage.** The guard holds no evidence. It emits and blocks.
- **A second canonicalizer.** `transit::jcs` is the one implementation, for the reason
  C7.7's own commentary gives.
- **`agbom_digest`.** Nothing computes it. Roadmap T4.
- **Redefining the T2/T3 boundary.** Where this design needs the boundary moved, it says
  so as a fork against the `ephemeris` spec rather than moving it unilaterally.

## The boundary, as this component sees it

```
client ──▶ transit guard                                        ephemeris
             1. read, bound, frame-check
             2. decide  ────────────────────▶ claim(before) ──────▶ append+fsync
             3. block   ◀────────────────────  ack        ◀───────
             4. forward ──▶ upstream           claim(during) ─────▶
             5. relay   ◀──                    claim(after)  ─────▶
```

Steps 2 and 4 exist today, in that order, with nothing between them. The whole of this
design is step 3 and the three claims.

---

## What is actually already computed

The five fields the roadmap assigns to T3, against `guard.rs` as it stands.

| field | roadmap says | code says | what T3 must actually do |
| --- | --- | --- | --- |
| `verdict` | computed | **yes** — `Decision::Forward` \| `Decision::Reject` | map two Rust variants onto a four-value enum. See [Verdicts](#the-verdict-enum-is-four-wide-and-the-guard-reaches-two) |
| `target_resource` | computed | **partly** — `normalize_target` yields a path, and only when the target parses | choose the resource's scope; handle the reject-before-normalization case |
| `canonical_snapshot_hash` | computed | **no** — `jcs::digest` is over the request *body*, is bare hex, is `""` for a bodiless request, and is never reached on a rejection | define the snapshot, tag the digest, cover every request |
| `policy_bundle_hash` | not computed | not computed | a stable identity for `GuardConfig` **and the code that reads it** |
| `path_summary_hash` | not computed | not computed, and nothing in the process holds path state | see [`path_summary_hash`](#path_summary_hash-the-honest-answer) |

Four specific contradictions with the roadmap's reading, each ground in the source:

**1. The digest is not the snapshot digest.** `jcs::digest(v)` (`src/jcs.rs:26`) is
`SHA-256` of the canonical form of the parsed *body value*. The schema's
`canonical_snapshot_hash` is "digest of the canonical snapshot the policy actually
evaluated", and the standard's own reference implementation
(`impl/poc/core.py:236`) digests an object over `{agent_id, action, path_summary,
step_index}`. A body-only digest commits to none of the method, the target, or the
headers the guard's rules turned on. Two requests posting the same body to different
endpoints have the same digest today.

**2. The digest is empty for a bodiless request.** `decide` returns
`(String::new(), String::new())` when `parsed` is `None` (`src/guard.rs:643`). Every
forwarded `GET`, `HEAD`, `OPTIONS`, and every bodiless `DELETE`, currently produces no
digest at all. `canonical_snapshot_hash` is a required field matching
`^(sha-256|…):[0-9a-f]{64,128}$`; the empty string is not a value it can take.

**3. Nothing is computed on a rejection.** Every `reject(…)` in `decide` returns before
line 642. A `DENY` record — the record an auditor most wants — has no canonical
snapshot hash under the current control flow, and for the C2 rejections it has no
canonical form *by construction*: the request was refused precisely because its bytes do
not canonicalize.

**4. The digest is untagged.** `jcs::digest` returns `hex::encode(…)`, 64 bare hex
characters. Every digest in the record needs the `sha-256:` prefix (C7.7.3, and the
schema's `digest` pattern). This is trivial and is called out only because it is the kind
of thing that gets discovered at integration time by a validator, three layers away from
the code that caused it.

So the honest count is: **one field free, one field a definition choice, one field a
redefinition plus new control flow, and two genuinely new.** T3 is not mostly
serialization. It is mostly deciding what three of the words mean.

---

## Restructuring `decide`

`decide` is a pure function of `(&GuardConfig, &Request)` and must stay one. The claim is
not built inside it; `decide` gains an output, and `handle_one` does the emitting.

Today `Decision::Forward(Forward)` carries the forward plan and `Decision::Reject` carries
a status, a condition and a reason. Neither carries what a record needs. The change is to
have `decide` return, alongside the decision, an `ActionSnapshot` — the object that gets
canonicalized — constructed **before** the C1/C3/C4 rule checks and populated as far as
the request got.

The snapshot is a `Json` value the guard builds, so it always canonicalizes, whatever
arrived on the wire:

| member | value | on a request that never got that far |
| --- | --- | --- |
| `method` | the uppercased method | the raw method, sanitized |
| `target` | `normalize_target`'s path | `null`, with `target_wire` carrying the sanitized raw target |
| `query` | the query string as received | `""` |
| `body` | the parsed `Json` value | `null` |
| `body_wire_sha256` | `SHA-256` of the wire body bytes, always | — |
| `headers_evaluated` | the names and values of the headers the rules read — `content-type`, `idempotency-key`, `if-match` | absent members, not empty strings |

Three properties this shape buys, each of which the body-only digest does not have:

- **It exists for every request.** A snapshot is computable for a `GET` with no body and
  for a payload that fails `parse_strict`, because the un-canonicalizable part is
  represented by a digest of its bytes inside a member that is itself canonical.
- **The ambiguity has a name.** A reader of the record can tell "the body was
  `{"a":1}`" from "the body did not parse and hashed to `9f86…`" by which member is
  populated, rather than by two meanings sharing one field. That is the C7.7 defect this
  suite exists to avoid, applied inward.
- **`headers_evaluated` makes the verdict re-derivable.** A `428 C3` refusal is only
  explicable if the record shows there was no `Idempotency-Key`. Without it, an auditor
  has the verdict and the policy and still cannot reproduce the decision.

`canonical_snapshot_hash = "sha-256:" ‖ jcs::digest(snapshot)`.

> **OPEN FORK: what `canonical_snapshot_hash` digests.**
>
> | option | for | against |
> | --- | --- | --- |
> | **A — the body only**, as `X-Transit-Digest` does today | zero change; already shipped, already the thing P02 verified; a relying party recomputing it needs only the payload | undefined for bodiless and rejected requests; commits to no target, method or header; two different actions collide |
> | **B — the constructed snapshot** above | total for every request; matches the reference implementation's shape; makes the verdict re-derivable | the value differs from `X-Transit-Digest`, so a record's field is not the header a relying party already checks. `poc-audit`'s `field/canonical` compares payload digests and would find neither of them equal to the record's value |
> | **C — both**: snapshot in `canonical_snapshot_hash`, body digest in an extra claim | nothing is lost; the wire contract stays | two digests in a record that a careless verifier will compare to each other |
>
> **Recommendation: C.** B's semantics with A's wire compatibility. `X-Transit-Digest`
> stays byte-identical to what ships today — it is an established contract and P02's
> result rests on it — and the record carries `snapshot_body_sha256` as an additional
> claim (`pocClaims` is `additionalProperties: true`). The cost is a documented
> two-digest record, which is cheaper than either breaking the header or shipping a
> field that is undefined on rejections.
>
> Whichever is chosen, it must be chosen **with `poc-audit` in hand**: `field/canonical`
> runs `transit::differential::run_payload` over the payload bytes and reports the
> digests two decoder models produce. If the record's value can never equal either, the
> auditor's `DIVERGES` finding is comparing the wrong things, and the seam test in
> [Testing](#testing) is what catches it.

> **OPEN FORK: the scope of `target_resource`.**
>
> The schema says only "the resource the action addresses". Three readings:
> the normalized path (`/v1/transfer`); the upstream-qualified path
> (`http://ledger.internal:8787/v1/transfer`); or the full effective request URI
> including the query.
>
> **Recommendation: upstream-qualified path, query excluded.** The path alone is
> ambiguous across deployments and an evidence record that says `/v1/transfer` names
> nothing an auditor can locate. The query is excluded because it is a selector rather
> than a resource, and because it is already committed to inside the snapshot — so
> C7.1.4(b)'s "bound to the evaluated snapshot digest *and* target resource" still binds
> it. Note the consequence: `upstream` is overridable by `TRANSIT_UPSTREAM`
> (`src/guard.rs:725`), so `target_resource` is deployment-dependent by design. That is
> correct for this field and disqualifying for the next one.

---

## `policy_bundle_hash`, and the trap it sits in

The schema: *"Digest of the exact policy that produced the verdict (C4.2). Without it a
verdict cannot be re-derived."*

[`docs/parallax-outcomes.md`](../../parallax-outcomes.md#the-defect-pattern-worth-carrying-to-transit-and-occultation)
records that four of five criticals in that tool traced to one root cause: *a field
participating in a value's identity was specified casually.* Positional mechanism tags
made a file incomparable to a reordering of itself; lexical duration identity made `12h`
and `720m` totally divergent. Both produced confident wrong answers rather than errors.
`policy_bundle_hash` is the same shape and needs the same discipline: **the derivation is
written down, and tested in both directions.**

### What is in the bundle

Not every field of `GuardConfig` produces a verdict. Reading `decide`:

| field | feeds a verdict? | in the bundle |
| --- | --- | --- |
| `route[]` | yes — the whole of the per-route relaxation | **yes** |
| `enforce.require_idempotency_key` | yes — C3, `428` | **yes** |
| `enforce.require_state_precondition` | yes — C4, `428` | **yes** |
| `enforce.max_body_bytes` | yes — `413` | **yes** |
| `enforce.strict_ingestion` | pinned `true`; `parse_config` refuses `false` | **yes**, for the record that it was on |
| `enforce.max_response_bytes` | no — response direction, after the verdict | no |
| `enforce.max_concurrent_requests` | no — shed in `serve` before `decide` runs | no, and see [Failure modes](#failure-modes) |
| `enforce.digest_header` | no — shapes the forwarded request, not the decision | no |
| `listen`, `upstream` | no — deployment coordinates, env-overridable | **no** |

Putting `listen` and `upstream` in the bundle would make the policy hash change when a
container moves to a different port. That is the "12h vs 720m" defect with the sign
flipped: two deployments running the identical policy would report different bundles.

### The normalization the derivation must apply

Every one of these is a place where two configs that `decide` treats identically would
otherwise hash differently. Each is a defect of the same class parallax shipped.

| what | why they are identical | canonical form |
| --- | --- | --- |
| `method = "post"` / `"POST"` | `route_matches` uses `eq_ignore_ascii_case` | uppercase |
| `path_prefix = "/v1/t"` / `"/v1/t/"` / `"/V1/T"` | `route_matches` trims trailing `/` and lowercases | lowercase, trailing `/` stripped |
| `require_parameters = ["to"]` / `[{name="to", type="string"}]` | `RequiredParam::param_type()` defaults `Name` to `String` | always the `{name, type}` form |
| `require_parameters` order | used only as a filter source; order never reaches a decision | sorted by name |
| absent `[enforce]` keys | `serde(default)` fills them | hash the **resolved struct**, never the file bytes |

And one place where order is genuinely load-bearing and must **not** be normalized:
`cfg.route.iter().find(…)` takes the *first* matching rule, so two rules that both match
a path resolve by position. `route[]` is hashed in order. The lesson from parallax is not
"position is never identity" — it is "know which", and get it wrong in either direction
and you get a confident wrong answer.

### The part config alone cannot cover

A bundle hash over configuration is not sufficient to re-derive a verdict, and this is not
a hypothetical. `transit`'s own fix rounds are the proof: the pre-fix guard forwarded
`/v1/search/../transfer` and matched no route rule against `/v1/tra%6Esfer`. Same TOML,
different verdict, different code. A record claiming its verdict is re-derivable from
`policy_bundle_hash` alone would be wrong.

The bundle therefore includes a `decide_semantics` integer alongside the config
projection. Bumping it by hand is exactly the kind of discipline that rots, so it is
pinned by a golden-decision corpus: a committed fixture of (request, expected decision)
pairs carrying the semantics version it was generated under. Any change to `decide`'s
behaviour makes that test fail, and the only way to make it pass is to regenerate the
fixture, which forces the bump. The test is the mechanism; the integer is just where the
mechanism writes its answer.

> **OPEN FORK: normalize route overrides to their effective value, or hash them as
> written.**
>
> `RouteRule::require_idempotency_key` is `Option<bool>`, resolved against the global via
> `unwrap_or`. So `None` with a global of `true`, and `Some(true)`, produce identical
> decisions for every request.
>
> - **Hash as written** — `None` and `Some(true)` are different bundles. Two operators
>   expressing the same policy get different hashes; the parallax defect, reproduced.
> - **Normalize to effective** — resolve each `Option` against the global before hashing.
>   Identical policies hash identically. The cost is that the bundle no longer records
>   *how* the policy was written, only what it does, so a diff between two bundle hashes
>   cannot be traced back to a config diff without the config.
>
> **Recommendation: normalize to effective.** The field's stated purpose is re-deriving a
> verdict, and the effective value is what produced it. The "how it was written"
> information is not lost — it is in the config file, which an auditor gets separately.

---

## `path_summary_hash`: the honest answer

C4.1.7 requires authorization to be path-aware: the evaluated context for each invocation
includes state carried from upstream invocations *in the same execution path*.
[P04](../../../papers/P04-bounded-summaries.md) is the paper attached to it, and its
finding is that the standard's own reference implementation keeps a bounded label set that
**no policy decision ever reads** — so the paper's reported null result on sweeping the
bound has a trivial explanation, and the experiment tested nothing.

`TOOLING.md` says the guard "would be the first thing that reads it". Reading the code,
that is not true today and is not a small step to make true.

**The guard has no path.** `decide(cfg, req)` is a pure function of one request and the
config. `serve` spawns a thread per admitted request, up to 256 concurrently
(`src/guard.rs:855`). There is no session, no task, no agent identity anywhere in the
request model — `hostile::Request` is method, path, headers, body. A path summary is a
fold over an ordered sequence of one agent's actions. The guard has: no agent identifier,
no ordering across its own concurrent threads, and no state that survives its own restart.

Each of those is separately fatal, and the third is the interesting one. If the summary
lives in guard process memory, **restarting the guard resets every path to empty** — which
is P04's eviction attack with no attack required. An adversary who can cause a restart, or
who simply waits for a deployment, gets a clean path. A bounded summary whose bound can be
cleared by a `SIGTERM` is not bounded, it is decorative.

So the field cannot be filled honestly by writing a fold and calling it done.

> **OPEN FORK: `path_summary_hash`. This is the fork that decides whether T3 closes five
> fields or four.**
>
> | option | what ships | what it costs |
> | --- | --- | --- |
> | **A — ship it unfilled** | the guard omits the field; `ephemeris` refuses the claim, per its own rule that a missing caller-supplied field is refused rather than defaulted. So **no record is produced at all** | T3 closes four fields, not five. `TOOLING.md`'s "18 fields after T3" becomes 17. Honest, and it stops the programme dead — the guard cannot emit a schema-valid record |
> | **B — a sentinel summary** | digest a canonical object declaring "this enforcement point holds no path state", e.g. `{"path_state":"none","reason":"stateless enforcement point"}` | the record validates and looks complete. It is P04's defect committed deliberately: a field whose digest commits to a structure nothing reads. `poc-audit` would report `ASSERTED` at best, and only if someone teaches it to recognise the sentinel |
> | **C — a real, load-bearing, sound summary** | a per-agent summary the guard maintains and **`decide` consults**, so a composed sequence can be refused. Bounded by *lattice height*, not by truncation — a monotone join over a finite label set, plus counters — so there is nothing to evict and P04's attack does not apply by construction | the guard becomes stateful. Needs agent identity (fork below), an ordering across concurrent threads, and durable state across restarts. This is not serialization; it is the research P04 asks for, and it belongs in its own spec |
> | **D — `ephemeris` computes it** | the log already holds the per-agent chain in order. The summary is a fold over the same sequence; `ephemeris` maintains it and returns the digest in the ack | it moves the field across the T2/T3 boundary, which the `ephemeris` spec explicitly draws the other way. It also makes the summary a property of the *log* rather than of the *evaluation*, which is the wrong side of C4.1.7 — the policy must have consulted it, and the policy runs here |
>
> **Recommendation: A now, C as its own designed work.** Ship the field unfilled, state
> plainly in the guard's output and in `TOOLING.md` that `transit guard` is not a
> path-aware authorization point and therefore cannot claim C4.1.7, and let the record be
> incomplete until something computes a summary a decision actually reads.
>
> A has a consequence somebody must accept: with the field absent and `ephemeris`
> refusing defaulted claims, **the pair produces no record**. That is not a bug in either
> design, it is the two designs correctly reporting that a required field of the standard
> has nothing behind it. If the programme needs a record to exist before C is built,
> resolve this by *relaxing `ephemeris`* — an explicit `absent_fields` list the log
> records and `poc-audit` reports as `UNCHECKED` — and not by inventing a value here. A
> visible gap beats implied coverage; a sentinel is implied coverage with extra steps.

---

## The verdict enum is four wide and the guard reaches two

`Decision` has two variants. The schema's `verdict` has four: `ALLOW`, `DENY`, `MODIFY`,
`ESCALATE`.

`ESCALATE` is unreachable and should be stated as such: the guard has no human-in-the-loop
path and no mechanism to suspend an action pending approval. It never emits one.

`MODIFY` is the interesting one. The schema: *"MODIFY means the dispatched action differs
from the proposed one and MUST itself be evidenced."* The guard's whole design is that the
dispatched action differs from the proposed one — it forwards the **canonical** body
rather than the wire body, strips hop-by-hop headers, rewrites `Content-Type` to
`application/json`, adds its own digest header, and forwards `normalize_target`'s decoded
path rather than the target as sent.

> **OPEN FORK: when is a guard forward `ALLOW` and when is it `MODIFY`?**
>
> - **Everything is `MODIFY`.** Defensible on the plain text, and useless: a verdict that
>   takes one value carries no information, and `ALLOW` would never appear in any record
>   this tool emits.
> - **Everything is `ALLOW`**, on the grounds that JCS canonicalization is semantics-
>   preserving and hop-by-hop stripping is required of every intermediary. Defensible, and
>   it hides a real event: `/v1/tra%6Esfer` in, `/v1/transfer` out, is a change to the
>   target the client named.
> - **A rule.** `ALLOW` when the difference is confined to (i) RFC 8785 canonicalization
>   of a body that parsed to the same JSON value and (ii) RFC 9110 §7.6.1 hop-by-hop
>   removal — both mandated transformations that preserve what was proposed. `MODIFY`
>   otherwise, which in practice means: the normalized target differs from the raw target,
>   or a non-hop-by-hop header was dropped (the client's own `X-Transit-Digest` is the
>   only one), or `Content-Type` was rewritten from a `+json` suffix type.
>
> **Recommendation: the rule.** It is the only option under which the field distinguishes
> anything, and the cases it flags — a re-encoded path, a stripped forged digest header —
> are exactly the ones an auditor should see. It costs `decide` a comparison against the
> raw request, which it already holds.

`Decision::Reject` maps to `DENY` in every case. `Reject.reason` maps to the schema's
optional advisory `reason`, already bounded and control-stripped by `sanitize` — and the
`Option<Condition>` maps to an additional claim, `transit_condition`, so that transit's own
C1–C4 finding is machine-readable inside the record rather than only in a log line.

---

## Three records per action, against a proxy that handles one cycle

C7.1.2 requires three records per intercepted action — request received (before), effect
performed (during), result returned (after) — each independently signed and linkable by one
action ID. The guard handles a request and a response. It has two moments, not three.

| record | when | `interception_point` | snapshot |
| --- | --- | --- | --- |
| **before** | after `decide`, before `forward` | `PRE_CALL_TOOL_INVOCATION` | the `ActionSnapshot` above |
| **during** | after `forward` writes the request, before the upstream responds | **no enum value exists** | the same snapshot, plus the dispatch time |
| **after** | after the upstream responds, before relaying | `POST_CALL_TOOL_RESULT` | a canonical object over the response: status, relayed header names, `body_sha256` of the response bytes |

Two findings here, both belonging in `docs/` when this lands.

**The `interception_point` enum has no value for "effect performed."** C7.1.2's
three-record axis and the eight-hook enum are described in the `ephemeris` spec as
different axes, which is right, but they are not independent: two of the three points have
a name and the third does not. `PRE_CALL_TOOL_INVOCATION` and `POST_CALL_TOOL_RESULT` are
the before and the after. There is nothing between them.

**The guard cannot witness the effect.** It witnesses that it dispatched a request. Whether
the upstream performed an effect is not observable from this side of the socket, and a
record claiming "effect performed" from a proxy is a claim the proxy has no basis for.

> **OPEN FORK: emit two records, or three.**
>
> - **Two, and declare C7.1.2 unmet.** The guard emits before and after, and its output
>   and README say plainly that the during record is not produced because this component
>   cannot observe an effect. Costs a Level-3 requirement; gains a record set where every
>   record is a fact the emitter observed.
> - **Three, with `during` meaning "dispatched".** The record carries
>   `interception_point = PRE_CALL_TOOL_INVOCATION` and an additional
>   `record_phase = "during"` claim (legal under `additionalProperties: true`), plus an
>   explicit `observed = "request_dispatched"` so nothing reads it as an effect claim.
>   Satisfies the shape of C7.1.2 and the count an auditor samples.
>
> **Recommendation: three, with `during` meaning dispatched and saying so.** The
> requirement's purpose is that the moment of dispatch is separately committed to — so
> that a forward which never returns is distinguishable from one that was never made — and
> that is a real fact the guard does observe. Emitting two and describing them as three
> would be the failure mode this programme attacks; emitting three and calling the middle
> one an effect record would be a second one. The third option, emitting three and
> labelling the middle honestly, is the only one that is neither.

The action ID linking the three is generated by the guard, once, per request — a random
128-bit value, not derived from the request, because a derived ID would make two identical
requests share an action ID and collapse two actions into one in the log.

---

## Write-before-forward, and what it does to `serve`

C7.1.3: *the gateway does not forward the action to the tool until the before record is
durably written.* Today `handle_one` calls `decide`, then calls `forward`, with nothing in
between (`src/guard.rs:947–978`). The change is one blocking call.

```
decide ──▶ claim(before) ──▶ [ephemeris: append + fsync] ──▶ ack ──▶ forward
                │                                                │
                └── no ack within the deadline ──▶ 503, and no forward ever happens
```

`ephemeris` acknowledges after `fsync` and never before, so the ack **is** the mechanism by
which the guard learns it may proceed. Nothing else needs to be verified on this side.

### The guard is fail-closed and this is where it matters

`occultation-gateway` fails open and defends that across eight tasks of review, because a
meter must not be able to take down the API it fronts. `transit guard` is the opposite by
construction — its own startup banner prints `fail-closed:` — and C7.1.3 makes the evidence
store a precondition of action release. **If `ephemeris` is unreachable, requests do not
forward.** Recorded explicitly because the fail-open culture across these repositories is
strong enough that someone would import it here by reflex; `poc-audit`'s design and
`ephemeris`'s design each had to say the same thing.

| condition | behaviour |
| --- | --- |
| `[evidence]` configured, socket absent at startup | **refuse to start.** A guard that starts without its recorder and 503s every request has already failed; failing at startup is louder and cheaper |
| ack does not arrive within the deadline | `503`, no forward. **Not `502`** — that means "upstream unreachable" and would be a lie about which component failed |
| `ephemeris` refuses the claim (missing field, malformed) | `503`, no forward, and log the refusal reason verbatim. A refused claim is a bug in this component and must not degrade into a retry loop |
| socket dies mid-stream after the before-record was acked | forward proceeds — the ack was the precondition and it was met. The during and after records are lost, and the loss is alerted (C7.6.1) |
| after-record write fails, effect already performed | relay the response anyway. Withholding it does not un-perform the effect; the action is in the log with a before and no after, which is exactly what happened. Alerted |
| `[evidence]` absent from config | claims are not emitted; the guard behaves as it does today |

Claims are opt-in by config section and, once the section is present, **not disableable
per-request and not overridable from the environment** — the same rule
`apply_env_overrides` already enforces for every `[enforce]` field, for the same reason.

### DENY records and the response path

C7.1.3 gates the *forward*. A rejection has no forward, so nothing about the response to a
refused request is a precondition of anything.

> **OPEN FORK: does the 4xx response block on the DENY record's durability?**
>
> - **Block.** C7.6.3 says in-scope actions are refused until the pipeline recovers, and a
>   refusal that is not recorded is an invisible refusal — an attacker probing the guard's
>   rules leaves no trace. Costs: every malformed request now costs an `fsync`, so a flood
>   of garbage is a write-amplification attack against the evidence store, and the store
>   filling is a fail-closed condition that takes the whole guard down.
> - **Do not block.** Respond immediately, emit the claim asynchronously, accept that a
>   crash between the two loses the denial record. Costs: exactly the invisible-refusal
>   hole, and it is the hole an attacker chooses.
>
> **Recommendation: block, with the flood accepted and measured.** The asymmetry is that a
> lost `ALLOW` record is an unevidenced effect and a lost `DENY` record is an unevidenced
> probe — and the probe is the reconnaissance phase of the attack the guard exists to stop.
> The write-amplification concern is real and its mitigation belongs at admission, not at
> the record: `max_concurrent_requests` already sheds at 256 without reading a byte or
> spawning a thread, and a shed request emits no record because `decide` never ran on it.
> That shedding is itself an unevidenced refusal, and it should be counted and reported
> rather than recorded per-request.

### Latency

C7.2.3's own commentary budgets 15 ms per action. Three records per action, each blocking
on a durable ack, is where that budget goes. `ephemeris` group-commits, so concurrent
claims share one `fsync`, and the guard's thread-per-request model feeds that naturally —
256 in-flight requests present up to 256 concurrent claims to batch. Nothing here needs a
new concurrency primitive; the existing `max_concurrent_requests` cap is also the cap on
how many claims can be waiting on one flush.

---

## Testing

Following the house pattern: each test paired with the mutation it must kill. Fully
offline — a stub `ephemeris` over a UDS in a tempdir, no network, no credentials.

| test | must fail when |
| --- | --- |
| **Bundle identity, both directions** — two configs differing only in method case, `path_prefix` trailing slash, `require_parameters` spelling (`"to"` vs `{name,type}`), ordering within `require_parameters`, and omitted-vs-explicit defaults, all hash equal; changing any *contributing* field changes the hash | a field feeding the bundle identity is specified casually — the root cause of four of parallax's five criticals |
| **Route order is load-bearing** — swapping two overlapping `route[]` entries changes the bundle hash *and* changes a decision | route order is normalized away, or the two are normalized inconsistently |
| **Deployment coordinates are not policy** — changing `listen`, `upstream`, `max_response_bytes`, `max_concurrent_requests` or `digest_header` leaves the bundle hash unchanged; changing `max_body_bytes` changes it | the bundle absorbs a field that does not produce a verdict, so moving a container reports a policy change |
| **`decide_semantics` is pinned by behaviour** — a golden corpus of (request, decision) pairs carrying its version; any change to `decide`'s output fails it | the semantics version rots into a constant nobody bumps, and `policy_bundle_hash` claims re-derivability it does not have |
| **Every request produces a snapshot** — a bodiless `GET`, a `405` on an unknown method, a `400` on a fragment target, a `413` oversized body, and a C2 unparseable payload each yield a snapshot that canonicalizes and a tagged digest | the `""` digest of `src/guard.rs:643`, or the early `reject` returns, leave a required field empty on the records an auditor most wants |
| **The un-canonicalizable case is named, not smuggled** — for a C2 rejection, `body` is `null` and `body_wire_sha256` is populated; for a valid body, the reverse | one field carries two meanings, which is the C7.7 defect turned inward |
| **`X-Transit-Digest` is unchanged** — byte-identical to what ships today for every existing guard test fixture | adding the record breaks the wire contract P02's result rests on |
| **Write-before-forward** — with the stub refusing to ack, the upstream receives **nothing** and the client gets `503` | an ack precedes durability, or a forward precedes an ack, removing C7.1.3. Asserted at the upstream, not at the guard: the only convincing form of this test is that the effect did not happen |
| **A refused claim is not a silent forward** — the stub rejects the claim as malformed; the request does not forward | a claim rejection degrades into a warning |
| **`502` is never used for an evidence failure** — the stub is unreachable, the upstream is healthy, the response is `503` | the two failure domains are collapsed and an operator debugs the wrong component |
| **Three records, one action ID** — a successful forward produces before/during/after sharing one ID; two identical concurrent requests produce two distinct IDs | the action ID is derived from the request, collapsing two actions into one |
| **`MODIFY` is reachable and `ALLOW` is not universal** — `/v1/tra%6Esfer` and a client-supplied `X-Transit-Digest` each produce `MODIFY`; a plain conforming request produces `ALLOW` | the verdict is hardcoded, or the rule collapses to one value |
| **`DENY` carries its condition** — a `428 C3` refusal produces a record whose `transit_condition` is `C3` and whose snapshot shows no `idempotency-key` in `headers_evaluated` | a denial is recorded as unexplainable, so the verdict cannot be re-derived from the record and the bundle |
| **Cross-check into `poc-audit`** — a claim this guard emits, chained by `ephemeris`, drives `field/canonical` off `UNCHECKED` against the same payload | the definition of `canonical_snapshot_hash` chosen here is not the one the auditor recomputes |
| **`path_summary_hash` is absent, and the absence is visible** — the emitted claim omits it, the guard's startup banner says it is not a path-aware authorization point, and `ephemeris` refuses the claim | a sentinel value appears, or the field is quietly defaulted, which is P04's defect committed on purpose |

The last row and the cross-check are the two that test something other than our own code.
The cross-check tests the seam between three components; the `path_summary_hash` row tests
that the programme's own ethos survived contact with a schema field it could have faked.

---

## Failure modes not covered above

**Admission shedding is an unevidenced refusal.** Past `max_concurrent_requests`, `serve`
responds `503` without reading a byte or spawning a thread (`src/guard.rs:860–869`).
`decide` never runs, so there is no snapshot, no verdict, and no record. This is correct —
the request was never intercepted, it was never admitted — but it means the evidence log
undercounts refusals, and an auditor computing a refusal rate from the log will be wrong.
Reported as a counter on the guard's own output, not as a record.

**Truncated reads and framing refusals are also unevidenced.** `Transfer-Encoding`,
`Connection: upgrade`, invalid UTF-8 and oversized bodies are all refused inside
`handle_one` before `decide` is called. Options are to hoist these into `decide` so they
produce records, or to accept the gap. This design accepts it and states it, on the
grounds that they are transport framing failures rather than policy decisions — but the
line between "not admitted" and "denied" is now load-bearing for a compliance number, and
it deserves to be drawn deliberately rather than by where the code happens to return.

**Where do `agent_id` and `initiating_user` come from?** The `ephemeris` contract makes
them caller-supplied, and the guard is the caller. Nothing in `hostile::Request` carries
either. This is not a T3 field by the roadmap's count — both are T6 — but the claim cannot
be assembled without them.

> **OPEN FORK: the source of `agent_id` and `initiating_user`.**
>
> - **Static config.** One guard, one agent. Simple, honest, and wrong for any fleet: a
>   shared guard in front of a tool serves many agents.
> - **A request header** (`X-Agent-Id`). Matches how a sidecar deployment actually works,
>   and is **attacker-controlled**: the agent asserts its own identity to the component
>   whose entire job is not to trust the agent. C7.1.1 requires the gateway to hold the
>   only path from agent to tools; it does not make the agent's self-assertion true.
> - **Refuse.** The guard emits claims only when identity arrives from a source it can
>   authenticate — a client certificate, or `parallax-proxy`'s verified RA-TLS peer, which
>   already exists in this programme and already establishes a workload identity.
>
> **Recommendation: static config now, RA-TLS peer identity as the real answer.** A header
> is the option that looks like it works and produces a record whose identity fields mean
> nothing, which is precisely the class of defect `poc-audit` was built to find. Static
> config is honest about the one-agent-per-guard limitation. The composition with
> `parallax-proxy` is the deployable path this programme already has — `TOOLING.md` calls
> it "the one place an operator gets a real, end-to-end, verified property" — and it is
> where the guard should get an identity it can stand behind. That composition is also the
> unresolved fail-open/fail-closed conflict, so it needs its own spec regardless.

---

## Risks

**The `ephemeris` contract and this design disagree about `path_summary_hash`.** That spec
lists it as caller-supplied and mandatory, with defaulting explicitly refused. This spec
concludes the caller cannot supply it. Neither is wrong; together they mean no record is
produced. Somebody has to resolve it, and the resolution belongs in `ephemeris` (an
explicit absent-field mechanism) rather than here (a fabricated value).

**Two digests in one record.** The recommended split — snapshot digest in
`canonical_snapshot_hash`, body digest in an additional claim — is a shape a careless
verifier will get wrong. Mitigated by naming the additional claim unambiguously and by the
`poc-audit` cross-check, and not by removing one of them, because each has a consumer.

**`transit` gains a dependency on `ephemeris`.** A research tool that was fully offline and
self-contained now optionally speaks to another repository's socket. Mitigated by making
the whole thing opt-in behind `[evidence]` and behind a cargo feature, so the default build
and the existing 100+ guard tests run unchanged, following `parallax-attest`'s pattern for
its TEE paths.

**Version pinning across repositories.** Same mitigation as `poc-audit` and `ephemeris`:
pin tags, and let the cross-check test fail loudly when a pinned version's behaviour moves.

---

## Build order

1. `ActionSnapshot` — construction, canonicalization, tagged digest, for every request
   shape including the ones that reject early. Pure, testable, emits nothing. End state:
   the "every request produces a snapshot" and "un-canonicalizable case is named" tests
   pass, and `X-Transit-Digest` is byte-identical to before.
2. `policy_bundle_hash` — the canonical projection, the normalization table, the
   `decide_semantics` integer and its golden corpus. End state: both-directions identity
   tests pass. Nothing is emitted yet.
3. The verdict mapping, including the `MODIFY` rule and the `transit_condition` claim.
4. The claim type and the UDS client, with a stub `ephemeris` in tests. Before-record only.
   End state: write-before-forward holds and is asserted at the upstream.
5. The during and after records, the action ID, and the response snapshot.
6. The failure matrix — `503` versus `502`, refuse-to-start, the alerting path.
7. The `poc-audit` cross-check, which requires released tags of both other repos.

Steps 1 and 2 are the whole of the work that is genuinely this component's, and neither
requires `ephemeris` to exist. `path_summary_hash` is not in this list, deliberately.

---

## Open forks, collected

For whoever resolves them. Each is stated in full above.

| # | fork | recommendation |
| :--: | --- | --- |
| 1 | What `canonical_snapshot_hash` digests: body / constructed snapshot / both | **both** — snapshot in the field, body digest as an additional claim, `X-Transit-Digest` unchanged |
| 2 | The scope of `target_resource` | upstream-qualified path, query excluded and committed inside the snapshot |
| 3 | Normalize route overrides to their effective value, or hash as written | **normalize to effective** |
| 4 | `path_summary_hash`: unfilled / sentinel / load-bearing summary / computed by `ephemeris` | **unfilled now**, load-bearing summary as its own designed work, and relax `ephemeris` rather than fabricate a value |
| 5 | When is a forward `ALLOW` and when `MODIFY` | the rule: `ALLOW` only for mandated semantics-preserving transformations |
| 6 | Two records or three, given no enum value for "effect performed" | **three**, with the middle one meaning "dispatched" and labelled as such |
| 7 | Does a `DENY` response block on the record's durability | **block**; mitigate the flood at admission, not at the record |
| 8 | Where `agent_id` and `initiating_user` come from | static config now; RA-TLS peer identity as the real answer; **never a request header** |
