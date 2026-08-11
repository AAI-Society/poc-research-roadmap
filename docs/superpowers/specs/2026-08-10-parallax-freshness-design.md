# Design — T5: freshness, the challenge, and re-checking the claim

**Date:** 2026-08-10 · **Status:** approved, forks resolved 2026-08-10, ready for implementation planning · **Repo:** extension to
[`parallax`](https://github.com/AAI-Society/parallax) —
no new repository

---

## Forks, resolved 2026-08-10

All ten are closed. Each block below is retained with its reasoning intact.

| fork | resolution |
| --- | --- |
| **A — what `measurement` denotes** | **The MRTD: `sha-384:<96 hex>`.** Any other shape is refused for `platform: INTEL_TDX` as a *record* error, not a comparison failure. This makes the standard's own `hardware-attested.json` invalid — its value is `sha-256:` + 64 hex, 32 bytes, and a TDX MRTD is 48 — and that ships as a finding filed upstream rather than as a reason to weaken the check. **A second, separate defect goes with it:** the schema's `digest` pattern does not tie the tag to the length, so `sha-384:` followed by 64 hex validates. |
| **B — MRTD or RTMR3** | **Both**, using the already shipped and hardware-validated `expected_rtmr3`. **This lands as a correction to `parallax` before the offline path is built.** Today `parallax-attest` extends RTMR3 with the workload digest and nothing ever reads it — `src/derive.rs:452` says so outright — so the pair attests the workload and the gate does not check it. Building the offline path first would enshrine that defect in a second place. |
| **C — does the record carry the quote** | **Not in T5.** T5 ships comparison-only, and splits the verdict from day one: `ESTABLISHED (compared)` versus `ESTABLISHED (re-verified)`. Carrying the quote is a schema addition and belongs to T2, which already holds it for C7.2.4 key binding. The split exists so the thin verdict can never be mistaken for the strong one — which is exactly the conflation that produced `TOOLING.md`'s † correction. |
| **D — unit of the bound** | Time only, `max_attestation_age`, named so `max_actions_per_attestation` is additive. The action counter is per-attester state nothing currently holds. |
| **E — unknowable age** | `require_fresh = true\|false`, default `false`, mirroring `require_reference_values`. An unmeasurable attestation is not a stale one, and refusing by default would break every deployment of the shipped pair on upgrade. |
| **F — what `--as-of` defaults to** | Required, no default. `SystemTime::now` stays in the binary where it already is; an operator who wants now writes `--as-of now`. |
| **G — freshness mechanism** | **Epoch by default**, folding a published epoch into `report_data[32..64]`; the per-connection challenge stays reachable because P03's adaptive-refresh question needs it. Epoch is one quote per interval regardless of traffic, and it mechanizes C7.2.3 — the declared interval and the enforced one become one number. **Stated honestly: an epoch bounds an honest attester only.** A compromised one replays within its epoch. |
| **H — who issues the `nonce`** | **The caller.** `ephemeris`'s design has been corrected: `nonce` moved to the caller-supplied column and a claim without one is refused. A challenge minted by the party being challenged defeats nothing. |
| **I — layout versioning** | A `GateConfig` policy field. Configuration that participates in what was verified belongs in configuration, where it is visible and compared — the same reasoning as `RootCa::Custom` carrying a whole PEM. |
| **J — where the offline path is invoked** | `parallax replay` as a default-build subcommand, **and** `poc-audit` calling the library. Not `parallax-proxy --replay`, which would pull `reqwest` and `rustls` in to read a file. |

---

## Why

`parallax-proxy` verifies a live TDX quote inside a TLS handshake. Nothing verifies the
`measurement` field of an evidence record against reference values, and nothing checks
that the record is recent or that its `nonce` was ever chosen by anybody. Those are
three separate holes and they share one cause: every attestation tool in this programme
was built to observe a handshake, and a record is what is left over after the handshake
is gone.

T5 emits no field. It makes four existing ones mean something — `iat`, `nonce`,
`platform`, `measurement` — and in `poc-audit`'s registry those are the rows currently
reading `Unaudited("issuance time is out of scope")`,
`Unaudited("freshness against a challenge is out of scope")`, and two `ASSERTED`s
(`poc-audit/src/registry.rs:23`, `:25`; `poc-audit/src/field/attestation.rs:45`, `:193`).
Success is those four rows changing, and nothing else in the table moving.

## Scope

**In:** an offline re-verification path for a record's measurement claim; a declared
staleness bound on `iat` enforced in both the live proxy and the offline path; nonce
issuance and round-trip verification; the seams in `parallax` that make all three reuse
the shipped comparison rather than a second copy of it.

**Out, deliberately:**

- **A second verifier.** Every cryptographic check runs through
  `parallax::verify::verify_quote`. If the offline path ever grows its own quote parser,
  the design has failed.
- **Fetching anything.** No PCCS call, no `reference_values_uri` fetch, no time-authority
  call. `poc-audit` already refuses to fetch the URI a record names
  (`poc-audit/src/reference_values.rs:6`) and this inherits that line.
- **Emitting a record.** T5 checks; T2 produces. A tool that read a record and wrote a
  better one would be signing a "you passed" token, which is the overclaim
  [`poc-audit`'s design](2026-08-09-poc-audit-design.md#scope) rules out.
- **External time anchoring (C7.2.2).** A staleness bound compares `iat` against a time
  the operator supplies. Whether that time is trustworthy is an RFC 3161 or
  transparency-log question, and it is
  [P07](../../../papers/P07-evidence-continuity.md)/T2 territory. What T5 must not do is
  imply it has been answered — see [What cannot be done](#what-cannot-be-done).

## What is actually there

Read before designing, so the reuse claims below are checkable.

| thing | where | what it does today |
| --- | --- | --- |
| `verify_quote` | `src/verify/chain.rs:292` | verifies a quote against collateral **as of an injected `now_secs`**; returns a `VerificationOutcome` carrying `mr_td`, `rt_mrs`, `report_data`, and the collateral's issue/expiry dates |
| `check_binding` | `src/verify/binding.rs:129` | `report_data[..32] == SHA-256(SPKI)` **and bytes 32..64 all zero** |
| `quote_from_cert` | `src/verify/quote.rs:87` | pulls the quote out of an X.509 extension, OID as a parameter |
| `derive` | `src/derive.rs:399` | turns an outcome into a residual trust set, or `Err(Refutation::Measurement)` |
| `reference_check` | `src/derive.rs:232`, **private** | the actual MRTD comparison: `NotConfigured` / `Matched` / `NoMatch` |
| `decide` | `src/proxy/gate.rs:313` | pure: outcome + `GateConfig` + `Policy` → `Decision`. Step 5 of the pipeline is its first statement, `derive(outcome, &cfg.derive)` |
| `parse_mrtd` | `src/proxy/config.rs:369`, **private** | 96 lowercase hex characters → `[u8; 48]` |
| `ProxyConfig::load` | `src/proxy/config.rs:259` | the only parser of `[reference_values].mrtd` |
| `Clock` / `FixedClock` | `src/proxy/serve.rs:78`, `:84`, behind `fetch-collateral` | the injected clock; `SystemClock` lives only in `src/bin/parallax-proxy.rs:60` |
| `expected_report_data` | `src/ratls.rs:45` | what the attester writes: SHA-256(SPKI), zero tail |
| `prepare` | `src/attest/serve.rs:234` | extends RTMR3, generates a key, requests **one** quote, mints **one** certificate — at process start, once |

Four facts from that reading constrain everything downstream, and each was a surprise.

**A TDX quote carries no timestamp.** `VerificationOutcome` has eleven fields and none of
them dates the quote. `collateral_issued_at` and `collateral_expires_at`
(`src/verify/chain.rs:128`, `:146`) date the *collateral*, which is Intel's TCBInfo
cadence — about 30 days on the committed fixture
(`the_collateral_validity_window_does_not_depend_on_the_current_time` pins 2 590 799 s).
They say nothing about when the quote was produced. **Freshness of a quote cannot be read
off the quote.** It can only come from a challenge the verifier chose, or from a
timestamp somebody else attaches.

**`parallax-attest` quotes once, ever.** `prepare` runs before the listener binds and the
certificate it mints is served for the process lifetime. `mint_with_key`
(`src/attest/cert.rs:31`) sets neither `not_before` nor `not_after`, so the certificate's
validity window is rcgen's default and dates nothing either. The age of the attestation a
`parallax-proxy` connection rests on is therefore the sidecar's uptime, unbounded and
invisible to the verifier. That is exactly the C7.2.3 exposure window, undeclared.

**`report_data` is full.** All 64 bytes are spoken for: 32 of digest and 32 that
`check_binding` *requires* to be zero. There is no space for a nonce without changing the
layout, and `check_binding`'s own documentation anticipates this and says what to do —
"a rule relaxed later breaks no deployment, whereas a rule tightened later breaks every
attester", and "if parallax ever has to talk to a second convention, this is the function
that grows a policy argument" (`src/verify/binding.rs:85`, `:110`).

**A `parallax` deployment does not name reference values.** `MechanismSpec::TeeAttestation`
carries `reference_values: String` (`src/deployment.rs:82`) and the shipped example writes
`reference_values = "did:web:rvp.example.org"` (`:349`). That is a *principal* — who
publishes them — not a digest. The only place in the repository holding actual MRTD bytes
is `[reference_values].mrtd` in a proxy config. TOOLING.md's phrase "the reference values a
`parallax` deployment names" is imprecise, and the imprecision matters: it names a party,
and the tool needs bytes.

---

## Part 1 — Offline re-verification of the measurement claim

### The two acts, stated apart

Verifying a live quote establishes *this connection terminates inside a trust domain
running code whose MRTD is one of these*. Re-checking a record establishes *the value
written in this field is one of these*. The second is strictly weaker, and pretending
otherwise is the failure this whole part exists to avoid. What T5 adds is not a stronger
claim; it is a claim made against **the same bytes the gate admits on**, so that the audit
and the enforcement point cannot drift.

`poc-audit --reference-values` already compares strings
(`poc-audit/src/field/attestation.rs:90`). It reaches `ESTABLISHED`. What it compares
against is a bespoke `{"measurements": [...]}` JSON file the operator writes separately
from the proxy config that actually gates traffic, using a comparison
(`ReferenceValues::contains`, `poc-audit/src/reference_values.rs:47`) that is a second
implementation of `reference_check`. Two lists and two comparisons is the drift this
programme names as its own defect pattern. **T5's contribution to `measurement` is the
seam, not the verdict.**

### The seam

Three changes in `parallax`, each promoting an existing private function rather than
adding logic:

1. **`parse_mrtd` becomes `pub`** (`src/proxy/config.rs:369`). It is the one place 96 hex
   characters become 48 bytes, and it already refuses non-ASCII, wrong lengths and the
   `+0` hazard that `parse_image_digest` documents.
2. **`reference_check` and `ReferenceCheck` become `pub`, re-signatured**
   (`src/derive.rs:223`, `:232`) from `(&VerificationOutcome, &DeriveConfig)` to
   `(&[u8; 48], &[[u8; 48]]) -> ReferenceCheck`. `derive` calls the new form, so there is
   still exactly one comparison in the crate and the live gate keeps running through it.
   This is the whole point: the offline path cannot construct a `VerificationOutcome`
   honestly — it has no quote — so the comparison must be callable without one.
3. **`ProxyConfig::load` is the reference-value source** (`src/proxy/config.rs:259`). The
   offline path takes `--proxy-config proxy.toml` and reads `gate.derive.reference_values`.
   No new file format. If the operator changes what the proxy admits, the audit changes
   with it, in the same commit.

`poc-audit`'s `field/attestation` then calls `parallax::derive::reference_check` through
a `--proxy-config` context field, and its `ReferenceValues` file becomes the fallback for
operators with no proxy rather than the primary path.

Nothing else moves. `derive`, `decide`, `evaluate_verified` and `verify_quote` are called,
not modified.

### The type mismatch, which is not a detail

The schema's `measurement` is `#/$defs/digest`:
`^(sha-256|sha-384|sha-512|sha3-256):[0-9a-f]{64,128}$`. The standard's own strongest
positive vector writes
`"measurement": "sha-256:a1d0bdcf…"` — 32 bytes. An MRTD is 48 bytes, and `parse_mrtd`
demands 96 hex characters. **The standard's best hardware-attested vector carries a
measurement that cannot be an Intel TDX MRTD**, and `poc-audit`'s existing `ESTABLISHED`
path passes only because it compares two strings without asking what either denotes.

Worth recording separately: the digest pattern does not tie the algorithm tag to a length,
so `sha-384:` followed by 64 hex characters validates. That is a schema defect and it
belongs upstream in `ov-poc-standard`, not worked around here.

> **RESOLVED — FORK A — what `measurement` denotes.**
>
> - **A1. `sha-384:<96 hex>` is the MRTD**, and the tool refuses any other shape for
>   `platform: INTEL_TDX` as a *record* error, not a comparison failure. Honest and
>   mechanically checkable; makes the standard's own vector invalid.
> - **A2. `measurement` is a platform-opaque code-identity digest**, and the mapping from
>   it to an MRTD is deployment-specific. Preserves the vector; makes the comparison
>   meaningless, because two opaque strings matching says nothing about which register
>   was measured.
> - **A3. Carry both** — `measurement` stays as the schema has it and a new
>   `submods.attestation.mrtd` carries the 48 bytes. Correct and costs a schema change,
>   which T5 was scoped not to need.
>
> **Recommend A1**, and file the vector as a finding against the standard. The whole
> purpose of the row is that the field denotes something a verifier can compare; A2 keeps
> the row green by making it vacuous, which is the exact move C7.7's commentary warns
> about ("the natural next step is to relax the comparison until interoperation works").
> A1 also makes `rt_mrs` reachable later: RTMR3 is where `parallax-attest`'s workload
> measurement lands, and MRTD is firmware.

> **RESOLVED — FORK B — MRTD or RTMR3.**
>
> `parallax-proxy` compares `mr_td` and nothing else (`src/derive.rs:235`), while
> `parallax-attest`'s entire contribution is extending **RTMR3** with the workload digest
> (`src/ratls.rs:78`, `expected_rtmr3`). `derive`'s own comment says it plainly: "`derive`
> does not read `o.rt_mrs`, and neither does anything else in this crate yet"
> (`src/derive.rs:452`). So the shipped pair attests the workload and the shipped gate
> does not check it.
>
> - **B1. Keep comparing MRTD only.** Status quo; T5 stays small; the workload digest
>   remains unchecked by anything.
> - **B2. Compare MRTD and RTMR3**, with RTMR3's expected value computed by the already
>   shipped and hardware-validated `expected_rtmr3`
>   (`expected_rtmr3_reproduces_what_the_hardware_reported`, `src/ratls.rs:142`).
>
> **Recommend B2**, as a separate change landing before the offline path, because it is a
> defect in the live gate that T5 would otherwise inherit and enshrine. It is also the
> only version under which `measurement` means "your code" rather than "your firmware".

> **RESOLVED — FORK C — does the record carry the quote?**
>
> Without a quote there is nothing cryptographic to re-verify: the offline path is a
> string comparison and its verdict should say so in those words.
>
> - **C1. No.** T5's offline path is comparison only. Cheap; the `ESTABLISHED` it produces
>   is thin.
> - **C2. Yes, optionally** — a `submods.attestation.evidence` member carrying the
>   base64 quote and the collateral bundle, which `ephemeris` would populate since it
>   already holds the quote for C7.2.4 key binding. The offline path then runs
>   `verify_quote(quote, collateral, iat, root, refresh)` → `check_binding` →
>   `decide` with a `FixedClock(iat)`, and reaches the same `Decision` the live proxy
>   would have reached, from a file. Every function in that chain is already pure and
>   already takes its time as a parameter.
>
> **Recommend C2 as the target and C1 as the shipping shape of T5**, with the verdict
> vocabulary distinguishing them from the start: `ESTABLISHED (compared)` versus
> `ESTABLISHED (re-verified)`. C2's schema addition is T2's to make; T5 should not block
> on it, and should not pretend C1 is C2.

---

## Part 2 — The staleness bound on `iat`

C7.2.3 requires the *claim* to state a maximum attestation refresh interval, and requires
the mechanism to "refresh within it or refuse to continue". Neither half exists. The
39.5 ms quote cost means amortization is compulsory; the requirement is that the
amortization window be written down.

### How the bound is declared

A `[freshness]` table in the proxy config, parsed by `ProxyConfig::load` alongside the
tables already there:

```toml
[freshness]
max_attestation_age = "15m"   # C7.2.3, as a duration
```

Parsed with `Latency::parse` (`src/latency.rs:23`) and rendered with `Latency::label`, so
it has one spelling in output like every other duration in the crate. `"never"` is refused
with the same reasoning `cache_ttl` already refuses it (`ConfigError::NeverIsNotABound`,
`src/proxy/config.rs:79`): `Never` is the lattice's top element, so the most
cautious-looking spelling means no bound at all. There is no spelling here for "do not
check".

The declared value must also reach the residual trust set, or it is a number in a file
that nothing depends on. `derive` gains one assumption — the attesting host is trusted
that its measured environment has not changed since the quote — carrying
`Latency::Bounded(max_attestation_age)` and `Impact::Soundness`. This is the entry that
makes the declared interval visible in the Residual Trust Manifest, which is where an
auditor reading C7.2.3's "the declared interval" would look.

Note the interaction with `pcs_detection_bound` (`src/derive.rs:281`): the collateral
bound is the *join* of measured and declared. The attestation-age bound has no measured
counterpart, because a quote carries no time. It is declared and unverified, and its
assumption text must say so.

### What the tool does at the boundary

Two paths, two behaviours, and the difference is deliberate.

**Live proxy.** The proxy cannot compute the age of a peer's quote — see the four facts
above — so today it cannot enforce this at all against an unmodified `parallax-attest`.
Enforcement requires either a challenge (Part 3) or an attester that publishes its quote's
minting time. With one of those, the boundary is: `age > max_attestation_age` refuses with
`REFUSAL_STATUS`; `age == max_attestation_age` allows. Inclusive, stated, and tested, so
"at the boundary" is not decided by an off-by-one.

**Offline path.** `iat` is compared against an evaluation time and the verdict is a row,
not a refusal: `ESTABLISHED` inside the bound, a new reason on `ASSERTED` outside it, and
exit 1 through `poc-audit`'s existing `DIVERGES` rung if the record is *newer* than the
evaluation time — a record issued in the future is not stale, it is wrong.

### What `iat` can and cannot establish

`iat` is written by the issuer. Comparing it against an evaluation time detects a record
that has aged; it detects nothing about a record that was back-dated, because the same
party wrote both the timestamp and the signature over it. The tool must say this in the
reason text of every finding it produces on this row. C7.2.2's external anchoring is the
requirement that would fix it, and nothing in this programme implements it.

There is a second gap, sharper: `iat` is the *record's* issuance time, not the *quote's*.
A record issued one second ago can rest on a quote taken six days ago, and nothing in the
record distinguishes those. Under C2 the quote is present and the gap closes; under C1 the
bound on `iat` bounds the record's age and says nothing about the measurement's age, which
is the quantity C7.2.3 is actually about. **T5 must not report a fresh `iat` as a satisfied
C7.2.3.**

> **RESOLVED — FORK D — the unit of the bound.** C7.2.3 says "the longest period, **or** the
> largest number of actions".
>
> - **D1. Time only.** One field, enforceable by anything holding a clock.
> - **D2. Actions only.** Matches the amortization arithmetic P03 asks for
>   (actions per interval × probability of change × damage per action) and is what a
>   deployment budgeting against 39.5 ms actually reasons about. Requires a counter that
>   survives across the proxy and the attester, which neither has.
> - **D3. Both, whichever binds first.**
>
> **Recommend D1 for T5, with the config key named so D3 is additive**
> (`max_attestation_age`, leaving room for `max_actions_per_attestation`). D2's counter is
> per-attester state that only the attester can hold, and adding cross-process counting to
> close a row is disproportionate. Record D2 as the thing P03 must answer before the
> guidance C7.2.3 lacks can be written.

> **RESOLVED — FORK E — what the proxy does when it cannot determine age at all.**
>
> Against an unmodified attester, age is unknowable. That is not a stale attestation; it
> is an unmeasurable one.
>
> - **E1. Refuse.** Consistent with the module's "fails closed, everywhere"
>   (`src/proxy/mod.rs:15`). Breaks every deployment of the shipped pair on upgrade.
> - **E2. Allow with a warning**, using the existing `warnings` mechanism
>   (`src/proxy/gate.rs:377`), which already exists precisely to say "an allow is not a
>   clean bill of health".
> - **E3. Operator's choice**, `require_fresh = true|false`, mirroring
>   `require_reference_values` (`src/proxy/config.rs:211`), default `false`.
>
> **Recommend E3.** It is the same shape as the decision the crate already made about
> reference values, for the same reason: refusing by default makes the tool
> undeployable against every peer that exists today, and allowing silently is how a
> deployment believes something it has no evidence for. E3 also gives the warning text
> somewhere to name the fix.

> **RESOLVED — FORK F — what the offline path evaluates `iat` against.**
>
> - **F1. `--as-of <rfc3339>`, required.** No default. Nothing is read from the system
>   clock anywhere, including the binary. Reproducible by construction.
> - **F2. `--as-of` optional, defaulting to the system clock in `main`.** Convenient;
>   makes the common invocation non-reproducible and makes "this record was fine
>   yesterday" a support conversation.
>
> **Recommend F1.** The crate's existing discipline is that `SystemTime::now` appears only
> in `src/bin/parallax-proxy.rs:60`, and a required flag keeps it from appearing anywhere
> else. An operator who wants now can write `--as-of now`, parsed in the binary.

---

## Part 3 — Nonce issuance

C7.1.4's `nonce` is a relying-party challenge, and the schema says so: "Binds the token to
one request and defeats replay." Nothing in this programme issues one. The standard's own
positive vector carries `"nonce": "n-00000001"`, which is a counter somebody typed.

### Why it cannot be dropped into the existing handshake

The proxy's peer presents a certificate minted before the connection existed. There is no
point in the RA-TLS exchange at which a verifier's challenge reaches the attester before
the quote is produced, and `report_data`'s 64 bytes are fully committed. So nonce issuance
is not a `parallax-proxy` change. **It necessarily touches `parallax-attest`, which puts
T5 outside the "extension to `parallax-proxy`" scope TOOLING.md gives it.** That scope
should be corrected rather than worked around.

### The layout

`report_data` grows a second half:

```
report_data[ 0..32] = SHA-256(SPKI)          unchanged
report_data[32..64] = SHA-256(challenge)     currently required to be zero
```

`check_binding` grows a policy argument, which is what its own documentation says should
happen when a second convention arrives (`src/verify/binding.rs:110`). The zero-tail rule
stays the default; the nonce layout is the second policy; a peer speaking one to a verifier
expecting the other is refused with a message naming both, exactly as
`BindingError::TrailingBytes` already does. `expected_report_data` (`src/ratls.rs:45`)
grows the matching constructor so the two sides keep reading one definition — the reason
`ratls.rs` exists.

### Delivery, and its cost

The attester exposes a challenge endpoint. The verifier POSTs a challenge, the attester
requests a fresh quote over the new `report_data` via `request_quote`
(`src/attest/tsm.rs:85`), and returns quote plus certificate. Round trip verification:
the verifier recomputes `SHA-256(challenge)`, compares it to `report_data[32..64]`, and
checks that the challenge is one it issued, has not seen returned before, and has not
expired.

That costs 39.5 ms per challenge, which is the number that started P03. A per-connection
challenge puts a full quote in every connection setup. That is exactly why C7.2.3 exists,
and it is why the challenge is not the default.

> **RESOLVED — FORK G — the freshness mechanism.** RFC 9334 §10 gives two; this is the choice.
>
> - **G1. Per-connection nonce.** Strongest: every connection carries evidence produced
>   after the verifier spoke. Costs 39.5 ms per connection and makes the attester's
>   quoting rate a function of client traffic — a denial-of-service surface on the
>   protected service, in the same shape `DEFAULT_MAX_CONNECTIONS` already guards against
>   (`src/proxy/config.rs:228`).
> - **G2. Epoch-based.** The attester re-quotes every `max_attestation_age`, folding a
>   published epoch value into `report_data[32..64]`. The verifier accepts a quote whose
>   epoch is within the declared bound. Cost is one quote per interval regardless of
>   traffic. This *is* C7.2.3's declared interval, mechanized: the declaration and the
>   enforcement become the same number.
> - **G3. Both** — epoch by default, challenge available per connection for a caller that
>   asks.
>
> **Recommend G2 as the default and G3 as the shape.** G2 is the only option whose cost an
> operator can budget, and it converts the declared interval from a promise into something
> the verifier observes. G1 must remain reachable because P03's open question 3 —
> adaptive refresh, quote before an irreversible action — is unanswerable without it.
>
> G2's honest cost: an epoch value published by the operator is chosen by the operator, so
> it bounds staleness against an *honest* attester and does not defeat a replaying one.
> Only a value from outside the operator's control does that, which is C7.2.2 again, and
> the assumption belongs in the trust set with `Impact::Soundness` rather than in a
> footnote.

> **RESOLVED — FORK H — who issues the `nonce` in a record.**
>
> A live handshake has an obvious relying party. A record does not. [T2's
> design](2026-08-10-ephemeris-design.md#what-the-claim-carries-and-what-ephemeris-adds)
> lists `nonce` among the fields **`ephemeris` adds** — the producer minting its own
> challenge, which is the issuer challenging itself and defeats no replay at all. That is a
> direct conflict with C7.1.4 and with the schema's own description, and it is in a design
> already written.
>
> - **H1. `ephemeris` mints it** (as designed). Then `nonce` is a uniqueness token, not a
>   challenge, and T5's honest verdict on the row is `ASSERTED` forever.
> - **H2. The caller supplies it**, moving `nonce` to the caller-supplied column of T2's
>   table. Correct per C7.1.4; means `transit guard` must obtain a challenge from whoever
>   it is producing evidence for, and nothing does that today.
> - **H3. Two fields** — a producer-minted uniqueness token and an optional
>   relying-party challenge, distinguished in the schema.
>
> **Recommend H2, and amending T2's design before it is built.** A field whose stated
> purpose is defeating replay, minted by the party a replay would benefit, is worse than an
> absent field: it validates. This fork is the highest-consequence one in this document
> because it changes a spec that is about to be implemented.

> **RESOLVED — FORK I — layout versioning.**
>
> - **I1. A `GateConfig` policy field**, `report_data_layout = "spki" | "spki+challenge"`,
>   with the attester configured to match. Simple; a mismatch is an operator error caught
>   at the first connection.
> - **I2. Self-describing** — a byte of the tail tags the layout. Removes the
>   configuration; spends a byte of a fully committed field; and a tag inside the region
>   whose meaning it describes is circular under an attacker who chooses the tail.
>
> **Recommend I1.** `RootCa::Custom` carries a whole PEM rather than a label for the same
> family of reasons (`src/verify/chain.rs:8`): configuration that participates in what was
> verified belongs in the configuration, where it is visible and compared.

---

## Time and randomness discipline

The crate's rule is that time is injected everywhere a test can reach, with
`SystemTime::now` appearing only in `src/bin/parallax-proxy.rs:60`. T5 does not weaken it
and extends it to a second ambient input.

- `Clock` and `FixedClock` (`src/proxy/serve.rs:78`) **move to the default build**. They
  sit behind `fetch-collateral` today only because `serve` does, and the offline path needs
  them in a build that links no HTTP client. This is a file move, not a change.
- Every new function takes `now_secs: u64`. The freshness comparison, the nonce expiry
  sweep and the `iat` check are all pure functions of their arguments, testable the way
  `decide` is testable — by construction rather than by standing up a server.
- **A nonce is randomness, and randomness gets the same treatment as time.** A
  `Challenges` trait with a `FixedChallenges` test implementation, so a replay test can
  issue the same challenge twice deliberately. The production implementation lives in the
  binary, beside `SystemClock`. A CSPRNG called from library code would be the same defect
  as a clock read from library code: an input the test cannot control, in the one place the
  test most needs to.
- The issued-challenge store is keyed by challenge with an issue time, swept against the
  injected clock. Single-use is enforced by removal on first successful round trip, and
  the test that matters is that the second presentation of the same challenge is refused.

---

## Where this lives

`parallax` ships four binaries (`parallax`, `parallax-proxy`, `parallax-attest`,
`fetch-collateral`; `Cargo.toml:14`–`:53`). **A fifth is not proposed.**

The live half — the `[freshness]` table, the challenge issuance, the round-trip check — is
`parallax-proxy` and its config, plus the attester's endpoint in `parallax-attest`. Both
extend binaries that already exist.

> **RESOLVED — FORK J — where the offline path is invoked.**
>
> - **J1. `parallax replay <record.json> --proxy-config <p.toml> --as-of <t>`** — a new
>   subcommand on the default-build binary, beside `solve`, `compare`, `check`, `tiers`
>   and `explain`. Links no HTTP client, no TLS stack. `parallax check` already means
>   "evaluate a manifest against a policy", so the new verb must not be `check`.
> - **J2. `parallax-proxy --replay <record.json>`** — reuses `ProxyConfig::load` in situ.
>   But that binary requires `fetch-collateral`, so an offline re-verification would pull
>   in reqwest and rustls to read a file. That is the opposite of the argument
>   `Cargo.toml:79`–`:101` makes for the feature existing at all.
> - **J3. No parallax-side CLI**; `poc-audit` calls the library. Fewest moving parts;
>   leaves `parallax` unable to demonstrate its own new capability.
>
> **Recommend J1 plus J3** — the subcommand exists so the capability is reachable and
> testable in the default build, and `poc-audit` calls the same library functions rather
> than shelling out. J2 is ruled out on the dependency argument the crate has already
> written down.

---

## What cannot be done

Stated because a design that omits this is the overclaim the programme exists to attack.

- **A record with no quote cannot be cryptographically re-verified.** Under fork C1 the
  measurement verdict is a comparison, and its reason text must use that word.
- **`iat` cannot be checked against anything but a supplied time.** A back-dated record is
  indistinguishable from a timely one to this tool. C7.2.2 anchoring is the fix and is not
  in scope.
- **A fresh `iat` does not satisfy C7.2.3**, which is about the age of the *measurement*.
  Only fork C2 closes the gap.
- **Nonce round-trip verification requires a live peer.** Offline, the most that can be
  said about a record's `nonce` is whether it is one the verifier's own issuance log
  recorded — which means the verifier kept a log, and only for records it challenged. For
  every other record, `nonce` stays `ASSERTED`. It cannot be otherwise: freshness is a
  property of an interaction, and a file is not one.
- **An operator-published epoch is chosen by the operator.** G2 bounds staleness against an
  honest attester only.
- **Nothing here detects a mid-session environment change.** P03's open question 2 —
  whether a cheap continuous freshness mechanism exists at all — is untouched. T5 bounds
  and declares the window; it does not shrink it.

---

## Testing

Fully offline, no network, no TEE, against the committed
`tests/fixtures/gcp-c3-tdx` quote and `tests/fixtures/gcp-c3-rtmr`.

| test | must fail when |
| --- | --- |
| **One comparison, two callers** — the same MRTD and the same reference values drive `decide`'s refusal and the offline path's verdict to the same answer, across matched / no-match / unconfigured | a second comparison is written, or the two drift |
| **Config is the only source** — an MRTD added to `[reference_values].mrtd` changes the offline verdict with no other edit | the offline path grows its own reference-value file and the two can disagree |
| **Shape refusal** — a `sha-256:` measurement against `platform: INTEL_TDX` is a record error naming the 48-byte requirement, not a `NoMatch` | fork A1 is implemented as a silent mismatch, so a wrong-length digest reads as the wrong workload |
| **RTMR3 round trip** (fork B2) — `expected_rtmr3` over a workload digest matches what the offline path compares, cross-checked against `quote-after.bin` | the workload measurement and the reference value are computed by two different bridges |
| **Staleness boundary, both sides** — `age == bound` allows, `age == bound + 1` refuses, and a record with `iat > as_of` is a distinct failure from a stale one | the comparison is `>=` where it should be `>`, or future and past collapse into one verdict |
| **The clock is genuinely injected** — the same record under two `--as-of` values yields fresh and stale, and no test can be made to pass by changing the machine's clock | a `SystemTime::now` reaches library code |
| **Never is refused** — `max_attestation_age = "never"` is a config error naming both readings | the lattice's top element is accepted as the tightest-looking bound |
| **Declared bound reaches the manifest** — two deployments differing only in `max_attestation_age` produce trust sets that compare `Incomparable`, not `Equal` | the declared interval is a number nothing depends on |
| **Challenge replay** — the same challenge presented twice is refused the second time, with `FixedChallenges` making the repeat deliberate | the single-use store forgets, or expiry is wired to the wrong clock |
| **Layout mismatch names both** — an attester writing a zero tail against a verifier configured for the challenge layout, and the reverse, each refuse with a message naming the expected and received layouts | a layout change reads as "this peer is not attesting" |
| **Zero tail still binds** — every existing `check_binding` test passes unchanged under the default policy | the relaxation becomes a weakening, and a quote committing to no challenge passes a verifier that wanted one |
| **Cross-check into `poc-audit`** — the same record and the same proxy config drive `field/attestation` off `ASSERTED` and the `iat` registry row off `Unaudited` | the seam between the two repositories drifts |

The last row is the load-bearing one, on the same reasoning
[`poc-audit`'s design](2026-08-09-poc-audit-design.md#testing) gives: every other row tests
our own code, and that one tests whether the four rows this work exists to move actually
move.

Two rows cannot be written from this repository. A successful binding against real
hardware still needs a fixture captured with a digest in `report_data` — the committed
quote's is 64 zero bytes and `the_real_fixtures_report_data_is_unbound`
(`src/verify/binding.rs:246`) pins that. The challenge round trip therefore has no
hardware-backed test until such a fixture exists, and the gap must be recorded in
`src/proxy/mod.rs`'s existing "what is not covered by a test, and why" section rather than
papered over with a synthetic quote.

## Risks

**The scope in TOOLING.md is wrong and this design says so.** T5 is listed as an extension
to `parallax-proxy`; the nonce half is impossible without changing `parallax-attest`, and
fork B2 changes the gate. The row should read "extension to `parallax`".

**Fork H contradicts a design that is about to be built.** If `ephemeris` ships minting its
own `nonce`, T5 can never do better than `ASSERTED` on that row, and the field will look
audited when it is not. This needs resolving before T2 starts, not after.

**Promoting private functions to `pub` fixes their signatures.** `reference_check`'s
re-signature is the right one — bytes and a list of bytes — but once public it cannot
absorb a fourth `ReferenceCheck` variant without a breaking change. Accepted: three
outcomes is the complete set for a comparison, and the alternative is `poc-audit`
reimplementing it, which is the defect being closed.

**Relaxing the `report_data` zero-tail rule is one-way.** `check_binding`'s documentation
argues at length that starting strict is what allows a later relaxation. This is that
relaxation, and it is the last one available: after fork I1 the tail has a meaning, and a
third convention would need a real negotiation rather than a policy enum.

**`--as-of` makes the tool's answer a function of an argument.** An operator can produce a
clean report by passing the record's own `iat`. Mitigated only by the report naming the
evaluation time on every freshness row, which the reason text must do.

## Build order

1. Move `Clock`/`FixedClock` into the default build. No behaviour change; end state is a
   clock injectable from a build that links no HTTP client.
2. Promote `parse_mrtd` and re-signatured `reference_check` to `pub`, with `derive` calling
   the new form. End state: the one-comparison test passes and nothing else has moved.
3. Fork B2 — compare RTMR3 as well as MRTD in the live gate, with the `expected_rtmr3`
   cross-check. End state: the shipped pair checks the workload it measures.
4. `parallax replay` over fork C1, plus `poc-audit`'s `--proxy-config`. End state:
   `measurement` reaches `ESTABLISHED (compared)` against the same bytes the gate uses.
5. `[freshness]` config, the derived assumption, and the `iat` check in the offline path.
   End state: `iat` leaves `Unaudited`, and the declared interval is in the manifest.
6. The `report_data` layout policy on `check_binding` and `expected_report_data`, with the
   layout-mismatch tests. End state: the seam exists and the default is unchanged.
7. The attester's re-quote loop and challenge endpoint, and the proxy's issuance store.
   End state: fork G2 works end to end, and G1 is reachable.

Steps 1–3 are corrections to shipped code and are worth landing whether or not the rest
proceeds. Step 4 is the first one that moves a number in TOOLING.md.
