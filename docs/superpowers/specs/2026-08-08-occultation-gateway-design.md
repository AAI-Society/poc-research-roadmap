# Design — `occultation-gateway`, a deployable linkability meter

**Date:** 2026-08-08 · **Status:** approved, ready for implementation planning

---

## Summary

`occultation` measures what unlinkability *costs*. It cannot give unlinkability
to anyone: its BBS+ is real but not interoperable, and two of the five layers
it prices are modelled stubs with no security. So it is a research artifact,
and an operator cannot deploy it against anything.

`occultation-gateway` is the deployable half. It is a **fail-open reverse
proxy** a relying party puts in front of its agent-facing API. For every
request it verifies whatever attestation arrived, measures what the request
gave away, and emits a finding. It never rejects until someone sets
`--enforce`.

The insight it is built on: **no agent is presenting an anonymous credential
today.** What actually arrives at a vendor is a TDX or SEV quote and something
thoroughly identifying — an OAuth token, an mTLS certificate, an `agent_id`
and an `initiating_user`. Verifying a real quote is a solved problem. Computing
what that quote's collateral gives away is what `occultation` is uniquely good
at. Pointing those two at live traffic needs no new cryptography, and it turns
the paper's finding into an operational alarm.

## Goals

1. Run against real traffic, in a real deployment, without new cryptography.
2. Tell a relying party what it just learned that it did not need to know.
3. Never claim to have verified something it did not.
4. Upgrade cleanly: when unlinkable presentations do appear, the same proxy
   verifies them rather than only measuring the leak.

## Non-goals

* **Verifying anonymous credentials.** Blocked on making `occultation`'s BBS+
  conformant to `draft-irtf-cfrg-bbs-signatures`' published test vectors. That
  is bounded, well-specified work, and it is a separate project that must land
  before phase 2.
* **Providing unlinkability.** This tool measures; it does not issue, present,
  or anonymize.
* **Being a general security gateway.** Quote verification and linkability
  measurement only. There are commodity products for WAF, rate limiting and
  authz, and this is not one.
* **Answering "has this agent been here before."** Refused by construction —
  see [The meter](#the-meter).

## Phasing

**Phase 1 — identified traffic (ships first).** Accepts today's reality: a
quote plus an identifying credential. Verifies the quote, measures the leak,
reports. No new cryptography.

**Phase 2 — the migration path.** Accepts unlinkable presentations as they
appear alongside identified traffic, so an operator can watch the property
arrive across their counterparties rather than flipping a switch. Gated on the
BBS+ conformance work.

The value of phase 1 standing alone is the argument for phase 2: it is the
thing that makes a relying party *want* the unlinkable stack.

## Where it lives

A **second binary in the `occultation` repository**, `src/bin/gateway.rs`, not
a new repository. The anonymity engine is already a standalone module with no
CLI coupling; the repo already carries the CI, the `results/` discipline and
the real/modelled conventions; and a separate repo would need a path
dependency because nothing here is published to crates.io. Splitting later is
cheap if it outgrows this.

## Architecture

```
agent ──TLS──▶ occultation-gateway ──▶ vendor API
                     │
                     ├── AttestationSource   pluggable: header │ RA-TLS │ none
                     ├── QuoteVerifier       real, or explicitly Unverified
                     ├── LinkabilityMeter    salted counts + marginal attributes
                     └── Findings            log · Prometheus · JSON report
```

Fail-open is the default and the only behaviour in phase 1: every internal
error, verification failure or meter fault forwards the request and records a
finding. The proxy must not be able to take down the API it fronts.

## Components

### `AttestationSource`

```rust
pub trait AttestationSource {
    fn extract(&self, req: &Request) -> Result<Option<RawAttestation>, SourceError>;
    /// Whether this transport binds the attestation to the session.
    fn session_binding(&self) -> SessionBinding;
}

pub enum SessionBinding { Bound, Unbound { why: &'static str } }
```

There is no convention for how a quote reaches a relying party over HTTP —
C7.2.4 specifies the key digest goes in the attested report body and says
nothing about transport. So this is pluggable, with:

* **`HeaderSource`** (phase 1) — `X-Attestation: <base64>`. Trivial, works
  with any client stack, `Unbound`: nothing ties the quote to this TLS
  session, so a captured quote is replayable.
* **`RaTlsSource`** (phase 1b) — quote in an X.509 extension on the client
  certificate, verified during the handshake. `Bound`. The only option that
  resists replay, and the one that matters.

`session_binding()` is not decoration: the gap between the two is itself a
finding the gateway reports.

### `QuoteVerifier`

```rust
pub enum QuoteVerdict {
    Verified { platform: Platform, tcb: TcbStatus, collateral: TcbCollateral },
    Invalid { reason: String },
    Unverified { why: &'static str },
}
```

Verifying a TDX quote for real means the whole chain: PCK certificate chain to
Intel's root, TCB status from PCS collateral, CRLs, QE identity. **Either the
gateway does that, or `QuoteVerdict::Unverified` propagates into every finding
downstream and is rendered as prominently as `MODELLED` is today.** A gateway
that appears to verify attestation and does not is the exact failure this
repository spent thirteen reviews making impossible, and it would be worse
here because it sits in production.

**Resolved before planning, by compile-probe.** [`dcap-qvl`](https://crates.io/crates/dcap-qvl)
0.6.1 does the full chain, supports TDX, and compiles clean against this stack.
Its shape is exactly right for a proxy:

```rust
// synchronous, offline, no network on the request path
pub fn verify(raw_quote: &[u8], collateral: &QuoteCollateralV3, now_secs: u64)
    -> Result<VerifiedReport>;

// async, separate, cacheable — fetched out of band
pub async fn CollateralClient::fetch(&self, quote: &[u8]) -> Result<QuoteCollateralV3>;
```

The split means collateral is fetched and cached out of band while
verification stays synchronous and in-line, so a PCS round trip never lands on
a request. `TcbStatus` is the real enum — `UpToDate`, `OutOfDate`,
`ConfigurationNeeded`, `Revoked` and the rest — not a boolean, so findings can
report *why* a TCB is stale.

The crate's only `unsafe` is in `src/ffi.rs`, where it exposes a C API
outward. Nothing on our consumption path is unsafe, so
`#![forbid(unsafe_code)]` in this crate is unaffected.

**Two prohibitions for the plan.** `dangerous_verify_with_tcb_override` is
public and must never be called — it is well named and it is the one API that
would turn this into a verifier that verifies nothing. And a stale collateral
cache must degrade to `Unverified { why }`, never to `Verified`.

`Unverified` therefore stops being the expected phase-1 outcome and becomes
the honest failure mode: PCS unreachable, collateral expired, unsupported
platform. **Writing a partial verifier remains off the list.**

### The meter

`LinkabilityMeter` retains exactly two structures:

```rust
counts:    Map<Hash, u64>,                  // H(salt ‖ tcb_fingerprint) → sessions
marginals: Map<Attribute, Map<Hash, u64>>,  // per-attribute value frequencies
```

No session→fingerprint map. No joint distribution across attributes. Set size,
effective set size and entropy derive from the size distribution alone;
"which attributes are doing the deanonymizing" derives from the marginals. The
salt rotates on a configured interval, ageing out correlation by construction.

This is the design's central tension, resolved rather than disclosed. A tool
that warns a relying party about silently accumulating a profile of its
counterparties must not accumulate that profile itself — and a store holding
per-session fingerprints would also be a high-value target whose breach hands
over exactly the correlation the design exists to prevent.

The cost is real and accepted: the gateway **cannot** answer "has this agent
been here before." Operators will ask for it. The answer is no.

### Findings

One finding per request, plus a rolling report and Prometheus metrics:

```
agent authorized ✓   quote: VERIFIED (TDX, TCB up to date)
  anonymity set     3 of 1,847 sessions
  varying           microcode, pce_svn
  session binding   NONE — quote arrived in a header; a captured quote is reusable
```

Reuses `occultation`'s existing provenance discipline: every number carries
its source, and anything unverified or modelled says so in the line that
states it, not in a footnote.

## Error handling

| Condition | Behaviour |
| --- | --- |
| No attestation present | forward; finding records absence |
| Malformed attestation | forward; `Invalid` finding |
| Verification chain unreachable (PCS down) | forward; `Unverified { why }`; metric increments |
| Meter fault or store full | forward; finding records measurement was skipped |
| Any panic in gateway code | forward; the proxy is not permitted to fail closed in phase 1 |

`--enforce` (off by default, phase 1b) converts `Invalid` and, configurably,
`Unverified` into rejections. Nothing else ever rejects.

## Testing

Follows the repository's existing discipline, and two items are load-bearing:

1. **A hostile agent fixture**, in the spirit of `transit`'s hostile server: an
   agent that replays a captured quote, sends a malformed quote, sends none,
   sends one for a different platform, and sends collateral crafted to look
   like a large anonymity set. Each is a test.
2. **The meter's refusal is asserted, not documented.** A test establishing the
   store exposes no API mapping a session to a fingerprint, and that two
   sessions with identical collateral are indistinguishable in what is
   retained. This is the analogue of the pool's no-reuse invariant, which is
   enforced by the type system and proved by a test that performs the attack
   it prevents.
3. Fail-open is tested by fault injection at every stage, asserting the request
   still reaches the upstream.

## Risks

| Risk | Mitigation |
| --- | --- |
| ~~No existing crate verifies the full TDX chain properly~~ | **Resolved by compile-probe before planning:** `dcap-qvl` 0.6.1 does the full chain for TDX, pure Rust on our path, with offline verification and separately cacheable collateral. Remaining risk is operational — collateral freshness — which degrades to `Unverified`, never to `Verified` |
| Observe-only tools get installed and ignored | The finding is genuinely alarming when true, and it has a report and CI surface rather than only a dashboard |
| Operators demand "seen before" | Refuse. Document the refusal and the reason in the README, as with reuse |
| The proxy adds latency to a production path | Measure it with the existing harness and publish the number; the meter is a hash and two map lookups |
| Phase 2 slips because BBS+ conformance is harder than scoped | Phase 1 has standalone value; phase 2 is explicitly gated and not promised |

## What ships first

Phase 1, minus RA-TLS and minus `--enforce`: header transport, quote
verification (real or honestly absent), the meter, findings and metrics, the
hostile agent fixture, and a README that says exactly what it does and does
not verify.
