# Design — `parallax-proxy`, an attestation-gating reverse proxy

**Date:** 2026-08-08 · **Status:** approved, ready for implementation planning ·
**Repo:** [`parallax`](https://github.com/AAI-Society/parallax)

---

## Why

`parallax` today takes a TOML description you wrote by hand and computes the
residual trust set. That can only tell you what you already knew well enough to
write down, which makes it an argument-settling tool rather than a verification
tool. Nobody deploys it.

`parallax-proxy` inverts the input. Instead of describing a deployment, you
point it at one. It verifies the upstream's attestation for real, derives the
trust set **from the verification steps it actually performed**, and refuses the
connection when that set violates your policy.

The gap it fills is concrete. The standard's reference implementation
(`ov-poc-standard/impl/poc/tdx.py`) *fetches* real TDX quotes on real hardware
via Linux configfs-tsm. Nothing anywhere in the programme *verifies* one — no
collateral fetch, no certificate chain validation, no TCB check. And no verifier
in the wider ecosystem tells an operator which parties they are still trusting
once verification succeeds.

## Goals

1. Verify a real Intel TDX quote: signature chain to the Intel root, TCB status,
   QE identity, revocation.
2. Bind the quote to the TLS session, so a valid quote cannot be replayed in
   front of a different key.
3. Derive the residual trust set from the verification itself, not from a file.
4. Enforce a policy — forward or refuse, with the violated assumption named.
5. Report the proxy's own contribution to the trust set.

## Non-goals for v1

SGX and SEV-SNP. Attestation transports other than RA-TLS. Multiple upstreams
per instance. Policy hot-reload. Anything that is not needed to demonstrate that
verification and enumeration are the same act.

---

## Architecture

```
client ──▶ parallax-proxy ──▶ upstream (confidential service)
                 │
                 │  1. TLS to upstream; capture the server certificate
                 │  2. extract the TDX quote from the certificate extension
                 │  3. verify the quote      → dcap-qvl + collateral
                 │  4. check report_data == SHA256(cert public key)
                 │  5. compare MRTD against configured reference values
                 │  6. derive TrustSet from steps 3–5
                 │  7. evaluate against policy
                 └─ 8. forward, or refuse with the violated assumption named
```

The proxy is **egress**: it protects a client from connecting to a service whose
trust profile the client does not accept. An ingress variant (attesting inbound
callers) is a later question and is deliberately out of scope.

### Verification *is* enumeration

This is the design's central claim and the reason the tool is worth building.
Each verification step establishes a fact *conditional on somebody's honesty*,
and that party is exactly a member of the residual trust set:

| Verification step | Assumption it introduces | Detection |
| :-- | :-- | :-- |
| chain validates to Intel SGX Root CA | Intel — silicon, microcode, provisioning key not misissued | `Never` |
| collateral (TCB info, QE identity, CRLs) fetched and current | Intel PCS — collateral is authentic | `Bounded`(collateral refresh) |
| QE identity matches | the quoting enclave signs honestly, key not leaked | `Never` |
| RTMRs present and well-formed | the cloud operator measured the firmware honestly | `Never` |
| **MRTD matches a configured reference value** | **the reference-value publisher knows what code that measurement is** | `Never` |

The composition rules already in `src/mechanism.rs` produce exactly these five
for a `tee_attestation` mechanism. The proxy must produce the *same* assumptions
by a different route — from a live quote rather than a description — and a test
must assert the two agree.

### The reference-value gap, which is the practical finding

The fifth row is conditional on configuration, and that is the point.

If no reference values are configured, the proxy does not perform that check, so
that assumption **does not enter the trust set** — because nothing was assumed.
What the operator has proven is weaker than they think: *some* code ran inside a
genuine trust domain. Not *their* code.

Most deployments verify a quote and stop there. Nothing in any existing verifier
tells them what they skipped. The proxy must say so on every allowed connection
where reference values are absent:

```
ALLOWED  10.0.3.9   3 assumptions, worst detect 43200s
         ⚠ no reference values configured — this attests that some code
           ran in a genuine trust domain, not that it is yours
```

This is a warning, not a refusal, unless policy says otherwise. A policy option
`require_reference_values = true` turns it into a refusal.

### The proxy is in its own trust set

Verifying with `dcap-qvl` means trusting `dcap-qvl`. Caching collateral means
trusting the cache. Terminating the connection means trusting the proxy.

The emitted trust set must include these. A tool that reports everyone else's
assumptions and omits its own would be committing precisely the overclaim this
project exists to attack. At minimum:

| Party | Capability | Detection |
| :-- | :-- | :-- |
| the verifier implementation (`dcap-qvl` at a pinned version) | sound quote verification | `Never` |
| the collateral cache | serves current, authentic collateral | `Bounded`(cache TTL) |
| the proxy operator | forwards only what it verified | `Never` |

---

## Components

| Path | Responsibility |
| :-- | :-- |
| `src/verify/quote.rs` | parse the TDX quote structure; extract MRTD, RTMRs, report_data |
| `src/verify/chain.rs` | drive `dcap-qvl`; chain, TCB status, QE identity, CRLs |
| `src/verify/binding.rs` | `report_data == SHA256(cert public key)` |
| `src/verify/refvals.rs` | compare MRTD against configured reference values |
| `src/collateral/mod.rs` | fetch from Intel PCS or a local PCCS; cache with a TTL |
| `src/derive.rs` | verification outcome → `TrustSet` |
| `src/proxy/mod.rs` | the listener, upstream dialler, and forwarding |
| `src/bin/parallax-proxy.rs` | CLI and configuration |

**Reused unchanged** from the existing crate: `Latency`, `Assumption`, `Impact`,
`TrustSet`, the entire policy engine (`src/policy.rs`), and the manifest emitter
(`src/manifest.rs`). The proxy is a new front end on machinery that already
works and is already tested — `parallax check` performs exactly the policy
evaluation this needs.

### Configuration

```toml
upstream    = "https://svc.internal:8443"
listen      = "127.0.0.1:8080"
policy      = "strict.toml"          # the existing policy format, unchanged

[collateral]
source = "https://api.trustedservices.intel.com/tdx/certification/v4"
cache_ttl = "12h"

[reference_values]
mrtd = ["9f2a...", "c41b..."]        # absent ⇒ the warning above
```

---

## Behaviour and failure modes

**Fail closed.** Any verification failure, collateral fetch failure, or policy
violation refuses the connection. There is no "allow on error" mode, because a
proxy that forwards when it could not verify is worse than no proxy — it
produces the appearance of a check.

**Exit and status codes.** A refused connection returns `502 Bad Gateway` with a
body naming the assumption or check that failed. The proxy's own exit codes
follow the existing convention: `0` clean shutdown, `1` policy violation at
startup (e.g. an unsatisfiable policy), `2` bad configuration.

**Per-connection manifest.** Every decision emits a Residual Trust Manifest —
the same schema `parallax solve --format json` already produces — to a log sink,
so an operator can reconcile what was allowed against what was assumed. This is
what makes the proxy an answer to C10.3.3's "automated validator", and the
manifests are the auditor evidence C10.2.1 asks for.

**No panics.** The proxy parses hostile input from the network by definition.
The existing no-panic guarantee extends to every new parser, and is tested with
malformed quotes and certificates.

---

## Testing

**Fixtures are real, not synthesised.** Capture genuine quotes and their matching
Intel collateral once from a GCP TDX instance — the existing
`impl/tdx/run_on_gcp.sh` already provisions one — and commit them:

```
tests/fixtures/gcp-c3-tdx/
  quote.bin          real, captured from hardware
  pck-chain.pem      collateral as it was that day
  tcb-info.json
  qe-identity.json
  crl-*.der
  captured-at        RFC 3339 timestamp
```

**Fixture rot is a real problem and must be handled explicitly.** CRLs and TCB
info carry validity windows, so a fixture that verifies today fails next month.
Tests pin the verification clock to `captured-at` and must inject that time
rather than reading the system clock. A verifier that cannot be told what time
it is cannot be tested offline; this shapes the `verify` API.

**A separate, opt-in test hits live Intel PCS** (`--ignored`, run in a scheduled
CI job rather than on every push) to catch collateral-format drift. When it
fails, the fixtures need recapturing — that is information, not a broken build.

**Cross-check against the existing calculus.** A test asserts that the trust set
derived from the captured quote equals the trust set `solve` computes for an
equivalent `tee_attestation` deployment description. Two independent routes to
the same answer is the strongest evidence available that the derivation is
right, and it is the independent-encoding experiment the paper proposes, in a
narrow form we can actually run.

**Negative tests, each its own case:** a quote whose chain does not validate; a
quote whose `report_data` does not match the certificate key; an expired CRL; a
revoked PCK certificate; a TCB level below policy; an MRTD matching no
configured reference value; a certificate carrying no quote extension at all.

---

## Risks

| Risk | Mitigation |
| :-- | :-- |
| `dcap-qvl`'s API does not expose the intermediate results needed to attribute assumptions per step | Prototype the attribution against a captured quote **before** building the proxy; if it only returns a boolean, derive from the collateral we fetch ourselves |
| No TDX hardware to capture fixtures from | `impl/tdx/run_on_gcp.sh` provisions a GCP C3 instance for a few tens of cents; capture is a one-off |
| Intel PCS requires an API key for some endpoints | Support a local PCCS URL as the primary configuration; document the key path |
| RA-TLS certificate extension OID is not standardised across stacks | Make the OID configurable, defaulting to the one Gramine and Intel use; a mismatch must fail loudly and name the OID it looked for |
| Verification succeeds but attributes the wrong parties | The cross-check test against `solve` is the guard; it must be written before the proxy is wired up |

## Build order

1. **Quote parsing and verification against a captured fixture**, with an
   injectable clock. No proxy, no network. This is the risky part and it should
   be proved first.
2. **Derivation** — verification outcome to `TrustSet`, with the cross-check
   against `solve`.
3. **Collateral fetch and cache**, with the live opt-in test.
4. **The proxy** — listener, dialler, forwarding, policy gate, per-connection
   manifests.
5. **Docs** — README, a deployment example, and the standard mapping updated to
   show C10.3.3 moving from "supported" to "implemented".

Steps 1 and 2 are worth doing even if the proxy is never built: they turn
`parallax` from a description tool into a verification tool on their own.
