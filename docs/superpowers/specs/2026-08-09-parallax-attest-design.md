# Design — `parallax-attest`, an attester sidecar for GCP Confidential VMs

**Date:** 2026-08-09 · **Status:** approved, ready for implementation planning ·
**Repo:** [`parallax`](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax)

---

## Why

`parallax-proxy` verifies an upstream's TDX attestation before forwarding to it.
It requires the upstream to serve **RA-TLS** — an X.509 certificate carrying a
TDX quote whose `report_data` commits to that certificate's public key.

Essentially nothing does this. No managed service on any cloud serves RA-TLS,
and the repository ships no way to make one. The verifier has nothing to verify,
which is why the tool reads as theoretical: `examples/` contains five research
deployments named Σ₁–Σ₅ and a `proxy.toml` pointing at a fictional host.

`parallax-attest` is the missing half. It runs *on* the confidential VM, mints
the RA-TLS certificate, and terminates TLS in front of an **unmodified**
application.

## Scope

**GCP only.** C3 instances with `--confidential-compute-type=TDX`, which is
where we already provision hardware for fixture capture. Azure DCesv5 is the
same shape and should follow cheaply; AWS Nitro is a different TEE entirely and
is out of scope for this and any near-term work.

**Non-goals:** GKE manifests (a Confidential VM with Docker Compose first,
because the core idea is unproven); JWT-based attestation (Confidential Space,
Azure MAA); anything that requires changing the application.

---

## Architecture

```
[ GCP C3, --confidential-compute-type=TDX ]

  parallax-attest :8443                      developer laptop
    1. digest the app image                    parallax-proxy :8080
    2. extend RTMR3 with that digest                  │
    3. generate keypair K                        curl localhost:8080
    4. quote, report_data = SHA-256(SPKI(K))
    5. mint self-signed X.509 carrying the quote
    6. serve TLS ─────────────────────────────────────┘
       └─ plaintext to the app on :3000  (UNMODIFIED)
```

The sidecar is an **ingress** terminator; `parallax-proxy` remains an **egress**
verifier. Together they are a deployable pair, and neither changes the
application.

### What the attestation covers, and why RTMR3 matters

On a bare C3 Confidential VM, **MRTD measures the guest firmware, not your
application.** RTMR0–2 cover the boot chain. Nothing automatically measures the
container or binary you deployed. A quote alone therefore proves *a genuine TDX
VM booted a known firmware image* and says nothing about what is running in it.

The sidecar closes that by extending **RTMR3** with a digest of the workload it
fronts before requesting its quote. Reference values then cover both MRTD (the
VM) and RTMR3 (the app), and the claim becomes *"this connection terminates
inside a genuine TDX trust domain running the image I expect."*

**This is the design's load-bearing assumption and it is unproven.** Nothing in
this ecosystem has ever extended an RTMR — `ov-poc-standard/impl/poc/tdx.py`
and every consumer in `parallax` read RTMRs only. See the spike below.

---

## The spike gates everything

**Task 1 is a spike that can kill this design**, and it must run before any
sidecar code is written. On one provisioned C3, answer empirically:

1. Can a guest extend RTMR3, and through which interface? Candidates to test in
   order: the TDX guest device (`/dev/tdx_guest`) ioctl, a vTPM if GCP exposes
   one, and `configfs-tsm` — which we already know serves quote *generation* at
   `/sys/kernel/config/tsm/report`, and which may or may not offer extension.
2. Does the extended value appear in a subsequent quote's RTMR3 field?
3. Is the extension deterministic — does extending the same digest into a
   freshly booted VM produce the same RTMR3?
4. **Is MRTD stable across instances?** Capture from two separate C3 instances
   and compare. If GCP's firmware measurement varies, reference values are
   unusable and the demo is fragile regardless of RTMR3.

**If extension is unavailable, report BLOCKED and fall back to the VM-only
design** — sidecar mints a key and serves RA-TLS, reference values cover MRTD
and RTMR0–2 only, and the emitted manifest carries an explicit
`workload_identity_was_never_measured` assumption. Do not synthesise, simulate,
or assume the capability. This is the Task-1-fixture pattern that worked: prove
the risky thing first.

---

## Components

| Path | Responsibility |
| --- | --- |
| `src/attest/rtmr.rs` | extend RTMR3; the interface the spike identifies |
| `src/attest/quote.rs` | request a quote over `configfs-tsm` with given `report_data` |
| `src/attest/cert.rs` | generate a keypair, mint the self-signed X.509 carrying the quote |
| `src/attest/serve.rs` | TLS listener, plaintext forward to the app |
| `src/bin/parallax-attest.rs` | CLI and configuration |
| `src/ratls.rs` | **shared constants** — see below |
| `deploy/gcp/` | provisioning script, `Dockerfile`, `docker-compose.yml`, sample app |
| `examples/gcp-c3.toml` | a real `parallax-proxy` config pointing at the VM |

### The sharp edge: attester and verifier must agree exactly

The sidecar must produce precisely what `check_binding` expects:

* the quote under OID `1.2.840.113741.1337.6`,
* `report_data[..32] = SHA-256(full DER SubjectPublicKeyInfo)`,
* `report_data[32..64] = 0`.

A disagreement on any of these yields a binding that always fails — or, worse,
one that succeeds on the wrong input. **These constants must be defined once in
`src/ratls.rs` and used by both sides**, not written twice. `check_binding`'s
existing `LAYOUT` constant moves there; `DEFAULT_QUOTE_OID` follows.

A test must assert the round trip: mint a certificate with `attest`, verify it
with `check_binding`, in one test, in one process.

---

## Configuration

```toml
listen = "0.0.0.0:8443"        # RA-TLS, faces the verifying proxy
app    = "127.0.0.1:3000"      # plaintext, the unmodified application

[workload]
# What gets extended into RTMR3. Exactly one of these.
image_digest = "sha256:9f2a…"  # container image the sidecar fronts
# binary = "/usr/local/bin/app"  # or a file to hash
```

`listen` binds a non-loopback interface by necessity — the verifier is on
another machine — which is the opposite of `parallax-proxy`'s posture and must
be documented as such. The RA-TLS certificate authenticates the *sidecar*; it
does not authenticate the client, and the sidecar performs no client
authentication.

---

## Behaviour and failure modes

**Fail closed at startup.** If RTMR3 extension fails, if the quote cannot be
obtained, or if `configfs-tsm` is absent, the sidecar **exits non-zero without
listening**. A sidecar that serves plain TLS because attestation was unavailable
would produce a certificate that the verifier rejects — which is safe — but
starting at all in that state invites an operator to disable the check. Exit
codes follow the existing convention: `0` clean, `2` bad configuration or
unavailable TEE.

**One quote per process lifetime.** The key is generated once at startup and the
quote covers it. Rotation means restarting, which re-extends RTMR3 — and
RTMR extension is cumulative within a boot, so a restart in the same VM produces
a *different* RTMR3 than the first start. The spike must establish this, and if
it holds, the sidecar must refuse to start twice in one boot rather than serve a
quote whose RTMR3 no longer matches any reference value.

**No panics on malformed input.** The sidecar parses no network input before the
handshake, but it does read `configfs-tsm` output and a config file. Both return
`Result`.

---

## The demo, which is the actual deliverable

Not "it forwards traffic" — anything forwards traffic:

```console
$ curl localhost:8080
200 OK                                    # manifest emitted, real trust set

$ docker compose up -d --build app        # deploy a different image
$ curl localhost:8080
502 Bad Gateway
    rtmr3 does not match any configured reference value
```

**The proxy refuses because you deployed something you did not declare.** That
is the property an application developer can evaluate, and it is not
demonstrable with anything in the repository today.

---

## Testing

**The spike's findings are recorded as fixtures**, the way the TDX quote was:
the captured RTMR3 before and after extension, and MRTD from two instances.

**A round-trip test** mints a certificate and verifies it with `check_binding`
in one process — the only test that can catch attester/verifier drift.

**The end-to-end run happens on real hardware** and produces the artifact this
repository has never had: **a real quote whose `report_data` genuinely commits
to a key we hold.** Task 5 could not produce one, so `check_binding`'s accepting
path is currently exercised only against `rcgen`-generated certificates. This
closes that gap, and the fixture should be committed with provenance in the same
form as `tests/fixtures/gcp-c3-tdx/`.

**Negative tests:** a certificate whose RTMR3 matches no reference value is
refused; a sidecar started without `configfs-tsm` exits 2; a certificate minted
for one key and served with another fails the binding.

---

## Risks

| Risk | Mitigation |
| --- | --- |
| **RTMR3 extension unavailable on GCP** | The spike is Task 1 and gates everything. Fall back to VM-only with an explicit unmeasured-workload assumption, and say so in the manifest. |
| MRTD varies across instances or firmware updates | Spike captures from two instances and compares. If unstable, reference values must name a set, and the README must say the set needs maintaining. |
| Container cannot reach `/sys/kernel/config/tsm` without privilege | Establish in the spike, before it lands in a manifest people copy. |
| Attester and verifier drift on the binding layout | Shared constants in `src/ratls.rs` plus the in-process round-trip test. |
| RTMR3 differs after a sidecar restart in the same boot | Spike establishes it; if true, refuse to start twice per boot rather than serve an unmatchable quote. |

## Build order

1. **The spike** — provision, establish whether RTMR3 can be extended, whether
   it appears in a quote, whether it is deterministic, and whether MRTD is
   stable. Commit findings as fixtures. **BLOCKED is an acceptable outcome.**
2. **Shared RA-TLS constants** — move `LAYOUT` and `DEFAULT_QUOTE_OID` into
   `src/ratls.rs`, used by `check_binding` and, later, by the sidecar.
3. **Certificate minting** — keypair, `report_data`, self-signed X.509, with the
   in-process round-trip test against `check_binding`.
4. **RTMR3 extension** — the interface the spike found, with the restart
   behaviour it established.
5. **The sidecar** — listener, plaintext forward, fail-closed startup.
6. **Deployment** — provisioning script, `Dockerfile`, `docker-compose.yml`,
   sample app, and `examples/gcp-c3.toml`.
7. **The end-to-end run and its fixture**, plus a README walkthrough whose first
   step is `gcloud compute instances create` and not "modify your application".
