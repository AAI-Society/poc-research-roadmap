# parallax-attest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `parallax-attest`, a sidecar that runs on a GCP C3 Confidential VM and makes an unmodified application serve RA-TLS, so `parallax-proxy` finally has something real to verify.

**Architecture:** The sidecar extends RTMR3 with a digest of the workload it fronts, generates a keypair, requests a TDX quote whose `report_data` commits to that key, mints a self-signed X.509 carrying the quote, and terminates TLS in front of the app. Attester and verifier share one definition of the RA-TLS layout so they cannot drift. Everything network- or TEE-touching sits behind a cargo feature, keeping the default build lean.

**Tech Stack:** Rust 2021, `rcgen` (promoted from dev-dependency), `rustls`/`tokio-rustls`, `tokio`, `sha2`, `x509-cert`, plus the existing `thiserror`/`anyhow`/`clap`/`serde`/`toml`.

## Global Constraints

- Rust edition **2021**, `rust-version = "1.90"`. `cargo clippy --all-targets -- -D warnings` clean in **every** feature configuration; warnings are errors.
- `thiserror` in libraries, `anyhow` in binaries. Errors print `{e}`, never `{e:#}`.
- **No panics on malformed input.** No `unwrap`, `expect`, indexing, or unchecked casts on anything read from a file, a socket, or `configfs-tsm`.
- **Time injected, never read from the system clock**, in anything reachable from a test.
- `cargo tree -i reqwest -e normal` must still match nothing in a default build,
  **and nothing with `--features attest`**. The attester is the process holding
  the attestation key inside the TEE; it fetches no collateral and serves none,
  so it has no business linking an HTTP client. The existing constraint covered
  only the default build, which would not have caught this.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` must be clean in the default build **and** with `--all-features`.
- **Fail closed.** If attestation is unavailable the sidecar exits non-zero **without listening**. There is no flag that starts it anyway.
- Exit codes: `0` clean shutdown, `2` bad configuration or unavailable TEE.
- Every commit message ends with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

## Verified facts about the existing code (do not re-derive)

Read from the repo at plan time:

- `pub fn check_binding(report_data: &[u8; 64], cert_der: &[u8]) -> Result<(), BindingError>` — `src/verify/binding.rs:154`.
- `const DIGEST_LEN: usize = 32` and `const LAYOUT: &str` are **private** to `binding.rs` (`:25`, `:46`). A `const_assert` at `:37` ties `DIGEST_LEN` to SHA-256's output size.
- `pub const DEFAULT_QUOTE_OID: &str = "1.2.840.113741.1337.6"` — `src/verify/quote.rs:24`. A parallel `DEFAULT_QUOTE_OID_ARCS: &[u64]` exists in that file's tests.
- `rcgen` is currently a **`[dev-dependencies]`** entry pinned to the `ring` backend, with a comment explaining that choice avoids a C toolchain. The sidecar needs it at runtime, so it becomes an optional real dependency — keep the `ring` backend and the reasoning.
- The existing feature `fetch-collateral` gates `reqwest`/`tokio`, with `required-features` on its binary. Follow that pattern exactly for the new `attest` feature.

## File Structure

| File | Responsibility |
| --- | --- |
| `docs/spike-rtmr-gcp.md` | Task 1's findings — the record that gates everything |
| `tests/fixtures/gcp-c3-rtmr/` | quotes before and after extension, MRTD from two instances |
| `src/ratls.rs` | the RA-TLS layout, shared by attester and verifier |
| `src/attest/mod.rs` | module wiring |
| `src/attest/cert.rs` | keypair, `report_data`, self-signed X.509 carrying the quote |
| `src/attest/rtmr.rs` | RTMR3 extension over the interface the spike identifies |
| `src/attest/tsm.rs` | quote request over `configfs-tsm` |
| `src/attest/serve.rs` | TLS listener, plaintext forward to the app |
| `src/bin/parallax-attest.rs` | CLI and configuration |
| `deploy/gcp/` | provisioning script, `Dockerfile`, `docker-compose.yml`, sample app |
| `examples/gcp-c3.toml` | a real `parallax-proxy` config pointing at the VM |

---

### Task 1: The spike — can a GCP guest extend RTMR3?

**Files:**
- Create: `docs/spike-rtmr-gcp.md`, `scripts/spike-rtmr.sh`, `tests/fixtures/gcp-c3-rtmr/`

**Interfaces:**
- Consumes: nothing.
- Produces: a documented answer that every later task depends on, plus fixtures.

**This task gates the plan and BLOCKED is an acceptable outcome.** Nothing in this ecosystem has ever extended an RTMR — `ov-poc-standard/impl/poc/tdx.py` and every consumer in `parallax` read them only. Do not write sidecar code until this is answered.

**Do not synthesise, simulate, or assume the capability.** If extension is unavailable, say so and stop; the fallback design is recorded in the spec.

- [ ] **Step 1: Provision one C3 Confidential VM**

Reuse the shape of `scripts/capture-on-gcp.sh`, which already provisions
`c3-standard-4` with `--confidential-compute-type=TDX` and tears down on every
path including interrupt. Copy its trap discipline verbatim — a leaked
confidential VM bills by the hour.

- [ ] **Step 2: Enumerate what the guest exposes**

On the instance, record the output of each of these into the spike document:

```bash
ls -la /sys/kernel/config/tsm/          # known to serve quote generation
ls -la /dev/tdx_guest /dev/tpm0 /dev/tpmrm0 2>&1
uname -r                                # configfs-tsm needs 6.7+
dmesg | grep -i "tdx\|tsm" | head -20
ls /sys/class/tpm/ 2>&1
```

- [ ] **Step 3: Answer the four questions, in order, recording each**

1. **Can RTMR3 be extended, and through which interface?** Test in this order:
   `/dev/tdx_guest` ioctl; a vTPM if one is present (GCP Confidential VMs
   generally expose one, and TDX RTMRs are often mapped to TPM PCRs 1–3);
   `configfs-tsm`, which we know serves quote generation and may or may not
   offer extension.
2. **Does the extended value appear in a subsequent quote's RTMR3?** Take a
   quote, extend, take another, and diff byte offset 472..520 — the RTMR3 field,
   per `ov-poc-standard/impl/poc/tdx.py:60`.
3. **Is it deterministic?** Extend the same digest into a freshly booted VM and
   compare. Note that extension is a hash chain, so a second extension in the
   same boot must produce a *different* value — confirm that, because the
   sidecar's restart behaviour depends on it.
4. **Is MRTD stable across instances?** Provision a **second** C3, capture its
   quote, and compare byte offset 184..232 against the first. If GCP's firmware
   measurement varies, reference values are unusable and the demo is fragile
   regardless of RTMR3.

- [ ] **Step 4: Commit the fixtures**

Save into `tests/fixtures/gcp-c3-rtmr/`: `quote-before.bin`, `quote-after.bin`,
`extended-digest.bin`, `instance-b-quote.bin`, `captured-at`, and a
`PROVENANCE.md` in the same form as `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`.

- [ ] **Step 5: Write the findings and tear down**

`docs/spike-rtmr-gcp.md` states, for each of the four questions: the answer, the
command that produced it, and the raw output. Then confirm both instances are
deleted — `gcloud compute instances list` and `gcloud compute disks list`, as
Task 1 of the previous plan did.

- [ ] **Step 6: Commit**

```bash
git add docs/spike-rtmr-gcp.md scripts/spike-rtmr.sh tests/fixtures/gcp-c3-rtmr/
git commit -m "$(cat <<'EOF'
Establish whether a GCP guest can extend RTMR3

Nothing in this ecosystem has ever extended an RTMR -- every consumer in
both repos reads them. The sidecar's whole premise is that a workload
digest can be measured into RTMR3 before the quote is taken, so this is
answered on real hardware before any of it is written.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Shared RA-TLS constants

**Files:**
- Create: `src/ratls.rs`
- Modify: `src/verify/binding.rs`, `src/verify/quote.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub const QUOTE_OID: &str`, `pub const DIGEST_LEN: usize`, `pub const LAYOUT: &str`, `pub fn expected_report_data(spki_der: &[u8]) -> [u8; 64]`, and `pub fn workload_measurement(image_digest: &[u8]) -> [u8; 48]`.

Attester and verifier disagreeing on any of this produces a binding that always
fails, or one that passes on the wrong input. One definition, used by both.

- [ ] **Step 1: Write the failing test**

Create `src/ratls.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_occupies_the_first_half_and_the_tail_is_zero() {
        let rd = expected_report_data(b"not really an SPKI, but bytes are bytes");
        assert_eq!(rd.len(), 64);
        assert!(rd[..DIGEST_LEN].iter().any(|&b| b != 0), "digest is not all zero");
        assert!(rd[DIGEST_LEN..].iter().all(|&b| b == 0), "the tail must be zero");
    }

    #[test]
    fn different_keys_give_different_report_data() {
        assert_ne!(expected_report_data(b"key one"), expected_report_data(b"key two"));
    }

    #[test]
    fn a_workload_measurement_is_the_48_bytes_an_rtmr_takes() {
        // RTMRs are SHA-384; a container digest is SHA-256. This is the bridge,
        // and both the attester and whoever predicts the reference value must
        // cross it the same way.
        let m = workload_measurement(&[0xab; 32]);
        assert_eq!(m.len(), 48);
        assert_ne!(workload_measurement(&[0xab; 32]), workload_measurement(&[0xac; 32]));
    }

    #[test]
    fn the_measurement_is_over_bytes_not_the_textual_digest() {
        // "sha256:abab…" and the bytes it denotes must not both be accepted at
        // this layer — callers parse first, so a caller that forgets is a bug
        // this pins rather than hides.
        let bytes = [0xabu8; 32];
        assert_ne!(workload_measurement(&bytes), workload_measurement(b"sha256:abab"));
    }

    #[test]
    fn the_oid_is_the_one_the_verifier_looks_for() {
        // If these ever diverge, a correctly-minted certificate becomes
        // invisible to `quote_from_cert` and the failure reads as "not an
        // RA-TLS certificate" rather than "we disagree about the OID".
        assert_eq!(QUOTE_OID, "1.2.840.113741.1337.6");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib ratls`
Expected: FAIL — `cannot find function expected_report_data in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/ratls.rs`:

```rust
//! The RA-TLS layout, defined once and used by both halves.
//!
//! `parallax-attest` writes `report_data`; `check_binding` reads it. A
//! disagreement here is not a compile error and not a test failure in either
//! module alone — it is a binding that always fails, or one that succeeds on
//! the wrong input. `src/attest/cert.rs`'s round-trip test is what catches it,
//! and it can only do that because both sides read these constants.

use sha2::{Digest, Sha256};

/// The X.509 extension carrying the quote. Gramine and Intel's stacks use this
/// OID; others differ, which is why the verifier takes it as a parameter and
/// only defaults to this value.
pub const QUOTE_OID: &str = "1.2.840.113741.1337.6";

/// Bytes of `report_data` occupied by the digest. The remainder must be zero.
pub const DIGEST_LEN: usize = 32;

/// Named in error messages so an operator meeting a peer with a different
/// convention sees a layout mismatch rather than an accusation.
pub const LAYOUT: &str = "the Gramine/Intel layout, SHA-256(SPKI) in \
                          report_data bytes 0..32, remainder zero";

/// What `report_data` must contain for a certificate whose SubjectPublicKeyInfo
/// is `spki_der`.
///
/// Takes the **full DER SubjectPublicKeyInfo**, not the raw key bits.
pub fn expected_report_data(spki_der: &[u8]) -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..DIGEST_LEN].copy_from_slice(&Sha256::digest(spki_der));
    rd
}

/// The value extended into RTMR3 to measure a workload.
///
/// RTMRs are SHA-384 and `TDG.MR.RTMR.EXTEND` takes 48 bytes, but a container
/// image digest is a 32-byte SHA-256. Something has to bridge that, and the
/// choice is arbitrary — which is exactly why it lives here rather than being
/// made twice. The attester extends this value; whoever computes a reference
/// value must predict it. If the two pick differently, RTMR3 never matches and
/// the proxy reports "you deployed an image you did not declare" about a
/// deployment that is correct.
///
/// Takes the digest **bytes**, not the `sha256:…` string: the textual form has
/// an encoding (case, prefix) and the bytes do not.
pub fn workload_measurement(image_digest: &[u8]) -> [u8; 48] {
    Sha384::digest(image_digest).into()
}
```

Import `Sha384` alongside `Sha256`; `sha2` already provides it.

Add `pub mod ratls;` to `src/lib.rs`.

- [ ] **Step 4: Point the verifier at the shared definitions**

In `src/verify/binding.rs`, delete the private `DIGEST_LEN` and `LAYOUT` and
`use crate::ratls::{DIGEST_LEN, LAYOUT};` instead. Keep the `const_assert`
tying `DIGEST_LEN` to SHA-256's output size — move it to `ratls.rs` so it
guards the definition rather than one consumer.

In `src/verify/quote.rs`, make `DEFAULT_QUOTE_OID` a re-export:
`pub use crate::ratls::QUOTE_OID as DEFAULT_QUOTE_OID;` so existing callers and
the tests referencing it keep working.

- [ ] **Step 5: Run the full suite**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all pass — this is a pure move, no behaviour changes.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Define the RA-TLS layout once, for both halves

The attester writes report_data and check_binding reads it. A
disagreement is not a compile error and not a test failure in either
module alone -- it is a binding that always fails, or one that passes on
the wrong input.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Mint an RA-TLS certificate, and prove the verifier accepts it

**Files:**
- Create: `src/attest/mod.rs`, `src/attest/cert.rs`
- Modify: `Cargo.toml`, `src/lib.rs`

**Interfaces:**
- Consumes: `ratls::{QUOTE_OID, expected_report_data}` (Task 2), `check_binding` and `quote_from_cert` (existing).
- Produces: `pub struct MintedIdentity { pub cert_der: Vec<u8>, pub key_der: Vec<u8>, pub report_data: [u8; 64] }` and `pub fn mint_with_key(quote: &[u8], subject: &str, key: rcgen::KeyPair, report_data: [u8; 64]) -> Result<MintedIdentity, MintError>`. There is no `mint` wrapper — Task 5's `prepare` is the only caller and it holds the key already.

**This task produces the test the whole design rests on:** mint a certificate,
verify it with the real `check_binding`, in one process. It is the only test
that can catch attester/verifier drift.

Note the ordering problem and how `mint` resolves it: `report_data` must commit
to the key, and the quote must contain that `report_data`, but the certificate
must contain the quote. So the caller generates a key, computes `report_data`,
obtains a quote, and hands both to `mint`. `mint` therefore takes a quote and is
responsible for checking the quote's `report_data` matches the key it is about
to certify — a mismatch is a programming error that must not produce a
certificate.

- [ ] **Step 1: Add the feature and dependency**

In `Cargo.toml`, promote `rcgen` out of `[dev-dependencies]` into an optional
real dependency, keeping the `ring` backend and its comment, and add the feature:

```toml
[features]
# Deliberately NOT `attest = ["fetch-collateral", ...]`, even though that
# feature already enables tokio and the TLS stack. Two features may enable the
# same optional dependency, and listing them again costs nothing; inheriting
# `fetch-collateral` would instead link reqwest into the one process that holds
# the attestation key inside the TEE. The attester serves collateral to nobody
# and fetches none: the verifier does that.
attest = ["dep:rcgen", "dep:tokio", "dep:tokio-rustls", "dep:rustls"]

[dependencies]
rcgen = { version = "0.13", default-features = false, features = ["ring", "pem"], optional = true }
```

Write that reasoning into the `[features]` comment block alongside the existing
`fetch-collateral` note, in the same voice — it is the kind of thing that gets
"simplified" by a later reader who sees the duplication and not the reason.

`rcgen` must remain available to the existing `binding.rs` and `quote.rs` tests,
which use it unconditionally — so also keep it in `[dev-dependencies]`. A crate
may list the same dependency in both; the dev entry covers `cargo test` without
the feature.

- [ ] **Step 2: Write the failing test**

Create `src/attest/cert.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratls::expected_report_data;
    use crate::verify::{check_binding, quote_from_cert, DEFAULT_QUOTE_OID};

    /// Bytes standing in for a quote. This task does not need a real one —
    /// `mint` treats the quote as opaque. Task 7 runs the real thing.
    const FAKE_QUOTE: &[u8] = b"not a quote, but mint does not parse it";

    fn mint_for_a_fresh_key() -> MintedIdentity {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let rd = expected_report_data(&key.public_key_der());
        mint_with_key(FAKE_QUOTE, "parallax-attest", key, rd).expect("mint")
    }

    #[test]
    fn the_verifier_accepts_what_the_attester_mints() {
        // The only test that can catch the two halves drifting apart.
        let id = mint_for_a_fresh_key();
        check_binding(&id.report_data, &id.cert_der).expect("the binding must hold");
    }

    #[test]
    fn the_quote_is_recoverable_under_the_shared_oid() {
        let id = mint_for_a_fresh_key();
        let got = quote_from_cert(&id.cert_der, DEFAULT_QUOTE_OID).expect("extension present");
        assert_eq!(got, FAKE_QUOTE);
    }

    #[test]
    fn a_report_data_naming_a_different_key_is_refused_before_a_certificate_exists() {
        // Minting a certificate whose quote commits to somebody else's key
        // would produce exactly the artifact `check_binding` exists to reject.
        let key = rcgen::KeyPair::generate().expect("keypair");
        let other = rcgen::KeyPair::generate().expect("keypair");
        let wrong = expected_report_data(&other.public_key_der());
        assert!(matches!(
            mint_with_key(FAKE_QUOTE, "parallax-attest", key, wrong),
            Err(MintError::ReportDataNamesAnotherKey)
        ));
    }

    #[test]
    fn an_empty_quote_is_refused() {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let rd = expected_report_data(&key.public_key_der());
        assert!(matches!(
            mint_with_key(&[], "parallax-attest", key, rd),
            Err(MintError::EmptyQuote)
        ));
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --features attest --lib attest::cert`
Expected: FAIL — `cannot find function mint_with_key in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `src/attest/cert.rs`:

```rust
use crate::ratls::{expected_report_data, QUOTE_OID};

/// A key and the certificate that commits to it, with the `report_data` that
/// ties them together.
pub struct MintedIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub report_data: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("the quote's report_data commits to a different key than the one being certified; \
             minting would produce exactly the artifact check_binding exists to reject")]
    ReportDataNamesAnotherKey,
    #[error("refusing to mint a certificate carrying an empty quote")]
    EmptyQuote,
    #[error("could not build the certificate: {0}")]
    Certificate(String),
}

/// Mint a self-signed certificate carrying `quote` under [`QUOTE_OID`].
///
/// The caller supplies the key and the `report_data` because the quote had to
/// be requested before the certificate could exist: `report_data` commits to
/// the key, the quote contains `report_data`, and the certificate contains the
/// quote. This function is the last point at which that chain can be checked,
/// so it checks it.
pub fn mint_with_key(
    quote: &[u8],
    subject: &str,
    key: rcgen::KeyPair,
    report_data: [u8; 64],
) -> Result<MintedIdentity, MintError> {
    if quote.is_empty() {
        return Err(MintError::EmptyQuote);
    }
    if report_data != expected_report_data(&key.public_key_der()) {
        return Err(MintError::ReportDataNamesAnotherKey);
    }

    let mut params = rcgen::CertificateParams::new(vec![subject.to_string()])
        .map_err(|e| MintError::Certificate(e.to_string()))?;

    let oid: Vec<u64> = QUOTE_OID
        .split('.')
        .map(|a| a.parse::<u64>())
        .collect::<Result<_, _>>()
        .map_err(|e| MintError::Certificate(format!("QUOTE_OID is not an OID: {e}")))?;

    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(&oid, quote.to_vec())];

    let cert = params
        .self_signed(&key)
        .map_err(|e| MintError::Certificate(e.to_string()))?;

    Ok(MintedIdentity {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
        report_data,
    })
}
```

Create `src/attest/mod.rs` with `pub mod cert;` and re-exports, and add
`#[cfg(feature = "attest")] pub mod attest;` to `src/lib.rs`.

Check `rcgen` 0.13's exact API for `CustomExtension::from_oid_content` and
`CertificateParams::self_signed` against the installed source before writing —
two earlier tasks in this project planned around function names that did not
exist. Use what the crate defines and note any difference in your report.

- [ ] **Step 5: Run the tests**

Run: `cargo test --features attest --lib attest`
Expected: PASS, 4 tests.

- [ ] **Step 6: Confirm the default build is untouched**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo tree -i reqwest -e normal`
Expected: existing tests pass, clippy clean, reqwest absent.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Mint an RA-TLS certificate the verifier accepts

The round-trip test is the point: mint with the attester, verify with the
real check_binding, in one process. It is the only test that can catch the
two halves drifting apart, and it works because both read the shared
layout rather than each spelling it out.

mint refuses a report_data naming a different key. Producing that
certificate would create exactly the artifact check_binding exists to
reject, and the caller assembling the chain by hand is where that mistake
would be made.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Read a quote, and extend RTMR3

**Files:**
- Create: `src/attest/tsm.rs`, `src/attest/rtmr.rs`
- Modify: `src/attest/mod.rs`

**Interfaces:**
- Consumes: Task 1's findings.
- Produces: `pub fn request_quote(report_data: &[u8; 64]) -> Result<Vec<u8>, TsmError>` and `pub fn extend_rtmr3(digest: &[u8; 48]) -> Result<(), RtmrError>`.

**Write this task against what the spike actually found**, not against this
plan's expectation. If the spike reported BLOCKED, implement `tsm.rs` only, make
`extend_rtmr3` return `RtmrError::Unsupported` with the spike's reasoning in the
message, and record in your report that the sidecar attests the VM rather than
the workload.

- [ ] **Step 1: Write the failing tests**

Both functions touch `/sys` and cannot run in CI, so the testable surface is the
parsing and the guards. In `src/attest/tsm.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_outblob_is_an_error_not_a_panic() {
        assert!(matches!(parse_outblob(&[0u8; 10]), Err(TsmError::TooShort { .. })));
    }

    #[test]
    fn an_empty_outblob_is_an_error_not_a_panic() {
        assert!(matches!(parse_outblob(&[]), Err(TsmError::TooShort { .. })));
    }

    #[test]
    fn trailing_zero_padding_is_trimmed_to_the_declared_length() {
        // configfs-tsm zero-pads outblob: the committed fixture is 8000 bytes
        // of which 4935 are quote. See tests/fixtures/gcp-c3-tdx/PROVENANCE.md.
        let real = std::fs::read("tests/fixtures/gcp-c3-tdx/quote.bin").expect("fixture");
        let parsed = parse_outblob(&real).expect("the fixture parses");
        assert_eq!(parsed.len(), 4935);
        assert!(real.len() > parsed.len(), "the fixture is padded");
    }

    #[test]
    fn the_absence_of_configfs_tsm_is_reported_as_unavailable() {
        assert!(matches!(
            request_quote_at(std::path::Path::new("/nonexistent/tsm"), &[0u8; 64]),
            Err(TsmError::Unavailable { .. })
        ));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --features attest --lib attest::tsm`
Expected: FAIL — `cannot find function parse_outblob in this scope`.

- [ ] **Step 3: Implement the quote request**

`request_quote` writes `report_data` to `<tsm>/inblob`, reads `<tsm>/outblob`,
and trims the padding using the quote's own declared length: a `u32`
little-endian auth-data size at offset 632, so the quote is
`632 + 4 + auth_data_size`. That arithmetic is documented in
`tests/fixtures/gcp-c3-tdx/PROVENANCE.md` and pinned by
`tests/fixture.rs::fixture_is_a_4935_byte_quote_zero_padded_to_8000`.

**Two things to know before writing this, both of which look like invitations
to reuse code and are not:**

* `quote_len` at `src/verify/chain.rs:663` implements exactly this arithmetic
  and **must not be copied**. It is inside a `#[cfg(test)]` module and
  `.expect()`s on a short buffer — correct for a known-good fixture, a panic on
  a malformed `outblob`, which the global constraints forbid. Write the
  `Result`-returning version; the tests above are what force it.
* **Trimming is not what makes verification work.** `dcap-qvl` already tolerates
  trailing zero padding — `src/collateral/mod.rs:775`'s `padding_does_not_change_the_key`
  pins that a padded and a trimmed quote produce the same cache key. Trim
  because 3,065 bytes of zero padding would otherwise ride inside the X.509
  extension of every certificate on every handshake, not because the binding
  depends on it. Do not write a comment claiming it does.

Split the path out so it is testable: `request_quote_at(base: &Path, ...)` does
the work, `request_quote(...)` calls it with the real
`/sys/kernel/config/tsm/report`. Every read returns `Result`; no indexing.

- [ ] **Step 4: Implement the extension, per the spike**

`extend_rtmr3` takes a 48-byte SHA-384 value, because that is what
`TDG.MR.RTMR.EXTEND` accepts. **It does not compute that value** — the caller
passes `ratls::workload_measurement(..)` (Task 2), which is the one place the
SHA-256-image-digest-to-SHA-384-RTMR-value mapping is defined. Do not hash
anything here; a second mapping is the bug Task 2's doc comment describes.

If the spike found the interface, implement it. If not, return
`RtmrError::Unsupported` whose message names what was tried and points at
`docs/spike-rtmr-gcp.md`.

Include the restart guard the spike established: if extension is cumulative
within a boot, a second start produces an RTMR3 no reference value matches, so
`extend_rtmr3` must refuse a second call in the same boot rather than silently
produce an unmatchable quote. Detect it with a marker file under `/run`, and
document that a restart requires a fresh VM.

- [ ] **Step 5: Run and commit**

Run: `cargo test --features attest && cargo clippy --all-targets --features attest -- -D warnings`

```bash
git add -A
git commit -m "$(cat <<'EOF'
Request a quote, and extend RTMR3 with the workload digest

The padding trim uses the quote's own declared length rather than a
constant: configfs-tsm hands back 8000 bytes of which the committed
fixture uses 4935.

Extension refuses a second call in one boot. RTMR extension is a hash
chain, so restarting the sidecar would produce an RTMR3 that no reference
value matches -- a quote that verifies and then fails policy for a reason
nobody could diagnose.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: The sidecar

**Files:**
- Create: `src/attest/serve.rs`, `src/bin/parallax-attest.rs`, `examples/attest.toml`
- Modify: `Cargo.toml`, `src/attest/mod.rs`

**Interfaces:**
- Consumes: everything from Tasks 2–4.
- Produces: the `parallax-attest` binary.

- [ ] **Step 1: Add the binary target**

```toml
[[bin]]
name = "parallax-attest"
path = "src/bin/parallax-attest.rs"
required-features = ["attest"]
```

- [ ] **Step 2: Write the startup sequence as a testable function**

The socket work must not be entangled with the decision to start. Write:

```rust
/// Everything that must succeed before the listener binds.
///
/// Fail closed: any error here exits without listening. A sidecar that
/// serves plain TLS because attestation was unavailable produces a
/// certificate the verifier rejects — which is safe — but starting at all
/// in that state invites an operator to disable the check.
pub fn prepare(cfg: &AttestConfig) -> Result<MintedIdentity, PrepareError>;
```

`prepare` resolves the workload to 32 digest bytes — parsing the `sha256:` hex
from `image_digest`, or hashing the file named by `binary` — passes them through
`ratls::workload_measurement` to get the 48-byte RTMR value, extends RTMR3,
generates a keypair, computes `report_data`, requests the quote, and mints.

Parsing `image_digest` is the one place that touches the textual form, so it is
where the strictness belongs: require the `sha256:` prefix, require exactly 64
hex characters, and reject anything else rather than truncating or padding. A
config carrying a half-typed digest must not produce a quote.

Tests cover: a config naming neither `image_digest` nor `binary` is refused;
naming both is refused; a missing binary path is refused; a digest with a bad
prefix, wrong length, or non-hex characters is refused; an uppercase-hex digest
and its lowercase spelling resolve to the same measurement; and `PrepareError`
renders each cause.

- [ ] **Step 3: Wire the listener**

`serve` binds `listen`, serves the minted certificate over TLS, and forwards
plaintext to `app`. Reuse `parallax-proxy`'s connection discipline — a
`Semaphore` cap acquired in its own `select!` branch so shutdown stays
responsive, and `copy_bidirectional` for the forward. `parallax-proxy`'s
`serve.rs` is the reference; follow it rather than inventing a second shape.

- [ ] **Step 4: Write `examples/attest.toml`**

```toml
# Faces the verifying proxy, which is on another machine — so unlike
# examples/proxy.toml this necessarily binds a non-loopback interface.
# The RA-TLS certificate authenticates this sidecar. It does not
# authenticate the client, and no client authentication is performed.
listen = "0.0.0.0:8443"

# Plaintext, on the loopback of the confidential VM.
app = "127.0.0.1:3000"

[workload]
# What gets extended into RTMR3, and therefore what a verifier's
# reference values must cover. Exactly one of these.
image_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
# binary = "/usr/local/bin/app"
```

- [ ] **Step 5: Run everything and commit**

Run: `cargo test --features attest && cargo clippy --all-targets --features attest -- -D warnings && cargo fmt --check`

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add parallax-attest: serve RA-TLS in front of an unmodified app

prepare() is separated from the listener so the decision to start is
testable without sockets, and so failure cannot reach a bind. Fail closed
throughout: there is no flag that starts the sidecar when attestation was
unavailable.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Deployment

**Files:**
- Create: `deploy/gcp/{provision.sh,Dockerfile,docker-compose.yml,app/}`, `examples/gcp-c3.toml`

**Interfaces:**
- Consumes: the `parallax-attest` binary.
- Produces: a runnable stack.

- [ ] **Step 1: `provision.sh`**

Creates one `c3-standard-4` with `--confidential-compute-type=TDX`, installs
Docker, copies the repo, and prints the external IP and the exact
`parallax-proxy` command to run from the laptop. Reuse `capture-on-gcp.sh`'s
teardown trap; a demo VM left running bills by the hour just as a capture VM
does. Deletion must be a separate explicit command, not on exit — the demo is
meant to stay up.

- [ ] **Step 2: `Dockerfile` and `docker-compose.yml`**

The sidecar container needs `/sys/kernel/config/tsm`. Whether that requires
`privileged: true` or a narrower mount was established in Task 1 — use what the
spike found and put the reason in a comment. The sample app is anything that
returns a fixed string on `:3000`; keep it to a few lines so the container is
obviously not the interesting part.

- [ ] **Step 3: `examples/gcp-c3.toml`**

A real `parallax-proxy` config with the instance's address, `policy-proxy.toml`,
and `[reference_values]` carrying the MRTD and RTMR3 the deployment actually
produces. Comment each value with the command that prints it, so a reader can
regenerate rather than trust.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add a GCP deployment for the attester and a proxy config for it

The first step of the walkthrough is `gcloud compute instances create`,
not "modify your application".

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: The end-to-end run, the fixture, and the walkthrough

**Files:**
- Create: `tests/fixtures/gcp-c3-bound/`, `docs/WALKTHROUGH.md`
- Modify: `README.md`, `docs/STANDARD-MAP.md`

**Interfaces:**
- Consumes: everything.
- Produces: the artifact this repository has never had.

- [ ] **Step 1: Run the stack and capture the demo**

Bring the VM up, point `parallax-proxy` at it from the laptop, and record both
halves verbatim:

```console
$ curl localhost:8080
$ docker compose up -d --build app        # a different image
$ curl localhost:8080
502 …  rtmr3 does not match any configured reference value
```

The refusal is the deliverable. Anything forwards traffic.

- [ ] **Step 2: Commit the successful-binding fixture**

Save the sidecar's certificate and quote into `tests/fixtures/gcp-c3-bound/`
with a `PROVENANCE.md`. **This is the first quote in the repository whose
`report_data` genuinely commits to a key we hold** — Task 5 of the previous plan
could not produce one, which is why `check_binding`'s accepting path is
currently exercised only against generated certificates.

Add a test asserting `check_binding` accepts it, and update
`tests/fixtures/gcp-c3-tdx/PROVENANCE.md`'s statement that no such fixture
exists.

- [ ] **Step 3: Write `docs/WALKTHROUGH.md`**

Provision, deploy, verify, then break it on purpose and watch the refusal. State
plainly what the attestation covers and what it does not — and if the spike
returned BLOCKED, say that the workload is unmeasured and the claim is about the
VM.

- [ ] **Step 4: Update the README and the standard map**

Replace the `sigma*` framing in the "Try it" section with the walkthrough.
Update "What is real and what is modelled": the accepting path now has a real
fixture. In `docs/STANDARD-MAP.md`, revisit **C7.2.4** — the requirement that
the attestation cryptographically bind the evidence signing key — which the
sidecar now implements on the producing side rather than only checking.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Run the pair end to end, and capture a real bound quote

The first quote in this repository whose report_data commits to a key we
hold. check_binding's accepting path has until now been exercised only
against certificates the tests generate.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage.** Every section maps to a task: the spike and its four questions (1), shared constants (2), certificate minting and the round-trip test (3), quote request and RTMR3 extension including the restart guard (4), the sidecar and fail-closed startup (5), Docker/Compose/provisioning and a real proxy config (6), the demo, the fixture and the walkthrough (7). The spec's fallback — VM-only attestation with an explicit unmeasured-workload assumption — is carried in Task 4 Step 4 and Task 7 Step 3.

**Deferred deliberately.** No GKE manifest, no Azure, no JWT paths, no AWS Nitro — all spec non-goals. `prepare` is tested but the listener is not tested over a real socket, matching the acknowledged gap in `parallax-proxy`'s own allow path; Task 7's end-to-end run is what covers it, on hardware rather than in CI.

**Type consistency.** `MintedIdentity`, `MintError`, `TsmError`, `RtmrError`, `PrepareError`, `AttestConfig`, `mint_with_key`, `request_quote`, `request_quote_at`, `parse_outblob`, `extend_rtmr3`, `prepare` are each defined once and referenced with matching signatures. `ratls::{QUOTE_OID, DIGEST_LEN, LAYOUT, expected_report_data}` are defined in Task 2 and consumed unchanged thereafter; `DEFAULT_QUOTE_OID` becomes a re-export so existing callers keep compiling.

**Two places the plan defers to the crate over itself**, both flagged in-task: `rcgen` 0.13's `CustomExtension::from_oid_content` and `CertificateParams::self_signed` signatures (Task 3), and the RTMR extension interface, which is whatever Task 1 found rather than whatever this plan guessed.

**The riskiest task is first and can stop the plan.** Task 1 needs hardware, and BLOCKED is an acceptable outcome with a documented fallback rather than a substitution.

---

## Plan complete

Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks.

**2. Inline Execution** — executed in this session with batch checkpoints.
