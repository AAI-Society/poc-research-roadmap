# ephemeris TEE signer Implementation Plan — Phase 2, item 2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the evidence-signing key inside a TEE, bind it to a quote through `report_data`, and make it impossible for a build without the hardware to claim it has any.

**Architecture:** A `tee` cargo feature adds a `TeeSigner` that generates its key, derives `report_data` from the key's **SPKI DER** using `parallax::ratls::expected_report_data` rather than a second implementation, and requests a quote through `parallax::attest::tsm`. `Custody::Tee` becomes constructible only from inside that feature-gated module. The default build is unchanged, still signs with the labelled software key, and a test asserts it cannot produce a root claiming hardware custody.

**Tech Stack:** Rust 2021, `parallax` (git, pinned by rev) for `ratls::expected_report_data` and `attest::tsm`, `ed25519-dalek` with the `pkcs8` feature for SPKI DER encoding.

**Design spec:** `../specs/2026-08-10-ephemeris-design.md`, "Key custody" section. It specifies `report_data = SHA-256(SPKI(signing_key))` via `parallax::attest::tsm::request_quote`, everything TEE-touching behind a cargo feature, and that a build without the feature **cannot** produce a root claiming hardware custody — "following `occultation`'s `ModelledPermit` pattern where a modelled implementation cannot construct a valid verdict."

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**. `#![forbid(unsafe_code)]` stays.
- `cargo clippy --all-targets -- -D warnings` **and** `cargo clippy --all-targets --features tee -- -D warnings` must be clean. Warnings are errors.
- `cargo fmt --check` clean.
- The **default build and default test suite must not pull `parallax`**, and must remain fully offline.
- **No second identity derivation.** `report_data` comes from `parallax::ratls::expected_report_data`. Writing `rd[..32].copy_from_slice(&Sha256::digest(spki))` locally would be a second implementation of a cross-tool identity derivation — the exact failure `transit::jcs` reuse exists to prevent. If that function is not reachable, **stop and report** rather than reimplementing.
- **`Custody::Tee` must be unconstructible outside the `tee` feature.** This is the task's central property, in the same family as Phase 1's single-`Ack`-construction-site rule.
- No panics on data read from a file, a socket, or `/sys`. Errors use `thiserror`, print with `{e}`, never `{e:#}`.
- Upstream pinned by **`rev`**, never branch.
- Everything testable **offline**: no TEE, no network, no credentials. `parallax::attest::tsm::request_quote_at` exists precisely so failure paths can be exercised without hardware — use it.

---

## The trap this plan exists to avoid

`parallax/src/verify/binding.rs` documents the contract that the two sides must agree on:

> **What is hashed:** the DER encoding of the certificate's entire `subjectPublicKeyInfo` — the `AlgorithmIdentifier` *and* the `subjectPublicKey` BIT STRING … **Not the bare key bits.** An attester that hashed only the key bits would produce a digest that never matches.
> **What the other 32 bytes must be: zero.**

`ephemeris`'s existing software signer reports `self.key.verifying_key().to_bytes()` — which **is** the bare key bits. An implementer reaching for the obvious value here produces a quote that binds nothing a verifier will accept, and it fails only on real hardware against a real verifier, which is the worst place to find out. Task 1 pins this with a test that the key-bits digest is rejected, mirroring parallax's own `the_digest_is_over_the_whole_spki_not_the_key_bits`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml` | **modify** — `tee` feature, optional `parallax` dep, `ed25519-dalek/pkcs8` |
| `src/sign.rs` | **modify** — `Custody::Tee` construction confined; `spki_der()` helper |
| `src/tee.rs` | new — `TeeSigner`, feature-gated; the only place `Custody::Tee` is built |
| `tests/tee_binding.rs` | the SPKI contract, both directions |
| `tests/software_cannot_claim_hardware.rs` | the default-build property |

---

## Task 1: The SPKI derivation, and the digest that must not be the key bits

**Files:** Modify `Cargo.toml`, `src/sign.rs`. Test: `tests/tee_binding.rs`.

**Interfaces:**
- Produces: `sign::spki_der(&VerifyingKey) -> Result<Vec<u8>, SignError>`; `sign::SignError`.

- [ ] **Step 1: Add the feature and dependencies**

In `Cargo.toml`, change the `ed25519-dalek` line to add `pkcs8`, and add the optional dep and feature:

```toml
ed25519-dalek = { version = "2", features = ["rand_core", "pkcs8"] }
parallax = { git = "https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax.git", rev = "030686d", optional = true }
```

```toml
# `tee` pulls parallax for the attestation call and the report_data
# derivation. Off by default: the default build signs with a labelled software
# key and cannot claim hardware custody. Note that, as with `bench`, cargo
# resolves optional dependencies regardless of features, so the parallax source
# must be fetchable for any build even though nothing from it compiles.
tee = ["dep:parallax"]
```

- [ ] **Step 2: Write the failing test**

`tests/tee_binding.rs`:

```rust
//! The report_data contract, pinned from ephemeris's side.
//!
//! These tests run WITHOUT the `tee` feature, because the property under test
//! is about what is hashed, not about talking to hardware.

use ed25519_dalek::pkcs8::EncodePublicKey;
use ephemeris::sign::{spki_der, SoftwareSigner};
use sha2::{Digest, Sha256};

fn key() -> ed25519_dalek::VerifyingKey {
    SoftwareSigner::generate([7u8; 32]).verifying_key()
}

#[test]
fn spki_der_is_the_whole_subject_public_key_info_not_the_key_bits() {
    // parallax's verifier hashes the entire SPKI DER — AlgorithmIdentifier and
    // the BIT STRING both. An attester that hashed the bare 32 key bytes
    // produces a digest that never matches, and finds out only on real
    // hardware against a real verifier.
    let k = key();
    let der = spki_der(&k).unwrap();
    let bare = k.to_bytes();

    assert_ne!(der.as_slice(), bare.as_slice(), "spki_der returned the bare key bits");
    assert!(der.len() > bare.len(), "an SPKI wraps the key, so it is longer");
    assert_ne!(
        Sha256::digest(&der).as_slice(),
        Sha256::digest(bare).as_slice(),
        "the key-bits digest must not equal the SPKI digest"
    );
}

#[test]
fn spki_der_matches_the_pkcs8_encoder() {
    // Our helper must not be a third encoding. It is the same DER
    // `EncodePublicKey` produces, which is what rustls, OpenSSL's i2d_PUBKEY
    // and rcgen's public_key_der all agree on.
    let k = key();
    let ours = spki_der(&k).unwrap();
    let theirs = k.to_public_key_der().unwrap();
    assert_eq!(ours.as_slice(), theirs.as_bytes());
}

#[test]
fn the_spki_changes_when_the_key_changes() {
    let a = spki_der(&SoftwareSigner::generate([1u8; 32]).verifying_key()).unwrap();
    let b = spki_der(&SoftwareSigner::generate([2u8; 32]).verifying_key()).unwrap();
    assert_ne!(a, b);
}
```

- [ ] **Step 3: Run it and confirm it fails**

Run: `cargo test --test tee_binding`
Expected: FAIL — `spki_der` and `SoftwareSigner::verifying_key` do not exist.

- [ ] **Step 4: Implement**

In `src/sign.rs`, add the error type and helper, and expose the verifying key:

```rust
use ed25519_dalek::pkcs8::EncodePublicKey;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("could not encode the public key as a SubjectPublicKeyInfo: {0}")]
    Spki(String),
}

/// The DER encoding of the key's entire `SubjectPublicKeyInfo`.
///
/// **Not the bare key bits.** `parallax`'s verifier hashes the whole SPKI —
/// the `AlgorithmIdentifier` and the `subjectPublicKey` BIT STRING — and an
/// attester that hashed `verifying_key().to_bytes()` instead would produce a
/// `report_data` that never matches, failing only on real hardware against a
/// real verifier. `tests/tee_binding.rs` pins the distinction.
pub fn spki_der(key: &ed25519_dalek::VerifyingKey) -> Result<Vec<u8>, SignError> {
    key.to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| SignError::Spki(e.to_string()))
}
```

And on `SoftwareSigner`:

```rust
    /// The public half, for callers that need to derive a binding from it.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }
```

- [ ] **Step 5: Verify and commit**

Run: `cargo test --test tee_binding && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 3 new tests pass; the existing suite still passes.

```bash
git add -A
git commit -m "Derive report_data from the whole SPKI, never the bare key bits"
```

---

## Task 2: `Custody::Tee`, constructible in exactly one place

**Files:** Create `src/tee.rs`. Modify `src/lib.rs`, `src/sign.rs`. Test: `tests/software_cannot_claim_hardware.rs`.

**Interfaces:**
- Produces: `tee::TeeSigner` with `generate(seed: [u8; 32]) -> Result<TeeSigner, TeeError>` and `quote(&self) -> &[u8]`; `tee::TeeError`; `sign::Custody::tee()` — a `#[cfg(feature = "tee")]` constructor.

The design asks for `occultation`'s `ModelledPermit` shape: the weaker implementation must be unable to construct the stronger claim. Phase 1 got half of this — `Custody::Tee` exists but nothing builds it. This task makes that structural rather than incidental.

- [ ] **Step 1: Write the failing test**

`tests/software_cannot_claim_hardware.rs`:

```rust
//! The property the design asks for: a build without the `tee` feature cannot
//! emit a root claiming hardware custody.

use ephemeris::sign::{Custody, Signer, SoftwareSigner};

#[test]
fn a_default_build_signs_with_software_custody() {
    let s = SoftwareSigner::generate([7u8; 32]);
    assert_eq!(s.custody(), Custody::Software);
    assert_eq!(s.sign_root(&[0u8; 32], 1).custody, Custody::Software);
}

#[test]
fn a_rendered_root_says_software_and_says_what_is_undefended() {
    let text = SoftwareSigner::generate([7u8; 32]).sign_root(&[0u8; 32], 1).render();
    assert!(text.contains("SOFTWARE"));
    assert!(!text.contains("TEE"), "a software build rendered a TEE claim");
    assert!(text.contains("C7.3.3"));
}

/// Compile-fail is the real assertion and it cannot be written as a runtime
/// test: without the `tee` feature there is no expression that produces
/// `Custody::Tee`. This test documents the property and fails loudly if a
/// future edit adds a public constructor reachable from a default build.
#[test]
fn nothing_in_a_default_build_constructs_tee_custody() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sign.rs"))
        .expect("sign.rs is part of this crate");
    for (i, line) in src.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        if code.contains("Custody::Tee") {
            assert!(
                code.contains("=>") || code.contains("cfg(feature = \"tee\")"),
                "src/sign.rs:{} constructs Custody::Tee outside a match arm or the tee feature: {}",
                i + 1,
                line.trim()
            );
        }
    }
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --test software_cannot_claim_hardware`
Expected: PASS for the first three (Phase 1 already satisfies them) — this test file is a regression guard, not a red-then-green cycle. Confirm all four pass before moving on; if `nothing_in_a_default_build_constructs_tee_custody` fails, something already constructs it and that must be understood before proceeding.

- [ ] **Step 3: Add the feature-gated constructor**

In `src/sign.rs`, add to `impl Custody`:

```rust
    /// The only constructor for hardware custody, and it exists only when the
    /// `tee` feature is on.
    ///
    /// `Custody` derives `Clone, Copy, PartialEq, Eq` and nothing else — no
    /// `Default`, no `Deserialize`, no `From` — so a default build has no
    /// expression that yields this variant. That is the same discipline that
    /// keeps `Ack` unforgeable in `commit.rs`.
    #[cfg(feature = "tee")]
    pub(crate) fn tee() -> Custody {
        Custody::Tee
    }
```

- [ ] **Step 4: Write `src/tee.rs`**

```rust
//! The TEE signer. Behind the `tee` feature, because it needs `parallax` and
//! a configfs-tsm report directory that only a TDX guest has.

use crate::sign::{spki_der, Custody, SignError, SignedRoot, Signer};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::SeedableRng;

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("could not derive the key binding: {0}")]
    Binding(#[from] SignError),
    #[error("the platform would not produce a quote over this key: {0}")]
    Quote(String),
}

/// A signing key bound to a quote through `report_data`.
///
/// The binding is `parallax::ratls::expected_report_data(spki)`, which is
/// `SHA-256(SPKI DER)` left-aligned into 64 bytes with the remainder zero.
/// **We call parallax's function rather than reproducing that layout**: the
/// verifier on the other side is parallax's, and two implementations of one
/// identity derivation is the failure this programme keeps finding in other
/// people's work.
pub struct TeeSigner {
    key: SigningKey,
    quote: Vec<u8>,
}

impl TeeSigner {
    /// Generate a key and obtain a quote committing to it.
    ///
    /// Fails closed: no quote, no signer. A `TeeSigner` that existed without a
    /// quote could sign roots claiming hardware custody it could not
    /// demonstrate, which is precisely the claim this type exists to make
    /// checkable.
    pub fn generate(seed: [u8; 32]) -> Result<Self, TeeError> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let key = SigningKey::generate(&mut rng);
        let spki = spki_der(&key.verifying_key())?;
        let report_data = parallax::ratls::expected_report_data(&spki);
        let quote = parallax::attest::tsm::request_quote(&report_data)
            .map_err(|e| TeeError::Quote(e.to_string()))?;
        Ok(Self { key, quote })
    }

    pub fn quote(&self) -> &[u8] {
        &self.quote
    }
}

impl Signer for TeeSigner {
    fn sign_root(&self, root: &[u8; 32], size: u64) -> SignedRoot {
        let sig = self.key.sign(&crate::sign::signing_bytes(root, size));
        SignedRoot {
            root: hex::encode(root),
            size,
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
            signature: hex::encode(sig.to_bytes()),
            custody: Custody::tee(),
        }
    }

    fn custody(&self) -> Custody {
        Custody::tee()
    }
}
```

Note `signing_bytes` is currently private in `sign.rs`; change it to `pub(crate)` so the TEE signer signs exactly the same bytes as the software one. Do **not** copy it.

Declare the module in `src/lib.rs`:

```rust
#[cfg(feature = "tee")]
pub mod tee;
```

- [ ] **Step 5: Verify and commit**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo check --features tee && cargo fmt --check`
Expected: default suite passes; `--features tee` compiles.

```bash
git add -A
git commit -m "Add the TEE signer, with Custody::Tee constructible only behind the feature"
```

---

## Task 3: The failure paths, exercised without hardware

**Files:** Modify `src/tee.rs`. Test: `tests/tee_offline.rs`.

`parallax::attest::tsm::request_quote_at` takes the report directory as a parameter, and its own doc comment says it is "split out so that the failure paths can be exercised without a TEE: the real path is `/sys`, which no test can create." Use it.

**Interfaces:**
- Produces: `tee::TeeSigner::generate_at(base: &Path, seed: [u8; 32]) -> Result<TeeSigner, TeeError>`.

- [ ] **Step 1: Write the failing test**

`tests/tee_offline.rs`:

```rust
#![cfg(feature = "tee")]

use ephemeris::tee::{TeeError, TeeSigner};

#[test]
fn no_report_directory_means_no_signer() {
    // The developer-laptop case, and the one that must fail closed. An empty
    // directory is not a TDX guest.
    let d = tempfile::tempdir().unwrap();
    let r = TeeSigner::generate_at(d.path(), [7u8; 32]);
    assert!(matches!(r, Err(TeeError::Quote(_))), "a machine with no TEE produced a signer");
}

#[test]
fn the_error_names_the_platform_not_the_key() {
    // A missing TEE is an environment problem. The message must not suggest
    // the key was at fault, or an operator will go looking in the wrong place.
    let d = tempfile::tempdir().unwrap();
    let msg = match TeeSigner::generate_at(d.path(), [7u8; 32]) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a temp dir is not a TEE"),
    };
    assert!(msg.contains("quote"), "message did not mention the quote: {msg}");
}

#[test]
fn a_failed_quote_leaves_no_signer_to_misuse() {
    // Fail-closed, stated as a type property: `generate_at` returns Result and
    // there is no other constructor, so a failed attestation cannot leave a
    // TeeSigner in scope that would sign roots claiming hardware custody.
    let d = tempfile::tempdir().unwrap();
    assert!(TeeSigner::generate_at(d.path(), [7u8; 32]).is_err());
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --features tee --test tee_offline`
Expected: FAIL — `generate_at` does not exist.

- [ ] **Step 3: Implement**

Refactor `generate` to delegate, exactly as parallax does:

```rust
    pub fn generate(seed: [u8; 32]) -> Result<Self, TeeError> {
        Self::generate_at(std::path::Path::new(parallax::attest::tsm::TSM_REPORT_DIR), seed)
    }

    /// [`TeeSigner::generate`], against a caller-supplied report directory.
    ///
    /// Split out for the same reason parallax split `request_quote_at`: the
    /// real path is `/sys`, which no test can create, so the failure paths
    /// would otherwise be untested — and the failure paths are where
    /// fail-closed either holds or does not.
    pub fn generate_at(base: &std::path::Path, seed: [u8; 32]) -> Result<Self, TeeError> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let key = SigningKey::generate(&mut rng);
        let spki = spki_der(&key.verifying_key())?;
        let report_data = parallax::ratls::expected_report_data(&spki);
        let quote = parallax::attest::tsm::request_quote_at(base, &report_data)
            .map_err(|e| TeeError::Quote(e.to_string()))?;
        Ok(Self { key, quote })
    }
```

If `TSM_REPORT_DIR` is not public in the pinned rev, use the literal `"/sys/kernel/config/tsm/report"` and add a comment saying it mirrors parallax's constant — but check first.

- [ ] **Step 4: Verify and commit**

Run: `cargo test --features tee && cargo clippy --all-targets --features tee -- -D warnings && cargo test && cargo fmt --check`

```bash
git add -A
git commit -m "Exercise the TEE failure paths offline, the way parallax made possible"
```

---

## Task 4: Say what changed, and what still has not

**Files:** Modify `README.md`, `paper/main.tex`, `paper/README.md`, `.github/workflows/ci.yml`, rebuild `paper/main.pdf`.

- [ ] **Step 1: CI**

Add to the `rust` job, after the bench steps:

```yaml
      - run: cargo clippy --all-targets --features tee -- -D warnings
      - run: cargo test --features tee
```

The auth step's comment and error message list the private repos; add `parallax`. Validate with `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); puts "YAML OK"'`.

- [ ] **Step 2: README**

Update "A labelled placeholder" — the signer is still software **by default**, but hardware custody now exists behind `--features tee`. State plainly:
- the default build is unchanged and still cannot claim hardware custody;
- the TEE path has never been run on real hardware, only its failure paths offline;
- **C7.3.3 is still not defended.** A TEE key changes *who can sign*, not *who publishes roots*. Attack A9 stands exactly as before. This is the most important sentence in the update and it must not be softened by the arrival of hardware custody.

- [ ] **Step 3: Paper**

§8 ("What We Still Don't Know") currently says the signer is a software key and that a TEE key "would change who can produce a signature, not who can publish a root, so it narrows the attack without closing it." That sentence is now describing shipped code rather than future work — update the tense, and add that the hardware path is **untested on hardware**: only its offline failure paths are covered.

Do not claim the TEE signer works. Nothing here has run in a TDX guest.

- [ ] **Step 4: Rebuild and verify everything**

```
cd paper && tectonic main.tex
cargo test && cargo test --features bench && cargo test --features tee
cargo fmt --check
cargo clippy --all-targets --features bench -- -D warnings
cargo clippy --all-targets --features tee -- -D warnings
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Report the TEE signer honestly: hardware custody exists, A9 still stands"
```

---

## Done

`Custody::Tee` is now reachable only from a build that has the hardware path compiled in, and the derivation that binds the key to the quote is parallax's, not a second copy of it.

**Not done, deliberately:** nothing here has run inside a TDX guest. The quote request is exercised only through its failure paths. Whether a real platform accepts this `report_data` is unverified, and the README and paper both say so.
