# Stable Workload Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an operator a workload digest that does not change unless the workload changes, by publishing the image to a registry once and deploying it by immutable manifest digest instead of rebuilding it on the confidential VM.

**Architecture:** The build moves off the VM. `publish.sh` builds and pushes to Artifact Registry and derives the `[reference_values]` block; `up.sh` pulls by manifest digest and refuses anything not digest-pinned. Because the VM pulls rather than rebuilds, the image config is transferred rather than regenerated, so the identity is stable by construction and reproducible builds stop being a prerequisite.

**Tech Stack:** Rust 2021, `clap`, `sha2`, `thiserror`; POSIX shell; Docker; GCP Artifact Registry.

**Spec:** `docs/superpowers/specs/2026-08-10-stable-workload-identity-design.md` (in the roadmap repo).

**Repository:** `parallax` at `/Users/jimschwoebel/Desktop/parallax`. Branch off `main` at `fcc86d5`.

## Global Constraints

- Rust edition **2021**, `rust-version = "1.90"`. `cargo clippy --all-targets -- -D warnings` clean in **every** feature configuration: default, `--features attest`, `--features fetch-collateral`, `--all-features`.
- `thiserror` in libraries, `anyhow` in binaries. Errors print `{e}`, never `{e:#}`.
- **No panics on malformed input.** No `unwrap`, `expect`, indexing, or unchecked casts on anything read from a file, a socket, `configfs-tsm`, or a command line. Unit tests are exempt.
- **Time injected, never read from the system clock**, in anything reachable from a test.
- **Fail closed.** If attestation is unavailable the sidecar exits non-zero without listening. There is no flag that starts it anyway.
- Exit codes: `0` clean shutdown, `2` bad configuration or unavailable TEE.
- `cargo tree -i reqwest -e normal` must match nothing in a default build **and nothing with `--features attest`**.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` clean in the default build **and** with `--all-features`.
- `cargo fmt --check` must pass. It is CI-gating and has tripped five tasks in the predecessor plan.
- **Nothing may be synthesised.** Every value recorded in a document or a transcript must come from a command actually run. If something cannot be measured, narrow the claim rather than inventing support for it.
- Shell scripts use `set -euo pipefail`, comments that explain *why*, and no silent failure — the register of `scripts/capture-on-gcp.sh`.
- GCP work happens in project `example-project`, zone `us-central1-a`. Every created resource is named `parallax-demo-*` and is recorded with its exact deletion command. **Never** stop, delete, or reconfigure a resource you did not create.
- Every commit message ends with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

## Already done, do not redo

The spec's final documentation bullet — `examples/gcp-c3.toml` naming a torn-down instance's ephemeral IP — was fixed before this plan, by a history rewrite that replaced the address with `203.0.113.10` (RFC 5737 TEST-NET-3) across all four affected commits. Commit `fcc86d5` records the substitution in `tests/fixtures/gcp-c3-bound/PROVENANCE.md` and the fixture transcript. **Do not re-fix it, and do not reintroduce a real address anywhere.**

## File Structure

| File | Responsibility |
| --- | --- |
| `src/ratls.rs` | gains `parse_image_digest` + `ImageDigestError` — the shared strict digest parser |
| `src/attest/serve.rs` | loses its private `parse_image_digest`, calls the shared one |
| `src/proxy/config.rs` | `parse_hex48` becomes `pub` so the new subcommand validates MRTD with the existing parser |
| `src/bin/parallax.rs` | gains the `reference-value` subcommand |
| `deploy/gcp/publish.sh` | **new** — build, push, read back the manifest digest, print the reference values |
| `deploy/gcp/up.sh` | takes an image reference, pulls by digest, no longer builds or does shell hashing |
| `deploy/gcp/provision.sh` | Artifact Registry repo, IAM, `configure-docker`, teardown inventory |
| `deploy/gcp/app/Dockerfile` | hedge replaced with the measured cause |
| `scripts/publish-digest-stability.sh` | **new** — the offline proof |
| `tests/fixtures/publish-digest-stability/` | **new** — its committed transcript |
| `docs/WALKTHROUGH.md`, `README.md`, `examples/gcp-c3.toml` | the flow, the trust boundary, the limitation |

---

### Task 1: Move the digest parser into `ratls.rs`

**Files:**
- Modify: `src/ratls.rs`, `src/attest/serve.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn parse_image_digest(value: &str) -> Result<[u8; 32], ImageDigestError>` and `pub struct ImageDigestError { pub value: String, pub reason: String }` in `crate::ratls`.

`parse_image_digest` currently lives in `src/attest/serve.rs:318`, is private, and returns `PrepareError` — so it is unreachable from the default build. Task 2's subcommand is in the default build. Moving it is the same argument Task 2 of the predecessor plan made when it hoisted the layout constants: a third digest parser is how the `+`-acceptance bug came to exist in two places.

**The existing error text must not change.** `PrepareError::ImageDigest`'s `#[error]` string and the tests asserting on it (`src/attest/serve.rs:671-672`) stay exactly as they are; `serve.rs` maps the new error into that variant field-for-field.

- [ ] **Step 1: Write the failing test**

Append to `src/ratls.rs`'s existing `mod tests`:

```rust
    #[test]
    fn a_well_formed_digest_parses_case_insensitively() {
        let lower = parse_image_digest(&format!("sha256:{}", "ab".repeat(32))).expect("lower");
        let upper = parse_image_digest(&format!("sha256:{}", "AB".repeat(32))).expect("upper");
        assert_eq!(lower, upper);
        assert_eq!(lower, [0xab; 32]);
    }

    #[test]
    fn a_leading_plus_is_refused_rather_than_parsed_as_zero() {
        // `u8::from_str_radix("+0", 16)` is `Ok(0)`, so without the explicit
        // hex-digit check this parses to the all-zero digest -- a *different,
        // valid* measurement rather than an error. That is worse than a
        // truncation: the sidecar would attest to a workload nobody described.
        let e = parse_image_digest(&format!("sha256:{}", "+0".repeat(32)))
            .expect_err("a leading + is not hex");
        assert!(e.to_string().contains("not hex"), "{e}");
    }

    #[test]
    fn the_prefix_and_the_length_are_both_required() {
        assert!(parse_image_digest(&"ab".repeat(32)).is_err(), "no prefix");
        assert!(parse_image_digest("sha256:abcd").is_err(), "too short");
        assert!(
            parse_image_digest(&format!("sha256:{}", "ab".repeat(33))).is_err(),
            "too long"
        );
    }

    #[test]
    fn whitespace_and_dashes_are_refused_like_any_other_non_hex() {
        for bad in ["sha256:-0", "sha256: 0"] {
            assert!(parse_image_digest(bad).is_err(), "{bad} must be refused");
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib ratls`
Expected: FAIL — `cannot find function parse_image_digest in this scope`.

- [ ] **Step 3: Add the parser and its error to `src/ratls.rs`**

Insert before `mod tests`:

```rust
/// Why an `image_digest` string could not be read as 32 bytes.
///
/// Carries the offending value and a reason rather than a bare unit, because
/// the attester renders both into `PrepareError::ImageDigest` and an operator
/// reading that message needs to see what they actually typed.
#[derive(Debug, thiserror::Error)]
#[error("{value} {reason}")]
pub struct ImageDigestError {
    pub value: String,
    pub reason: String,
}

/// `sha256:` followed by exactly 64 hex characters, into the 32 bytes they
/// denote.
///
/// Case-insensitive by construction, so an uppercase digest and its lowercase
/// spelling parse to the same bytes and therefore the same measurement; there
/// is no separate case-folding step to keep in sync with that fact. Every
/// slice is `get`, never indexed, so a multi-byte UTF-8 character landing
/// mid-pair is a refusal rather than a panic — the same discipline
/// [`crate::proxy::config::parse_hex48`] uses for the same reason.
///
/// **Each pair is checked with `is_ascii_hexdigit` before it is parsed.**
/// `u8::from_str_radix` alone is not strict enough: it accepts a leading `+`
/// on an unsigned integer, so `"+0"` parses to `0` exactly as `"00"` would,
/// and `sha256:` followed by `"+0"` repeated 32 times would become the
/// all-zero digest — a different, valid measurement rather than an error.
pub fn parse_image_digest(value: &str) -> Result<[u8; 32], ImageDigestError> {
    let bad = |reason: String| ImageDigestError {
        value: value.to_string(),
        reason,
    };
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| bad("does not start with `sha256:`".to_string()))?;
    if hex.len() != 64 {
        return Err(bad(format!(
            "is {} hex characters after the prefix, not 64",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| bad("is not ASCII hex".to_string()))?;
        if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad(format!("`{pair}` at character {} is not hex", i * 2)));
        }
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| bad(format!("`{pair}` at character {} is not hex: {e}", i * 2)))?;
    }
    Ok(out)
}
```

- [ ] **Step 4: Delete the copy in `src/attest/serve.rs` and call the shared one**

Delete the whole `fn parse_image_digest` (currently `src/attest/serve.rs:297-345`, doc comment included). In `digest_bytes`, replace the `(Some(digest), None)` arm with:

```rust
        (Some(digest), None) => {
            crate::ratls::parse_image_digest(digest).map_err(|e| PrepareError::ImageDigest {
                value: e.value,
                reason: e.reason,
            })
        }
```

Leave `PrepareError::ImageDigest`'s `#[error]` string untouched — its wording is what the existing tests assert on.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib ratls && cargo test --features attest --lib attest::serve`
Expected: PASS. The four new `ratls` tests pass, and every pre-existing `attest::serve` digest test still passes **unmodified** — if any needed editing, the move was not behaviour-preserving; stop and report that rather than adjusting the test.

- [ ] **Step 6: Full verification**

```bash
cargo test && cargo test --features attest && cargo test --all-features
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features attest -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

- [ ] **Step 7: Commit**

```bash
git add src/ratls.rs src/attest/serve.rs
git commit -m "$(cat <<'EOF'
Hoist the image-digest parser into the shared module

reference-value is in the default build and the parser was behind the
attest feature, so the choice was to move it or write a third one. A
third is how the +-acceptance bug came to exist in two places.

The error text an operator sees is unchanged: PrepareError::ImageDigest
keeps its own wording and maps the new error field-for-field.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: The `reference-value` subcommand

**Files:**
- Modify: `src/bin/parallax.rs`, `src/proxy/config.rs`
- Test: `tests/reference_value_cli.rs` (create)

**Interfaces:**
- Consumes: `ratls::{parse_image_digest, workload_measurement, expected_rtmr3}` (Task 1 and existing).
- Produces: the `parallax reference-value` subcommand. `deploy/gcp/publish.sh` (Task 3) calls it as `cargo run --quiet --bin parallax -- reference-value --image-digest <d> --mrtd <m>`.

Deriving a reference value by hand is where an operator silently gets it wrong, and a wrong reference value fails closed but is miserable to diagnose. This is also what retires `up.sh`'s shell reimplementation of the arithmetic.

**MRTD is validated with the parser that already exists.** `parse_hex48` in `src/proxy/config.rs` was written for exactly this shape and already carries the `is_ascii_hexdigit` fix. Make it `pub` rather than writing a fourth parser.

- [ ] **Step 1: Make `parse_hex48` public**

In `src/proxy/config.rs`, change `fn parse_hex48` to `pub fn parse_hex48` and extend its doc comment with:

```rust
/// Public because `parallax reference-value` validates the `--mrtd` it echoes
/// with it. A second 48-byte hex parser is what this function's own
/// `is_ascii_hexdigit` check exists to stop being necessary.
```

- [ ] **Step 2: Write the failing test**

Create `tests/reference_value_cli.rs`:

```rust
//! The CLI that derives reference values must agree with the library that
//! defines the arithmetic.
//!
//! `deploy/gcp/up.sh` used to compute this in shell with `xxd` and
//! `sha384sum`, cross-checked only on real hardware. Nothing offline pinned
//! the shell to the Rust. This is that pin.

use parallax::ratls::{expected_rtmr3, parse_image_digest, workload_measurement};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An arbitrary well-formed digest. This test pins the arithmetic against the
/// library, not any particular image, so the value carries no meaning beyond
/// being parseable — do not describe it as a real image's digest.
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

#[test]
fn the_cli_emits_the_rtmr3_the_library_computes() {
    let bytes = parse_image_digest(DIGEST).expect("the digest parses");
    let want = hex(&expected_rtmr3(&workload_measurement(&bytes)));

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", DIGEST])
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "exit: {:?}", out.status);

    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        stdout.contains(&want),
        "stdout does not carry the library's RTMR3 ({want}):\n{stdout}"
    );
}

#[test]
fn omitting_mrtd_emits_an_empty_array_and_says_so_on_stderr() {
    // Never a plausible-looking placeholder: an operator pasting a fabricated
    // MRTD gets a config that looks configured and checks nothing.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", DIGEST])
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    // Two spaces: the emitted block aligns `mrtd` with `rtmr3`.
    assert!(stdout.contains("mrtd  = []"), "{stdout}");
    assert!(stderr.contains("mrtd"), "stderr must say where MRTD comes from:\n{stderr}");
}

#[test]
fn a_malformed_digest_exits_non_zero_without_emitting_a_block() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", "sha256:nothex"])
        .output()
        .expect("the binary runs");
    assert!(!out.status.success(), "a malformed digest must not succeed");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        !stdout.contains("[reference_values]"),
        "no pasteable block may be emitted for a bad digest:\n{stdout}"
    );
}

#[test]
fn a_malformed_mrtd_is_refused_rather_than_echoed() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", DIGEST, "--mrtd", "nothex"])
        .output()
        .expect("the binary runs");
    assert!(!out.status.success(), "a malformed MRTD must not be echoed");
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --test reference_value_cli`
Expected: FAIL — `unrecognized subcommand 'reference-value'`.

- [ ] **Step 4: Add the subcommand**

In `src/bin/parallax.rs`, add to the `Command` enum:

```rust
    /// Derive the `[reference_values]` block for a workload image digest.
    ///
    /// RTMR3 is computable offline from the digest alone, which is what lets
    /// an operator write a reference value *before* deploying. Reading it off
    /// the running deployment instead would be circular: a reference derived
    /// from the image you are checking cannot detect that you deployed the
    /// wrong image.
    ReferenceValue {
        /// The workload image's registry manifest digest: `sha256:` and 64 hex.
        #[arg(long)]
        image_digest: String,
        /// The platform's MRTD, 96 hex characters. Omitted, the `mrtd` array
        /// is emitted empty rather than filled with a guess.
        #[arg(long)]
        mrtd: Option<String>,
    },
```

And to the `match cli.cmd` at `src/bin/parallax.rs:137`:

```rust
        Command::ReferenceValue { image_digest, mrtd } => {
            let digest = match parallax::ratls::parse_image_digest(&image_digest) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("parallax: {e}");
                    return ExitCode::from(2);
                }
            };
            let rtmr3 = parallax::ratls::expected_rtmr3(&parallax::ratls::workload_measurement(
                &digest,
            ));
            let mrtd_line = match mrtd {
                Some(m) => match parallax::proxy::config::parse_hex48(&m, 0, "mrtd") {
                    Ok(_) => format!("mrtd  = [\"{m}\"]"),
                    Err(e) => {
                        eprintln!("parallax: --mrtd {e}");
                        return ExitCode::from(2);
                    }
                },
                None => {
                    eprintln!(
                        "parallax: no --mrtd given, so the mrtd array is empty. MRTD measures \
                         the platform firmware, not the workload, so it cannot be derived from \
                         an image digest -- read it from a quote this platform produced."
                    );
                    "mrtd  = []".to_string()
                }
            };
            let hex: String = rtmr3.iter().map(|b| format!("{b:02x}")).collect();
            println!("[reference_values]");
            println!("{mrtd_line}");
            println!("rtmr3 = [\"{hex}\"]");
            ExitCode::SUCCESS
        }
```

`src/proxy/mod.rs:134` already declares `pub mod config;` and `src/lib.rs:12` declares `pub mod proxy;`, so making the function `pub` is the only visibility change needed. Its real signature is `parse_hex48(hex: &str, index: usize, field: &'static str)` — three arguments, the third naming the field for the error message.

- [ ] **Step 5: Run the tests**

Run: `cargo test --test reference_value_cli`
Expected: PASS, 4 tests.

- [ ] **Step 6: Full verification**

```bash
cargo test && cargo test --all-features
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

- [ ] **Step 7: Commit**

```bash
git add src/bin/parallax.rs src/proxy/config.rs tests/reference_value_cli.rs
git commit -m "$(cat <<'EOF'
Derive reference values with the library, not with shell

up.sh computed the RTMR3 reference with xxd and sha384sum, cross-checked
only on hardware, with nothing offline pinning the shell to the Rust.
tests/reference_value_cli.rs is that pin.

Omitting --mrtd emits an empty array and says why on stderr. A
plausible-looking placeholder would give an operator a config that looks
configured and checks nothing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `publish.sh` — build once, push, read the digest back

**Files:**
- Create: `deploy/gcp/publish.sh`

**Interfaces:**
- Consumes: `parallax reference-value` (Task 2).
- Produces: a pushed image and, on stdout, the manifest digest, the `[reference_values]` block, and the exact `up.sh` invocation Task 4 expects.

Runs on the operator's machine, never on the VM. This is where the workload's identity is born, so it is where the reference value is derived.

- [ ] **Step 1: Write the script**

Create `deploy/gcp/publish.sh`, `set -euo pipefail`, taking `PROJECT`, `REGION`, and a repository name. It must:

1. `docker build -t "$IMAGE:latest" deploy/gcp/app`
2. `docker push "$IMAGE:latest"`
3. Read the manifest digest back with `docker image inspect -f '{{json .RepoDigests}}'`, requiring **exactly one** entry whose repository matches `$IMAGE`. Zero entries, or several that disagree, is a hard failure.
4. Print the digest, then run `cargo run --quiet --bin parallax -- reference-value --image-digest "$DIGEST" ${MRTD:+--mrtd "$MRTD"}`
5. Print the exact `up.sh` command to run on the VM, with the digest-pinned reference.

The failure in step 3 carries this comment, because it is the whole point of the change:

```sh
# No fallback to `.Id`. That fallback is the bug this script exists to remove:
# `.Id` is the digest of the image *config JSON*, which embeds a `created`
# timestamp with nanosecond precision, so it changes on every build regardless
# of content. If the registry did not give us a manifest digest, we do not have
# a stable identity and must not pretend otherwise.
```

- [ ] **Step 2: Verify it fails cleanly with no Docker daemon**

Run: `deploy/gcp/publish.sh` with no arguments.
Expected: a usage message and a non-zero exit, naming the arguments it needs. It must not reach `docker build`.

- [ ] **Step 3: Syntax check**

Run: `bash -n deploy/gcp/publish.sh`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add deploy/gcp/publish.sh
git commit -m "$(cat <<'EOF'
Publish the workload image, and derive its reference value there

The digest is born at publish time on the operator's machine, so that is
where the reference value is derived. The script fails rather than
falling back to .Id if the registry returns no manifest digest: .Id is
the config JSON's digest, it embeds a nanosecond timestamp, and reaching
for it is exactly the bug being removed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `up.sh` pulls by digest instead of building

**Files:**
- Modify: `deploy/gcp/up.sh`

**Interfaces:**
- Consumes: the digest-pinned image reference `publish.sh` (Task 3) prints.
- Produces: `attest.toml` with `image_digest` set to the registry manifest digest.

- [ ] **Step 1: Take an image reference and refuse anything unpinned**

`up.sh` gains a required argument: the full image reference. Before anything else it must refuse a reference that is not digest-pinned:

```sh
case "$IMAGE_REF" in
    *@sha256:*) ;;
    *)
        # A tag reintroduces exactly the drift this design removes: it can
        # resolve to different bytes tomorrow, and RTMR3 would change under a
        # reference value the operator already wrote down.
        echo "up.sh: '$IMAGE_REF' is not digest-pinned." >&2
        echo "up.sh: pass <registry>/<repo>@sha256:<manifest>, as publish.sh prints." >&2
        exit 2
        ;;
esac
```

- [ ] **Step 2: Replace the build with a pull**

Delete the `docker build` block (currently around `deploy/gcp/up.sh:72`) and the `APP_IMAGE_ID="$($DOCKER image inspect -f '{{.Id}}' …)"` line at `:79`. Replace with `$DOCKER pull "$IMAGE_REF"`, failing before `attest.toml` is written if the pull fails. `image_digest` in the rendered `attest.toml` becomes the `sha256:…` portion of `$IMAGE_REF`.

- [ ] **Step 3: Delete the shell arithmetic**

Remove the `measurement=`/`expected_rtmr3=` computation (currently `deploy/gcp/up.sh:130-133`) and the `echo "==> RTMR3 this deployment should produce (derived offline): …"` line at `:134`. Reference values now come from `publish.sh`. Replace the "reference values for examples/gcp-c3.toml" section at `:199` with a pointer to `publish.sh`'s output.

- [ ] **Step 4: Verify the refusal**

Run: `bash -n deploy/gcp/up.sh`, then `deploy/gcp/up.sh some/repo:latest`
Expected: exit 2, with the message naming the tag. This runs anywhere — it must refuse before touching Docker.

- [ ] **Step 5: Commit**

```bash
git add deploy/gcp/up.sh
git commit -m "$(cat <<'EOF'
Pull the workload by digest rather than building it on the VM

The config is then transferred rather than regenerated, so the identity
is stable by construction and reproducible builds stop being a
prerequisite. A tag is refused: it can resolve to different bytes
tomorrow, under a reference value the operator already wrote down.

The shell reimplementation of the measurement arithmetic goes with it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `provision.sh` gains the registry plumbing

**Files:**
- Modify: `deploy/gcp/provision.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: an Artifact Registry repository the VM can pull from.

- [ ] **Step 1: Create the repository and grant the pull role**

Add, before the instance is created:

- `gcloud artifacts repositories create parallax-demo --repository-format=docker --location="$REGION" --project="$PROJECT"`, tolerating "already exists" without masking other failures.
- Grant the VM's service account `roles/artifactregistry.reader` on that repository — the narrowest scope that works, not project-wide.
- `gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet` for the operator's Docker client.

- [ ] **Step 2: Add both to the teardown inventory**

The repository is a new billable resource. Add it to the inventory the script prints, with its exact deletion command:

```
gcloud artifacts repositories delete parallax-demo --location=<REGION> --project=<PROJECT> --quiet
```

**Do not add it to any EXIT trap.** The demo VM is meant to stay up and deletion is a separate explicit command; the registry follows the same policy.

- [ ] **Step 3: Syntax check**

Run: `bash -n deploy/gcp/provision.sh`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add deploy/gcp/provision.sh
git commit -m "$(cat <<'EOF'
Provision the registry the VM pulls from

A repository, a reader role scoped to it rather than to the project, and
configure-docker for the operator's client. Both new resources are in
the teardown inventory with their delete commands, and neither is on an
exit trap: the demo is meant to stay up.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: The offline proof, and the Dockerfile's measured cause

**Files:**
- Create: `scripts/publish-digest-stability.sh`, `tests/fixtures/publish-digest-stability/transcript.txt`, `tests/fixtures/publish-digest-stability/PROVENANCE.md`
- Modify: `deploy/gcp/app/Dockerfile`

**Interfaces:**
- Consumes: `parallax reference-value` (Task 2).
- Produces: the evidence that the new flow is stable and the old one was not.

Needs Docker and a registry the operator can push to. Needs **no TDX and no GCP**: Task 1 of the predecessor plan already established on real hardware that RTMR3 is a deterministic function of the digest, across boots. The only new claim is about digests.

- [ ] **Step 1: Write the script**

`scripts/publish-digest-stability.sh`, in the register of `scripts/spike-rtmr.sh` — echo each command before running it, capture output verbatim, `set -euo pipefail`. It establishes two things:

1. **The old flow is unstable, and why.** Build `deploy/gcp/app` twice from byte-identical source. Print both `.Id` values and show they differ. Then `docker image inspect` both and **diff the two config JSONs**, showing `created` is the differing field. This is what converts the Dockerfile's current "most likely cause … this repository has not isolated which" into a measured statement.
2. **The new flow is stable.** Push once; `docker rmi` the local copy; pull by manifest digest twice. Show the config is byte-identical both times, `.Id` identical, and `parallax reference-value` yields the identical RTMR3.

- [ ] **Step 2: Run it and commit the transcript**

Run the script and save its verbatim output to `tests/fixtures/publish-digest-stability/transcript.txt`. Write `PROVENANCE.md` beside it in the register of `tests/fixtures/gcp-c3-rtmr/PROVENANCE.md`: what each claim is, what was run, and a SHA-256 manifest of every committed file in the directory except `PROVENANCE.md` itself.

**If step 1's diff shows something other than `created` as the differing field, record what it actually shows.** The hypothesis is well-founded but it is a hypothesis; the transcript is the truth. A finding that contradicts the spec is a real result — report it rather than forcing agreement.

- [ ] **Step 3: Replace the Dockerfile's hedge with the measurement**

`deploy/gcp/app/Dockerfile:1-13` currently says the cause is "most likely" tag resolution or a timestamp and that "this repository has not isolated which." Replace with what step 2 measured, citing the transcript. Also delete the claim that the image can be rebuilt byte-for-byte — the final whole-branch review flagged it as asserting the exact property §5 disproved.

- [ ] **Step 4: Verify**

```bash
bash -n scripts/publish-digest-stability.sh
shasum -a 256 -c   # against the manifest you wrote, from inside the fixture dir
```

- [ ] **Step 5: Commit**

```bash
git add scripts/publish-digest-stability.sh tests/fixtures/publish-digest-stability deploy/gcp/app/Dockerfile
git commit -m "$(cat <<'EOF'
Measure why the old digest drifted, and that the new one does not

Two builds of byte-identical source differ, and the diff of their image
configs names the field responsible -- so the Dockerfile can state the
cause instead of hedging between two candidates. Pulling the same
manifest digest twice gives a byte-identical config and the same RTMR3.

No TDX needed: that RTMR3 is a deterministic function of the digest was
measured on real hardware by the spike. The only new claim is about
digests.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: The hardware run — re-capture the demo and the bound fixture

**Files:**
- Modify: `examples/gcp-c3.toml`, `tests/fixtures/gcp-c3-bound/` (all files), `tests/fixtures/gcp-c3-bound/PROVENANCE.md`
- Create: capture transcripts for Task 8 to write from

**Interfaces:**
- Consumes: Tasks 3–5's deploy tooling.
- Produces: the transcripts and fixture Task 8 documents.

**This task spends real money.** Provisioning on `example-project` is pre-approved. `gcloud` tokens on this org expire within about an hour and cannot be renewed non-interactively: **if they fail, stop and report, putting the full inventory of created resources with their deletion commands at the top of the reply.** Do not retry in a loop.

**RTMR3 is a hash chain, zero at boot, reset only by reboot.** The sidecar extends it once per boot and refuses a second time, so a failed full run costs a VM reboot. Use `parallax-attest --check` — which probes both interfaces *without* extending — to shake out configuration before spending the boot's one extension.

- [ ] **Step 1: Publish, provision, deploy**

Run `publish.sh`, then `provision.sh`, then `up.sh` with the digest-pinned reference. Capture every command and its output verbatim.

- [ ] **Step 2: Capture the accepting run**

`parallax-proxy` from the laptop against the deployment, with `examples/gcp-c3.toml`'s reference values updated to the ones `publish.sh` derived. Capture the successful `curl` and the proxy's decision output.

- [ ] **Step 3: Capture the refusal**

Publish a **different** app image, redeploy it (a reboot is required — RTMR3 is already extended), and capture the refusal verbatim. **Record whatever the refusal actually says.** The predecessor plan guessed at this wording and was wrong; the transcript is the truth and the plan's expectation is not.

- [ ] **Step 4: Re-capture the bound fixture**

Save the new certificate, quote, collateral and capture time into `tests/fixtures/gcp-c3-bound/`, replacing the previous capture, and update its `PROVENANCE.md` — including a fresh SHA-256 manifest and the reason for the recapture. Preserve the existing note recording the `203.0.113.10` substitution, and apply the same substitution to any new transcript: **no real external address may enter the repository.**

- [ ] **Step 5: Update `examples/gcp-c3.toml`**

Set `mrtd` and `rtmr3` to the values `publish.sh` derived, each commented with the command that regenerates it. Confirm the derived RTMR3 matches what the deployment actually reported, and **say so in the report.** A mismatch is a real finding, not something to paper over by copying the observed value in.

- [ ] **Step 6: Verify and tear down**

```bash
cargo test --all-features
```

`mrtd_and_rtmr3_match_examples_gcp_c3_toml` loads `examples/gcp-c3.toml` and compares against the fixture, so this passing is what proves the config and the recapture agree.

Then delete the VM, the firewall rule and the Artifact Registry repository, and confirm `gcloud compute instances list` matches the pre-provisioning baseline with no `parallax-*` resource remaining.

- [ ] **Step 7: Commit**

```bash
git add examples/gcp-c3.toml tests/fixtures/gcp-c3-bound
git commit -m "$(cat <<'EOF'
Re-run the pair on the published-image flow

The reference values now come from an artifact published to a registry
rather than from an image this host built, so they survive a rebuild.
The bound fixture is recaptured against the same deployment, which keeps
mrtd_and_rtmr3_match_examples_gcp_c3_toml pinning a single coherent
story rather than two captures that no longer agree.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: The documentation

**Files:**
- Modify: `docs/WALKTHROUGH.md`, `README.md`

**Interfaces:**
- Consumes: Task 6's and Task 7's transcripts.
- Produces: the operator-facing account of the new flow.

- [ ] **Step 1: Rewrite the walkthrough's flow sections**

Replace the build-on-VM steps with publish-then-pull, using Task 7's verbatim transcripts. Every command shown must appear in a committed transcript.

- [ ] **Step 2: Reframe §5**

§5 currently reads as an unresolved finding. It becomes the cause plus the fix: identical source produced a different `.Id`, Task 6 measured which field is responsible, and the flow no longer depends on rebuilds reproducing. **Keep the finding** — it is true and it is why the design changed — relabelled as what the naive flow exposes.

- [ ] **Step 3: Add the trust boundary and the limitation**

Both go in the walkthrough's up-front "what this does not prove" block **and** its "does not cover" accounting, because the final review found §5's earlier placement was missed by a reader who goes straight to the config:

- **Trust boundary:** `parallax-attest` measures the digest its configuration declares. It does not verify that the app container it fronts is that image; the deploy tooling asserts that. An attestation that silently means "the operator claimed X" rather than "X is running" is the kind of overclaim this project exists to attack.
- **The limitation:** a registry manifest digest and a local image-config digest are both 32-byte SHA-256 values and are indistinguishable by form. `reference-value` cannot tell an operator they pasted the wrong one. What enforces the distinction is `up.sh` refusing an unpinned reference, and this documentation — not a check in the tool.

- [ ] **Step 4: Update the README**

The "Try it" section points at the new flow. Anything describing the workload digest as coming from a local build is now wrong.

- [ ] **Step 5: Verify every claim resolves**

Check that every file path, command and value the docs cite exists and matches. Cite no file outside this repository: the final review found seven citations pointing at SDD artifacts in another repo, two of them load-bearing.

```bash
cargo test --all-features && cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

- [ ] **Step 6: Commit**

```bash
git add docs/WALKTHROUGH.md README.md
git commit -m "$(cat <<'EOF'
Document the published-image flow, and what it still does not prove

The walkthrough follows publish-then-pull, from transcripts. The
rebuild-drift finding stays -- it is why the design changed -- but as
what the naive flow exposes rather than as an open problem.

Two statements moved up front rather than living in section 5, because
a reader who takes the config and deploys never reaches section 5: the
attester measures what its config declares and does not verify the
running container, and a manifest digest is indistinguishable by form
from the local config digest an operator might paste by mistake.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage.** Every section maps to a task: the shared parser (1), the subcommand (2), `publish.sh` (3), `up.sh` (4), `provision.sh` (5), the offline proof and the Dockerfile's measured cause (6), the hardware run and the fixture recapture (7), the docs including the trust boundary and the indistinguishability limitation (8). The spec's last documentation bullet — the ephemeral IP — was completed before this plan and is marked "already done" rather than given a task.

**Non-goals held.** No reproducible-build work, no container-runtime verification, no attester trust-set principal, no `require_rtmr3` flag, no config-format change. `image_digest` keeps its current form throughout.

**Type consistency.** `parse_image_digest` returns `Result<[u8; 32], ImageDigestError>` in Task 1 and is called with that signature in Tasks 1 and 2. `ImageDigestError`'s fields `value` and `reason` are the ones Task 1's `serve.rs` mapping reads. `parse_hex48(&str, usize)` matches its existing signature in `src/proxy/config.rs`, which Task 2 makes `pub` and calls with an index of `0`. `workload_measurement(&[u8]) -> [u8; 48]` and `expected_rtmr3(&[u8; 48]) -> [u8; 48]` are used as they already exist.

**Two places the plan defers to reality over itself**, both flagged in-task: Task 6 records what the config diff actually shows rather than assuming `created`, and Task 7 records the refusal message verbatim rather than the wording this plan expects. The predecessor plan guessed at that message and was wrong.

**The riskiest task is late and costs money.** Task 7 needs hardware and an unexpired `gcloud` token. Tasks 1–6 are entirely offline and leave the repository in a working state, so a blocked Task 7 does not strand the branch.
