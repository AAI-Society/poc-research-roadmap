# parallax freshness Implementation Plan — T5

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `parallax` so that a Proof-of-Control evidence record's `measurement` claim can be re-checked offline against **the same bytes the live gate admits on**, so that a declared attestation staleness bound exists, reaches the residual trust set, and is enforced at a stated boundary, and so that epoch-based freshness has a mechanism — a `report_data` layout policy, a challenge issuance store, and a single-use rule — that a test can drive without hardware.

**Architecture:** No new repository and no fifth binary. Three private functions in `parallax` become public (`parse_mrtd`, `reference_check`, `ReferenceCheck`), one of them re-signatured so it is callable without a `VerificationOutcome`; `derive` calls the new form, so there stays exactly one comparison in the crate. A new default-build `replay` module reads a record, refuses any `measurement` that cannot be an Intel TDX MRTD, and drives that one comparison from `ProxyConfig::load`'s reference values. `Clock`/`FixedClock` move out from behind `fetch-collateral` into the default build so the offline path can inject time in a build that links no HTTP client. `check_binding` grows the policy argument its own documentation says it should grow, and `ratls.rs` grows the matching constructor, so the two halves keep reading one definition of the layout. A `Challenges` trait puts randomness under the same discipline as time.

**Tech stack:** Rust 2021, toolchain floor 1.90. No new dependencies except `serde_json` (already present) for reading a record. `sha2`, `humantime`, `thiserror`, `anyhow`, `clap` 4, `toml` — all already in `Cargo.toml`.

**Deliberately not in this plan:** the attester's HTTP challenge endpoint and its re-quote loop (design build order step 7's second half). That half needs `parallax-attest` to grow a listener route and a timer, it is behind the `attest` feature, and — see Task 10's note — there is no hardware-backed fixture that can test a *successful* binding at all. Everything here is verifier-side, offline, and drivable from the committed fixtures. What this plan ships is the seam the attester will plug into: `ratls::expected_report_data_for`, which the attester calls, and `check_binding`, which the verifier calls, reading one layout definition.

---

## Before you start: three things about the repository

**1. Check which branch you are on.** `parallax` is currently on a branch called `attest` with **no upstream**. `main` is at `efd1b64`; `attest` is eleven commits ahead and unpushed. Everything this plan builds on lives on `attest`, not on `main`. Run this first and do not proceed until it agrees:

```bash
cd /Users/jimschwoebel/Desktop/parallax
git branch -vv          # expect: * attest 9cd0852 ... (no [origin/...] marker)
git log --oneline -1    # expect: 9cd0852 Add a GCP deployment for the attester and a proxy config for it
```

If you are on `main`, none of the RTMR3 work described below exists and Task 1 is a different, much larger task than the one written here.

**2. Fork B has already landed, and the design does not know it.** The design's fork B says the shipped pair attests the workload and the shipped gate does not check it, citing `src/derive.rs:452`'s comment that nothing reads `rt_mrs`. That was true when the design was written. It is not true now. Commit `f907736` ("Task 5.5: let the verifier check RTMR3, the axis that actually names a workload") shipped the whole axis: `DeriveConfig::rtmr3_reference_values` (`src/derive.rs:128`), `rtmr3_check` (`src/derive.rs:325`), `Refutation::Rtmr3` (`src/derive.rs:236`), `[reference_values].rtmr3` and `parse_rtmr3` (`src/proxy/config.rs:225`, `:434`), the refusal prose (`src/proxy/gate.rs:435`), the floor's accounting for it (`src/proxy/gate.rs:542`), and the hardware cross-check `the_rtmr3_config_path_agrees_with_the_attesters_arithmetic` (`src/derive.rs:1186`) which pins `expected_rtmr3(workload_measurement(d))` against the real `quote-after.bin`. **Task 1 is therefore what fork B left unfinished, not fork B.** It is still first, and for the design's stated reason: the residue is a live-gate defect the offline path would otherwise inherit.

**3. The design's line numbers into `src/derive.rs` and `src/proxy/config.rs` are all stale**, by exactly the amount commit `f907736` inserted. Every citation in this plan was re-read on the working tree. Where the design and the code disagree, the code wins; the disagreements are listed in "What the design gets wrong about the code", below.

---

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**. These are already set; do not change them.
- `cargo clippy --all-targets -- -D warnings` must be clean, and so must `cargo clippy --all-targets --features fetch-collateral -- -D warnings` and `--features attest`. Warnings are errors.
- **`cargo test` with no features must pass, and the default build must link no HTTP client and no TLS stack.** This is the crate's central architectural claim (`Cargo.toml:79`–`:101`) and Task 3 turns it from a comment into an assertion.
- **Time is injected, never read from library code.** `SystemTime::now` appears in `src/bin/parallax-proxy.rs` and — new in Task 9 — in `src/bin/parallax.rs`, and nowhere else. Every new function takes `now_secs: u64` or an `as_of: u64`.
- **Randomness is injected too.** A nonce is an ambient input in exactly the way a clock is, and a CSPRNG called from library code would be the same defect. The `Challenges` trait is Task 11; its production implementation is not in this plan, because nothing in this plan needs one.
- **Every configuration surface rejects unknown keys** via `#[serde(deny_unknown_fields)]`, which every table in `src/proxy/config.rs` already carries. **An evidence record is not a configuration surface** and must *not* deny unknown fields — see Task 5.
- **No panics on anything read from a file.** Every parse, index and lookup on a record, a config or a fixture returns `Result`. No `unwrap`, `expect`, slice indexing or unchecked integer conversion on such data.
- Library errors use `thiserror`; the binaries use `anyhow`. Errors print with `{e}`, never `{e:#}` — `src/bin/parallax.rs:104` explains why.
- Exit codes for the new subcommand: `0` clean, `1` a verification or freshness failure, `2` bad input or configuration. This matches `parallax check`.
- **A promoted function's signature is frozen.** `reference_check` and `ReferenceCheck` become part of the public API in Task 2 and `poc-audit` starts calling them in Task 12. `ReferenceCheck` cannot absorb a fourth variant afterwards without a breaking change; three outcomes is the complete set for a comparison, and the alternative is `poc-audit` keeping its own copy, which is the defect being closed.
- **Never weaken a check to make a test pass.** Two things in this plan are relaxations of shipped strictness — the `report_data` zero-tail rule and the argument list of `check_binding` — and both are one-way. If a test fails, fix the code against the design, not the assertion.
- Every test runs **offline**: no network, no credentials, no TEE, against `tests/fixtures/gcp-c3-tdx` and `tests/fixtures/gcp-c3-rtmr`.
- Do not commit to `main`. Work on `attest`, or a branch off it.

---

## File Structure

| File | Responsibility | Status |
| --- | --- | --- |
| `src/clock.rs` | `Clock`, `FixedClock` — the injected clock, in the default build | **new** (moved from `src/proxy/serve.rs`) |
| `src/challenge.rs` | `Challenges` trait, `FixedChallenges`, `ChallengeStore`, single-use rule | **new** |
| `src/replay.rs` | the offline path: record reading, MRTD shape refusal, the two verdicts | **new** |
| `src/derive.rs` | `ReferenceCheck` and `reference_check` become `pub`; the staleness assumption | modified |
| `src/ratls.rs` | `ReportDataLayout`, `challenge_digest`, `expected_report_data_for` | modified |
| `src/verify/binding.rs` | `check_binding` grows the layout policy argument | modified |
| `src/proxy/config.rs` | `parse_mrtd` becomes `pub`; the `[freshness]` table | modified |
| `src/proxy/gate.rs` | the RTMR3 axis in `warnings` and the require gate; the layout reaches `check_binding` | modified |
| `src/proxy/mod.rs` | re-export `Clock`/`FixedClock` unconditionally; record the untestable gap | modified |
| `src/proxy/serve.rs` | uses `crate::clock::Clock` rather than defining it | modified |
| `src/bin/parallax.rs` | the `replay` subcommand and `--as-of` | modified |
| `src/lib.rs` | `pub mod clock; pub mod challenge; pub mod replay;` | modified |
| `tests/no_http_client.rs` | asserts the default build's dependency graph | **new** |
| `tests/replay.rs` | the offline path end to end, over the committed proxy config | **new** |
| `examples/proxy-freshness.toml` | a config that declares a bound, for the tests and the reader | **new** |
| `/Users/jimschwoebel/Desktop/poc-audit/src/field/attestation.rs` | `--proxy-config` reaches `ESTABLISHED (compared)` | modified, Task 12 |
| `/Users/jimschwoebel/Desktop/poc-audit/src/field/freshness.rs` | the `iat` auditor | **new**, Task 12 |

---

I will write the twelve tasks in three passes so each stays reviewable. Pass one is Tasks 1–4: the corrections to shipped code plus the configuration surface. Pass two is Tasks 5–9: the offline path and its CLI. Pass three is Tasks 10–12: the layout policy, the challenge store, and the cross-check into `poc-audit`.

---

## Task 1: Finish fork B — the RTMR3 axis in the admission rule

**Files:**
- Modify: `src/proxy/gate.rs`, `src/derive.rs`
- Test: in `src/proxy/gate.rs`'s `mod tests`

**Interfaces:**
- Consumes: `derive::DeriveConfig::rtmr3_reference_values`, already shipped.
- Produces: no new signature. `warnings` and `decide` change behaviour; `GateConfig` is untouched.

Commit `f907736` gave the verifier the RTMR3 axis and gave `derive` a refutation for it. What it did not give is the *admission rule*: `decide`'s require-gate reads `cfg.derive.reference_values.is_empty()` and nothing else (`src/proxy/gate.rs:353`), and `warnings` warns about the MRTD axis and nothing else (`src/proxy/gate.rs:379`–`:387`). So a proxy today can admit a connection whose **workload identity was never compared to anything** and say nothing at all about it, while an operator who wrote `require = true` believes they closed that hole.

That is the fork B defect in its remaining form, and it is exactly what the design says must not be inherited: the offline path in Task 6 reports what was compared, and if the live gate is silent about an uncompared axis the two will report different things about the same configuration.

Two changes. `warnings` gains an RTMR3 entry, unconditionally, on the same reasoning the MRTD entry exists: an allow is not a clean bill of health. And `require_reference_values` covers both axes, naming which one is missing. The second is a tightening, and its cost is stated: an operator who set `require = true` with only `mrtd` configured is now refused. That is within what `require = true` asks for — the key sits on the `[reference_values]` table, whose RTMR3 half is the only one that can tell one deployed image from another — and the shipped example sets `require = false`, so nothing in the repository changes behaviour.

- [ ] **Step 1: Write the failing tests**

Add to `src/proxy/gate.rs`'s `mod tests`. Use whatever helper the module already has for building a `GateConfig` — read the existing tests first and match them rather than inventing a second builder.

```rust
    /// Fork B's remaining half. The RTMR3 axis is what names the workload, and
    /// an allow that never compared it must say so — the same reason the MRTD
    /// warning exists. Without this, a proxy admits a connection whose
    /// workload identity was compared to nothing and reports a clean allow.
    #[test]
    fn an_allow_warns_when_the_rtmr3_axis_was_never_compared() {
        let mut cfg = gate_config(vec![[0xAB; 48]]);
        cfg.derive.rtmr3_reference_values = Vec::new();
        let mut o = most_favourable_outcome(&cfg);
        o.rt_mrs[3] = [0x11; 48];

        let d = decide(&o, &cfg, &Policy::default()).expect("the policy evaluates");
        let Decision::Allow { warnings, .. } = &d else {
            panic!("expected an allow, got {d:?}");
        };
        assert!(
            warnings.iter().any(|w| w.contains("RTMR3")),
            "no warning named the uncompared RTMR3 axis: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("urn:reference-values:rtmr3:unconfigured")),
            "the warning must name the principal the trust set records: {warnings:?}"
        );
    }

    /// The two axes get two warnings, not one shared one. A deployment that
    /// configured MRTD and forgot RTMR3 is in a different position from one
    /// that configured neither, and a single warning would print the same
    /// text for both.
    #[test]
    fn the_two_uncompared_axes_produce_two_distinguishable_warnings() {
        let mut none = gate_config(Vec::new());
        none.derive.rtmr3_reference_values = Vec::new();
        let Decision::Allow { warnings: both, .. } =
            decide(&most_favourable_outcome(&none), &none, &Policy::default())
                .expect("the policy evaluates")
        else {
            panic!("expected an allow");
        };

        let mut mrtd_only = gate_config(vec![[0xAB; 48]]);
        mrtd_only.derive.rtmr3_reference_values = Vec::new();
        let Decision::Allow { warnings: one, .. } = decide(
            &most_favourable_outcome(&mrtd_only),
            &mrtd_only,
            &Policy::default(),
        )
        .expect("the policy evaluates") else {
            panic!("expected an allow");
        };

        assert!(
            both.len() > one.len(),
            "configuring MRTD must remove exactly the MRTD warning, leaving the \
             RTMR3 one: both={both:?} one={one:?}"
        );
        assert!(one.iter().any(|w| w.contains("RTMR3")));
        assert!(
            !one.iter().any(|w| w.contains("(MRTD)")),
            "the MRTD warning must be gone once MRTD is configured: {one:?}"
        );
    }

    /// `require = true` on the `[reference_values]` table must cover the axis
    /// that actually names the workload. Before this, an operator could set
    /// it, configure only `mrtd`, and be admitted with the workload's identity
    /// unchecked — which is the hole `require` exists to close.
    #[test]
    fn requiring_reference_values_requires_the_rtmr3_axis_too() {
        let mut cfg = gate_config(vec![[0xAB; 48]]);
        cfg.derive.rtmr3_reference_values = Vec::new();
        cfg.require_reference_values = true;

        let d = decide(&most_favourable_outcome(&cfg), &cfg, &Policy::default())
            .expect("the policy evaluates");
        let Some(reason) = d.reason() else {
            panic!("expected a refusal, got {d:?}");
        };
        assert!(
            reason.contains("RTMR3"),
            "the refusal must name the axis that is missing, got: {reason}"
        );
        assert!(
            !reason.contains("MRTD reference values are configured"),
            "the refusal must not accuse the axis that IS configured: {reason}"
        );
    }

    /// The negative control. With both axes configured, `require = true`
    /// admits — otherwise the test above would pass against a gate that
    /// refuses everything.
    #[test]
    fn requiring_reference_values_admits_when_both_axes_are_configured() {
        let mut cfg = gate_config(vec![[0xAB; 48]]);
        cfg.derive.rtmr3_reference_values = vec![[0xCD; 48]];
        cfg.require_reference_values = true;
        assert!(
            decide(&most_favourable_outcome(&cfg), &cfg, &Policy::default())
                .expect("the policy evaluates")
                .is_allow(),
            "both axes configured must still admit"
        );
    }
```

**The mutation each kills.** The first two kill "delete the RTMR3 branch of `warnings`" and "merge the two warnings into one string" — the second is the one that matters, because a shared warning makes "you checked the firmware but not the workload" print the same words as "you checked nothing". The third kills "leave the require gate reading only `reference_values`". The fourth kills "make the require gate refuse unconditionally", which the third alone would accept.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib proxy::gate`
Expected: FAIL — four new tests, on the missing warning and the missing refusal.

- [ ] **Step 3: Write the implementation**

In `src/proxy/gate.rs`, beside the two existing constants at `:369`–`:374`, add the RTMR3 pair:

```rust
/// The principal `derive` names when no RTMR3 reference values were
/// configured. A separate constant from [`NO_REFERENCE_VALUES`] because it is
/// a separate principal in the trust set — see `derive`'s
/// `NO_RTMR3_REFERENCE_VALUES`, of which this is the copy, and
/// `the_unconfigured_rtmr3_principal_is_the_one_derive_emits` for the
/// assertion that the copy has not drifted.
const NO_RTMR3_REFERENCE_VALUES: &str = "urn:reference-values:rtmr3:unconfigured";

/// The capability that stands in place of the workload check nobody made.
const NEVER_MEASURED: &str = "workload_measurement_was_never_compared";
```

Replace `no_reference_values_refusal` with a function that names the axis. The old function took no argument and produced one string; it now needs to say *which* list is empty, because "you required reference values and supplied none" and "you required reference values, supplied firmware ones, and left the workload unchecked" are different operator errors:

```rust
/// Which reference-value axes are unconfigured, given a gate configuration.
///
/// Returned as a pair rather than a boolean because both the refusal and the
/// warnings need the same answer and must not compute it twice — `require =
/// true` refusing on an axis the warnings did not mention would be a gate and
/// a report disagreeing about the same configuration.
fn unconfigured_axes(cfg: &GateConfig) -> (bool, bool) {
    (
        cfg.derive.reference_values.is_empty(),
        cfg.derive.rtmr3_reference_values.is_empty(),
    )
}

/// The refusal text when `require = true` and an axis is unconfigured.
///
/// **Both axes, because the key sits on the `[reference_values]` table and
/// RTMR3 is the half of that table that can tell one deployed image from
/// another.** MRTD names the platform firmware, which is identical across
/// every workload that runs on it; a deployment that compared only MRTD has
/// established that it is running *a* trust domain it recognises, and nothing
/// at all about what is running inside it. `parallax-attest`'s entire
/// contribution is the RTMR3 extension, so a proxy paired with it that
/// requires reference values and does not require this one is requiring the
/// half that its own attester does not produce.
///
/// The cost of the tightening, stated: an operator who set `require = true`
/// with only `mrtd` configured is refused after this change. That is the
/// intended direction — they asked to fail closed on an uncompared
/// measurement — and the message names the key to add rather than only the
/// failure. `examples/proxy.toml` ships `require = false`, so nothing in this
/// repository changes behaviour.
fn no_reference_values_refusal(mrtd_missing: bool, rtmr3_missing: bool) -> String {
    let mut out = String::from(
        "this proxy is configured to require reference values \
         (`[reference_values].require = true`), and an axis has none. ",
    );
    if mrtd_missing {
        let _ = write!(
            out,
            "No MRTD reference values are configured, so the attested platform \
             measurement was compared to nothing: what the attestation proves is \
             that some code ran in a genuine Intel TDX trust domain, not that it \
             is yours. The trust set records that hole as \
             {NO_REFERENCE_VALUES} ({NEVER_COMPARED}). ",
        );
    }
    if rtmr3_missing {
        let _ = write!(
            out,
            "No RTMR3 reference values are configured, so the workload's own \
             measurement — the register `parallax-attest` extends, and the only \
             one that tells one deployed image from another — was compared to \
             nothing. The trust set records that hole as \
             {NO_RTMR3_REFERENCE_VALUES} ({NEVER_MEASURED}). Compute a value \
             with `ratls::expected_rtmr3(&ratls::workload_measurement(d))` for \
             your workload digest `d` and write it to \
             `[reference_values].rtmr3`.",
        );
    }
    out
}
```

`write!` into a `String` is infallible, and `std::fmt::Write` is already imported at `src/proxy/gate.rs:38`. The `let _ =` is there because clippy will otherwise want the `Result` handled; match whatever the module already does for this and follow it.

In `decide`, replace the require-gate block:

```rust
    let (mrtd_missing, rtmr3_missing) = unconfigured_axes(cfg);
    if cfg.require_reference_values && (mrtd_missing || rtmr3_missing) {
        return Ok(Decision::Refuse {
            reason: no_reference_values_refusal(mrtd_missing, rtmr3_missing),
            trust_set: Some(trust_set),
            mr_td: Some(outcome.mr_td),
        });
    }
```

In `warnings`, replace the single MRTD branch with the pair:

```rust
    let (mrtd_missing, rtmr3_missing) = unconfigured_axes(cfg);

    if mrtd_missing {
        out.push(format!(
            "no MRTD reference values are configured, so the attested platform \
             measurement (MRTD) was compared to nothing: this connection proves that \
             some code ran in a genuine Intel TDX trust domain, not that it is your \
             code. The trust set records the hole as {NO_REFERENCE_VALUES} \
             ({NEVER_COMPARED})."
        ));
    }

    // The second axis, and its own warning rather than a clause on the first.
    // "You checked the firmware and not the workload" is a different position
    // from "you checked neither", and one shared warning prints the same text
    // for both — which is precisely the conflation `derive` avoids by giving
    // the two axes two principals.
    if rtmr3_missing {
        out.push(format!(
            "no RTMR3 reference values are configured, so the workload's own \
             measurement was compared to nothing: RTMR3 is the register \
             `parallax-attest` extends with the workload digest, and it is the only \
             axis that distinguishes one deployed image from another running on the \
             same firmware. The trust set records the hole as \
             {NO_RTMR3_REFERENCE_VALUES} ({NEVER_MEASURED})."
        ));
    }
```

Note the MRTD warning's wording gained the word "MRTD" in its opening clause, so `the_two_uncompared_axes_produce_two_distinguishable_warnings`'s `!one.contains("(MRTD)")` assertion has something to key on. Check the existing tests in this module that assert on the old warning text and update their expectations — do not weaken them to substring-of-a-substring matches.

Now fix the stale comment. `src/derive.rs:544`–`:549` still says:

```
    // The RTMRs. Unconditional, and deliberately so: `derive` does not read
    // `o.rt_mrs`, and neither does anything else in this crate yet, so this is
```

That has been false since `f907736` and it is the exact sentence the design quotes as its evidence for fork B. Replace the first two sentences, keeping the rest of the block as it stands:

```rust
    // The RTMRs, as a measurement chain. Unconditional, and deliberately so —
    // but no longer because nothing reads them. `rtmr3_check` below compares
    // `o.rt_mrs[3]` against the configured reference values, so the workload's
    // own extension *is* checked. What stays unconditional is the property
    // this assumption names, which no comparison can establish: the host
    // extends the RTMRs with what it loads, and nothing in a quote
    // distinguishes a firmware measurement the host executed from one it
    // merely wrote. Comparing RTMR3 to a golden value tells you the register
    // holds what you expected; it does not tell you the host put it there by
    // running the code.
```

Also add the copy-drift assertion beside the existing `the_unconfigured_principal_is_the_one_derive_emits` in `src/proxy/gate.rs`'s tests, matching its shape:

```rust
    /// `NO_RTMR3_REFERENCE_VALUES` and `NEVER_MEASURED` in this module are
    /// copies of `derive`'s private constants. A copy that drifts prints a
    /// principal the trust set does not contain, which is worse than printing
    /// none: an operator would grep for it and find nothing.
    #[test]
    fn the_unconfigured_rtmr3_principal_is_the_one_derive_emits() {
        let mut cfg = gate_config(vec![[0xAB; 48]]);
        cfg.derive.rtmr3_reference_values = Vec::new();
        let t = derive(&most_favourable_outcome(&cfg), &cfg.derive).expect("derives");
        assert!(
            t.0.iter().any(|a| a.principal == NO_RTMR3_REFERENCE_VALUES
                && a.capability == NEVER_MEASURED),
            "gate.rs's copy has drifted from derive.rs's constant"
        );
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib` then `cargo test --all-targets`
Expected: PASS. Existing gate tests that asserted on the old single warning string will need their expectations updated; that is expected churn, not a regression.

- [ ] **Step 5: Update the shipped example's commentary**

`examples/proxy.toml`'s trailing block lists `[reference_values].require = false # warn rather than refuse` and, further down, explains that `require = true` "is the same gate as putting `urn:reference-values:unconfigured` on the policy's forbidden list". That sentence is now half the truth. Amend it to name both principals:

```
# Setting `require = true` turns both warnings above into refusals: MRTD and
# RTMR3 are separate axes with separate principals, and `require` covers both,
# because the half that names your workload is the RTMR3 half. It is the same
# gate as putting `urn:reference-values:unconfigured` and
# `urn:reference-values:rtmr3:unconfigured` on the policy's forbidden list ---
# see `requiring_reference_values_is_the_same_gate_as_forbidding_the_principal`.
```

Check whether `requiring_reference_values_is_the_same_gate_as_forbidding_the_principal` still holds with both axes, and extend it if it only forbids one principal.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Finish fork B: the workload axis reaches the admission rule, not only the refutation"
```

---

## Task 2: Promote the one comparison

**Files:**
- Modify: `src/derive.rs`, `src/proxy/config.rs`, `src/lib.rs`
- Test: `src/derive.rs`'s `mod tests`, `src/proxy/config.rs`'s `mod tests`

**Interfaces:**
- Produces: `derive::ReferenceCheck` (`pub`), `derive::reference_check(attested: &[u8; 48], configured: &[[u8; 48]]) -> ReferenceCheck` (`pub`), `proxy::config::parse_mrtd(hex: &str, index: usize) -> Result<[u8; 48], ConfigError>` (`pub`).
- Consumes: nothing new.

The design describes promoting `reference_check` from `(&VerificationOutcome, &DeriveConfig)` to `(&[u8; 48], &[[u8; 48]])`. **The code has already done most of that work and the design does not know it.** `check_measurement(configured: &[[u8; 48]], attested: [u8; 48]) -> ReferenceCheck` at `src/derive.rs:302` is exactly the function the design asks to create, in the opposite argument order, with two thin wrappers over it. So this task is a rename, an argument-order fix to the one the design fixes, and three `pub`s — not new logic. That is the right amount of work: the promotion the design wanted is real, and the crate had already factored it internally for the RTMR3 axis.

Argument order matters and is worth one sentence: `(attested, configured)` reads as "is this among those", which is the question, and it puts the singular value first the way `contains` does not. The design fixes this order and it is now permanent.

- [ ] **Step 1: Write the failing test**

Create `tests/one_comparison.rs`. It is an integration test rather than a unit test on purpose: it can only import what is `pub`, so it fails to compile until the promotion is real, which is a stronger statement about the API than a `#[cfg(test)]` test that can see private items.

```rust
//! The design's load-bearing property for Part 1: **one comparison, two
//! callers.** The gate's refusal and the offline path's verdict must come out
//! of the same function over the same bytes, or the audit and the enforcement
//! point can drift — and two lists with two comparisons is the defect pattern
//! this programme names as its own.
//!
//! This file only exercises the promotion. Task 6 adds the offline caller and
//! `tests/replay.rs` asserts the two agree end to end.

use parallax::derive::{derive, reference_check, DeriveConfig, ReferenceCheck, Refutation};
use parallax::latency::Latency;
use parallax::proxy::config::parse_mrtd;
use parallax::verify::VerificationOutcome;

/// The bytes an operator would write in `[reference_values].mrtd`.
const GOOD: &str = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56";
const OTHER: &str = "1122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677 88";

#[test]
fn the_comparison_is_reachable_without_a_verification_outcome() {
    // The whole reason for the re-signature: the offline path has no quote,
    // so it cannot honestly construct a `VerificationOutcome`. If this
    // function needed one, the offline path would have to fabricate eleven
    // fields it has no evidence for, or write a second comparison.
    let attested = parse_mrtd(GOOD, 0).expect("96 hex characters");
    assert_eq!(
        reference_check(&attested, &[attested]),
        ReferenceCheck::Matched
    );
    assert_eq!(
        reference_check(&attested, &[[0x00; 48]]),
        ReferenceCheck::NoMatch
    );
    assert_eq!(reference_check(&attested, &[]), ReferenceCheck::NotConfigured);
}

#[test]
fn parse_mrtd_is_the_one_place_hex_becomes_bytes() {
    let a = parse_mrtd(GOOD, 0).expect("96 hex characters");
    assert_eq!(a.len(), 48);
    // The `+0` hazard the parser documents: a typo must be refused, not
    // silently read as a different, valid reference value.
    let plus = format!("+0{}", &GOOD[2..]);
    assert!(parse_mrtd(&plus, 0).is_err(), "a leading + must be refused");
    assert!(parse_mrtd(&GOOD[..94], 0).is_err(), "94 characters is not an MRTD");
}

#[test]
fn the_gate_and_the_bare_comparison_agree_on_every_outcome() {
    // The property, stated over `derive` rather than over `reference_check`
    // twice: whatever the bare comparison says about these bytes, the gate
    // reaches the matching verdict. If someone reintroduces a second
    // comparison inside `derive`, the two can disagree and this fails.
    let good = parse_mrtd(GOOD, 0).expect("96 hex characters");
    let other = parse_mrtd(&OTHER.replace(' ', ""), 0).expect("96 hex characters");

    for (configured, attested, expected) in [
        (vec![good], good, ReferenceCheck::Matched),
        (vec![good], other, ReferenceCheck::NoMatch),
        (Vec::new(), good, ReferenceCheck::NotConfigured),
    ] {
        assert_eq!(reference_check(&attested, &configured), expected);

        let mut o = healthy_outcome();
        o.mr_td = attested;
        let cfg = DeriveConfig {
            reference_values: configured.clone(),
            rtmr3_reference_values: Vec::new(),
            verifier_id: "test".into(),
            cache_ttl: Latency::Bounded(43_200),
            collateral_source: "https://pccs.example".into(),
            max_attestation_age: None,
        };
        match (expected, derive(&o, &cfg)) {
            (ReferenceCheck::NoMatch, Err(Refutation::Measurement { mr_td, configured })) => {
                assert_eq!(mr_td, attested);
                assert_eq!(configured, 1);
            }
            (ReferenceCheck::NoMatch, other) => {
                panic!("the bare comparison refuted and the gate did not: {other:?}")
            }
            (_, Ok(_)) => {}
            (_, Err(e)) => panic!("the bare comparison admitted and the gate refuted: {e}"),
        }
    }
}

/// A `VerificationOutcome` with every field at its least-assuming value. Not
/// `most_favourable_outcome`, which needs a `GateConfig`; this file is about
/// `derive`, so it builds the outcome directly the way `derive`'s own tests
/// do.
fn healthy_outcome() -> VerificationOutcome {
    use dcap_qvl::{PckCertFlag, TcbStatus, TcbStatusWithAdvisory};
    VerificationOutcome {
        tcb_status: TcbStatus::UpToDate,
        qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        advisory_ids: Vec::new(),
        mr_td: [0u8; 48],
        rt_mrs: [[0u8; 48]; 4],
        report_data: [0u8; 64],
        attested_len: 0,
        dynamic_platform: PckCertFlag::False,
        cached_keys: PckCertFlag::False,
        smt_enabled: PckCertFlag::False,
        collateral_expires_at: 0,
        collateral_issued_at: 0,
        tcb_eval_data_number: 0,
        collateral_refresh: Latency::Bounded(43_200),
        root_ca: parallax::verify::RootCa::IntelProduction,
    }
}
```

Note `max_attestation_age: None` in the `DeriveConfig` literal — that field arrives in Task 8. Until then, delete that line; add it back when Task 8 lands, and the compiler will tell you where. `dcap_qvl` must be reachable from an integration test; check whether `parallax` re-exports what is needed, and if it does not, add a `dev-dependencies` entry pinned to the same version `Cargo.toml:184` resolves, or re-export the types from `parallax::verify`. Prefer the re-export: a second version of `dcap-qvl` in the graph would be a genuine problem, and `VerificationOutcome` is already `pub` with `pub` fields, so its field types being unreachable is a real API gap.

**The mutation each kills.** The first kills "leave `reference_check` taking an outcome", which would force the offline path to fabricate a `VerificationOutcome`. The second kills "let the offline path do its own hex decoding", which would reintroduce the `+0` hazard that `parse_hex48` documents. The third kills "write a second comparison inside `derive`" — the two callers would then agree by coincidence until one changed.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test one_comparison`
Expected: FAIL to compile — `reference_check`, `ReferenceCheck` and `parse_mrtd` are private.

- [ ] **Step 3: Write the implementation**

In `src/derive.rs`, make the enum public and rewrite its doc comment to describe both axes rather than only the MRTD one:

```rust
/// Whether a measurement was compared to anything, and if so how it went.
///
/// **`pub`, and its three variants are frozen.** `poc-audit` calls
/// [`reference_check`] directly so that the audit and the live gate admit on
/// the same bytes; a fourth variant would be a breaking change to that
/// caller. Three outcomes is the complete set for a comparison — nothing was
/// compared, it matched, it did not — and the alternative to fixing them is
/// `poc-audit` keeping a second implementation, which is the drift this
/// promotion exists to close.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReferenceCheck {
    /// No reference values were configured, so no comparison happened.
    NotConfigured,
    /// `attested` is one of the configured values.
    Matched,
    /// Reference values were configured and `attested` is not among them.
    NoMatch,
}
```

Replace `check_measurement`, `reference_check` and `rtmr3_check` with the single public function. Delete all three; do not keep the wrappers.

```rust
/// Whether `attested` is among `configured`, or nothing was configured to
/// compare it against.
///
/// **The only comparison in this crate**, over both registers and both
/// callers. `derive` calls it twice — once for `mr_td` against
/// [`DeriveConfig::reference_values`], once for `rt_mrs[3]` against
/// [`DeriveConfig::rtmr3_reference_values`] — and `replay` calls it once, for
/// an evidence record's `measurement`. That is the point of it being `pub`
/// and of it taking bytes rather than a [`VerificationOutcome`]: the offline
/// path has no quote, so it cannot construct an outcome honestly, and a
/// comparison it could not call is a comparison it would rewrite.
///
/// Argument order is `(attested, configured)` — "is this among those" —
/// rather than the container-first order `contains` uses. It is fixed by this
/// function being public and is worth getting right once.
///
/// **Empty `configured` is `NotConfigured`, not `NoMatch`.** The distinction
/// is the whole reason this returns three values instead of a `bool`: a
/// measurement nobody compared is a hole in the evidence, and a measurement
/// somebody compared and rejected is a refutation. Collapsing them makes the
/// first read as the second, or — far worse, and the direction a `bool`
/// naturally goes — makes the first read as a pass.
///
/// Not constant-time, and it does not need to be: both sides are public
/// measurements, and the attacker who would learn something from the timing
/// already knows both.
pub fn reference_check(attested: &[u8; 48], configured: &[[u8; 48]]) -> ReferenceCheck {
    if configured.is_empty() {
        ReferenceCheck::NotConfigured
    } else if configured.contains(attested) {
        ReferenceCheck::Matched
    } else {
        ReferenceCheck::NoMatch
    }
}
```

In `derive`, replace the two `match` scrutinees. The bodies of both matches stay exactly as they are:

```rust
    match reference_check(&o.mr_td, &cfg.reference_values) {
```

```rust
    match reference_check(&o.rt_mrs[3], &cfg.rtmr3_reference_values) {
```

Keep `rtmr3_check`'s doc comment — the part explaining why `rt_mrs[3]` is read as an array index rather than as byte offset 520, and citing `rtmr3_is_at_absolute_offset_520_and_472_is_rtmr2` — by moving it to a comment above the second `match`. That reasoning is load-bearing and deleting the function must not delete it.

In `src/proxy/config.rs`, make `parse_mrtd` public and say why. `parse_rtmr3` stays private for now — nothing outside the crate compares an RTMR3 from a record, because the schema has no field for one, which is itself worth recording:

```rust
/// 96 hex characters into 48 bytes: an MRTD reference value.
///
/// **`pub` so the offline path parses reference values the same way the proxy
/// does.** `replay` reads a record's `measurement` and has to turn 96 hex
/// characters into the same 48 bytes `[reference_values].mrtd` produces, or
/// the audit and the gate can disagree about a value that is textually
/// identical. It is also where the `+0` hazard is refused, and a second
/// decoder would be a second place to forget that.
///
/// `index` reaches the error message as "reference value #N". A caller with
/// only one value — which `replay` is — passes 0.
///
/// **Case-insensitive**, unlike the schema's `digest` pattern, which is
/// `[0-9a-f]` and so lowercase-only. That is deliberate on both sides and the
/// difference is `replay`'s to enforce, not this function's: a config file is
/// written by an operator who may reasonably paste uppercase hex, whereas a
/// record's `measurement` has a normative spelling and a record that departs
/// from it is malformed. See `replay::mrtd_of`, which checks the case before
/// calling this.
pub fn parse_mrtd(hex: &str, index: usize) -> Result<[u8; 48], ConfigError> {
    parse_hex48(hex, index, "MRTD")
}
```

Re-export from `src/lib.rs` beside the existing `derive` re-export, so the common path is short:

```rust
pub use derive::{derive, reference_check, DeriveConfig, ReferenceCheck, Refutation};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test one_comparison && cargo test --all-targets`
Expected: PASS. `derive.rs`'s existing tests referenced `check_measurement`/`rtmr3_check` only through `derive`, so they should be untouched; if any named the private functions directly, rewrite them against `reference_check` rather than reintroducing a wrapper.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Promote the one comparison: reference_check takes bytes, and both callers reach it"
```

---

## Task 3: `Clock` in the default build, and the dependency claim as an assertion

**Files:**
- Create: `src/clock.rs`, `tests/no_http_client.rs`
- Modify: `src/lib.rs`, `src/proxy/mod.rs`, `src/proxy/serve.rs`

**Interfaces:**
- Produces: `clock::Clock` (trait, `fn now_secs(&self) -> u64`), `clock::FixedClock(pub u64)`, both in the default build.
- Consumes: nothing. `proxy::serve` keeps using them through `crate::clock`.

A file move and one new test. `Clock` and `FixedClock` sit behind `fetch-collateral` today only because `serve` does, and the offline path needs an injectable clock in a build that links no HTTP client. Nothing about them is proxy-specific.

The test is the more interesting half. `Cargo.toml:91`–`:94` lists four commands a reader is told to run rather than trust, and one of them — `cargo tree -i reqwest -e normal` matching nothing — is the crate's central architectural claim. A comment telling you to check something is not a check.

- [ ] **Step 1: Write the failing test**

`tests/no_http_client.rs`:

```rust
//! The claim `Cargo.toml`'s `[features]` block makes, as an assertion.
//!
//! parallax's argument for the `fetch-collateral` feature existing at all is
//! that a tool which verifies attestations *offline*, against collateral
//! frozen on disk, should not ship an HTTP client and a TLS stack it never
//! calls. That claim is currently four commands in a comment. This is the
//! same four commands, run.
//!
//! It matters more after this plan than before it: T5 adds an offline
//! re-verification path and a `parallax replay` subcommand to the **default**
//! binary, and fork J ruled out `parallax-proxy --replay` precisely on the
//! grounds that it would pull reqwest and rustls in to read a file. If the
//! default graph ever grows either, that argument has quietly stopped being
//! true and this is what says so.

use std::process::Command;

/// `cargo tree -i <pkg>` exits non-zero with "did not match any packages" when
/// the package is absent from the graph, and exits zero printing the reverse
/// dependency tree when it is present. Both are unambiguous, so this reads the
/// status rather than parsing the output.
fn is_in_default_graph(package: &str) -> bool {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args(["tree", "-i", package, "-e", "normal", "--offline", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    out.status.success()
}

#[test]
fn the_default_build_links_no_http_client() {
    assert!(
        !is_in_default_graph("reqwest"),
        "reqwest is in the default dependency graph. parallax's whole argument \
         for `fetch-collateral` being a feature is that the default build \
         verifies offline and links no HTTP client; something has just made \
         that false. Run `cargo tree -i reqwest -e normal` to see what pulled \
         it in."
    );
}

#[test]
fn the_default_build_links_no_tls_stack() {
    assert!(
        !is_in_default_graph("rustls"),
        "rustls is in the default dependency graph. See \
         `the_default_build_links_no_http_client`; the same argument covers \
         this one, and fork J ruled out `parallax-proxy --replay` on it."
    );
}

/// The negative control. Without it, a `cargo tree` invocation that failed for
/// an unrelated reason — a bad flag, a missing lockfile, the wrong working
/// directory — would make both tests above pass while checking nothing.
#[test]
fn the_probe_can_find_a_package_that_is_there() {
    assert!(
        is_in_default_graph("dcap-qvl"),
        "the cargo tree probe found nothing at all, so the two assertions \
         above are vacuous. Check that `cargo tree --offline --locked` works \
         in this checkout."
    );
}
```

**The mutation this kills.** Adding `dep:reqwest` to `default`, or making `replay` reach for a network client, or wiring the new subcommand behind `fetch-collateral` — each of which would be caught only by a reader running a command from a comment.

If nested `cargo` turns out to deadlock on the package-cache lock in your environment, that is a real constraint and not a reason to delete the test: mark the two assertions `#[ignore]` with a comment naming the constraint, and add the three commands to whatever CI script the repository has. Do not replace them with something weaker that passes.

- [ ] **Step 2: Run the test to verify it passes, then break it deliberately**

Run: `cargo test --test no_http_client`
Expected: PASS, 3 tests — this one starts green, which is unusual for this plan and is fine: it is a regression guard, not a specification of new behaviour. Confirm it can fail: temporarily add `default = ["fetch-collateral"]` to `Cargo.toml`, re-run, see both assertions fail, then revert. Do not skip this; a guard nobody has seen fail is a guard nobody has checked.

- [ ] **Step 3: Move the clock**

`src/clock.rs`:

```rust
//! The injected clock, and nothing else.
//!
//! **Why this is its own module rather than part of `proxy::serve`.** It was
//! part of `serve` until T5, which put it behind the `fetch-collateral`
//! feature — not because a clock needs an HTTP client, but because `serve`
//! does. The offline re-verification path needs an injectable clock in a build
//! that links neither, so the trait moved out to where both halves can see it.
//! This is a file move: no behaviour changed, and `proxy` re-exports both
//! items so existing callers are unaffected.
//!
//! The discipline it exists to serve is the crate's, stated in
//! `proxy::serve`'s module documentation: nothing in this library calls
//! `SystemTime::now`. The implementations that do live in the binaries —
//! `SystemClock` in `src/bin/parallax-proxy.rs`, and `--as-of now` in
//! `src/bin/parallax.rs`. A clock read from library code is an input a test
//! cannot control, in the one place a test most needs to.

/// Seconds since the Unix epoch, supplied rather than read.
///
/// `Debug` is a supertrait so that a value holding one can derive it: a proxy
/// printed in a log should say which clock it was built with, and "the system
/// one" and "a pinned one" are not interchangeable facts.
pub trait Clock: std::fmt::Debug + Send + Sync + 'static {
    fn now_secs(&self) -> u64;
}

/// A clock that does not move. What the tests use.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_clock_does_not_move() {
        let c = FixedClock(1_700_000_000);
        assert_eq!(c.now_secs(), 1_700_000_000);
        assert_eq!(c.now_secs(), c.now_secs());
    }

    /// Two fixed clocks at different times are different clocks. Stated
    /// because the tests that matter in this crate — the freshness boundary,
    /// the challenge expiry sweep — all turn on driving the same input past
    /// two different clocks and getting two different answers.
    #[test]
    fn two_clocks_at_different_times_disagree() {
        assert_ne!(FixedClock(1).now_secs(), FixedClock(2).now_secs());
    }
}
```

Delete the trait, the struct and the `impl` from `src/proxy/serve.rs` (they are at `:73`–`:91`, immediately after `DRAIN_DEADLINE` and the rustls imports). Add `use crate::clock::Clock;` to `serve.rs`'s import block — it already refers to `Clock` in `Proxy`'s `clock: Arc<dyn Clock>` field and in `Proxy::new`'s signature, and those stay as they are.

In `src/lib.rs`, add `pub mod clock;` in alphabetical position (before `collateral`).

In `src/proxy/mod.rs`, change the re-export block at the bottom so the clock is unconditional and only the socket types stay behind the feature:

```rust
pub use config::{ConfigError, ProxyConfig, Upstream};
pub use gate::{decide, Decision, GateConfig};

// Re-exported here as well as from `crate::clock`, because every existing
// caller reaches them through `proxy::` and a move should not be a breaking
// change. Unconditional: the clock is in the default build as of T5, and only
// the things that open a socket are behind the feature.
pub use crate::clock::{Clock, FixedClock};

#[cfg(feature = "fetch-collateral")]
pub use serve::{Proxy, ServeError};
```

- [ ] **Step 4: Run the tests to verify they pass in both builds**

```bash
cargo test --all-targets
cargo test --all-targets --features fetch-collateral
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features fetch-collateral -- -D warnings
```
Expected: PASS everywhere. `tests/proxy.rs` constructs a `FixedClock` through `parallax::proxy::FixedClock`; the re-export keeps that working.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Move the clock into the default build, and assert the dependency claim it exists for"
```

---

## Task 4: The `[freshness]` table

**Files:**
- Create: `examples/proxy-freshness.toml`
- Modify: `src/proxy/config.rs`
- Test: `src/proxy/config.rs`'s `mod tests`

**Interfaces:**
- Produces: `ProxyConfig::max_attestation_age: Option<Latency>`, `ProxyConfig::require_fresh: bool`, `ConfigError::FreshnessNeverIsNotABound`.
- Consumes: `Latency::parse`, `Latency::label`.

C7.2.3 requires the claim to state a maximum attestation refresh interval. Nothing in this crate has anywhere to write one. This task adds the place and the parser, and stops there: the value does not reach the trust set until Task 8 and does not gate anything until Tasks 7 and 11, so this task's whole deliverable is that a number can be written down and read back with one spelling.

`require_fresh` defaults to `false`, mirroring `require_reference_values` (`src/proxy/config.rs:230`) for the reason fork E gives: against an unmodified `parallax-attest` the age of an attestation is *unmeasurable*, not stale, and refusing by default would break every deployment of the shipped pair on upgrade.

- [ ] **Step 1: Write the failing tests**

Add to `src/proxy/config.rs`'s `mod tests`. Follow the existing tests' shape for writing a temporary config — read `rtmr3_reference_values_load` at `:634` and reuse whatever it does rather than inventing a second temp-file helper.

```rust
    /// C7.2.3's declared interval, with one spelling. `Latency::parse` is
    /// many-to-one and `label` is the inverse that picks one, so two configs
    /// that mean 15 minutes must not produce two different manifests.
    #[test]
    fn a_declared_attestation_age_loads_with_one_spelling() {
        for spelling in ["15m", "900s", "900 seconds"] {
            let cfg = load_with(&format!(
                "[freshness]\nmax_attestation_age = \"{spelling}\"\n"
            ));
            assert_eq!(
                cfg.max_attestation_age,
                Some(Latency::Bounded(900)),
                "`{spelling}` must normalise like every other spelling of 15m"
            );
            assert_eq!(
                cfg.max_attestation_age.as_ref().map(Latency::label),
                Some("900s".to_string())
            );
        }
    }

    /// The table is optional, and its absence is not zero. A deployment that
    /// declares no bound has declared no bound; defaulting to some number
    /// would put a promise in the manifest the operator never made.
    #[test]
    fn an_absent_freshness_table_declares_no_bound() {
        let cfg = load_with("");
        assert_eq!(cfg.max_attestation_age, None);
        assert!(!cfg.require_fresh, "require_fresh defaults to false");
    }

    /// The lattice trap, arriving through a fourth door. `Never` is the top
    /// element, so the most cautious-looking spelling means *no bound at all*
    /// — and the message must name both readings, or an operator "fixes" it
    /// by picking the one the error mentioned.
    #[test]
    fn never_is_refused_as_an_attestation_age_and_names_both_readings() {
        let e = load_err("[freshness]\nmax_attestation_age = \"never\"\n");
        let text = e.to_string();
        assert!(
            matches!(e, ConfigError::FreshnessNeverIsNotABound),
            "got {e:?}"
        );
        assert!(
            text.contains("no bound"),
            "must say that `never` sets no bound: {text}"
        );
        assert!(
            text.contains("refresh") || text.contains("re-quote"),
            "must name the other reading — that it looks like `refresh \
             constantly` — or the operator fixes the wrong half: {text}"
        );
        assert!(
            !text.contains("cache_ttl"),
            "this is the freshness key, not the collateral one; a shared \
             message would send the operator to the wrong line: {text}"
        );
    }

    /// `require_fresh` is the operator's choice, mirroring
    /// `[reference_values].require`, and defaults the same way and for the
    /// same reason: an unmeasurable attestation age is not a stale one, and
    /// refusing by default makes the tool undeployable against every peer
    /// that exists today.
    #[test]
    fn require_fresh_is_opt_in() {
        assert!(!load_with("[freshness]\nmax_attestation_age = \"15m\"\n").require_fresh);
        assert!(
            load_with("[freshness]\nmax_attestation_age = \"15m\"\nrequire_fresh = true\n")
                .require_fresh
        );
    }

    /// `deny_unknown_fields`, on the new table as on every other. A silently
    /// ignored typo in a security-relevant key is a gate that fails open —
    /// and `max_attestation_ttl` is exactly the typo someone will write.
    #[test]
    fn an_unknown_freshness_key_is_refused() {
        let e = load_err("[freshness]\nmax_attestation_ttl = \"15m\"\n");
        assert!(matches!(e, ConfigError::Parse { .. }), "got {e:?}");
    }

    /// `require_fresh = true` with nothing to enforce is a configuration that
    /// cannot mean what it says. Refused at load rather than at the first
    /// connection, for the same reason `max_connections = 0` is.
    #[test]
    fn requiring_freshness_without_declaring_a_bound_is_refused() {
        let e = load_err("[freshness]\nrequire_fresh = true\n");
        assert!(matches!(e, ConfigError::RequireFreshWithoutBound), "got {e:?}");
        assert!(
            e.to_string().contains("max_attestation_age"),
            "the error must name the key to add: {e}"
        );
    }

    /// The shipped example loads and declares a bound, so the reader has one
    /// worked instance and `tests/replay.rs` has something to run against.
    #[test]
    fn the_freshness_example_loads() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = ProxyConfig::load(&root.join("examples/proxy-freshness.toml"))
            .expect("the shipped freshness example is loadable");
        assert_eq!(cfg.max_attestation_age, Some(Latency::Bounded(900)));
        assert!(!cfg.require_fresh);
        assert_eq!(cfg.gate.derive.reference_values.len(), 1);
    }
```

You will need two small helpers in the test module if the existing tests do not already have equivalents; write them once and use them from every later task's config tests:

```rust
    /// Write a proxy config whose body is the shipped example's preamble plus
    /// `extra`, load it, and return the result. The preamble is fixed so that
    /// every test in this module varies exactly one thing.
    fn config_text(extra: &str) -> String {
        format!(
            "upstream = \"https://svc.internal:8443\"\n\
             listen = \"127.0.0.1:8080\"\n\
             policy = \"examples/policy-proxy.toml\"\n\
             [collateral]\n\
             source = \"https://api.trustedservices.intel.com/tdx/certification/v4\"\n\
             cache_ttl = \"12h\"\n\
             {extra}"
        )
    }

    fn load_with(extra: &str) -> ProxyConfig {
        load_result(extra).expect("this configuration is meant to load")
    }

    fn load_err(extra: &str) -> ConfigError {
        load_result(extra).expect_err("this configuration is meant to be refused")
    }
```

`load_result` writes `config_text(extra)` to a uniquely-named temporary file — include `std::process::id()` and a nanosecond count, the way `poc-audit`'s `unique_temp_path` does, because `cargo test` runs these in parallel — calls `ProxyConfig::load`, removes the file, and returns the result. The policy path is relative to the repository root, which is what `the_shipped_example_loads` already assumes, so run these from `CARGO_MANIFEST_DIR`.

**The mutation each kills.** Spelling: "render the duration with `{:?}`", which puts `Bounded(900)` in a manifest and makes two identical deployments compare `Incomparable`. Absent table: "default to some number", which fabricates a declaration. `never`: "accept it", which reports the loosest possible claim for whatever the deployment actually does — the same inversion `cache_ttl` already refuses. `require_fresh` default: "default to true", which breaks every shipped deployment on upgrade. Unknown key: "drop `deny_unknown_fields`". Require-without-bound: "accept it", producing a proxy that requires freshness it has no number for.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib proxy::config`
Expected: FAIL — no `freshness` field on `File`, no `max_attestation_age` on `ProxyConfig`, `ConfigError` has neither new variant.

- [ ] **Step 3: Write the implementation**

Add the two error variants to `ConfigError`, after `NeverIsNotABound`:

```rust
    /// `[freshness].max_attestation_age = "never"` inverts what it says, the
    /// same way [`ConfigError::NeverIsNotABound`] does for the collateral
    /// cache, and it is a separate variant so the message can name the right
    /// key and the right two readings.
    ///
    /// The two readings here are worse than the cache's, because they point in
    /// opposite directions with the same word. As a *bound*, `never` is
    /// `Latency`'s top element: no bound at all, an attestation of any age
    /// accepted, and a manifest reporting the attester as never detectable. As
    /// an *interval*, "never re-quote" reads to an operator as the tightest
    /// possible setting, since it is the one word in the vocabulary that
    /// sounds like a refusal. There is no spelling here for "do not check":
    /// omit the key.
    #[error(
        "`freshness.max_attestation_age = \"never\"` sets no bound at all, and \
         this build refuses it rather than reporting the opposite of what it \
         does. `never` is the top element of the latency lattice, so as a bound \
         it accepts an attestation of any age and reports the attesting host as \
         never detectable in the manifest — the loosest possible claim, written \
         with the most cautious-looking word. Read as a refresh interval it \
         says the attester never re-quotes, which is the opposite. Write a \
         duration such as `15m`; to declare no bound, omit the key."
    )]
    FreshnessNeverIsNotABound,
    /// `require_fresh = true` with no `max_attestation_age` to enforce.
    ///
    /// Refused at load rather than at the first connection, for the same
    /// reason [`ConfigError::MaxConnections`] refuses zero: the configuration
    /// cannot mean what it says, and a listener that binds and then refuses
    /// every connection tells the operator far less than an exit code does.
    #[error(
        "`freshness.require_fresh = true` refuses an attestation that is older \
         than the declared bound, and no `freshness.max_attestation_age` is \
         declared, so there is no bound to be older than. Add \
         `max_attestation_age = \"15m\"` (or whatever interval this deployment \
         re-quotes at), or remove `require_fresh`."
    )]
    RequireFreshWithoutBound,
```

Add the table to `File` and its type:

```rust
    /// C7.2.3's declared refresh interval, and whether to enforce it. Absent
    /// means no bound is declared, which is not the same as a bound of zero
    /// and not the same as `never`.
    #[serde(default)]
    freshness: FreshnessTable,
```

```rust
/// The declared staleness bound on an attestation, and what to do at its edge.
///
/// **Named `max_attestation_age` so that `max_actions_per_attestation` is
/// additive.** C7.2.3 says "the longest period, **or** the largest number of
/// actions", and this build implements only the first. The action counter is
/// per-attester state that only the attester can hold, and adding cross-process
/// counting to close a row would be disproportionate; the naming leaves the
/// door open. What the count would buy is the amortization arithmetic P03 asks
/// for — actions per interval times probability of change times damage per
/// action — which is the thing a deployment budgeting against a 39.5 ms quote
/// actually reasons about, and it is recorded as P03's to answer.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessTable {
    /// A duration, in `Latency::parse`'s vocabulary. `"never"` is refused —
    /// see [`ConfigError::FreshnessNeverIsNotABound`].
    #[serde(default)]
    max_attestation_age: Option<String>,
    /// Refuse rather than warn when the age is outside the bound or cannot be
    /// determined at all. Default `false`, mirroring
    /// `[reference_values].require`, and for the same reason it does: against
    /// an unmodified `parallax-attest` the age of a peer's quote is
    /// **unmeasurable**, not stale, and an unmeasurable attestation is not a
    /// stale one. Refusing by default would break every deployment of the
    /// shipped pair on upgrade; allowing silently is how a deployment believes
    /// something it has no evidence for. So it is the operator's choice, and
    /// the warning names the fix.
    #[serde(default)]
    require_fresh: bool,
}
```

In `ProxyConfig`, add the two fields with the doc comments the manifest reader will need:

```rust
    /// C7.2.3's declared maximum attestation age, or `None` if this deployment
    /// declares none.
    ///
    /// Always [`Latency::Bounded`] when `Some`: [`ProxyConfig::load`] refuses
    /// [`Latency::Never`] with [`ConfigError::FreshnessNeverIsNotABound`].
    ///
    /// **Declared and unverified.** Unlike `cache_ttl`, which has a measured
    /// counterpart in the collateral's own validity window, this has none: a
    /// TDX quote carries no timestamp, so there is nothing in the evidence to
    /// take the join against. `derive` records that in the assumption's text
    /// rather than implying a measurement happened — see Task 8.
    pub max_attestation_age: Option<Latency>,
    /// Refuse rather than warn outside the bound. See
    /// [`FreshnessTable::require_fresh`].
    pub require_fresh: bool,
```

In `load`, after the `cache_ttl` block:

```rust
        let max_attestation_age = match &file.freshness.max_attestation_age {
            None => None,
            Some(text) => {
                let parsed = Latency::parse(text).map_err(|source| ConfigError::Duration {
                    field: "freshness.max_attestation_age",
                    value: text.clone(),
                    source,
                })?;
                // Refused here, at the one place the string becomes a
                // configuration, so no consumer downstream has to decide which
                // of the two readings it meant.
                if parsed == Latency::Never {
                    return Err(ConfigError::FreshnessNeverIsNotABound);
                }
                Some(parsed)
            }
        };
        if file.freshness.require_fresh && max_attestation_age.is_none() {
            return Err(ConfigError::RequireFreshWithoutBound);
        }
```

and add both to the returned `ProxyConfig`.

- [ ] **Step 4: Write the example**

`examples/proxy-freshness.toml`. It differs from `examples/proxy.toml` in three ways — it declares a bound, it configures one MRTD reference value so the offline path has something to compare against, and it names `policy-proxy.toml` so it does not fail its own startup check — and it says so:

```toml
# A proxy configuration that declares a C7.2.3 attestation refresh interval.
#
# `examples/proxy.toml` is the reference file and this is not a replacement for
# it: it configures reference values (which that one deliberately leaves empty,
# to demonstrate the warning) and points at the permissive policy (which that
# one deliberately does not, to demonstrate the startup check). It exists so
# that `parallax replay` and `tests/replay.rs` have a configuration that
# actually compares something, and so that a reader has one worked instance of
# the `[freshness]` table.

upstream = "https://svc.internal:8443"
listen   = "127.0.0.1:8080"
policy   = "examples/policy-proxy.toml"

[collateral]
source    = "https://api.trustedservices.intel.com/tdx/certification/v4"
cache_ttl = "12h"

[reference_values]
# Not a real deployment's MRTD. `tests/fixtures/gcp-c3-tdx`'s quote is the only
# real one this repository holds, and this file is read by tests that compare
# against a record rather than against that quote, so the value here is a
# recognisable placeholder rather than a measurement anyone could mistake for
# their own.
mrtd = ["ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56"]

[freshness]
# C7.2.3: "the longest period ... between attestation refreshes". This is the
# amortization window the 39.5 ms quote cost makes compulsory, written down.
#
# What it bounds and what it does not: it bounds the age of an attestation the
# verifier can date. It does **not** bound the age of a *measurement* reached
# through an evidence record's `iat` — a record issued one second ago can rest
# on a quote taken six days ago, and nothing in a record distinguishes those.
# See `replay`'s freshness verdict, which says so in the row it prints.
max_attestation_age = "15m"

# Default. `true` refuses an attestation outside the bound, or one whose age
# cannot be determined at all — which, against an unmodified `parallax-attest`,
# is every attestation, because a TDX quote carries no timestamp. Turning it on
# without an attester that publishes an epoch refuses everything, so it is off
# here and the warning names the fix.
require_fresh = false
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib proxy::config`
Expected: PASS, 7 new tests.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add the [freshness] table: a declared bound, refused when it is `never`"
```

---

## Task 5: The record, and the measurement shape that is a record error

**Files:**
- Create: `src/replay.rs`
- Modify: `src/lib.rs`
- Test: `src/replay.rs`'s `mod tests`

**Interfaces:**
- Produces: `replay::EvidenceRecord`, `replay::Submods`, `replay::Attestation`, `replay::RecordError`, `replay::INTEL_TDX`, `replay::MRTD_ALGORITHM`, `replay::MRTD_HEX_LEN`, `replay::read(path: &Path) -> Result<EvidenceRecord, RecordError>`, `replay::mrtd_of(a: &Attestation) -> Result<[u8; 48], RecordError>`.
- Consumes: `proxy::config::parse_mrtd` (promoted in Task 2).

Fork A, and it is the task most likely to be argued with, so the reasoning goes in the code. `submods.attestation.measurement` under `platform: INTEL_TDX` **is the MRTD**: `sha-384:` followed by 96 lowercase hex characters, 48 bytes. Anything else is a *record* error and not a comparison failure, because a value that cannot be an MRTD was never a candidate for the comparison — reporting it as `NoMatch` would say "you are running the wrong workload" about a record that does not describe a workload at all.

This makes the standard's own strongest positive vector invalid. That is finding 1, it ships as a finding rather than as a reason to weaken the check, and a test pins it so that nobody quietly relaxes the parser to make the vector pass.

- [ ] **Step 1: Write the failing test**

`src/replay.rs`'s `mod tests` — the whole module arrives in Step 3, so write the tests first in a file that does not compile yet:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The MRTD from `examples/proxy-freshness.toml`, as a record would carry
    /// it: the algorithm tag, a colon, and 96 lowercase hex characters.
    const GOOD: &str = "sha-384:ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56";

    fn attestation(platform: &str, measurement: &str) -> Attestation {
        Attestation {
            platform: platform.to_string(),
            measurement: measurement.to_string(),
        }
    }

    #[test]
    fn a_well_formed_mrtd_reaches_48_bytes() {
        let m = mrtd_of(&attestation(INTEL_TDX, GOOD)).expect("a 48-byte sha-384 digest");
        assert_eq!(m.len(), 48);
        assert_eq!(m[0], 0xab);
        assert_eq!(m[47], 0x96);
    }

    /// **Finding 1, pinned, and deliberate.**
    ///
    /// This is the exact value carried by the standard's own strongest
    /// positive vector, `schema/vectors/positive/hardware-attested.json`,
    /// whose `platform` is `INTEL_TDX`. It is `sha-256:` and 64 hex characters
    /// — 32 bytes. An Intel TDX MRTD is 48. So the standard's best
    /// hardware-attested vector carries a measurement that cannot be the
    /// measurement it claims to be, and this build refuses it.
    ///
    /// **Do not "fix" this test by relaxing the parser.** The whole purpose of
    /// the field is that a verifier can compare it to a reference value, and a
    /// comparison that accepts any digest of any width says nothing about
    /// which register was measured. Relaxing until interoperation works is the
    /// move C7.7's own commentary warns about, and the vector is filed as a
    /// finding against the standard instead. See
    /// `docs/standard-findings.md` finding 1 in the roadmap repository.
    #[test]
    fn the_standards_own_hardware_attested_vector_is_refused() {
        let vector =
            "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81";
        let e = mrtd_of(&attestation(INTEL_TDX, vector))
            .expect_err("32 bytes cannot be a TDX MRTD");
        assert!(
            matches!(e, RecordError::WrongAlgorithm { .. }),
            "must be a record error, not a comparison failure: {e:?}"
        );
        let text = e.to_string();
        assert!(text.contains("48 bytes"), "must state the requirement: {text}");
        assert!(
            text.contains("sha-384"),
            "must name the algorithm that can denote an MRTD: {text}"
        );
        assert!(
            !text.to_lowercase().contains("match"),
            "must not read as a failed comparison — nothing was compared: {text}"
        );
    }

    /// **Finding 2, pinned.** The schema's `digest` pattern is
    /// `^(sha-256|sha-384|sha-512|sha3-256):[0-9a-f]{64,128}$`, which does not
    /// tie the tag to the length, so `sha-384:` plus 64 hex characters
    /// validates cleanly. A verifier that trusted the tag would read 32 bytes
    /// as a 48-byte register. This is where that record stops.
    #[test]
    fn the_right_tag_with_the_wrong_length_is_refused() {
        let short = format!("sha-384:{}", "ab".repeat(32));
        let e = mrtd_of(&attestation(INTEL_TDX, &short)).expect_err("64 hex is not 96");
        assert!(matches!(e, RecordError::WrongLength { found: 64 }), "{e:?}");
        assert!(
            e.to_string().contains("96"),
            "must state the length required: {e}"
        );
    }

    /// The schema's pattern is `[0-9a-f]`. `parse_mrtd` is deliberately
    /// case-insensitive, because an operator pasting a config value may
    /// reasonably write uppercase; a record has a normative spelling and one
    /// that departs from it is malformed. The check lives here rather than in
    /// the config parser so that neither is loosened to accommodate the other.
    #[test]
    fn uppercase_hex_is_refused_in_a_record_though_a_config_would_take_it() {
        let upper = format!("sha-384:{}", "AB".repeat(48));
        assert!(matches!(
            mrtd_of(&attestation(INTEL_TDX, &upper)),
            Err(RecordError::NotLowercaseHex { .. })
        ));
        // The same characters, through the config parser, are fine. If this
        // half ever starts failing, someone has tightened `parse_mrtd` and
        // broken configs that used to load.
        assert!(crate::proxy::config::parse_mrtd(&"AB".repeat(48), 0).is_ok());
    }

    #[test]
    fn a_measurement_with_no_algorithm_tag_is_refused() {
        let e = mrtd_of(&attestation(INTEL_TDX, &"ab".repeat(48)))
            .expect_err("no tag is not a digest");
        assert!(matches!(e, RecordError::NoAlgorithmTag { .. }), "{e:?}");
    }

    /// A non-hex character inside a correctly tagged, correctly sized value
    /// reaches `parse_mrtd`, which is the one place hex becomes bytes and the
    /// one place the `+0` hazard is refused. A second decoder here would be a
    /// second place to forget it.
    #[test]
    fn non_hex_reaches_the_shared_parser_and_is_refused_there() {
        let bad = format!("sha-384:{}zz", "ab".repeat(47));
        let e = mrtd_of(&attestation(INTEL_TDX, &bad)).expect_err("zz is not hex");
        assert!(matches!(e, RecordError::NotHex { .. }), "{e:?}");
    }

    /// A platform this build cannot map to a register is refused rather than
    /// compared. `SOFTWARE` in particular: comparing a software measurement
    /// against a list of MRTDs would produce a `NoMatch` that reads as "wrong
    /// workload" about a record that never claimed a TEE at all.
    #[test]
    fn a_platform_other_than_intel_tdx_is_refused_rather_than_compared() {
        for platform in ["SOFTWARE", "AMD_SEV_SNP", "", "intel_tdx"] {
            let e = mrtd_of(&attestation(platform, GOOD))
                .expect_err("only INTEL_TDX maps to an MRTD here");
            assert!(
                matches!(e, RecordError::UnsupportedPlatform { .. }),
                "{platform}: {e:?}"
            );
        }
    }

    /// A record carries many fields this crate has no opinion about, and
    /// refusing them would make `parallax` a second, worse schema validator
    /// competing with `validate.py`. This is the one place in the crate where
    /// `deny_unknown_fields` is deliberately absent, and the test says so.
    #[test]
    fn a_record_may_carry_fields_this_crate_does_not_read() {
        let json = r#"{
            "iss": "did:web:example.org",
            "iat": 1700000000,
            "nonce": "n-00000001",
            "eat_profile": "https://advancedaisociety.org/poc/v0.1",
            "poc_claims": { "verdict": "ALLOW", "step_index": 0 },
            "submods": {
                "attestation": {
                    "platform": "INTEL_TDX",
                    "measurement": "sha-384:ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56",
                    "reference_values_uri": "https://rv.example/v.json"
                }
            }
        }"#;
        let r = parse(json, "test").expect("a record with extra fields parses");
        assert_eq!(r.iat, 1_700_000_000);
        assert_eq!(r.nonce, "n-00000001");
        assert_eq!(r.submods.attestation.platform, INTEL_TDX);
    }

    /// A record missing a field this crate *does* read is a parse failure
    /// naming the field, not a default. A defaulted `iat` of 0 would make
    /// every record look infinitely stale, and a defaulted `measurement` of ""
    /// would make every record a record error — both are wrong answers
    /// delivered confidently.
    #[test]
    fn a_record_missing_a_field_this_crate_reads_is_refused() {
        let json = r#"{"iat": 1700000000, "nonce": "n-1", "submods": {}}"#;
        let e = parse(json, "test").expect_err("submods.attestation is required here");
        assert!(matches!(e, RecordError::Parse { .. }), "{e:?}");
    }
}
```

**The mutation each kills.** `the_standards_own_hardware_attested_vector_is_refused` kills the relaxation this whole fork exists to prevent — accepting any `digest` shape so the standard's vector passes — and its third assertion additionally kills "implement fork A1 as a silent mismatch", where a 32-byte digest reads as the wrong workload rather than as a malformed record. `the_right_tag_with_the_wrong_length_is_refused` kills "trust the algorithm tag". `uppercase_hex_is_refused...` kills both directions of the case question: dropping the record-side check, and tightening the config parser to compensate. `non_hex_reaches_the_shared_parser` kills "write a second hex decoder", which is how the `+0` hazard comes back. `a_record_may_carry_fields...` kills "add `deny_unknown_fields`", which would refuse every real record.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib replay`
Expected: FAIL to compile — `parallax::replay` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod replay;` to `src/lib.rs`, in alphabetical position (after `policy`, before `proxy`).

`src/replay.rs`, the first half:

```rust
//! Offline re-verification of a Proof-of-Control evidence record's claims.
//!
//! # The two acts, stated apart
//!
//! Verifying a live quote establishes *this connection terminates inside a
//! trust domain running code whose MRTD is one of these*. Re-checking a record
//! establishes *the value written in this field is one of these*. **The second
//! is strictly weaker**, and pretending otherwise is the failure this module
//! exists to avoid. What it adds is not a stronger claim; it is a claim made
//! against **the same bytes the gate admits on** — `derive::reference_check`,
//! reached from the same `ProxyConfig` the proxy runs with — so that the audit
//! and the enforcement point cannot drift.
//!
//! The verdict vocabulary carries the distinction from the first commit:
//! [`Established::Compared`] is what this module can produce, and
//! [`Established::ReVerified`] is what a record carrying its own quote would
//! earn. Only the first is reachable today. The split exists so the thin
//! verdict can never be mistaken for the strong one.
//!
//! # What this deliberately does not do
//!
//! - **Fetch anything.** No PCCS call, no `reference_values_uri` fetch, no
//!   time-authority call. `poc-audit` already refuses to fetch the URI a
//!   record names and this inherits that line.
//! - **Emit a record.** This checks; `ephemeris` produces. A tool that read a
//!   record and wrote a better one would be signing a "you passed" token.
//! - **Parse a quote.** Every cryptographic check in this crate runs through
//!   `verify::verify_quote`. If this module ever grows its own quote parser,
//!   the design has failed.
//! - **Validate a record against the schema.** `validate.py` does that, and a
//!   second validator here would be a worse one competing with it. This module
//!   reads five fields and refuses a record only when one of those five cannot
//!   mean what it has to mean.

use crate::latency::Latency;
use crate::proxy::config::parse_mrtd;
use serde::Deserialize;
use std::path::Path;

/// The only `platform` value this build can map to a hardware register.
pub const INTEL_TDX: &str = "INTEL_TDX";

/// The only algorithm tag that can denote an Intel TDX MRTD.
///
/// An MRTD is 48 bytes and the four algorithms the schema's `digest` type
/// admits are SHA-256 (32), SHA-384 (48), SHA-512 (64) and SHA3-256 (32). Only
/// one of them is the right width, and a register is not a hash function: the
/// value is whatever TDX put there, and its width is the property that has to
/// match.
pub const MRTD_ALGORITHM: &str = "sha-384";

/// 48 bytes as lowercase hex.
pub const MRTD_HEX_LEN: usize = 96;

/// The fields of a Proof-of-Control evidence record this crate reads.
///
/// **No `deny_unknown_fields`, uniquely in this crate.** Every configuration
/// surface here refuses unknown keys, because a mistyped key in a config is a
/// setting the operator believes they made. A record is the opposite case: it
/// is written by another tool against a schema this crate does not own, it
/// carries a dozen fields with no bearing on attestation, and refusing them
/// would make `parallax` a second schema validator — a worse one, competing
/// with `validate.py`, and reporting its disagreements as record errors.
///
/// This is a *second reader* of a file `poc-audit` also parses, and that is a
/// real duplication rather than a comfortable one. It is accepted for one
/// reason: fork J requires `parallax replay` to exist in the default build so
/// the capability is reachable and testable without `poc-audit`, and a
/// dependency in that direction would make the tool that audits depend on the
/// tool being audited. The guard is the cross-check in `poc-audit`'s own test
/// suite, which drives the same record through both readers and asserts they
/// agree — the row the design calls load-bearing.
#[derive(Clone, Debug, Deserialize)]
pub struct EvidenceRecord {
    /// Issuance time, seconds since the Unix epoch. `i64` because that is what
    /// a JWT `iat` is and what `poc-audit`'s `Record` uses; a negative value
    /// is a record before 1970 and is handled by [`freshness`] rather than
    /// refused here, since it is a nonsense timestamp and not a malformed one.
    pub iat: i64,
    /// The relying party's challenge (C7.1.4). Read but not checked offline —
    /// see [`Replay`]'s documentation for why a file cannot establish
    /// freshness against a challenge.
    pub nonce: String,
    pub submods: Submods,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Submods {
    pub attestation: Attestation,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Attestation {
    pub platform: String,
    pub measurement: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path} as a Proof-of-Control evidence record: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    /// A platform whose `measurement` this build cannot map to a register.
    ///
    /// Refused rather than compared, and that is the point. Comparing a
    /// `SOFTWARE` measurement against a list of MRTDs would produce a
    /// `NoMatch` reading "you are running a workload you did not declare",
    /// about a record that never claimed a trust domain at all.
    #[error(
        "`submods.attestation.platform` is `{platform}`, and this build only knows \
         how to compare a measurement against reference values for `{INTEL_TDX}`. \
         Nothing was compared: this is a record this tool cannot audit, not a \
         measurement that failed to match."
    )]
    UnsupportedPlatform { platform: String },
    #[error(
        "`submods.attestation.measurement` is `{measurement}`, which carries no \
         `<algorithm>:` prefix. Under platform {INTEL_TDX} it must be \
         `{MRTD_ALGORITHM}:` followed by {MRTD_HEX_LEN} lowercase hex characters, \
         the 48 bytes of an Intel TDX MRTD."
    )]
    NoAlgorithmTag { measurement: String },
    /// The record's algorithm tag cannot denote an MRTD.
    ///
    /// **This is the finding, not a bug.** The standard's own strongest
    /// positive vector, `schema/vectors/positive/hardware-attested.json`,
    /// carries `sha-256:` and 64 hex characters under `platform: INTEL_TDX` —
    /// 32 bytes, where a TDX MRTD is 48. Refusing it is deliberate and the
    /// vector is filed upstream as finding 1 rather than accommodated here.
    /// The alternative reading, that `measurement` is a platform-opaque digest
    /// whose mapping to a register is deployment-specific, keeps the record
    /// valid by making the comparison meaningless: two opaque strings matching
    /// says nothing about which register was measured.
    #[error(
        "`submods.attestation.measurement` declares algorithm `{tag}`, but this \
         record's `platform` is {INTEL_TDX} and an Intel TDX MRTD is 48 bytes, so \
         `{MRTD_ALGORITHM}` is the only algorithm that can denote one. This is a \
         defect in the record: nothing was compared to anything."
    )]
    WrongAlgorithm { tag: String },
    /// The tag is right and the width is not.
    ///
    /// Reachable because the schema's `digest` pattern is
    /// `^(sha-256|sha-384|sha-512|sha3-256):[0-9a-f]{64,128}$`, which does not
    /// tie the algorithm to the length — so `sha-384:` followed by 64 hex
    /// characters validates cleanly. That is finding 2, and this is where such
    /// a record stops.
    #[error(
        "`submods.attestation.measurement` declares `{MRTD_ALGORITHM}` but carries \
         {found} hex characters, not {MRTD_HEX_LEN}; an Intel TDX MRTD is 48 bytes. \
         The schema's `digest` pattern does not tie the algorithm tag to a length, \
         so a record in this shape validates against the schema — that is a defect \
         in the schema, and this build refuses the record rather than reading \
         {found} hex characters as a 48-byte register."
    )]
    WrongLength { found: usize },
    #[error(
        "`submods.attestation.measurement` contains `{found}` at character {at} of \
         its digest, which is uppercase; the schema's digest pattern is `[0-9a-f]`, \
         so a measurement is lowercase hex. (This crate's *config* parser accepts \
         either case on purpose — an operator pasting a reference value may \
         reasonably write uppercase — and a record has a normative spelling that \
         an operator does not choose.)"
    )]
    NotLowercaseHex { found: char, at: usize },
    /// Anything `parse_mrtd` refuses that the checks above did not catch:
    /// non-hex characters, and the `+0` hazard its own documentation
    /// describes, where a typo silently becomes a different valid value.
    #[error("`submods.attestation.measurement` is not hex: {reason}")]
    NotHex { reason: String },
}

/// Read a record from `path`.
pub fn read(path: &Path) -> Result<EvidenceRecord, RecordError> {
    let text = std::fs::read_to_string(path).map_err(|source| RecordError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse(&text, &path.display().to_string())
}

/// Parse a record from `text`. `origin` reaches the error message.
pub fn parse(text: &str, origin: &str) -> Result<EvidenceRecord, RecordError> {
    serde_json::from_str(text).map_err(|source| RecordError::Parse {
        path: origin.to_string(),
        source,
    })
}

/// The 48 bytes an attestation's `measurement` denotes, or why it denotes none.
///
/// Every failure here is a **record** error and none is a comparison failure.
/// That distinction is fork A's whole content: a value that cannot be an MRTD
/// was never a candidate for the comparison, and reporting it as a mismatch
/// would say "you are running the wrong workload" about a record that does not
/// describe a workload.
///
/// The hex decode itself goes through [`parse_mrtd`], the config parser, so
/// that a record's measurement and a proxy's reference value become bytes by
/// exactly one route. The checks above it — the tag, the length, the case —
/// are the constraints the *schema* imposes and the config file does not, and
/// they live here for that reason rather than being pushed down into a parser
/// two callers share.
pub fn mrtd_of(a: &Attestation) -> Result<[u8; 48], RecordError> {
    if a.platform != INTEL_TDX {
        return Err(RecordError::UnsupportedPlatform {
            platform: a.platform.clone(),
        });
    }
    let Some((tag, hex)) = a.measurement.split_once(':') else {
        return Err(RecordError::NoAlgorithmTag {
            measurement: a.measurement.clone(),
        });
    };
    if tag != MRTD_ALGORITHM {
        return Err(RecordError::WrongAlgorithm {
            tag: tag.to_string(),
        });
    }
    if hex.len() != MRTD_HEX_LEN {
        return Err(RecordError::WrongLength { found: hex.len() });
    }
    // `char_indices` rather than `bytes`, so the reported offset is a
    // character position in the string the operator is looking at, and so a
    // multi-byte character cannot land this mid-character. `parse_mrtd` does
    // the hex validation; this only adds the case constraint the schema has
    // and the config parser deliberately does not.
    if let Some((at, found)) = hex.char_indices().find(|(_, c)| c.is_ascii_uppercase()) {
        return Err(RecordError::NotLowercaseHex { found, at });
    }
    parse_mrtd(hex, 0).map_err(|e| RecordError::NotHex {
        reason: e.to_string(),
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib replay`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Read a record's measurement as an MRTD, and refuse the standard's own vector"
```

---

## Task 6: The verdict, and the two `ESTABLISHED`s

**Files:**
- Modify: `src/replay.rs`
- Test: `src/replay.rs`'s `mod tests`, `tests/replay.rs`

**Interfaces:**
- Produces: `replay::Established` (`Compared`, `ReVerified`), `replay::MeasurementVerdict`, `replay::measurement(record, configured) -> Result<MeasurementVerdict, RecordError>`.
- Consumes: `derive::reference_check`, `derive::ReferenceCheck`.

`Established::ReVerified` is unreachable in this plan and is written anyway. The design is explicit about why: the split has to exist from day one, because the conflation it prevents — a comparison reported in the same words as a cryptographic re-verification — is exactly what produced `TOOLING.md`'s † correction. A verdict enum that grows a second `Established` later would have shipped every intervening report under the strong-sounding name.

- [ ] **Step 1: Write the failing test**

Add to `src/replay.rs`'s `mod tests`:

```rust
    /// The whole point of the split. Both are `ESTABLISHED`; they must not
    /// render as the same string, because a comparison against an operator's
    /// list and a cryptographic re-verification of a quote are different
    /// claims and one of them is far weaker.
    #[test]
    fn the_two_established_verdicts_are_distinguishable() {
        assert_ne!(
            Established::Compared.label(),
            Established::ReVerified.label()
        );
        assert!(Established::Compared.label().contains("compared"));
        assert!(Established::ReVerified.label().contains("re-verified"));
        assert!(Established::Compared.label().starts_with("ESTABLISHED"));
        assert!(Established::ReVerified.label().starts_with("ESTABLISHED"));
    }

    /// `ReVerified` is unreachable in this build and is written anyway, so
    /// that no report ever ships the weak verdict under the strong name while
    /// waiting for the strong one to exist. This asserts it stays unreachable
    /// rather than being wired up by accident to a path that compares strings.
    #[test]
    fn nothing_in_this_build_produces_the_re_verified_verdict() {
        let attested = mrtd_of(&attestation(INTEL_TDX, GOOD)).expect("parses");
        for configured in [vec![attested], vec![[0u8; 48]], Vec::new()] {
            let v = measurement(&attestation(INTEL_TDX, GOOD), &configured)
                .expect("a well-formed record");
            assert!(
                !matches!(v, MeasurementVerdict::Established(Established::ReVerified)),
                "a string comparison produced the cryptographic verdict"
            );
        }
    }

    #[test]
    fn a_matching_measurement_is_established_as_compared() {
        let attested = mrtd_of(&attestation(INTEL_TDX, GOOD)).expect("parses");
        assert_eq!(
            measurement(&attestation(INTEL_TDX, GOOD), &[attested]).expect("well-formed"),
            MeasurementVerdict::Established(Established::Compared)
        );
    }

    #[test]
    fn a_measurement_among_none_of_several_diverges_and_says_how_many() {
        let v = measurement(&attestation(INTEL_TDX, GOOD), &[[0u8; 48], [1u8; 48]])
            .expect("well-formed");
        assert_eq!(v, MeasurementVerdict::Diverges { configured: 2 });
    }

    /// Nothing configured is not a mismatch and must not read as one. It is
    /// the hole the live gate records as
    /// `urn:reference-values:unconfigured`, and the offline path reports the
    /// same hole rather than inventing a pass or a failure.
    #[test]
    fn no_reference_values_is_asserted_not_diverges() {
        assert_eq!(
            measurement(&attestation(INTEL_TDX, GOOD), &[]).expect("well-formed"),
            MeasurementVerdict::Asserted
        );
    }

    /// A record error propagates as an error rather than becoming a verdict.
    /// If it became `Diverges`, a malformed record would be reported as a
    /// workload mismatch — the exact confusion Task 5 exists to prevent, one
    /// layer up.
    #[test]
    fn a_record_error_is_not_a_verdict() {
        let e = measurement(&attestation("SOFTWARE", GOOD), &[[0u8; 48]])
            .expect_err("SOFTWARE has no MRTD");
        assert!(matches!(e, RecordError::UnsupportedPlatform { .. }), "{e:?}");
    }

    /// Every reason text this module produces must use the word that says what
    /// actually happened. A report that says "verified" about a string
    /// comparison is the overclaim the whole programme attacks.
    #[test]
    fn the_established_reason_says_compared_and_not_verified() {
        let attested = mrtd_of(&attestation(INTEL_TDX, GOOD)).expect("parses");
        let v = measurement(&attestation(INTEL_TDX, GOOD), &[attested]).expect("well-formed");
        let reason = v.reason(1);
        assert!(reason.contains("compared"), "{reason}");
        assert!(
            !reason.contains("verified") || reason.contains("not re-verified"),
            "the reason must not claim verification, or must explicitly deny it: {reason}"
        );
        assert!(
            reason.contains("no quote"),
            "the reason must say why it is only a comparison: {reason}"
        );
    }
```

**The mutation each kills.** The first two kill collapsing the two `Established`s into one, in both directions — deleting `ReVerified`, and wiring it to the comparison path. `no_reference_values_is_asserted_not_diverges` kills "treat an empty list as a mismatch", which would make every unconfigured audit look like a workload compromise. `a_record_error_is_not_a_verdict` kills "map `RecordError` onto `Diverges`", which is the shape a `Result`-flattening refactor naturally reaches for. The last kills the overclaim in the prose, which no type can catch.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib replay`
Expected: FAIL to compile — `Established`, `MeasurementVerdict` and `measurement` do not exist.

- [ ] **Step 3: Write the implementation**

Append to `src/replay.rs`:

```rust
/// Which of the two `ESTABLISHED`s a measurement row earned.
///
/// **Both are `ESTABLISHED` and they are not the same claim.** The split
/// exists from the first commit rather than being added when the second
/// becomes reachable, because a vocabulary that had only one of them would
/// have reported every comparison under a name that also covers cryptographic
/// re-verification — which is the conflation that produced `TOOLING.md`'s †
/// correction, and the reason this repository is careful about verdict words
/// at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Established {
    /// The value written in the record's `measurement` field is one of the
    /// reference values the operator's proxy config names. **A string
    /// comparison, over bytes nobody re-derived from a quote.** It establishes
    /// that the record says what the operator expects it to say. It does not
    /// establish that any hardware produced it, that the record was not
    /// fabricated, or that the quote it summarises ever existed.
    Compared,
    /// The record carried its own quote and collateral, that quote verified
    /// against the trust anchor, its `report_data` bound it to a key, and the
    /// measurement compared here came out of the verified quote rather than
    /// out of a JSON field.
    ///
    /// **Unreachable in this build**, and deliberately present. It needs a
    /// `submods.attestation.evidence` member carrying the quote and the
    /// collateral bundle, which is a schema addition and belongs to whoever
    /// owns the producer. When it exists, the path is
    /// `verify_quote(quote, collateral, iat, root, refresh)` → `check_binding`
    /// → `decide` with a `FixedClock(iat)`, and every function in that chain
    /// is already pure and already takes its time as a parameter. Until then
    /// no code constructs this variant, and
    /// `nothing_in_this_build_produces_the_re_verified_verdict` is what keeps
    /// it that way.
    ReVerified,
}

impl Established {
    /// The one rendering. Both start with `ESTABLISHED` because both are, and
    /// both carry the qualifier because the difference between them is the
    /// difference between a claim and a proof.
    pub fn label(&self) -> &'static str {
        match self {
            Established::Compared => "ESTABLISHED (compared)",
            Established::ReVerified => "ESTABLISHED (re-verified)",
        }
    }
}

/// What re-checking a record's `measurement` established.
///
/// Three variants and not four: they are `ReferenceCheck`'s three outcomes,
/// carried up with the reason text each one needs. A fourth would mean this
/// module had learned something `reference_check` does not know, which would
/// mean a second comparison.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MeasurementVerdict {
    Established(Established),
    /// Reference values were configured and the record's MRTD is not among
    /// them. **The highest-value output this path can produce**: attested code
    /// that is not the code the operator approved.
    Diverges { configured: usize },
    /// No reference values were configured, so nothing was compared. The same
    /// hole the live gate records as `urn:reference-values:unconfigured`, and
    /// reported here in the same terms rather than as a pass or a failure.
    Asserted,
}

impl MeasurementVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            MeasurementVerdict::Established(e) => e.label(),
            MeasurementVerdict::Diverges { .. } => "DIVERGES",
            MeasurementVerdict::Asserted => "ASSERTED",
        }
    }

    /// One line, naming what was compared against what and — for the
    /// established case — naming what was *not* done.
    ///
    /// `configured_total` is the number of reference values the config
    /// carried, passed in rather than stored on the verdict so that
    /// `Established` and `Asserted` do not each need a copy of it.
    pub fn reason(&self, configured_total: usize) -> String {
        match self {
            MeasurementVerdict::Established(Established::Compared) => format!(
                "this record's measurement is one of the {configured_total} MRTD \
                 reference value(s) in the proxy configuration — the same list the \
                 gate admits on, through the same comparison. This is a comparison \
                 of the value written in the field, not a re-verification: the \
                 record carries no quote, so nothing cryptographic was checked and \
                 nothing establishes that any hardware produced this value."
            ),
            MeasurementVerdict::Established(Established::ReVerified) => format!(
                "this record carried a quote, the quote verified, and the \
                 measurement it attests is one of the {configured_total} MRTD \
                 reference value(s) in the proxy configuration."
            ),
            MeasurementVerdict::Diverges { configured } => format!(
                "this record's measurement is none of the {configured} MRTD \
                 reference value(s) in the proxy configuration: the record names a \
                 trust domain this deployment does not admit. Note what this does \
                 and does not say — the record is a claim, so this is a \
                 disagreement between two written values, not evidence that any \
                 particular code ran."
            ),
            MeasurementVerdict::Asserted => String::from(
                "the proxy configuration names no MRTD reference values, so this \
                 record's measurement was compared to nothing. What the record \
                 attests, taken at its word, is that some code ran in a genuine \
                 trust domain — not that it is your code. Add \
                 `[reference_values].mrtd` to the proxy configuration this audit \
                 reads, and the gate and this row change together.",
            ),
        }
    }
}

/// Compare a record's `measurement` against `configured`.
///
/// **The comparison is `derive::reference_check`**, the same function
/// `derive` calls for the live gate, over bytes produced by the same
/// `parse_mrtd`. There is no second comparison and no second list: `configured`
/// comes from `ProxyConfig::load`'s `gate.derive.reference_values`, which is
/// the list the proxy actually admits on. If an operator changes what the
/// proxy admits, this changes with it, in the same commit.
pub fn measurement(
    a: &Attestation,
    configured: &[[u8; 48]],
) -> Result<MeasurementVerdict, RecordError> {
    let attested = mrtd_of(a)?;
    Ok(match crate::derive::reference_check(&attested, configured) {
        crate::derive::ReferenceCheck::Matched => {
            MeasurementVerdict::Established(Established::Compared)
        }
        crate::derive::ReferenceCheck::NoMatch => MeasurementVerdict::Diverges {
            configured: configured.len(),
        },
        crate::derive::ReferenceCheck::NotConfigured => MeasurementVerdict::Asserted,
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib replay`
Expected: PASS, 16 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Split ESTABLISHED (compared) from ESTABLISHED (re-verified) before either ships"
```

---

## Task 7: The staleness boundary, both sides

**Files:**
- Modify: `src/replay.rs`
- Test: `src/replay.rs`'s `mod tests`

**Interfaces:**
- Produces: `replay::FreshnessVerdict`, `replay::freshness(iat: i64, as_of: u64, bound: Option<&Latency>) -> FreshnessVerdict`.

The boundary is inclusive, stated and tested, so that "at the boundary" is not decided by an off-by-one that nobody wrote down. A record *newer* than the evaluation time is a distinct verdict from a stale one, because a record issued in the future is not stale — it is wrong.

The reason text on every verdict here has two jobs beyond naming the verdict, and both are requirements the design states outright. It must name the evaluation time, because `--as-of` makes the tool's answer a function of an argument and an operator can produce a clean report by passing the record's own `iat`. And it must state that a fresh `iat` **does not** satisfy C7.2.3, which is about the age of the *measurement*: a record issued one second ago can rest on a quote taken six days ago, and nothing in the record distinguishes those.

- [ ] **Step 1: Write the failing test**

```rust
    const HOUR: u64 = 3600;

    /// The boundary, both sides, stated rather than inherited from whichever
    /// comparison operator got typed. `age == bound` is inside.
    #[test]
    fn the_staleness_boundary_is_inclusive() {
        let bound = Latency::Bounded(900);
        let iat = 1_700_000_000i64;
        assert!(matches!(
            freshness(iat, 1_700_000_900, Some(&bound)),
            FreshnessVerdict::Fresh { age_secs: 900, .. }
        ));
        assert!(matches!(
            freshness(iat, 1_700_000_901, Some(&bound)),
            FreshnessVerdict::Stale { age_secs: 901, .. }
        ));
        // And the trivial inside case, so a verdict that reported everything
        // stale would not pass the pair above by accident.
        assert!(matches!(
            freshness(iat, 1_700_000_000, Some(&bound)),
            FreshnessVerdict::Fresh { age_secs: 0, .. }
        ));
    }

    /// A record issued after the evaluation time is not stale. Collapsing the
    /// two loses the only signal that distinguishes a clock disagreement or a
    /// forged timestamp from an old record.
    #[test]
    fn a_future_dated_record_is_its_own_verdict() {
        let v = freshness(1_700_000_060, 1_700_000_000, Some(&Latency::Bounded(900)));
        assert!(
            matches!(v, FreshnessVerdict::FutureDated { ahead_secs: 60 }),
            "{v:?}"
        );
        // And it is future-dated whether or not a bound was declared: the
        // question "is this record from the future" does not depend on how
        // long records are allowed to live.
        assert!(matches!(
            freshness(1_700_000_060, 1_700_000_000, None),
            FreshnessVerdict::FutureDated { ahead_secs: 60 }
        ));
    }

    /// The clock is genuinely injected: the same record under two evaluation
    /// times yields fresh and stale, and no test here can be made to pass or
    /// fail by changing the machine's clock.
    #[test]
    fn the_same_record_is_fresh_and_stale_under_two_evaluation_times() {
        let bound = Latency::Bounded(900);
        let iat = 1_700_000_000i64;
        assert!(matches!(
            freshness(iat, 1_700_000_060, Some(&bound)),
            FreshnessVerdict::Fresh { .. }
        ));
        assert!(matches!(
            freshness(iat, 1_700_000_000 + HOUR, Some(&bound)),
            FreshnessVerdict::Stale { .. }
        ));
    }

    /// No declared bound is not a bound of zero and not a bound of infinity.
    /// It is the absence of a declaration, and it is reported as such, with
    /// the age still measured so an operator can see the number the
    /// declaration would have to cover.
    #[test]
    fn an_undeclared_bound_reports_the_age_without_a_verdict_on_it() {
        assert!(matches!(
            freshness(1_700_000_000, 1_700_000_000 + HOUR, None),
            FreshnessVerdict::NoBoundDeclared { age_secs: 3600 }
        ));
    }

    /// `Latency::Never` cannot reach here through `ProxyConfig::load`, which
    /// refuses it. It is handled anyway, and handled as *no bound*, because
    /// `Never` is the lattice's top element and that is what it means — the
    /// same reading the config error's message argues for. Sorting it into
    /// `Fresh` would make the loosest possible setting produce the cleanest
    /// possible row.
    #[test]
    fn never_is_no_bound_and_not_always_fresh() {
        assert!(matches!(
            freshness(1_700_000_000, 1_700_000_000 + HOUR, Some(&Latency::Never)),
            FreshnessVerdict::NoBoundDeclared { .. }
        ));
    }

    /// Nonsense timestamps do not panic and do not silently wrap. `iat` is
    /// `i64` off a JSON file and nothing stops it being negative or enormous.
    #[test]
    fn extreme_timestamps_do_not_panic_or_wrap() {
        let bound = Latency::Bounded(900);
        assert!(matches!(
            freshness(i64::MIN, 0, Some(&bound)),
            FreshnessVerdict::Stale { .. }
        ));
        assert!(matches!(
            freshness(i64::MAX, 0, Some(&bound)),
            FreshnessVerdict::FutureDated { .. }
        ));
        assert!(matches!(
            freshness(0, u64::MAX, Some(&bound)),
            FreshnessVerdict::Stale { .. }
        ));
    }

    /// Every freshness reason must name the evaluation time, because
    /// `--as-of` makes this tool's answer a function of an argument: an
    /// operator can produce a clean report by passing the record's own `iat`,
    /// and the only mitigation available is that the report says which time it
    /// used.
    #[test]
    fn every_freshness_reason_names_the_evaluation_time() {
        let bound = Latency::Bounded(900);
        for v in [
            freshness(1_700_000_000, 1_700_000_060, Some(&bound)),
            freshness(1_700_000_000, 1_700_009_999, Some(&bound)),
            freshness(1_700_000_060, 1_700_000_000, Some(&bound)),
            freshness(1_700_000_000, 1_700_000_060, None),
        ] {
            let r = v.reason(1_700_000_060);
            assert!(
                r.contains("1700000060") || r.contains("evaluation time"),
                "{v:?} did not name the evaluation time: {r}"
            );
        }
    }

    /// The gap the design says the tool must not paper over: a fresh `iat`
    /// bounds the age of the *record*, and C7.2.3 is about the age of the
    /// *measurement*. A record issued one second ago can rest on a quote taken
    /// six days ago and nothing in the record distinguishes those.
    #[test]
    fn a_fresh_iat_reason_denies_satisfying_c7_2_3() {
        let r = freshness(1_700_000_000, 1_700_000_060, Some(&Latency::Bounded(900)))
            .reason(1_700_000_060);
        assert!(r.contains("C7.2.3"), "{r}");
        assert!(
            r.contains("quote") && r.contains("record"),
            "the reason must distinguish the record's age from the quote's: {r}"
        );
    }

    /// And the second honest limitation, on every row: `iat` is written by the
    /// issuer, and the same party wrote the signature over it, so a back-dated
    /// record is indistinguishable from a timely one to this tool.
    #[test]
    fn every_freshness_reason_names_the_back_dating_limitation() {
        let bound = Latency::Bounded(900);
        for v in [
            freshness(1_700_000_000, 1_700_000_060, Some(&bound)),
            freshness(1_700_000_000, 1_700_009_999, Some(&bound)),
            freshness(1_700_000_000, 1_700_000_060, None),
        ] {
            let r = v.reason(1_700_000_060);
            assert!(
                r.contains("back-dated") || r.contains("issuer"),
                "{v:?} did not name who wrote the timestamp: {r}"
            );
        }
    }
```

**The mutation each kills.** The boundary pair kills `>=` where `>` belongs and the reverse. `a_future_dated_record_is_its_own_verdict` kills collapsing future and past into one verdict, in both the declared and undeclared cases. `the_same_record_is_fresh_and_stale...` kills a `SystemTime::now` reaching this function. `never_is_no_bound...` kills sorting `Never` into `Fresh`. `extreme_timestamps...` kills the `as u64` casts that would wrap. The three reason-text tests kill the omissions that would let the tool imply it has answered C7.2.2 or C7.2.3.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib replay`
Expected: FAIL to compile — `FreshnessVerdict` and `freshness` do not exist.

- [ ] **Step 3: Write the implementation**

Append to `src/replay.rs`:

```rust
/// What comparing a record's `iat` against an evaluation time established.
///
/// **Every variant carries the age**, including the ones where it does not
/// decide the verdict, because the number is what an operator needs in order
/// to choose a bound — and a row that reports "stale" without saying by how
/// much is a row nobody can act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreshnessVerdict {
    /// `iat` is at most `bound_secs` before the evaluation time. Inclusive.
    Fresh { age_secs: u64, bound_secs: u64 },
    /// `iat` is more than `bound_secs` before the evaluation time.
    Stale { age_secs: u64, bound_secs: u64 },
    /// `iat` is *after* the evaluation time.
    ///
    /// A distinct verdict, not a stale one with a negative age. A record from
    /// the future is not old; it is wrong, and the two have different causes —
    /// a clock disagreement, a wrong `--as-of`, or a fabricated timestamp —
    /// none of which "stale" would lead anyone to look for.
    FutureDated { ahead_secs: u64 },
    /// No bound was declared, so there is nothing to be inside or outside of.
    ///
    /// The age is still reported. Not a pass and not a failure: an absent
    /// declaration is C7.2.3 unmet, and saying so is different from saying the
    /// record failed a check.
    NoBoundDeclared { age_secs: u64 },
}

impl FreshnessVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            FreshnessVerdict::Fresh { .. } => "ESTABLISHED (compared)",
            FreshnessVerdict::Stale { .. } => "ASSERTED",
            FreshnessVerdict::FutureDated { .. } => "DIVERGES",
            FreshnessVerdict::NoBoundDeclared { .. } => "ASSERTED",
        }
    }

    /// One line, naming the evaluation time and the two things this row cannot
    /// establish.
    ///
    /// **Both caveats appear on every variant, including the clean one.** A
    /// report that names its limitations only when it fails is a report whose
    /// clean rows overclaim, and the clean row is the one somebody quotes.
    pub fn reason(&self, as_of: u64) -> String {
        // Said on every row. `iat` is written by the issuer and the same party
        // signed over it, so this detects a record that has aged and detects
        // nothing about one that was back-dated. C7.2.2's external anchoring
        // is the requirement that would fix it and nothing in this programme
        // implements it.
        let issuer = "`iat` is written by the issuer, who also signed over it, so this \
                      detects a record that has aged and nothing about one that was \
                      back-dated; external time anchoring (C7.2.2) is what would fix \
                      that and is not implemented anywhere in this programme";
        // Said on every row that reports a bound. The bound is on the
        // *record's* age; C7.2.3 is about the *measurement's*.
        let gap = "a fresh `iat` does not satisfy C7.2.3: this bounds the age of the \
                   record, and C7.2.3 is about the age of the measurement. A record \
                   issued one second ago can rest on a quote taken six days ago, and \
                   nothing in a record distinguishes those — only a record carrying \
                   its own quote would close the gap";
        match self {
            FreshnessVerdict::Fresh {
                age_secs,
                bound_secs,
            } => format!(
                "the record was issued {age_secs}s before the evaluation time {as_of}, \
                 within the declared maximum attestation age of {bound_secs}s. Note \
                 that {gap}. Note also that {issuer}."
            ),
            FreshnessVerdict::Stale {
                age_secs,
                bound_secs,
            } => format!(
                "the record was issued {age_secs}s before the evaluation time {as_of}, \
                 outside the declared maximum attestation age of {bound_secs}s. This \
                 is not a refutation of anything the record claims — the measurement \
                 row is separate — it is the declared interval having elapsed. Note \
                 that {issuer}."
            ),
            FreshnessVerdict::FutureDated { ahead_secs } => format!(
                "the record's `iat` is {ahead_secs}s *after* the evaluation time \
                 {as_of}. A record issued in the future is not stale, it is wrong: \
                 either the evaluation time is earlier than intended, the issuer's \
                 clock disagrees with it, or the timestamp was fabricated. Note that \
                 {issuer}."
            ),
            FreshnessVerdict::NoBoundDeclared { age_secs } => format!(
                "the record was issued {age_secs}s before the evaluation time \
                 {as_of}, and the proxy configuration declares no \
                 `[freshness].max_attestation_age`, so there is no interval for it to \
                 be inside or outside. C7.2.3 requires the claim to state a maximum \
                 attestation refresh interval; this deployment states none. Note that \
                 {issuer}."
            ),
        }
    }
}

/// Compare a record's `iat` against an evaluation time.
///
/// Pure, total, and reads no clock — `as_of` is supplied by the caller, which
/// is what makes the "same record, two evaluation times" test possible and
/// what keeps a machine's clock out of the answer.
///
/// **`bound` of `None` and of `Some(Latency::Never)` are the same verdict.**
/// `ProxyConfig::load` refuses `never` so the second cannot arrive through a
/// config, but this function is `pub` and the reading has to be right either
/// way: `Never` is the top element of the latency lattice, so as a bound it is
/// the absence of one. Sorting it into `Fresh` would make the loosest possible
/// setting produce the cleanest possible row, which is the inversion
/// `ConfigError::FreshnessNeverIsNotABound` exists to refuse.
///
/// Arithmetic in `i128` throughout: `iat` is an `i64` read off a file and
/// `as_of` is a `u64`, so neither their difference nor its sign fits in either
/// type, and an `as` cast between them is where a wrap would hide. The
/// saturating conversion at the end reports an absurd age as `u64::MAX` rather
/// than as a small number, which is the safe direction — a record dated to the
/// year 300 billion reads as maximally stale rather than as fresh.
pub fn freshness(iat: i64, as_of: u64, bound: Option<&Latency>) -> FreshnessVerdict {
    let iat = i128::from(iat);
    let now = i128::from(as_of);

    if iat > now {
        return FreshnessVerdict::FutureDated {
            ahead_secs: u64::try_from(iat - now).unwrap_or(u64::MAX),
        };
    }
    let age_secs = u64::try_from(now - iat).unwrap_or(u64::MAX);

    match bound {
        None | Some(Latency::Never) => FreshnessVerdict::NoBoundDeclared { age_secs },
        Some(Latency::Bounded(bound_secs)) => {
            // Inclusive: `age == bound` is inside. Stated in one place, with
            // one operator, so "at the boundary" is a decision rather than an
            // accident. An operator declaring a 15-minute interval means a
            // record exactly 15 minutes old is the last acceptable one.
            if age_secs <= *bound_secs {
                FreshnessVerdict::Fresh {
                    age_secs,
                    bound_secs: *bound_secs,
                }
            } else {
                FreshnessVerdict::Stale {
                    age_secs,
                    bound_secs: *bound_secs,
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib replay`
Expected: PASS, 25 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Compare iat against an injected evaluation time, inclusively, and say what that cannot show"
```

---

## Task 8: The declared bound reaches the manifest

**Files:**
- Modify: `src/derive.rs`, `src/proxy/config.rs`, `src/proxy/gate.rs`
- Test: `src/derive.rs`'s `mod tests`

**Interfaces:**
- Produces: `DeriveConfig::max_attestation_age: Option<Latency>`; two new principals in `derive`.
- Consumes: `ProxyConfig::max_attestation_age` from Task 4.

A declared interval that nothing depends on is a number in a file. This is where it becomes visible in the Residual Trust Manifest, which is where an auditor reading C7.2.3's "the declared interval" would look.

The shape follows `undeclared_flag_assumptions` (`src/derive.rs:441`) rather than the obvious one. The obvious one — push an assumption when a bound is declared, push nothing when it is not — makes the *less* informative deployment produce the smaller trust set, so a deployment that declares nothing looks cleaner than one that declares fifteen minutes. That is the exact failure the crate already documents for undeclared PCK flags: "the absence of the evidence is itself something the operator is resting on, so it gets a name." So both cases push, on two principals.

Note the interaction with `pcs_detection_bound` (`src/derive.rs:368`), which takes the join of a measured bound and a declared one. This assumption has no measured counterpart, because a TDX quote carries no timestamp — there is nothing in the evidence to take a join against. It is declared and unverified, and the capability string has to say so.

- [ ] **Step 1: Write the failing test**

```rust
    /// C7.2.3's declared interval, in the manifest. Two deployments that
    /// differ only in `max_attestation_age` must not compare `Equal` — if they
    /// do, the number is a promise nothing depends on.
    #[test]
    fn the_declared_attestation_age_reaches_the_trust_set() {
        let o = healthy();
        let mut short = cfg(Vec::new());
        short.max_attestation_age = Some(Latency::Bounded(900));
        let mut long = cfg(Vec::new());
        long.max_attestation_age = Some(Latency::Bounded(86_400));

        let a = derive(&o, &short).expect("derives");
        let b = derive(&o, &long).expect("derives");
        assert_ne!(a, b, "the declared interval must change the trust set");
        assert_eq!(
            compare(&a, &b),
            Relation::Incomparable,
            "two different declared intervals are not ordered by inclusion; \
             neither deployment's assumptions are a subset of the other's"
        );
    }

    /// The direction that matters more, and the one the obvious
    /// implementation gets backwards: declaring nothing must not produce a
    /// *smaller* set than declaring something. An operator who writes no bound
    /// has not removed an assumption; they have declined to bound one.
    #[test]
    fn declaring_no_bound_is_not_cleaner_than_declaring_one() {
        let o = healthy();
        let mut declared = cfg(Vec::new());
        declared.max_attestation_age = Some(Latency::Bounded(900));
        let undeclared = cfg(Vec::new());

        let d = derive(&o, &declared).expect("derives");
        let u = derive(&o, &undeclared).expect("derives");
        assert_eq!(
            d.len(),
            u.len(),
            "both must carry an entry for the attestation's age; only the \
             principal and the bound differ"
        );
        assert_eq!(compare(&d, &u), Relation::Incomparable);

        // And the undeclared one must be the *worse* bound, not the absent one.
        let entry = u
            .0
            .iter()
            .find(|a| a.principal == NO_ATTESTATION_AGE)
            .expect("an undeclared bound has its own principal");
        assert_eq!(entry.latency, Latency::Never);
        assert_eq!(entry.impact, Impact::Soundness);
    }

    /// The capability string must say the bound is declared and unverified.
    /// Unlike the collateral bound, which takes the join of a declared
    /// interval and a measured window, this one has no measured counterpart:
    /// a TDX quote carries no timestamp, so nothing in the evidence can
    /// contradict the declaration.
    #[test]
    fn the_attestation_age_assumption_says_it_is_unverified() {
        let mut c = cfg(Vec::new());
        c.max_attestation_age = Some(Latency::Bounded(900));
        let t = derive(&healthy(), &c).expect("derives");
        let entry = t
            .0
            .iter()
            .find(|a| a.principal == ATTESTER)
            .expect("a declared bound names the attesting host");
        assert_eq!(entry.latency, Latency::Bounded(900));
        assert_eq!(entry.impact, Impact::Soundness);
        assert!(
            entry.capability.contains("unverified") || entry.capability.contains("declared"),
            "the capability must not read as a measured bound: {}",
            entry.capability
        );
    }

    /// The two principals are distinct, for the same reason
    /// `REFERENCE_VALUES` and `NO_REFERENCE_VALUES` are: `principals()` is an
    /// aggregate consumers read, and "somebody declared an interval" must not
    /// present the same list of parties as "nobody did".
    #[test]
    fn declared_and_undeclared_attestation_ages_are_different_principals() {
        assert_ne!(ATTESTER, NO_ATTESTATION_AGE);
        let mut declared = cfg(Vec::new());
        declared.max_attestation_age = Some(Latency::Bounded(900));
        let d = derive(&healthy(), &declared).expect("derives");
        let u = derive(&healthy(), &cfg(Vec::new())).expect("derives");
        assert!(d.principals().contains(&ATTESTER.to_string()));
        assert!(!d.principals().contains(&NO_ATTESTATION_AGE.to_string()));
        assert!(u.principals().contains(&NO_ATTESTATION_AGE.to_string()));
        assert!(!u.principals().contains(&ATTESTER.to_string()));
    }
```

Use whatever `cfg(...)` and `healthy()` helpers `derive.rs`'s test module already has — read them first — and `TrustSet::principals`'s actual return type, which may be a `Vec<String>` or a set; adjust the two `contains` calls to match rather than changing the method.

**The mutation each kills.** The first kills "parse the bound and never read it", which is the whole failure mode of a declared interval. The second kills the obvious implementation where `None` pushes nothing — and it is the one to watch, because that implementation passes the first test. The third kills a capability string that implies the bound was measured. The fourth kills merging the two cases onto one principal.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib derive`
Expected: FAIL to compile — `DeriveConfig` has no `max_attestation_age`, and `ATTESTER`/`NO_ATTESTATION_AGE` do not exist.

- [ ] **Step 3: Write the implementation**

In `src/derive.rs`, add the two principals beside the existing ones:

```rust
/// The host running the attesting workload, as the party whose measured
/// environment is assumed not to have changed since it produced its quote.
///
/// A different principal from [`HOST`], which is the machine the TD runs on.
/// This one is about the trust domain's own contents over time, and the two
/// are distinct parties in the sense that matters here: the platform operator
/// chooses the firmware, and whoever runs the workload chooses how often it
/// re-attests.
const ATTESTER: &str = "urn:parallax:attester";
/// Stands in for the attestation refresh interval nobody declared.
///
/// Its own principal, for the reason [`NO_REFERENCE_VALUES`] is distinct from
/// [`REFERENCE_VALUES`]: `TrustSet::principals()` is an aggregate consumers
/// read, and "this deployment declared a fifteen-minute interval" must not
/// present the same list of parties as "this deployment declared none".
const NO_ATTESTATION_AGE: &str = "urn:parallax:attester:undeclared";
```

Add the field to `DeriveConfig`:

```rust
    /// C7.2.3's declared maximum attestation age, or `None` if this deployment
    /// declares none. See `ProxyConfig::max_attestation_age`.
    ///
    /// **Declared and unverified, with no measured counterpart.** Contrast
    /// `cache_ttl`, whose assumption is bounded by `pcs_detection_bound` —
    /// the *join* of the operator's declared refresh interval and the width of
    /// the window Intel actually issued the collateral for, so the promise
    /// cannot make the bound look tighter than the evidence allows. There is
    /// no such measurement here: a TDX quote carries no timestamp, so nothing
    /// in the evidence bounds the age of the attestation. The capability
    /// string this produces says so.
    ///
    /// Participates in `DeriveConfig`'s `PartialEq`, and so in trust-set
    /// identity, which is the point — see
    /// `the_declared_attestation_age_reaches_the_trust_set`.
    pub max_attestation_age: Option<Latency>,
```

In `derive`, after the RTMR3 match and before the proxy's own contribution:

```rust
    // C7.2.3's declared interval, as an assumption.
    //
    // **Both arms push.** The obvious shape — an entry when a bound is
    // declared and nothing when it is not — makes the deployment that declares
    // nothing produce the smaller trust set, so declining to state an interval
    // looks cleaner than stating one. That is the failure
    // `undeclared_flag_assumptions` above already guards against on a
    // different axis, and the fix is the same: the absence of the declaration
    // is itself something the operator is resting on, so it gets a name and a
    // bound of `Never`.
    //
    // `Impact::Soundness` rather than `Revocation`: what a violation buys is
    // a quote that no longer describes the environment serving the traffic,
    // which makes a false claim verify. It is not a revoked component passing
    // as valid.
    match &cfg.max_attestation_age {
        Some(bound) => push(a(
            ATTESTER,
            "measured_environment_is_unchanged_since_the_quote_within_the_declared_unverified_interval",
            bound.clone(),
            Impact::Soundness,
            m,
        )),
        None => push(a(
            NO_ATTESTATION_AGE,
            "measured_environment_is_unchanged_since_the_quote_for_an_undeclared_interval",
            Latency::Never,
            Impact::Soundness,
            m,
        )),
    }
```

The capability strings are long. That is deliberate and matches the module's existing style — `undeclared_configuration_and_software_hardening_are_applied` is the neighbouring precedent — because the string is what an auditor reads out of the manifest, and "the interval is declared and nothing verified it" is the fact the row exists to carry.

In `src/proxy/config.rs`'s `load`, add the field to the `DeriveConfig` literal:

```rust
                // The declared interval reaches the trust set from the same
                // parse that reaches the enforcement point, so the manifest
                // reports the bound this deployment actually runs with rather
                // than a second number typed next to it — the same argument
                // `cache_ttl` makes two fields above.
                max_attestation_age: max_attestation_age.clone(),
```

Every other construction site of `DeriveConfig` — `src/proxy/gate.rs`'s tests, `tests/one_comparison.rs` — needs the field. The compiler will list them. Set them to `None` unless the test is about this field.

Finally, `most_favourable_outcome` needs no change: `max_attestation_age` is read from `cfg.derive`, not from the outcome, so the floor already accounts for it. But `startup_check`'s meaning has shifted slightly — a policy forbidding `urn:parallax:attester:undeclared` now refuses at startup for a config with no `[freshness]` table, which is correct and is the mechanism by which an operator can make the declaration mandatory. Add a test for that beside the existing startup-check tests.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --all-targets`
Expected: PASS. Existing tests that assert on trust-set *sizes* will each gain one, since every derivation now carries an attestation-age entry. Update the numbers; do not delete the assertions.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Put the declared attestation age in the manifest, and name the deployment that declares none"
```

---

## Task 9: `parallax replay`

**Files:**
- Modify: `src/replay.rs`, `src/bin/parallax.rs`
- Test: `src/replay.rs`'s `mod tests`, `tests/replay.rs`

**Interfaces:**
- Produces: `replay::Replay`, `replay::replay(record, cfg, as_of) -> Result<Replay, RecordError>`, `Replay::render()`, `Replay::exit_code()`; the `replay` subcommand.
- Consumes: `ProxyConfig::load`.

Fork J: a subcommand on the default-build binary, beside `solve`, `compare`, `diff`, `check`, `tiers` and `explain`. Not `parallax-proxy --replay`, which requires `fetch-collateral` and would pull reqwest and rustls in to read a file — the opposite of the argument `Cargo.toml` makes for the feature existing.

Fork F: `--as-of` is **required with no default**. An operator who wants now writes `--as-of now`, and `now` is parsed in the binary, where `SystemTime::now` is allowed to appear. The crate's discipline is that it appears in no library code, and a required flag is what keeps it from creeping in.

- [ ] **Step 1: Write the failing test**

`tests/replay.rs`:

```rust
//! The offline path, end to end, over the shipped configuration.
//!
//! The design's two load-bearing properties for Part 1 are asserted here:
//! **one comparison, two callers** — `decide`'s refusal and this path's
//! verdict reach the same answer over the same bytes — and **config is the
//! only source** — adding an MRTD to `[reference_values].mrtd` changes the
//! offline verdict with no other edit.

use parallax::derive::ReferenceCheck;
use parallax::proxy::ProxyConfig;
use parallax::replay::{
    replay, Established, FreshnessVerdict, MeasurementVerdict, RecordError,
};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The MRTD `examples/proxy-freshness.toml` configures, spelled as a record
/// carries it.
const CONFIGURED: &str = "sha-384:ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56";
const OTHER: &str = "sha-384:1122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677 88";

fn record(measurement: &str, iat: i64) -> String {
    format!(
        r#"{{
            "iss": "did:web:example.org",
            "iat": {iat},
            "nonce": "n-00000001",
            "eat_profile": "https://advancedaisociety.org/poc/v0.1",
            "poc_claims": {{ "verdict": "ALLOW", "step_index": 0 }},
            "submods": {{ "attestation": {{
                "platform": "INTEL_TDX",
                "measurement": "{measurement}"
            }} }}
        }}"#
    )
}

fn parse(json: &str) -> parallax::replay::EvidenceRecord {
    parallax::replay::parse(json, "test").expect("a well-formed record")
}

#[test]
fn config_is_the_only_source_of_reference_values() {
    // The offline path reads `gate.derive.reference_values` from the proxy
    // configuration, so an operator who changes what the proxy admits changes
    // what the audit says, in the same commit. If this path ever grows its own
    // reference-value file, the two can disagree and this fails.
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml"))
        .expect("the freshness example loads");
    assert_eq!(cfg.gate.derive.reference_values.len(), 1);

    let matched = replay(&parse(&record(CONFIGURED, 1_700_000_000)), &cfg, 1_700_000_060)
        .expect("well-formed");
    assert_eq!(
        matched.measurement,
        MeasurementVerdict::Established(Established::Compared)
    );

    let other = OTHER.replace(' ', "");
    let diverged =
        replay(&parse(&record(&other, 1_700_000_000)), &cfg, 1_700_000_060).expect("well-formed");
    assert_eq!(diverged.measurement, MeasurementVerdict::Diverges { configured: 1 });
}

#[test]
fn one_comparison_two_callers() {
    // The gate and the offline path over the same bytes and the same list.
    // Driven through `reference_check` on one side and `replay` on the other,
    // across all three outcomes.
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml"))
        .expect("the freshness example loads");
    let configured = &cfg.gate.derive.reference_values;
    let other = OTHER.replace(' ', "");

    for (measurement, expected_check, expected_verdict) in [
        (
            CONFIGURED.to_string(),
            ReferenceCheck::Matched,
            MeasurementVerdict::Established(Established::Compared),
        ),
        (
            other,
            ReferenceCheck::NoMatch,
            MeasurementVerdict::Diverges { configured: 1 },
        ),
    ] {
        let r = parse(&record(&measurement, 1_700_000_000));
        let attested = parallax::replay::mrtd_of(&r.submods.attestation).expect("well-formed");
        assert_eq!(
            parallax::derive::reference_check(&attested, configured),
            expected_check
        );
        assert_eq!(
            replay(&r, &cfg, 1_700_000_060).expect("well-formed").measurement,
            expected_verdict
        );
    }

    // And the unconfigured case, through the example that ships with no
    // reference values at all.
    let bare = ProxyConfig::load(&root().join("examples/proxy.toml"))
        .expect("the reference example loads");
    assert!(bare.gate.derive.reference_values.is_empty());
    assert_eq!(
        replay(&parse(&record(CONFIGURED, 1_700_000_000)), &bare, 1_700_000_060)
            .expect("well-formed")
            .measurement,
        MeasurementVerdict::Asserted
    );
}

#[test]
fn the_declared_bound_reaches_the_offline_verdict() {
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml"))
        .expect("the freshness example loads");
    assert_eq!(cfg.max_attestation_age, Some(parallax::Latency::Bounded(900)));

    let r = parse(&record(CONFIGURED, 1_700_000_000));
    assert!(matches!(
        replay(&r, &cfg, 1_700_000_900).expect("well-formed").freshness,
        FreshnessVerdict::Fresh { .. }
    ));
    assert!(matches!(
        replay(&r, &cfg, 1_700_000_901).expect("well-formed").freshness,
        FreshnessVerdict::Stale { .. }
    ));

    // The example with no `[freshness]` table declares no bound, and the
    // offline path says so rather than inventing one.
    let bare = ProxyConfig::load(&root().join("examples/proxy.toml")).expect("loads");
    assert!(matches!(
        replay(&r, &bare, 1_700_000_901).expect("well-formed").freshness,
        FreshnessVerdict::NoBoundDeclared { .. }
    ));
}

#[test]
fn the_exit_code_separates_a_divergence_from_a_stale_record() {
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml")).expect("loads");
    let other = OTHER.replace(' ', "");

    // Clean.
    assert_eq!(
        replay(&parse(&record(CONFIGURED, 1_700_000_000)), &cfg, 1_700_000_060)
            .expect("well-formed")
            .exit_code(),
        0
    );
    // Stale: exit 0. The declared interval elapsed; nothing the record claims
    // was refuted, and the measurement row is separate.
    assert_eq!(
        replay(&parse(&record(CONFIGURED, 1_700_000_000)), &cfg, 1_800_000_000)
            .expect("well-formed")
            .exit_code(),
        0
    );
    // A measurement that matches nothing: exit 1.
    assert_eq!(
        replay(&parse(&record(&other, 1_700_000_000)), &cfg, 1_700_000_060)
            .expect("well-formed")
            .exit_code(),
        1
    );
    // A record from the future: exit 1. Not stale, wrong.
    assert_eq!(
        replay(&parse(&record(CONFIGURED, 1_700_009_999)), &cfg, 1_700_000_060)
            .expect("well-formed")
            .exit_code(),
        1
    );
}

#[test]
fn the_rendered_report_names_the_evaluation_time_and_the_config_it_read() {
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml")).expect("loads");
    let text = replay(&parse(&record(CONFIGURED, 1_700_000_000)), &cfg, 1_700_000_060)
        .expect("well-formed")
        .render();
    assert!(text.contains("1700000060"), "{text}");
    assert!(text.contains("ESTABLISHED (compared)"), "{text}");
    assert!(text.contains("C7.2.3"), "{text}");
    assert!(
        !text.contains("re-verified"),
        "nothing here re-verified anything: {text}"
    );
}

/// A record error is an error, not a row. A malformed measurement must not
/// render as a divergence — the operator's next move is different for each.
#[test]
fn a_record_error_does_not_become_a_report() {
    let cfg = ProxyConfig::load(&root().join("examples/proxy-freshness.toml")).expect("loads");
    let sha256 = "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81";
    let e = replay(&parse(&record(sha256, 1_700_000_000)), &cfg, 1_700_000_060)
        .expect_err("32 bytes cannot be a TDX MRTD");
    assert!(matches!(e, RecordError::WrongAlgorithm { .. }), "{e:?}");
}
```

**The mutation each kills.** `config_is_the_only_source...` kills "give the offline path its own reference-value file", which is the two-lists drift this work exists to close. `one_comparison_two_callers` kills a second comparison. `the_declared_bound_reaches...` kills parsing the bound without wiring it to the verdict. The exit-code test kills collapsing stale and diverged into one outcome, which would make a routine expiry look like a compromise. The render test kills dropping the evaluation time and kills the word "re-verified" reaching a report that re-verified nothing.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test replay`
Expected: FAIL to compile — `replay::replay`, `Replay`, `render` and `exit_code` do not exist.

- [ ] **Step 3: Write the library half**

Append to `src/replay.rs`:

```rust
/// What re-checking one record established.
#[derive(Clone, Debug)]
pub struct Replay {
    /// The MRTD the record's `measurement` denotes. Present whenever the
    /// record was well-formed enough to reach a verdict at all, which is what
    /// makes the difference between "the wrong workload" and "the wrong
    /// reference value" visible in the report — the same reason
    /// `Decision::mr_td` carries it on a refusal.
    pub mrtd: [u8; 48],
    pub measurement: MeasurementVerdict,
    pub freshness: FreshnessVerdict,
    /// The evaluation time, carried so that every rendering names it. See
    /// [`Replay::render`].
    pub as_of: u64,
    /// How many reference values the configuration carried.
    pub configured: usize,
    /// Where the configuration came from, for the report.
    pub config_path: String,
}

impl Replay {
    /// `0` clean, `1` a verification or freshness failure.
    ///
    /// **A stale record is exit 0 and a divergent one is exit 1**, which is
    /// worth arguing rather than asserting. A measurement matching none of the
    /// configured reference values is a disagreement about *what ran*: the
    /// record names a trust domain this deployment does not admit. A record
    /// outside the declared interval is a disagreement about *when*: the
    /// interval elapsed, which is a routine fact about an old file and not
    /// evidence that anything is wrong with it. Collapsing them would make
    /// every archived record fail, and an exit code that fires on everything
    /// stops being read.
    ///
    /// A record *newer* than the evaluation time is exit 1, because it is not
    /// old — it is wrong, and it means either the evaluation time or the
    /// timestamp is untrue.
    pub fn exit_code(&self) -> u8 {
        let diverged = matches!(self.measurement, MeasurementVerdict::Diverges { .. });
        let future = matches!(self.freshness, FreshnessVerdict::FutureDated { .. });
        u8::from(diverged || future)
    }

    /// The two rows, and the header that says what was read.
    ///
    /// **The evaluation time appears on every rendering.** `--as-of` makes
    /// this tool's answer a function of an argument: an operator can produce a
    /// clean freshness row by passing the record's own `iat`. Nothing here can
    /// prevent that, and the only mitigation available is that the report
    /// always says which time it used, so a reader can see the argument that
    /// produced the answer.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "record re-checked against {} as of {} ({} MRTD reference value(s))",
            self.config_path, self.as_of, self.configured
        );
        let _ = writeln!(out, "attested MRTD: {}", crate::collateral::hex_lower(&self.mrtd));
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "submods.attestation.measurement  {}\n  {}",
            self.measurement.label(),
            self.measurement.reason(self.configured)
        );
        let _ = writeln!(
            out,
            "iat                              {}\n  {}",
            self.freshness.label(),
            self.freshness.reason(self.as_of)
        );
        out
    }
}

/// Re-check one record against one proxy configuration, as of one time.
///
/// The three arguments are the whole input: a record, the configuration the
/// proxy runs with, and a time the caller supplies. Nothing is fetched and no
/// clock is read.
pub fn replay(
    record: &EvidenceRecord,
    cfg: &crate::proxy::ProxyConfig,
    as_of: u64,
) -> Result<Replay, RecordError> {
    let configured = &cfg.gate.derive.reference_values;
    let mrtd = mrtd_of(&record.submods.attestation)?;
    Ok(Replay {
        mrtd,
        measurement: measurement(&record.submods.attestation, configured)?,
        freshness: freshness(record.iat, as_of, cfg.max_attestation_age.as_ref()),
        as_of,
        configured: configured.len(),
        config_path: cfg.upstream.url.clone(),
    })
}
```

`hex_lower` is `pub(crate)` in `src/collateral/mod.rs` — check its visibility and widen it to `pub` if the render needs it from outside, or keep the render inside the crate, which it is. `config_path` is set from `upstream.url` rather than the file path because `ProxyConfig` does not carry the path it was loaded from; if the report should name the file, add a `source_path: PathBuf` to `ProxyConfig` in Task 4's edit rather than threading it separately here. Prefer adding the field — the report naming a file the operator can open is worth more than naming an upstream URL.

- [ ] **Step 4: Write the CLI half**

In `src/bin/parallax.rs`, add the subcommand to `enum Cmd`:

```rust
    /// Re-check an evidence record's measurement claim and its issuance time
    /// against a proxy configuration, offline
    ///
    /// This compares the value written in the record's
    /// `submods.attestation.measurement` field against the reference values
    /// the given proxy configuration admits on, using the same comparison the
    /// proxy's own gate uses. It is a comparison and not a re-verification:
    /// the record carries no quote, so nothing cryptographic is checked. The
    /// verdict says so in those words.
    ///
    /// `check` already means "evaluate a manifest against a policy", so this
    /// is a different verb for a different question.
    Replay {
        /// The evidence record to re-check
        record: PathBuf,
        /// The proxy configuration whose reference values and declared
        /// attestation age to check against. **The same file the proxy runs
        /// with** — the point of reading it rather than a separate list is
        /// that the audit and the enforcement point cannot disagree.
        #[arg(long)]
        proxy_config: PathBuf,
        /// The evaluation time, as RFC 3339, or the literal `now`.
        ///
        /// Required, with no default, deliberately: this tool's answer is a
        /// function of this argument, and a default would make the common
        /// invocation non-reproducible. Nothing in the parallax *library*
        /// reads a clock; `now` is resolved here, in the binary, which is the
        /// only place that is allowed to.
        #[arg(long, value_name = "RFC3339|now")]
        as_of: String,
    },
```

and the arm in `run`:

```rust
        Cmd::Replay {
            record,
            proxy_config,
            as_of,
        } => {
            let cfg = parallax::proxy::ProxyConfig::load(&proxy_config)?;
            let rec = parallax::replay::read(&record)?;
            let out = parallax::replay::replay(&rec, &cfg, as_of_secs(&as_of)?)?;
            print!("{}", out.render());
            Ok(ExitCode::from(out.exit_code()))
        }
```

and the resolver, beside `require_same_claim`:

```rust
/// Resolve `--as-of` to seconds since the Unix epoch.
///
/// **The one place in this binary that reads a clock**, and it does so only
/// for the literal `now`. The parallax library reads no clock anywhere: every
/// function that needs a time takes it as an argument, which is what makes the
/// freshness tests able to drive the same record past two different times and
/// what stops any test from being made to pass by changing the machine's
/// clock. A `--as-of` with a default would have put a clock read on the common
/// path; requiring the flag keeps `now` an explicit request.
fn as_of_secs(text: &str) -> Result<u64> {
    if text == "now" {
        return Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("the system clock is before the Unix epoch: {e}"))?
            .as_secs());
    }
    let t = humantime::parse_rfc3339(text).map_err(|e| {
        anyhow::anyhow!(
            "`--as-of {text}` is neither `now` nor an RFC 3339 timestamp \
             (for example `2026-08-10T12:00:00Z`): {e}"
        )
    })?;
    Ok(t.duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("`--as-of {text}` is before the Unix epoch: {e}"))?
        .as_secs())
}
```

`humantime::parse_rfc3339` is already a dependency and is already used this way in `src/derive.rs:1194`.

Add two CLI tests to `tests/acceptance.rs`, matching whatever shape that file already uses for invoking the binary:

```rust
/// `--as-of` is required. A default would make the common invocation
/// non-reproducible and turn "this record was fine yesterday" into a support
/// conversation.
#[test]
fn replay_requires_an_evaluation_time() { /* invoke without --as-of, expect exit 2 */ }

/// `--as-of now` is the escape hatch, and it is spelled out rather than
/// implied.
#[test]
fn replay_accepts_now_as_an_evaluation_time() { /* invoke with --as-of now, expect exit 0 or 1, not 2 */ }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test --test replay
cargo test --all-targets
cargo test --test no_http_client        # the subcommand must not have pulled anything in
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add `parallax replay`: the offline path, in the default build, with a required --as-of"
```

---

## Task 10: `check_binding` grows its policy argument

**Files:**
- Modify: `src/ratls.rs`, `src/verify/binding.rs`, `src/verify/mod.rs`, `src/proxy/gate.rs`, `src/proxy/config.rs`
- Test: `src/ratls.rs`'s and `src/verify/binding.rs`'s `mod tests`, `src/proxy/config.rs`'s `mod tests`

**Interfaces:**
- Produces: `ratls::ReportDataLayout` (`Spki`, `SpkiChallenge { challenge_digest: [u8; 32] }`), `ratls::LAYOUT_CHALLENGE`, `ratls::challenge_digest(challenge: &str) -> [u8; 32]`, `ratls::expected_report_data_for(spki_der: &[u8], layout: &ReportDataLayout) -> [u8; 64]`; `GateConfig::report_data_layout: ReportDataLayout`.
- Re-signatured: `verify::check_binding(report_data: &[u8; 64], cert_der: &[u8], layout: &ReportDataLayout) -> Result<(), BindingError>`.

`check_binding`'s own documentation (`src/verify/binding.rs:110`) says what should happen when a second convention arrives: "if parallax ever has to talk to a second convention, this is the function that grows a policy argument." This is that. It is also, as the design says, **the last relaxation available**: after this the tail has a meaning, and a third convention would need a real negotiation rather than a policy enum.

The layout type lives in `src/ratls.rs`, not in `binding.rs`, because `ratls.rs` exists precisely so that the attester and the verifier read one definition — its module doc says a disagreement there "is not a compile error and not a test failure in either module alone". A layout enum defined on the verifier's side would recreate exactly that hazard.

Fork I: the layout is a `GateConfig` field, configured, not self-describing. A tag inside the region whose meaning it describes is circular under an attacker who chooses the tail, and `RootCa::Custom` carrying a whole PEM (`src/verify/chain.rs:8`) is the crate's existing precedent for configuration that participates in what was verified living in the configuration.

**Two rows of the design's testing table cannot be written from this repository**, and the gap goes in `src/proxy/mod.rs`'s existing "what is not covered by a test, and why" section rather than being papered over with a synthetic quote. The committed fixture's `report_data` is 64 zero bytes — `the_real_fixtures_report_data_is_unbound` (`src/verify/binding.rs:246`) pins that — so a *successful* binding against real hardware needs a fixture that does not exist, and the challenge round trip therefore has no hardware-backed test at all.

- [ ] **Step 1: Write the failing tests**

In `src/ratls.rs`'s `mod tests`:

```rust
    /// The two halves read one definition. `expected_report_data_for` is what
    /// the attester writes and `check_binding` is what the verifier checks,
    /// and they must agree byte for byte or the binding always fails — or,
    /// worse, succeeds on the wrong input.
    #[test]
    fn the_challenge_layout_fills_the_tail_the_verifier_reads() {
        let spki = b"not really an SPKI, but bytes are bytes";
        let d = challenge_digest("challenge-one");
        let rd = expected_report_data_for(&spki[..], &ReportDataLayout::SpkiChallenge {
            challenge_digest: d,
        });
        assert_eq!(&rd[..DIGEST_LEN], &expected_report_data(spki)[..DIGEST_LEN]);
        assert_eq!(&rd[DIGEST_LEN..], &d[..]);
    }

    /// The default layout is byte-identical to what shipped. This is the
    /// relaxation's whole safety argument: an attester that knows nothing about
    /// challenges keeps producing exactly the bytes it produced before.
    #[test]
    fn the_spki_layout_is_unchanged() {
        let spki = b"not really an SPKI, but bytes are bytes";
        assert_eq!(
            expected_report_data_for(spki, &ReportDataLayout::Spki),
            expected_report_data(spki)
        );
    }

    /// Different challenges give different report_data, or the tail carries no
    /// information and the whole mechanism is decoration.
    #[test]
    fn different_challenges_give_different_report_data() {
        let spki = b"spki";
        let a = expected_report_data_for(spki, &ReportDataLayout::SpkiChallenge {
            challenge_digest: challenge_digest("one"),
        });
        let b = expected_report_data_for(spki, &ReportDataLayout::SpkiChallenge {
            challenge_digest: challenge_digest("two"),
        });
        assert_ne!(a, b);
        // And the key still matters under the challenge layout: a challenge
        // does not displace the binding, it accompanies it.
        let c = expected_report_data_for(b"other spki", &ReportDataLayout::SpkiChallenge {
            challenge_digest: challenge_digest("one"),
        });
        assert_ne!(a, c);
    }

    /// The two layouts are named in errors, so an operator meeting a peer with
    /// the other convention sees a layout mismatch rather than an accusation.
    #[test]
    fn the_two_layouts_have_distinguishable_names_and_config_keys() {
        assert_ne!(
            ReportDataLayout::Spki.label(),
            ReportDataLayout::SpkiChallenge { challenge_digest: [0; 32] }.label()
        );
        assert_eq!(ReportDataLayout::Spki.key(), "spki");
        assert_eq!(
            ReportDataLayout::SpkiChallenge { challenge_digest: [0; 32] }.key(),
            "spki+challenge"
        );
    }

    /// A challenge digest is over the challenge's bytes, and an empty
    /// challenge is not a zero digest — which matters, because a zero tail is
    /// what the *other* layout looks like, and the two must not collide.
    #[test]
    fn an_empty_challenge_does_not_produce_a_zero_tail() {
        assert_ne!(challenge_digest(""), [0u8; 32]);
    }
```

In `src/verify/binding.rs`'s `mod tests`:

```rust
    /// Every existing binding assertion, under the default policy, unchanged.
    /// The relaxation must not become a weakening: a quote committing to no
    /// challenge must still fail a verifier that wanted one, and a zero tail
    /// must still bind under the layout that expects it.
    #[test]
    fn the_zero_tail_still_binds_under_the_default_policy() {
        let (cert_der, spki) = self_signed_for_test();
        let rd = crate::ratls::expected_report_data(&spki);
        assert!(check_binding(&rd, &cert_der, &ReportDataLayout::Spki).is_ok());

        // And a non-zero tail is still refused under it.
        let mut tampered = rd;
        tampered[40] = 0x01;
        assert!(matches!(
            check_binding(&tampered, &cert_der, &ReportDataLayout::Spki),
            Err(BindingError::TrailingBytes { offset: 40, .. })
        ));
    }

    /// Direction one of the layout mismatch: an attester writing a zero tail
    /// against a verifier configured for the challenge layout. It must name
    /// both layouts, so the operator can tell "this peer speaks the other
    /// convention" from "this peer is not attesting".
    #[test]
    fn a_zero_tail_against_a_challenge_verifier_names_both_layouts() {
        let (cert_der, spki) = self_signed_for_test();
        let rd = crate::ratls::expected_report_data(&spki);
        let e = check_binding(
            &rd,
            &cert_der,
            &ReportDataLayout::SpkiChallenge {
                challenge_digest: crate::ratls::challenge_digest("c"),
            },
        )
        .expect_err("a zero tail is not a challenge answer");
        assert!(matches!(e, BindingError::MissingChallenge { .. }), "{e:?}");
        let text = e.to_string();
        assert!(text.contains("SHA-256(challenge)"), "expected layout: {text}");
        assert!(text.contains("remainder zero"), "received layout: {text}");
    }

    /// Direction two: an attester writing a challenge tail against a verifier
    /// configured for the zero-tail layout.
    #[test]
    fn a_challenge_tail_against_an_spki_verifier_names_both_layouts() {
        let (cert_der, spki) = self_signed_for_test();
        let rd = crate::ratls::expected_report_data_for(
            &spki,
            &ReportDataLayout::SpkiChallenge {
                challenge_digest: crate::ratls::challenge_digest("c"),
            },
        );
        let e = check_binding(&rd, &cert_der, &ReportDataLayout::Spki)
            .expect_err("a challenge tail is not a zero tail");
        let text = e.to_string();
        assert!(matches!(e, BindingError::TrailingBytes { .. }), "{e:?}");
        assert!(text.contains("remainder zero"), "expected layout: {text}");
        assert!(
            text.contains("SHA-256(challenge)"),
            "the message must name the layout the peer appears to be speaking, or \
             a layout change reads as `this peer is not attesting`: {text}"
        );
    }

    /// The challenge layout binds when both halves agree.
    #[test]
    fn the_challenge_layout_binds_when_the_challenge_matches() {
        let (cert_der, spki) = self_signed_for_test();
        let layout = ReportDataLayout::SpkiChallenge {
            challenge_digest: crate::ratls::challenge_digest("the-challenge"),
        };
        let rd = crate::ratls::expected_report_data_for(&spki, &layout);
        assert!(check_binding(&rd, &cert_der, &layout).is_ok());
    }

    /// The answer to a *different* challenge is refused, and that is what the
    /// tail is for. Without this, a quote minted for one challenge would
    /// satisfy a verifier that issued another, and the freshness the challenge
    /// exists to provide would be zero.
    #[test]
    fn the_answer_to_a_different_challenge_is_refused() {
        let (cert_der, spki) = self_signed_for_test();
        let minted = ReportDataLayout::SpkiChallenge {
            challenge_digest: crate::ratls::challenge_digest("challenge-one"),
        };
        let wanted = ReportDataLayout::SpkiChallenge {
            challenge_digest: crate::ratls::challenge_digest("challenge-two"),
        };
        let rd = crate::ratls::expected_report_data_for(&spki, &minted);
        assert!(matches!(
            check_binding(&rd, &cert_der, &wanted),
            Err(BindingError::ChallengeMismatch { .. })
        ));
    }

    /// The key still binds under the challenge layout. A quote answering the
    /// right challenge in front of the wrong key proves nothing about the
    /// peer, exactly as before — the challenge is an addition to the binding,
    /// not a replacement for it.
    #[test]
    fn the_challenge_layout_still_requires_the_right_key() {
        let (cert_der, _) = self_signed_for_test();
        let (_, other_spki) = self_signed_for_test();
        let layout = ReportDataLayout::SpkiChallenge {
            challenge_digest: crate::ratls::challenge_digest("c"),
        };
        let rd = crate::ratls::expected_report_data_for(&other_spki, &layout);
        assert!(matches!(
            check_binding(&rd, &cert_der, &layout),
            Err(BindingError::Mismatch)
        ));
    }

    /// 64 zero bytes are unbound under *either* layout, and stay their own
    /// error. The committed fixture is exactly this, and reading it as a
    /// layout disagreement would hide what it actually is: a quote that
    /// commits to no key at all.
    #[test]
    fn sixty_four_zero_bytes_are_unbound_under_both_layouts() {
        let (cert_der, _) = self_signed_for_test();
        for layout in [
            ReportDataLayout::Spki,
            ReportDataLayout::SpkiChallenge { challenge_digest: [0u8; 32] },
        ] {
            assert!(matches!(
                check_binding(&[0u8; 64], &cert_der, &layout),
                Err(BindingError::Unbound)
            ));
        }
    }
```

`self_signed_for_test` is whatever the module's existing tests use to build an rcgen certificate and its SPKI — read them and reuse it rather than adding a second helper.

In `src/proxy/config.rs`'s `mod tests`:

```rust
    #[test]
    fn the_report_data_layout_defaults_to_spki() {
        assert_eq!(
            load_with("").gate.report_data_layout,
            ReportDataLayout::Spki
        );
    }

    /// The challenge layout needs a challenge to compare against, and the
    /// epoch is where it comes from. A layout without one is a verifier that
    /// would refuse everything, refused at load instead.
    #[test]
    fn the_challenge_layout_without_an_epoch_is_refused() {
        let e = load_err(
            "[freshness]\nmax_attestation_age = \"15m\"\nreport_data_layout = \"spki+challenge\"\n",
        );
        assert!(matches!(e, ConfigError::LayoutNeedsEpoch), "{e:?}");
        assert!(e.to_string().contains("epoch"), "{e}");
    }

    /// And the reverse: an epoch nothing reads is a value the operator
    /// believes is in force and is not.
    #[test]
    fn an_epoch_without_the_challenge_layout_is_refused() {
        let e = load_err("[freshness]\nmax_attestation_age = \"15m\"\nepoch = \"e-1\"\n");
        assert!(matches!(e, ConfigError::EpochWithoutLayout), "{e:?}");
        assert!(e.to_string().contains("report_data_layout"), "{e}");
    }

    /// The epoch becomes the challenge digest the verifier compares against,
    /// at load, so there is one place the string becomes bytes.
    #[test]
    fn the_epoch_becomes_the_layouts_challenge_digest() {
        let cfg = load_with(
            "[freshness]\nmax_attestation_age = \"15m\"\n\
             report_data_layout = \"spki+challenge\"\nepoch = \"2026-08-10T00:00:00Z\"\n",
        );
        assert_eq!(
            cfg.gate.report_data_layout,
            ReportDataLayout::SpkiChallenge {
                challenge_digest: parallax_ratls_challenge_digest("2026-08-10T00:00:00Z"),
            }
        );
    }

    /// An unknown layout name is refused rather than defaulted. Defaulting a
    /// misspelled `spki+challange` to `spki` would silently drop the freshness
    /// mechanism the operator asked for.
    #[test]
    fn an_unknown_report_data_layout_is_refused() {
        let e = load_err("[freshness]\nreport_data_layout = \"sha512-everywhere\"\n");
        assert!(matches!(e, ConfigError::UnknownLayout { .. }), "{e:?}");
        assert!(e.to_string().contains("spki"), "must list what is accepted: {e}");
    }
```

(`parallax_ratls_challenge_digest` is `crate::ratls::challenge_digest`; import it at the top of the test module.)

**The mutation each kills.** `the_zero_tail_still_binds...` kills turning the relaxation into a weakening — accepting any tail under the default. The two direction tests kill a message that names only one layout, which is what makes a layout change read as "this peer is not attesting". `the_answer_to_a_different_challenge_is_refused` kills comparing the tail to nothing, which would make the challenge decorative. `the_challenge_layout_still_requires_the_right_key` kills replacing the SPKI digest with the challenge digest rather than adding to it — the mutation that removes the binding entirely while every challenge test still passes. `sixty_four_zero_bytes_are_unbound...` kills reordering the checks so `Unbound` is shadowed by `MissingChallenge`. The config tests kill defaulting a misspelled layout and kill accepting either half of the layout/epoch pair alone.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib ratls verify::binding proxy::config`
Expected: FAIL to compile — `ReportDataLayout` does not exist and `check_binding` takes two arguments.

- [ ] **Step 3: Write the implementation**

In `src/ratls.rs`, after `LAYOUT`:

```rust
/// Named in error messages beside [`LAYOUT`], so a peer speaking one
/// convention to a verifier expecting the other sees both named.
pub const LAYOUT_CHALLENGE: &str = "the challenge layout, SHA-256(SPKI) in report_data \
                                    bytes 0..32 and SHA-256(challenge) in bytes 32..64";

/// Which convention a `report_data` follows.
///
/// **A policy, carried in configuration, not a tag inside the field.** A byte
/// of the tail could describe the tail's meaning, and it would spend a byte of
/// a fully committed 64 and be circular under an attacker who chooses the
/// tail. `RootCa::Custom` carries a whole PEM rather than a label for the same
/// family of reasons (`src/verify/chain.rs:8`): configuration that
/// participates in what was verified belongs in the configuration, where it is
/// visible and compared. A mismatch is an operator error caught at the first
/// connection, with a message naming both sides.
///
/// **This is the last relaxation available.** `check_binding`'s documentation
/// argues at length that starting strict is what makes a later relaxation
/// possible; this is that relaxation, and after it the tail has a meaning. A
/// third convention would need a real negotiation rather than another variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReportDataLayout {
    /// Gramine's and Intel's: `SHA-256(SPKI)` in bytes 0..32, zero in 32..64.
    /// The default, and byte-identical to what shipped before this type
    /// existed.
    Spki,
    /// `SHA-256(SPKI)` in bytes 0..32, `SHA-256(challenge)` in 32..64.
    ///
    /// The digest rather than the challenge itself, because a challenge is a
    /// string of unbounded length and the field is 32 bytes. The verifier
    /// carries the digest rather than the challenge for the same reason
    /// `check_binding` should not have to hash anything the caller already
    /// hashed — and so that this type stays `Copy`.
    SpkiChallenge { challenge_digest: [u8; 32] },
}

impl ReportDataLayout {
    /// The prose name, for error messages.
    pub fn label(&self) -> &'static str {
        match self {
            ReportDataLayout::Spki => LAYOUT,
            ReportDataLayout::SpkiChallenge { .. } => LAYOUT_CHALLENGE,
        }
    }

    /// The name this layout is written as in a proxy configuration.
    pub fn key(&self) -> &'static str {
        match self {
            ReportDataLayout::Spki => "spki",
            ReportDataLayout::SpkiChallenge { .. } => "spki+challenge",
        }
    }
}

/// What `report_data[32..64]` must hold for `challenge`.
///
/// SHA-256 over the challenge's bytes, matching the digest in the first half —
/// one hash in the layout, not two. An **empty** challenge produces the
/// SHA-256 of the empty string and not 32 zeroes, which matters: 32 zeroes is
/// what the *other* layout looks like, and the two must not be able to
/// collide.
pub fn challenge_digest(challenge: &str) -> [u8; 32] {
    Sha256::digest(challenge.as_bytes()).into()
}

/// What `report_data` must contain, under `layout`, for a certificate whose
/// SubjectPublicKeyInfo is `spki_der`.
///
/// The attester calls this and [`crate::verify::check_binding`] checks it, and
/// they read the one definition above. That is the reason this module exists —
/// a disagreement between the two halves is not a compile error and not a test
/// failure in either module alone.
pub fn expected_report_data_for(spki_der: &[u8], layout: &ReportDataLayout) -> [u8; 64] {
    let mut rd = expected_report_data(spki_der);
    if let ReportDataLayout::SpkiChallenge { challenge_digest } = layout {
        rd[DIGEST_LEN..].copy_from_slice(challenge_digest);
    }
    rd
}
```

`rd[DIGEST_LEN..]` is exactly 32 bytes and `challenge_digest` is 32; the `const` assertion at `src/ratls.rs:30` already makes any change to `DIGEST_LEN` a build failure, and this `copy_from_slice` is a second reason it must stay true. Add a sentence to that assertion's comment saying so.

In `src/verify/binding.rs`, extend `BindingError` and re-signature the function:

```rust
    /// A non-zero byte at or after offset 32, under the zero-tail layout.
    ///
    /// The message names **both** layouts. The likeliest cause is not a
    /// misbehaving attester but a peer speaking the other convention, and an
    /// operator reading this needs to tell "the attester filled a field it
    /// should not have" from "this peer answers challenges and this verifier
    /// does not issue them". Naming only the expected layout makes a layout
    /// change read as "this peer is not attesting", which sends the operator
    /// looking in the wrong place.
    #[error(
        "report_data byte {offset} is 0x{value:02x}, but this verifier is configured \
         for {expected}. A non-zero tail is what {received} looks like, so this peer \
         may be speaking the other convention rather than failing to attest; a peer \
         using a report_data convention this verifier is not configured for is \
         refused here rather than guessed at"
    )]
    TrailingBytes {
        offset: usize,
        value: u8,
        expected: &'static str,
        received: &'static str,
    },
    /// A zero tail under the challenge layout: the mirror of
    /// [`BindingError::TrailingBytes`], and it names both layouts for the same
    /// reason.
    #[error(
        "report_data bytes 32..64 are zero, but this verifier is configured for \
         {expected} and expected SHA-256 of the challenge it issued. A zero tail is \
         {received}, so this peer is attesting under the other convention rather \
         than failing to attest — which means its quote was minted before this \
         verifier spoke and establishes no freshness at all"
    )]
    MissingChallenge {
        expected: &'static str,
        received: &'static str,
    },
    /// A non-zero tail under the challenge layout that is not the right
    /// digest.
    ///
    /// Distinct from [`BindingError::MissingChallenge`] because the causes are
    /// different and so is the operator's next move: a zero tail is a peer
    /// speaking the other convention, and a wrong digest is a peer answering
    /// some *other* challenge — a replayed quote, a stale epoch, or two
    /// verifiers with different epochs configured.
    #[error(
        "report_data bytes 32..64 do not match SHA-256 of the challenge this \
         verifier issued, under {expected}: the peer answered a different challenge, \
         or replayed a quote minted for one. A quote is only fresh against the \
         challenge it commits to"
    )]
    ChallengeMismatch { expected: &'static str },
```

```rust
pub fn check_binding(
    report_data: &[u8; 64],
    cert_der: &[u8],
    layout: &ReportDataLayout,
) -> Result<(), BindingError> {
    // First, and under both layouts. A quote requested with no `report_data`
    // commits to no key, which is a different thing from a layout
    // disagreement, and reading it as one would hide what the committed
    // fixture actually is.
    if report_data.iter().all(|byte| *byte == 0) {
        return Err(BindingError::Unbound);
    }

    // The tail, according to the policy. `iter().skip(DIGEST_LEN)` and
    // `zip` rather than slicing: both are total for any length, so there is no
    // index here that could be out of range.
    match layout {
        ReportDataLayout::Spki => {
            if let Some((offset, value)) = report_data
                .iter()
                .enumerate()
                .skip(DIGEST_LEN)
                .find(|(_, byte)| **byte != 0)
            {
                return Err(BindingError::TrailingBytes {
                    offset,
                    value: *value,
                    expected: LAYOUT,
                    received: LAYOUT_CHALLENGE,
                });
            }
        }
        ReportDataLayout::SpkiChallenge { challenge_digest } => {
            if report_data.iter().skip(DIGEST_LEN).all(|byte| *byte == 0) {
                return Err(BindingError::MissingChallenge {
                    expected: LAYOUT_CHALLENGE,
                    received: LAYOUT,
                });
            }
            if !challenge_digest
                .iter()
                .zip(report_data.iter().skip(DIGEST_LEN))
                .all(|(e, r)| e == r)
            {
                return Err(BindingError::ChallengeMismatch {
                    expected: LAYOUT_CHALLENGE,
                });
            }
        }
    }

    // The key half, unchanged and unconditional. The challenge accompanies the
    // binding; it does not replace it. A quote answering the right challenge
    // in front of the wrong key proves that a trust domain answered, not that
    // it is the peer on this connection.
    let expected = Sha256::digest(spki_der(cert_der)?);
    if expected.iter().zip(report_data.iter()).all(|(e, r)| e == r) {
        Ok(())
    } else {
        Err(BindingError::Mismatch)
    }
}
```

Import `ReportDataLayout` and `LAYOUT_CHALLENGE` alongside the existing `use crate::ratls::{DIGEST_LEN, LAYOUT};`. Re-export `ReportDataLayout` from `src/verify/mod.rs` beside `check_binding`, so callers reach one path:

```rust
pub use crate::ratls::ReportDataLayout;
pub use binding::{check_binding, BindingError};
```

Add the field to `GateConfig`:

```rust
    /// Which `report_data` convention this verifier expects. See
    /// [`ReportDataLayout`], and fork I for why it is configured rather than
    /// self-describing.
    pub report_data_layout: ReportDataLayout,
```

and pass it in `evaluate_verified`:

```rust
    if let Err(e) = check_binding(&outcome.report_data, cert_der, &cfg.report_data_layout) {
```

In `src/proxy/config.rs`, extend `FreshnessTable`:

```rust
    /// `"spki"` (default) or `"spki+challenge"`. See
    /// [`crate::ratls::ReportDataLayout`].
    #[serde(default)]
    report_data_layout: Option<String>,
    /// The published epoch this verifier folds into `report_data[32..64]`.
    ///
    /// Required with, and only with, `report_data_layout = "spki+challenge"`.
    ///
    /// **An epoch published by the operator is chosen by the operator**, so it
    /// bounds staleness against an *honest* attester and does not defeat a
    /// replaying one: a compromised attester re-quotes within its own epoch
    /// exactly as an honest one does. Only a value from outside the operator's
    /// control would do better, which is C7.2.2 again. What it does buy is
    /// that C7.2.3's declared interval and the enforced interval become the
    /// same number — the verifier observes the epoch rather than taking the
    /// interval on trust — at a cost of one quote per interval regardless of
    /// traffic, which is the only version of this whose cost an operator can
    /// budget.
    #[serde(default)]
    epoch: Option<String>,
```

three error variants:

```rust
    #[error(
        "`freshness.report_data_layout = \"{value}\"` is not a layout this build \
         knows; write `spki` (the Gramine/Intel convention, SHA-256(SPKI) with a \
         zero tail) or `spki+challenge` (the same, with SHA-256 of the published \
         epoch in bytes 32..64)"
    )]
    UnknownLayout { value: String },
    #[error(
        "`freshness.report_data_layout = \"spki+challenge\"` makes this verifier \
         compare `report_data[32..64]` against SHA-256 of a challenge, and no \
         `freshness.epoch` says what that challenge is. Without one every peer \
         would be refused. Add `epoch = \"...\"`, or remove the layout key."
    )]
    LayoutNeedsEpoch,
    #[error(
        "`freshness.epoch` is set and `freshness.report_data_layout` is not \
         `\"spki+challenge\"`, so nothing reads the epoch: this verifier still \
         requires a zero tail and would refuse every attester that folded the \
         epoch in. A value the operator believes is in force and is not is worse \
         than an absent one."
    )]
    EpochWithoutLayout,
```

and the resolution in `load`:

```rust
        let report_data_layout = match (
            file.freshness.report_data_layout.as_deref(),
            file.freshness.epoch.as_deref(),
        ) {
            (None | Some("spki"), None) => ReportDataLayout::Spki,
            (None | Some("spki"), Some(_)) => return Err(ConfigError::EpochWithoutLayout),
            (Some("spki+challenge"), None) => return Err(ConfigError::LayoutNeedsEpoch),
            (Some("spki+challenge"), Some(epoch)) => ReportDataLayout::SpkiChallenge {
                // The one place the epoch string becomes bytes, so the
                // verifier and anything that reports the configuration read
                // one derivation.
                challenge_digest: crate::ratls::challenge_digest(epoch),
            },
            (Some(other), _) => {
                return Err(ConfigError::UnknownLayout {
                    value: other.to_string(),
                })
            }
        };
```

- [ ] **Step 4: Record the gap that cannot be tested**

Add to `src/proxy/mod.rs`'s "What is not covered by a test, and why" section, in the enumerated list's style:

```
//! **The challenge layout has no hardware-backed test, and cannot have one
//! from this repository.** `ReportDataLayout::SpkiChallenge` is exercised
//! against certificates and `report_data` buffers this crate constructs, which
//! proves the two halves of `ratls` agree with each other. It does not prove
//! that a real TDX platform, asked for a quote over a `report_data` with a
//! non-zero tail, returns one carrying those bytes. The only real quote
//! committed here has 64 zero bytes of `report_data` — a capture-time
//! placeholder recorded in `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`, pinned by
//! `the_real_fixtures_report_data_is_unbound` — so this repository has never
//! seen a successful binding against real hardware under *either* layout, let
//! alone the new one. Closing this needs a fixture captured on TDX hardware
//! with a digest in `report_data`, and until such a fixture exists the gap is
//! stated here rather than papered over with a synthesised quote. Synthesising
//! one would mean synthesising Intel's PKI, which is the option ruled out
//! above for the forwarding path and is ruled out here for the same reason.
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test --all-targets
cargo test --all-targets --features fetch-collateral
cargo test --all-targets --features attest
```
Expected: PASS. Every existing `check_binding` call site — `src/proxy/gate.rs`, its tests, `src/attest/cert.rs`'s round-trip test, `tests/proxy.rs` — needs the third argument. Pass `&ReportDataLayout::Spki` at each unless the test is about the new layout, and check that the assertions themselves are unchanged: this task's whole safety claim is that the default behaviour is byte-identical.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Grow check_binding the policy argument its own documentation asked for"
```

---

## Task 11: Challenges, and the replay that must be refused

**Files:**
- Create: `src/challenge.rs`
- Modify: `src/lib.rs`
- Test: `src/challenge.rs`'s `mod tests`

**Interfaces:**
- Produces: `challenge::Challenges` (trait, `fn issue(&self) -> String`), `challenge::FixedChallenges`, `challenge::ChallengeStore`, `challenge::ChallengeError`.

A nonce is randomness, and randomness gets the same treatment as time. A CSPRNG called from library code would be the same defect as a clock read from library code: an input the test cannot control, in the one place the test most needs to. **The production implementation is not in this plan** — nothing here needs one, and it belongs in the binary beside `SystemClock`.

The test that matters is that the second presentation of the same challenge is refused, with `FixedChallenges` making the repeat deliberate rather than a coincidence a real generator would never produce.

- [ ] **Step 1: Write the failing test**

`src/challenge.rs`'s `mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole store exists for. A challenge answered once
    /// cannot be answered again, and `FixedChallenges::repeating` is what makes
    /// the second attempt happen on purpose — a real generator would never
    /// produce the collision, so a real generator could never test this.
    #[test]
    fn the_same_challenge_is_refused_the_second_time() {
        let source = FixedChallenges::repeating("c-1");
        let mut store = ChallengeStore::new(900);

        let a = store.issue(&source, 1_000);
        assert_eq!(a, "c-1");
        assert!(store.redeem(&a, 1_010).is_ok());

        // Issued again — the source repeats — and redeemed again. The store,
        // not the source, is what refuses it.
        let b = store.issue(&source, 1_020);
        assert_eq!(b, "c-1");
        let e = store.redeem(&b, 1_030).expect_err("single use");
        assert!(matches!(e, ChallengeError::AlreadyRedeemed { .. }), "{e:?}");
    }

    /// Re-issuing must not reset a redeemed challenge to outstanding. If it
    /// did, the single-use rule would depend on the randomness source never
    /// repeating — which is exactly the assumption a test cannot make and an
    /// attacker would attack.
    #[test]
    fn re_issuing_does_not_resurrect_a_redeemed_challenge() {
        let source = FixedChallenges::repeating("c-1");
        let mut store = ChallengeStore::new(900);
        let c = store.issue(&source, 1_000);
        assert!(store.redeem(&c, 1_001).is_ok());
        for t in [1_002, 1_003, 1_004] {
            let again = store.issue(&source, t);
            assert!(
                store.redeem(&again, t).is_err(),
                "re-issuing at {t} made a redeemed challenge redeemable again"
            );
        }
    }

    /// A challenge nobody issued is refused, and distinguishably so: the
    /// operator's next move differs between "this peer invented a challenge"
    /// and "this peer replayed one".
    #[test]
    fn an_unissued_challenge_is_refused_distinguishably() {
        let mut store = ChallengeStore::new(900);
        let e = store.redeem("never-issued", 1_000).expect_err("not issued");
        assert!(matches!(e, ChallengeError::NotIssued { .. }), "{e:?}");
    }

    /// Expiry is against the injected clock, and the boundary is stated: a
    /// challenge exactly `ttl` old is still redeemable.
    #[test]
    fn expiry_runs_on_the_injected_clock_and_its_boundary_is_inclusive() {
        let source = FixedChallenges::repeating("c-1");
        let mut store = ChallengeStore::new(900);
        let c = store.issue(&source, 1_000);
        assert!(store.redeem(&c, 1_900).is_ok(), "age == ttl is inside");

        let mut store = ChallengeStore::new(900);
        let c = store.issue(&source, 1_000);
        let e = store.redeem(&c, 1_901).expect_err("age == ttl + 1 is outside");
        assert!(matches!(e, ChallengeError::Expired { .. }), "{e:?}");
    }

    /// Sweeping frees memory and must never turn a refusal into an
    /// acceptance. Both post-sweep outcomes — the entry is gone, so the
    /// challenge is unissued — are refusals, and this pins that the sweep
    /// cannot produce an `Ok`.
    #[test]
    fn sweeping_never_turns_a_refusal_into_an_acceptance() {
        let source = FixedChallenges::repeating("c-1");
        let mut store = ChallengeStore::new(900);
        let c = store.issue(&source, 1_000);
        assert!(store.redeem(&c, 1_001).is_ok());
        assert_eq!(store.sweep(1_000_000), 1, "the redeemed entry is swept");
        assert!(
            store.redeem(&c, 1_000_001).is_err(),
            "a swept challenge must still be refused, not accepted"
        );
        assert_eq!(store.len(), 0);
    }

    /// A sequence source, so a test with several distinct challenges does not
    /// need a generator either.
    #[test]
    fn a_cycling_source_issues_its_values_in_order() {
        let source =
            FixedChallenges::cycling(vec!["a".into(), "b".into()]).expect("non-empty");
        let mut store = ChallengeStore::new(900);
        assert_eq!(store.issue(&source, 1), "a");
        assert_eq!(store.issue(&source, 2), "b");
        assert_eq!(store.issue(&source, 3), "a");
        assert_eq!(store.len(), 2, "the third issue is the first value again");
    }

    /// An empty source would issue the empty string forever, which is a
    /// challenge every peer can answer. Refused at construction.
    #[test]
    fn an_empty_challenge_source_cannot_be_constructed() {
        assert!(FixedChallenges::cycling(Vec::new()).is_none());
    }

    /// The trait is object-safe and `Send + Sync`, because a verifier holds
    /// one behind an `Arc` across connection tasks exactly as it holds a
    /// `Clock`. Asserted by construction rather than by comment.
    #[test]
    fn a_challenge_source_is_usable_behind_an_arc() {
        let source: std::sync::Arc<dyn Challenges> =
            std::sync::Arc::new(FixedChallenges::repeating("c"));
        let mut store = ChallengeStore::new(60);
        assert_eq!(store.issue(source.as_ref(), 0), "c");
    }
}
```

**The mutation each kills.** The first kills a store that forgets. The second kills `insert` where `or_insert` belongs — the mutation that makes single-use depend on the generator rather than on the store, and the one that would survive the first test alone. `an_unissued_challenge_is_refused_distinguishably` kills merging the two refusals, which loses the signal that separates an invented challenge from a replayed one. The expiry test kills wiring the sweep to a different clock than the redemption, and kills an unstated boundary. `sweeping_never_turns_a_refusal_into_an_acceptance` kills a sweep that removes a redeemed entry and lets it be re-redeemed — the specific way "free some memory" becomes "accept a replay".

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib challenge`
Expected: FAIL to compile — `parallax::challenge` does not exist.

- [ ] **Step 3: Write the implementation**

Add `pub mod challenge;` to `src/lib.rs`, after `pub mod attest;`'s block and before `collateral`.

`src/challenge.rs`:

```rust
//! Challenges: where they come from, and the rule that each is used once.
//!
//! **Randomness gets the same treatment as time.** The crate's discipline is
//! that a clock is injected everywhere a test can reach, with `SystemTime::now`
//! confined to the binaries. A nonce is the same kind of input for the same
//! reason: a CSPRNG called from library code is an input the test cannot
//! control, in the one place the test most needs to — the replay test, which
//! has to issue the *same* challenge twice on purpose, and which no real
//! generator would ever let it do.
//!
//! So [`Challenges`] is a trait, [`FixedChallenges`] is its test
//! implementation, and the production implementation belongs in a binary
//! beside `SystemClock`. Nothing in this plan needs one, so nothing here has
//! one; a trait with only a test implementation is honest about that, and a
//! `rand` dependency added for a code path nobody calls would not be.
//!
//! # What a challenge does and does not buy
//!
//! A challenge the verifier chose, answered inside a quote's `report_data`, is
//! evidence produced *after the verifier spoke*. That is the only mechanism in
//! this crate that establishes freshness at all: a TDX quote carries no
//! timestamp, so the age of an attestation cannot be read off the attestation.
//!
//! It costs a full quote — about 39.5 ms — per challenge, which is why the
//! per-connection version is not the default. The epoch is the same mechanism
//! with the challenge chosen once per interval instead of once per connection:
//! one quote per interval regardless of traffic, at the cost that an epoch the
//! operator publishes is an epoch the operator chose, so it bounds staleness
//! against an honest attester and not against a replaying one.

use std::collections::BTreeMap;

/// Where a challenge comes from.
///
/// `Send + Sync + 'static` and object-safe, so a verifier can hold one behind
/// an `Arc` across connection tasks exactly as it holds a
/// [`Clock`](crate::clock::Clock). `Debug` is a supertrait for the same reason
/// it is on `Clock`: a verifier printed in a log should say which source it
/// was built with, and "the system CSPRNG" and "a scripted list" are not
/// interchangeable facts.
pub trait Challenges: std::fmt::Debug + Send + Sync + 'static {
    /// A challenge to issue. **Not required to be unique** — [`ChallengeStore`]
    /// does not rely on it, and `FixedChallenges::repeating` deliberately
    /// violates it, which is how the single-use rule gets tested at all.
    fn issue(&self) -> String;
}

/// A scripted source. What the tests use.
#[derive(Debug)]
pub struct FixedChallenges {
    values: Vec<String>,
    next: std::sync::atomic::AtomicUsize,
}

impl FixedChallenges {
    /// The same challenge every time.
    ///
    /// A real generator would never do this, which is exactly why it exists: a
    /// store whose single-use rule depended on the source never repeating
    /// would be a store whose single-use rule was untestable and, worse,
    /// untrue.
    pub fn repeating(value: impl Into<String>) -> Self {
        Self {
            values: vec![value.into()],
            next: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The given values, in order, then round again.
    ///
    /// `None` for an empty list rather than a source that issues the empty
    /// string forever, which would be a challenge every peer can answer.
    pub fn cycling(values: Vec<String>) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        Some(Self {
            values,
            next: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl Challenges for FixedChallenges {
    fn issue(&self) -> String {
        // `Relaxed` is sufficient: the only property wanted is that concurrent
        // callers get successive indices, which `fetch_add` gives on its own.
        // No other memory is published through it. `values` is non-empty by
        // construction, so the modulo cannot divide by zero and the index
        // cannot be out of range.
        let i = self
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.values.len();
        self.values[i].clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    /// Never issued by this verifier, or issued so long ago it has been swept.
    ///
    /// Distinct from [`ChallengeError::AlreadyRedeemed`] because the operator's
    /// next move differs: this is a peer presenting a challenge nobody chose,
    /// which means either it invented one or it is answering a *different*
    /// verifier.
    #[error(
        "challenge `{challenge}` was not issued by this verifier, or was issued long \
         enough ago to have been swept: a challenge this verifier did not choose \
         establishes nothing, because the whole property is that the evidence was \
         produced after the verifier spoke"
    )]
    NotIssued { challenge: String },
    /// Presented a second time.
    #[error(
        "challenge `{challenge}` was already redeemed at {redeemed_at}; a challenge \
         is single-use, and a second presentation is a replay of the quote minted \
         for the first"
    )]
    AlreadyRedeemed { challenge: String, redeemed_at: u64 },
    #[error(
        "challenge `{challenge}` was issued at {issued_at} and this verifier accepts \
         an answer for {ttl_secs}s, so it expired before {now_secs}"
    )]
    Expired {
        challenge: String,
        issued_at: u64,
        ttl_secs: u64,
        now_secs: u64,
    },
}

/// Whether a challenge is outstanding or spent, and when that last changed.
///
/// Two states rather than removal-on-redeem, so that a replay is reported as a
/// replay rather than as an unissued challenge. Both are refusals either way —
/// see [`ChallengeStore::sweep`] — but a message that says "already redeemed"
/// tells the operator something a message that says "never issued" does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Outstanding { at: u64 },
    Redeemed { at: u64 },
}

impl State {
    fn at(&self) -> u64 {
        match self {
            State::Outstanding { at } | State::Redeemed { at } => *at,
        }
    }
}

/// The challenges this verifier issued, and which have been spent.
///
/// **Keyed by challenge, swept against the injected clock, single-use enforced
/// by state rather than by absence.** Nothing here reads a clock: `issue`,
/// `redeem` and `sweep` all take `now_secs`, so the boundary tests can drive
/// the same store past two times and every expiry assertion is a fact about
/// the arguments rather than about the machine.
#[derive(Debug)]
pub struct ChallengeStore {
    ttl_secs: u64,
    issued: BTreeMap<String, State>,
}

impl ChallengeStore {
    /// `ttl_secs` is how long an issued challenge may be answered for. It is
    /// the exposure window a challenge creates: a quote minted for a challenge
    /// is replayable, to this verifier, for exactly this long.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            issued: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.issued.len()
    }

    pub fn is_empty(&self) -> bool {
        self.issued.is_empty()
    }

    /// Take a challenge from `source` and record it as outstanding.
    ///
    /// **`or_insert`, not `insert`.** A source that repeats a value must not be
    /// able to reset that value's state back to outstanding: if it could, the
    /// single-use rule would hold only because real generators do not repeat,
    /// which is an assumption about the source rather than a property of this
    /// store. `FixedChallenges::repeating` violates it on purpose and
    /// `re_issuing_does_not_resurrect_a_redeemed_challenge` is the assertion.
    pub fn issue(&mut self, source: &dyn Challenges, now_secs: u64) -> String {
        self.sweep(now_secs);
        let challenge = source.issue();
        self.issued
            .entry(challenge.clone())
            .or_insert(State::Outstanding { at: now_secs });
        challenge
    }

    /// Accept `challenge` once, if this verifier issued it and it has not
    /// expired.
    pub fn redeem(&mut self, challenge: &str, now_secs: u64) -> Result<(), ChallengeError> {
        match self.issued.get(challenge).copied() {
            None => Err(ChallengeError::NotIssued {
                challenge: challenge.to_string(),
            }),
            Some(State::Redeemed { at }) => Err(ChallengeError::AlreadyRedeemed {
                challenge: challenge.to_string(),
                redeemed_at: at,
            }),
            Some(State::Outstanding { at }) => {
                // Inclusive: an answer exactly `ttl_secs` after issuance is
                // accepted, matching the freshness boundary in `replay`.
                // `saturating_sub` because `now_secs` before `at` is a caller
                // passing a clock that went backwards, and an age of zero is
                // the safe reading of that — it accepts, but only inside the
                // window, whereas a wrap would accept forever.
                if now_secs.saturating_sub(at) > self.ttl_secs {
                    return Err(ChallengeError::Expired {
                        challenge: challenge.to_string(),
                        issued_at: at,
                        ttl_secs: self.ttl_secs,
                        now_secs,
                    });
                }
                self.issued
                    .insert(challenge.to_string(), State::Redeemed { at: now_secs });
                Ok(())
            }
        }
    }

    /// Drop entries older than `ttl_secs` and return how many went.
    ///
    /// **Sweeping can never turn a refusal into an acceptance**, which is the
    /// property that makes it safe to run on every `issue`. An outstanding
    /// entry old enough to sweep would have been refused as
    /// [`ChallengeError::Expired`]; after sweeping it is refused as
    /// [`ChallengeError::NotIssued`]. A redeemed entry old enough to sweep
    /// would have been refused as [`ChallengeError::AlreadyRedeemed`]; after
    /// sweeping it is refused as `NotIssued`. Both transitions lose diagnostic
    /// detail and neither loses the refusal, and
    /// `sweeping_never_turns_a_refusal_into_an_acceptance` pins it.
    pub fn sweep(&mut self, now_secs: u64) -> usize {
        let before = self.issued.len();
        self.issued
            .retain(|_, state| now_secs.saturating_sub(state.at()) <= self.ttl_secs);
        before - self.issued.len()
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib challenge && cargo test --all-targets`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Put randomness under the clock's discipline, and refuse the second use of a challenge"
```

---

## Task 12: The cross-check into `poc-audit`

**Files:**
- Modify: `/Users/jimschwoebel/Desktop/poc-audit/Cargo.toml`, `src/verdict.rs`, `src/main.rs`, `src/registry.rs`, `src/field/mod.rs`, `src/field/attestation.rs`
- Create: `/Users/jimschwoebel/Desktop/poc-audit/src/field/freshness.rs`

**Interfaces:**
- Produces: `Context::proxy_config: Option<PathBuf>`, `Context::as_of: Option<u64>`, `field::freshness::Freshness("iat")`.
- Consumes: `parallax::replay::{read, measurement, freshness, mrtd_of, MeasurementVerdict, FreshnessVerdict, Established}`, `parallax::proxy::ProxyConfig`.

**This is the load-bearing task**, on the reasoning `poc-audit`'s own design gives: every other test in this plan tests our own code, and this one tests whether the rows the work exists to move actually move. Success is `submods.attestation.measurement` reaching `ESTABLISHED (compared)`, `iat` leaving `Unaudited`, and **nothing else in the table changing**.

**Sequencing dependency, and it is real.** `poc-audit`'s `Cargo.toml` pins `parallax` at `rev = "efd1b64"`, which is `main`. The `attest` branch is unpushed, so there is no rev to bump to until somebody pushes it. Push the branch first, take the resulting commit hash, and pin that — **by `rev`, never by branch**, matching what the file already does for all three upstream tools. Do not add a `path` dependency: it would make `poc-audit` build only on a machine that has `parallax` checked out beside it, and it would make the pin meaningless.

- [ ] **Step 1: Push the branch and bump the pin**

```bash
cd /Users/jimschwoebel/Desktop/parallax
git push -u origin attest
git rev-parse --short HEAD
```

Set that hash as `parallax`'s `rev` in `/Users/jimschwoebel/Desktop/poc-audit/Cargo.toml`, then:

```bash
cd /Users/jimschwoebel/Desktop/poc-audit
cargo build
```

Expect this to fail to compile if anything in `poc-audit` used an API this plan changed. Nothing should have — `poc-audit` uses `Deployment::load`, `solve`, `Latency::label` and `Impact`, none of which moved — but check rather than assume, and if something did break, that is a finding about the promotion's blast radius and belongs in the commit message.

- [ ] **Step 2: Write the failing tests**

In `src/field/attestation.rs`'s `mod tests`, and a new `mod tests` in `src/field/freshness.rs`:

```rust
    /// **The row this whole work exists to move.** `--proxy-config` reaches
    /// `ESTABLISHED (compared)` against the same reference values the proxy
    /// gates traffic on, through `parallax`'s own comparison rather than a
    /// second one here.
    #[test]
    fn a_matching_measurement_against_a_proxy_config_is_established_as_compared() {
        let cfg = write_proxy_config(&[MRTD_HEX]);
        let ctx = Context {
            proxy_config: Some(cfg.clone()),
            as_of: Some(1_700_000_060),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement")
            .audit(&record_with_measurement(&format!("sha-384:{MRTD_HEX}")), &ctx);
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "ESTABLISHED", "reason: {}", f.reason);
        assert!(
            f.reason.contains("compared") && !f.reason.contains("re-verified"),
            "the reason must say which of the two ESTABLISHEDs this is: {}",
            f.reason
        );
        assert!(
            f.reason.contains("parallax") || f.reason.contains("proxy config"),
            "the reason must name what backs the comparison: {}",
            f.reason
        );
    }

    /// The seam's whole point: the audit and the gate read one list. Change
    /// the proxy config and the audit changes, with no second file edited.
    #[test]
    fn changing_the_proxy_config_changes_the_verdict() {
        let matching = write_proxy_config(&[MRTD_HEX]);
        let other = write_proxy_config(&[&"11".repeat(48)]);
        let rec = record_with_measurement(&format!("sha-384:{MRTD_HEX}"));

        let a = AttestationField("submods.attestation.measurement").audit(
            &rec,
            &Context {
                proxy_config: Some(matching.clone()),
                as_of: Some(1_700_000_060),
                ..Context::default()
            },
        );
        let b = AttestationField("submods.attestation.measurement").audit(
            &rec,
            &Context {
                proxy_config: Some(other.clone()),
                as_of: Some(1_700_000_060),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&matching);
        let _ = std::fs::remove_file(&other);
        assert_eq!(a.verdict.label(), "ESTABLISHED");
        assert_eq!(b.verdict.label(), "DIVERGES");
    }

    /// **Finding 1, at the audit layer.** The fixture this test module already
    /// uses — the standard's own `hardware-attested.json` — carries a
    /// `sha-256:` measurement under `platform: INTEL_TDX`, which is 32 bytes
    /// where a TDX MRTD is 48. Against a proxy config it is a **record error**
    /// and not a `DIVERGES`: nothing was compared, so nothing failed to match.
    /// This is deliberate and is filed upstream rather than accommodated.
    #[test]
    fn the_standards_own_vector_is_a_record_error_not_a_divergence() {
        let cfg = write_proxy_config(&[MRTD_HEX]);
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", None),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: Some(1_700_000_060),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_ne!(
            f.verdict.label(),
            "DIVERGES",
            "a measurement that cannot be an MRTD was never compared, so it \
             cannot have failed a comparison: {}",
            f.reason
        );
        assert!(f.reason.contains("48 bytes"), "{}", f.reason);
        assert!(f.reason.contains("sha-384"), "{}", f.reason);
    }

    /// The old path must keep working. `--reference-values` is the fallback
    /// for an operator with no proxy, and it must not regress to UNCHECKED
    /// because a new flag exists.
    #[test]
    fn the_reference_values_path_still_reaches_established_without_a_proxy_config() {
        // (the body of the existing
        // `measurement_in_the_supplied_reference_values_is_established`,
        // unchanged, asserted here so the fallback is pinned after the new
        // path lands)
    }

    /// `--proxy-config` without `--as-of` cannot produce a freshness row, and
    /// must say which flag would deepen it rather than guessing at a time.
    #[test]
    fn a_proxy_config_without_an_evaluation_time_is_unchecked_naming_the_flag() {
        let cfg = write_proxy_config(&[MRTD_HEX]);
        let f = crate::field::freshness::Freshness("iat").audit(
            &record_with_measurement(&format!("sha-384:{MRTD_HEX}")),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: None,
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "UNCHECKED");
        assert!(f.reason.contains("--as-of"), "{}", f.reason);
    }
```

In `src/field/freshness.rs`'s tests:

```rust
    /// `iat` leaves `Unaudited`. The registry row this work exists to move.
    #[test]
    fn a_record_inside_the_declared_bound_is_established() {
        let cfg = write_proxy_config_with_freshness("15m");
        let f = Freshness("iat").audit(
            &record_with_iat(1_700_000_000),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: Some(1_700_000_060),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "ESTABLISHED", "reason: {}", f.reason);
        assert!(f.reason.contains("1700000060"), "{}", f.reason);
        assert!(f.reason.contains("C7.2.3"), "{}", f.reason);
    }

    /// Outside the bound is ASSERTED with a new reason, not DIVERGES. The
    /// interval elapsed; nothing the record claims was refuted.
    #[test]
    fn a_record_outside_the_declared_bound_is_asserted() {
        let cfg = write_proxy_config_with_freshness("15m");
        let f = Freshness("iat").audit(
            &record_with_iat(1_700_000_000),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: Some(1_800_000_000),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "ASSERTED", "reason: {}", f.reason);
    }

    /// A record newer than the evaluation time is DIVERGES, and so exit 1.
    /// Not stale — wrong.
    #[test]
    fn a_future_dated_record_diverges() {
        let cfg = write_proxy_config_with_freshness("15m");
        let f = Freshness("iat").audit(
            &record_with_iat(1_800_000_000),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: Some(1_700_000_000),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "DIVERGES", "reason: {}", f.reason);
        assert!(f.verdict.is_failure(), "a future-dated record must set exit 1");
    }

    /// No `--proxy-config` at all: UNCHECKED naming the flag, not ASSERTED.
    /// The distinction `poc-audit` is built on — "I checked and there is
    /// nothing behind this" is not "I did not check".
    #[test]
    fn no_proxy_config_is_unchecked_naming_the_flag() {
        let f = Freshness("iat").audit(&record_with_iat(1_700_000_000), &Context::default());
        assert_eq!(f.verdict.label(), "UNCHECKED");
        assert!(f.verdict.is_unchecked_missing_input());
        assert!(f.reason.contains("--proxy-config"), "{}", f.reason);
    }

    /// A config declaring no bound is ASSERTED and says C7.2.3 is unmet by
    /// the *deployment*, not by the record. The record did nothing wrong.
    #[test]
    fn a_config_declaring_no_bound_is_asserted_against_the_deployment() {
        let cfg = write_proxy_config_without_freshness();
        let f = Freshness("iat").audit(
            &record_with_iat(1_700_000_000),
            &Context {
                proxy_config: Some(cfg.clone()),
                as_of: Some(1_700_000_060),
                ..Context::default()
            },
        );
        let _ = std::fs::remove_file(&cfg);
        assert_eq!(f.verdict.label(), "ASSERTED");
        assert!(f.reason.contains("C7.2.3"), "{}", f.reason);
        assert!(
            f.reason.contains("declares no") || f.reason.contains("states none"),
            "the reason must put the omission on the deployment, not on the \
             record: {}",
            f.reason
        );
    }
```

And, in `tests/`, the row the design calls load-bearing:

```rust
/// **The cross-check.** Four rows move and nothing else does. If this ever
/// fails on a row it does not name, the seam between the two repositories has
/// drifted and something in `parallax` changed a verdict here by accident.
#[test]
fn exactly_the_four_intended_rows_move() {
    let before = poc_audit::registry::run(&record(), &Context::default());
    let after = poc_audit::registry::run(
        &record(),
        &Context {
            proxy_config: Some(proxy_config_path()),
            as_of: Some(1_700_000_060),
            ..Context::default()
        },
    );
    assert_eq!(before.len(), after.len(), "the table changed shape");

    let moved: Vec<&str> = before
        .iter()
        .zip(after.iter())
        .filter(|(b, a)| b.verdict.label() != a.verdict.label())
        .map(|(b, _)| b.field)
        .collect();
    assert_eq!(
        moved,
        vec!["iat", "submods.attestation.measurement"],
        "exactly these rows move; anything else is drift"
    );
}
```

(`nonce` stays `Unaudited` and its reason text changes rather than its verdict — see Step 4. Adjust the expected list if the `nonce` row's *coverage* changes; do not adjust it to accommodate an unexpected row.)

**The mutation each kills.** The first kills leaving `measurement` at `ASSERTED`, which is the state of the world today. `changing_the_proxy_config_changes_the_verdict` kills reading a second list. `the_standards_own_vector_is_a_record_error_not_a_divergence` kills the tempting shortcut of mapping every `RecordError` onto `DIVERGES`, which would make a malformed record look like a compromised workload. `the_reference_values_path_still_reaches_established...` kills breaking the fallback. The freshness tests kill collapsing stale with divergent, and kill defaulting `--as-of`. `exactly_the_four_intended_rows_move` kills everything else: it is the one test here that checks the seam rather than our own code.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test`
Expected: FAIL to compile — `Context` has no `proxy_config` or `as_of`, and `field::freshness` does not exist.

- [ ] **Step 4: Write the implementation**

`src/verdict.rs`, on `Context`:

```rust
    /// The proxy configuration whose reference values and declared attestation
    /// age to check against.
    ///
    /// **Distinct from `reference_values`, and the primary path.** That flag
    /// takes a bespoke `{"measurements": [...]}` file the operator writes
    /// separately from the config that actually gates traffic, and compares it
    /// with this crate's own `ReferenceValues::contains` — two lists and two
    /// comparisons, which is the drift this programme names as its own defect
    /// pattern. This flag reads the file the proxy runs with and compares
    /// through `parallax::derive::reference_check`, the same function the gate
    /// admits on. `reference_values` remains as the fallback for an operator
    /// with no proxy.
    pub proxy_config: Option<PathBuf>,
    /// The evaluation time for freshness, seconds since the Unix epoch.
    ///
    /// Required for the `iat` row and with no default, deliberately: this
    /// tool's freshness answer is a function of this argument — an operator
    /// can produce a clean row by passing the record's own `iat` — and a
    /// default would make the common invocation non-reproducible while hiding
    /// that the argument exists. `--as-of now` is the explicit request, parsed
    /// in `main`.
    pub as_of: Option<u64>,
```

`src/main.rs`, two flags with `conflicts_with = "chain"` like the rest, and `--as-of` resolved the same way `parallax`'s binary resolves it (`now` or RFC 3339). Validate both eagerly beside the existing `--deployment` and `--reference-values` pre-checks, so a bad path is a loud exit 2 rather than a quiet `UNCHECKED`:

```rust
    if let Some(p) = cli.proxy_config.as_ref() {
        if let Err(e) = parallax::proxy::ProxyConfig::load(p) {
            eprintln!("error: cannot use --proxy-config {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }
```

`src/field/attestation.rs` — add the branch at the top of `measurement_finding`, before the `--reference-values` branch, so the proxy config wins when both are given:

```rust
        if let Some(path) = ctx.proxy_config.as_ref() {
            return self.measurement_against_proxy_config(rec, path);
        }
```

and the method:

```rust
    /// The primary path: compare through `parallax`'s own comparison, against
    /// the reference values the proxy actually gates traffic on.
    ///
    /// **This produces `ESTABLISHED (compared)`, never `(re-verified)`.** The
    /// record carries no quote, so nothing cryptographic happens here: what is
    /// established is that the value written in the field is one the operator's
    /// gate admits. The reason text says so in those words, because the
    /// difference between a comparison and a re-verification is the difference
    /// this whole tool exists to keep visible.
    fn measurement_against_proxy_config(&self, rec: &Record, path: &std::path::Path) -> Finding {
        let cfg = match parallax::proxy::ProxyConfig::load(path) {
            Ok(c) => c,
            Err(e) => {
                return Finding {
                    field: self.0,
                    verdict: Verdict::Unchecked(Why::AuditorFailed(e.to_string())),
                    reason: format!("could not use --proxy-config {}: {e}", path.display()),
                    residual: Vec::new(),
                }
            }
        };
        let attestation = parallax::replay::Attestation {
            platform: rec.submods.attestation.platform.clone(),
            measurement: rec.submods.attestation.measurement.clone(),
        };
        let configured = &cfg.gate.derive.reference_values;

        // A record whose `measurement` cannot be an MRTD is a **record**
        // error, not a comparison failure. `DIVERGES` would say "you are
        // running a workload you did not declare" about a record that does not
        // describe a workload — and the standard's own positive vector is in
        // exactly this state, which is finding 1 and ships as a finding.
        let verdict = match parallax::replay::measurement(&attestation, configured) {
            Ok(v) => v,
            Err(e) => {
                return Finding {
                    field: self.0,
                    verdict: Verdict::Unchecked(Why::AuditorFailed(e.to_string())),
                    reason: format!(
                        "this record's measurement was not compared to anything, because \
                         it cannot denote the value it claims to: {e}"
                    ),
                    residual: Vec::new(),
                }
            }
        };

        let reason = format!(
            "compared against the {} MRTD reference value(s) in {} — the same list the \
             proxy gates traffic on, through parallax's own \
             `derive::reference_check` rather than a second comparison here. {}",
            configured.len(),
            path.display(),
            verdict.reason(configured.len()),
        );

        match verdict {
            parallax::replay::MeasurementVerdict::Established(
                parallax::replay::Established::Compared,
            ) => Finding {
                field: self.0,
                verdict: Verdict::Established(
                    BackedBy::new("parallax::derive::reference_check (compared, not re-verified)")
                        .expect("non-empty literal"),
                ),
                reason,
                residual: Vec::new(),
            },
            // Unreachable: `replay::measurement` compares strings and cannot
            // produce the cryptographic verdict. Written out rather than
            // wildcarded so that the day a record carries its own quote, this
            // is a compile-time decision rather than a silent relabelling.
            parallax::replay::MeasurementVerdict::Established(
                parallax::replay::Established::ReVerified,
            ) => Finding {
                field: self.0,
                verdict: Verdict::Established(
                    BackedBy::new("parallax::verify::verify_quote (re-verified)")
                        .expect("non-empty literal"),
                ),
                reason,
                residual: Vec::new(),
            },
            parallax::replay::MeasurementVerdict::Diverges { .. } => Finding {
                field: self.0,
                verdict: Verdict::Diverges,
                reason,
                residual: Vec::new(),
            },
            parallax::replay::MeasurementVerdict::Asserted => Finding {
                field: self.0,
                verdict: Verdict::Asserted,
                reason,
                residual: Vec::new(),
            },
        }
    }
```

If `parallax::replay::Attestation`'s fields are not `pub` enough to construct from here — they are, per Task 5 — prefer that over adding a constructor. If it becomes awkward, add `replay::measurement_of(platform: &str, measurement: &str, configured: &[[u8; 48]])` to `parallax` rather than reaching into `Record`'s internals from two places.

`src/field/freshness.rs` is the same shape: load the config, require `ctx.as_of` with `Why::MissingInput("--as-of")`, call `parallax::replay::freshness(rec.iat, as_of, cfg.max_attestation_age.as_ref())`, and map `FreshnessVerdict` onto `Verdict` exactly as `FreshnessVerdict::label` already decides — `Fresh` → `Established`, `Stale` and `NoBoundDeclared` → `Asserted`, `FutureDated` → `Diverges` — carrying `verdict.reason(as_of)` into the finding's reason. Do not re-derive the mapping; read it off `label()` so the two tools cannot disagree about what a verdict is called.

`src/registry.rs`: move `iat` from `Unaudited` to `Audited` and add `Box::new(crate::field::freshness::Freshness("iat"))` to `auditors()`.

The `nonce` row **stays `Unaudited`**, and its reason changes. It cannot do better, and saying why is the honest output:

```rust
    (
        "nonce",
        Coverage::Unaudited(
            "freshness against a challenge is a property of an interaction, and a \
             file is not one: offline, the most that could be said about a nonce is \
             whether it is one this verifier's own issuance log recorded, which \
             requires having challenged this record's producer. See parallax's \
             challenge store, which is what a live verifier would check it against",
        ),
    ),
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/jimschwoebel/Desktop/poc-audit
cargo test
cargo clippy --all-targets -- -D warnings
```
Expected: PASS. `every_required_field_is_accounted_for` will need no change — `iat` was already in `ACCOUNTED`, only its coverage moved.

- [ ] **Step 6: Update the README's exit-codes and flags sections**

`--proxy-config` and `--as-of` need entries, `--reference-values`'s entry needs a sentence saying it is now the fallback for an operator with no proxy, and the exit-code section needs to say that a future-dated record is exit 1 while a stale one is not. Match whatever the file already does; do not invent a new section.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Reach ESTABLISHED (compared) through parallax's own comparison, and move iat off Unaudited"
```

---

## After the twelve tasks

Four rows in `poc-audit`'s registry have moved and nothing else has. Three things are worth doing next and are not in this plan:

- **The attester's half of fork G2**: `parallax-attest` re-quoting every `max_attestation_age` and folding the published epoch into `report_data[32..64]` via `ratls::expected_report_data_for`, plus the challenge endpoint that makes G1 reachable for P03's adaptive-refresh question. The seam is built; the loop is not.
- **A hardware fixture with a real digest in `report_data`.** Two rows of the design's testing table are unwritable without one, and this repository has never seen a successful binding against real hardware under either layout. That is recorded in `src/proxy/mod.rs` by Task 10 and it should not stay recorded forever.
- **Filing findings 1 and 2 upstream.** `docs/standard-findings.md` says none of the eight have been filed. Tasks 5 and 12 pin both of them by test, on both sides of the seam, which is the strongest form the argument can take: the vector is refused, deliberately, by a tool that says why.

---

## What the design gets wrong about the code

Recorded here rather than only in the preamble, because an implementer who reads the design after this plan needs the list.

1. **Fork B is already implemented.** The design's central factual claim about it — `src/derive.rs:452`, "`derive` does not read `o.rt_mrs`, and neither does anything else in this crate yet" — was true when written and is false now. Commit `f907736` shipped the whole axis, including the hardware cross-check the design's testing table asks for (`the_rtmr3_config_path_agrees_with_the_attesters_arithmetic`, `src/derive.rs:1186`). What remains, and what Task 1 does, is the admission rule: `warnings` and the `require` gate still read the MRTD axis only. The stale comment itself is still in the tree at `src/derive.rs:544` and Task 1 corrects it.

2. **`reference_check`'s current signature is not the one the design describes.** The design says it is `(&VerificationOutcome, &DeriveConfig)` at `src/derive.rs:232`. It is at `:312`, it is a two-line wrapper, and the function that actually compares is `check_measurement(configured: &[[u8; 48]], attested: [u8; 48]) -> ReferenceCheck` at `:302` — which is the design's target signature with the arguments the other way round. The promotion is therefore smaller than the design assumes, and Task 2 fixes the argument order to the one the design fixes rather than the one the code happens to have.

3. **Every design line number into `src/derive.rs` and `src/proxy/config.rs` is stale.** `derive` is at `:491` not `:399`; `ReferenceCheck` at `:290` not `:223`; `parse_mrtd` at `:429` not `:369`; `ProxyConfig::load` at `:274` not `:259`; `require_reference_values` at `:230` not `:211`. The `src/verify/*`, `src/ratls.rs` and `src/proxy/serve.rs` citations are all correct.

4. **`parse_mrtd` is case-insensitive; the design and its own doc comment both say "96 lowercase hex characters".** `parse_hex48` (`src/proxy/config.rs:402`) checks `is_ascii_hexdigit`, which accepts `A`–`F`. This matters for the offline path: the schema's `digest` pattern is `[0-9a-f]`, lowercase-only, so a record whose `measurement` carries uppercase hex is schema-invalid but would parse cleanly here. Task 5 adds the case check on the record side rather than tightening the config parser, and says why at the site.

5. **The design's `Latency::parse` citation is `src/latency.rs:23`; it is correct**, and `label` is at `:44` rather than the design's implied nearby line. Both are as described.

6. **`poc-audit` pins `parallax` at `rev = "efd1b64"`, which is `main`.** None of the `attest` branch is visible to it — not the RTMR3 axis, not `ratls`, none of this plan. Task 12 has to bump the pin, and until the `attest` branch is pushed there is no rev to bump it to. That is a real sequencing dependency and Task 12 states it.

7. **Fork E's citation for `warnings` is `src/proxy/gate.rs:377`, which is correct**, but the mechanism it points at warns about one axis. Task 1 is what makes the citation mean what fork E assumed.
