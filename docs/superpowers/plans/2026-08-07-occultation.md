# occultation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `occultation`, a Rust tool that measures what verifiable unlinkability costs at agent action rates, reproduces the composition error the P05 desk study made, and tests whether the pre-computation pool the whole construction depends on is sound.

**Architecture:** A single Cargo package exposing a library and an `occultation` binary. Real BBS+ presentation and verification are implemented over `blstrs` BLS12-381 against the IETF BBS draft, with an Ed25519 baseline from `ed25519-dalek`. ECDAA and threshold ElGamal escrow are **modelled** behind `trait AnonymousAttestation` and `trait EscrowTag`; a modelled implementation cannot be constructed without a `ModelledPermit`, cannot return a `Valid` verdict, and is labelled at every point it reaches output. Every number the tool prints carries a `Source` saying whether it was measured here or read from a publication.

**Tech Stack:** Rust 2021, `blstrs` 0.7 (BLS12-381), `ed25519-dalek` 2 (baseline), `sha2` 0.10, `rand_chacha` 0.3 + `rand_core` 0.6 (seeded, deterministic), `criterion` 0.8 (developer microbenchmarks), `serde` + `toml` + `serde_json`, `clap` 4 (derive), `thiserror`, `anyhow`, `humantime`, `log` + `env_logger`.

---

## Global Constraints

- Rust edition **2021**. Toolchain floor **1.90**.
- **`#![forbid(unsafe_code)]` in `src/lib.rs`.** This is a cryptography repository; no `unsafe`, and therefore no raw `blst` FFI. Where `blstrs` lacks an API (wide scalar reduction) it is reimplemented in safe Rust.
- **Every reported number carries a `Source`.** `Source::MeasuredHere { iters }` or `Source::Published { citation }`. There is no way to construct a `Measurement` without one. A published figure renders with the word `PUBLISHED` and its citation; it is never presented as something this tool measured.
- **Modelled components provide no security and must be impossible to mistake for real.** Four independent barriers, all asserted by test: (1) a modelled implementation cannot be constructed without a `ModelledPermit`, which only `--allow-modelled` produces; (2) `AttestationVerdict::Valid` is unreachable from a modelled implementation — it returns `ModelledNoSecurity`; (3) every modelled invocation emits `log::warn!`; (4) every value it produces carries `Provenance::Modelled` and the report layer renders `MODELLED` beside it.
- **Blinding-factor reuse is a security invariant, not a tuning choice.** The pool stalls on exhaustion. There is no reuse option, no flag, no config key. `PoolItem` is not `Clone` and is consumed by value, so reuse is unrepresentable through the public API.
- **RNG is seeded and deterministic.** `rand_chacha::ChaCha20Rng` seeded from `--seed` (default 7) everywhere. No `thread_rng` in library code — a benchmark that cannot be rerun to the same numbers is not a measurement.
- **Dependency pin, and why:** `blstrs` 0.7 pins `ff`/`group` 0.13, which are built on `rand_core` **0.6**. `ed25519-dalek` **3.x** requires `rand_core` **0.9**. Both in one crate puts two incompatible `RngCore` traits in scope and fails to compile. Pin `ed25519-dalek = "2"` with feature `rand_core`. Verified by compiling both together.
- Library errors use `thiserror`; the binary uses `anyhow`.
- **No panics on malformed input.** Every parse, lookup and index path returns `Result`. Asserted by test.
- Exit codes: `0` success, `1` policy violation (anonymity set below `--min-set`, stall above `--max-stall`, budget exceeded under `--enforce-budget`), `2` bad input, `3` a modelled component was requested without `--allow-modelled`.
- The latency budget is **15 ms**, from P05 and the desk study. It is a named constant, `cost::BUDGET`, used by every verdict.
- Durations in TOML and on the CLI are `humantime` strings (`"15ms"`, `"10s"`) — never bare numbers.
- Licensing: **Apache-2.0 throughout**, code and paper alike, single `LICENSE` plus `NOTICE`. Copyright "Advanced AI Society and the Proof-of-Control contributors".
- Repo is **private** in the `Task-force-for-AI-agents-in-Healthcare` org.
- Every commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- **`results/` is split, and this differs from `parallax`.** `results/deterministic/` holds artifacts that are byte-identical on any host (the desk-study composition, anonymity partitions, the seeded pool simulation); CI regenerates these and fails on a diff. `results/measured/` holds wall-clock timings, which differ per host; CI regenerates them and asserts only that the file's `tool_version` matches the crate version and its schema is intact. Diffing timings would fail CI on jitter; not regenerating them lets a stale figure outlive a code change. This split is the compromise, and `results/README.md` states it.

---

## What is real, what is real-but-not-interoperable, and what is modelled

The design spec names two categories. Implementation needs three, and the README must carry all three — a two-way split would force our BBS+ into "real" and quietly overclaim interoperability.

| Category | Components | What it means |
| --- | --- | --- |
| **Real** | Ed25519 baseline; BLS12-381 group and pairing arithmetic; the pre-computation pool; the anonymity-set calculator; the timing harness | Sound, and does what it says |
| **Real but not interoperable** | BBS+ key generation, signing, verification, presentation and proof verification | Genuine cryptography with genuine security properties — forgeries fail, tampered proofs fail, undisclosed attributes stay hidden — implemented over `blstrs` against `draft-irtf-cfrg-bbs-signatures`. **Not validated against the draft's test vectors**, so the wire encoding will not interoperate with another BBS+ implementation. The cost profile is the deliverable; interoperability is not claimed |
| **Modelled** | ECDAA (`ModelledEcdaa`), threshold ElGamal escrow (`ModelledThresholdElGamal`) | **No security whatsoever.** Correct interface and a representative cost profile, nothing else. Requires `--allow-modelled` |

---

## File Structure

| File | Responsibility |
| --- | --- |
| `Cargo.toml` | package manifest, lib + bin + bench targets |
| `src/lib.rs` | module wiring, `#![forbid(unsafe_code)]`, public re-exports |
| `src/cost.rs` | `Source`, `Measurement`, `CostProfile`, `BUDGET`, `compose`, `BudgetVerdict` |
| `src/harness.rs` | the timing harness: warmup, iteration count, median/p95/p99 |
| `src/baseline.rs` | Ed25519 sign/verify baseline |
| `src/modelled.rs` | `Provenance`, `AttestationVerdict`, `ModelledPermit`, `trait AnonymousAttestation`, `trait EscrowTag` |
| `src/ecdaa.rs` | `ModelledEcdaa` — no security |
| `src/escrow.rs` | `ModelledThresholdElGamal` — no security |
| `src/bls.rs` | `expand_message_xmd`, `hash_to_scalar`, `create_generators`, `PreparedIssuer` |
| `src/bbs/mod.rs` | BBS+ public API and shared types |
| `src/bbs/keys.rs` | `SecretKey`, `PublicKey`, `KeyPair` |
| `src/bbs/sign.rs` | `sign`, `verify` and the signature pairing equation |
| `src/bbs/proof.rs` | `ProofScalars`, `prove_with_scalars`, `prove`, `verify_proof` |
| `src/pool.rs` | `PoolItem` (not `Clone`), `PrecomputationPool`, the deterministic burst simulation |
| `src/anonymity.rs` | fleet TOML model, TCB partitioning, anonymity metrics |
| `src/report.rs` | table and JSON rendering shared by every command; renders `MODELLED` and `PUBLISHED` |
| `src/bin/occultation.rs` | clap CLI |
| `benches/primitives.rs` | criterion microbenchmarks for developers |
| `examples/fleet-uniform.toml` | a fleet on one TCB configuration |
| `examples/fleet-drifted.toml` | a fleet with per-host TCB drift |
| `tests/acceptance.rs` | the four acceptance tests from the spec |
| `tests/robustness.rs` | no-panic guarantees on malformed input |
| `paper/main.tex` | the P05 paper, AAS branded |

---

## Risks

Verified before planning, not discovered in Task 6.

| Risk | Status | Mitigation |
| --- | --- | --- |
| **No maintained BBS+ crate at the needed API.** `bbs` 0.4.1 is 2020-era, predates the IETF draft and is unmaintained; `pairing_crypto` and `docknetwork-crypto` are not on crates.io | **Confirmed** by crates.io lookup | Implement presentation and verification over `blstrs` directly (Tasks 4–6). Well-specified, and it is the measurement rather than novel cryptography |
| **RNG trait fragmentation.** `blstrs` 0.7 → `ff`/`group` 0.13 → `rand_core` 0.6. `ed25519-dalek` 3.0 → `rand_core` 0.9. Together they do not compile: `ThreadRng: CryptoRng` is unsatisfied and `Field::random` rejects the rng | **Confirmed** by compiling the combination and reading the error | Pin `ed25519-dalek = "2"`, `rand_core = "0.6"`, `rand_chacha = "0.3"`. Verified to compile and run together |
| **`blstrs` has no wide scalar reduction and no `hash_to_scalar`.** `Scalar::from_bytes_be` rejects non-canonical input; there is no `from_okm`/`from_bytes_wide` | **Confirmed** by grepping the 0.7.1 source | Implement `expand_message_xmd` (RFC 9380 §5.3.1) over `sha2`, then reduce 48 bytes mod r by Horner's rule in safe Rust. 48 field multiply-adds; no `unsafe`, no `blst` FFI |
| **The measured composed path will not exceed 15 ms.** Measured here: G1 scalar mult 68 µs, 10-term `multi_exp` 135 µs, 2-pairing with cached `G2Prepared` 331 µs. A real BBS+ present-and-verify projects to **~1.3 ms**, roughly 10× cheaper than the desk study's 18 ms | **Confirmed** by warm-loop measurement | **Acceptance test 1 is asserted against the desk-study profile**, which is deterministic arithmetic over published figures and reproduces anywhere. The measured profile is reported beside it and asserted only on machine-independent properties (composed total equals the sum of its halves; ratio to the Ed25519 baseline). Pinning a wall-clock threshold to measured time would be both host-dependent and, on this hardware, false. **This is a deliberate interpretation of acceptance test 1 and it is stated in the README and the paper, not buried** |
| **Cached pairing pre-computation saves far less than claimed.** Desk study: 4.2 ms → 1.1 ms, a 74% saving. Measured here: 410 µs → 331 µs, a **19%** saving, because `G2Prepared::from` costs 35 µs against a 331 µs multi-Miller-loop-plus-final-exponentiation | **Confirmed** by measurement | Report it. It is a finding: the desk study's optimization arithmetic is as unexamined as its composition arithmetic. It does not change the headline, because the pool (which removes group operations from the online path entirely) is what makes the construction fit, and that part holds |
| **Our BBS+ will not interoperate.** Byte-exact draft conformance needs the draft's test vectors, and validating against them is a separate piece of work | Known, accepted | The three-way real / real-but-not-interoperable / modelled split above. Stated in the README, in `bbs/mod.rs` module documentation, and in the paper's method section |
| **Modelled stubs mistaken for real** — the single biggest risk in this repo | Mitigated by design | Four independent barriers (see Global Constraints), each asserted by test in Task 3 and Task 12 |
| **Timing artifacts in `results/` cannot be diffed by CI** the way `parallax` diffs its manifests | Known | The `results/deterministic` / `results/measured` split in Global Constraints |

---

### Task 1: Repository skeleton and the cost model

**Files:**
- Create: `Cargo.toml`, `src/lib.rs`, `src/cost.rs`, `src/bin/occultation.rs`
- Create: `README.md`, `LICENSE`, `NOTICE`, `.gitignore`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: `occultation::cost::{Source, Measurement, BudgetVerdict, Composed, CostProfile, BUDGET, compose}`. `Measurement::new(label, cost, source)` is the only constructor. `CostProfile::desk_study()` returns the published P05 figures, each carrying its citation. `compose(present, verify) -> Composed` sums the two halves and judges the sum against `BUDGET`.

This task fixes the discipline the whole tool rests on: a number cannot exist without saying where it came from, and a budget verdict cannot be issued against half a path.

- [ ] **Step 1: Create the repo and manifest**

```bash
gh repo create Task-force-for-AI-agents-in-Healthcare/occultation --private --clone
cd occultation
cargo init --name occultation
```

Replace `Cargo.toml` with:

```toml
[package]
name = "occultation"
version = "0.1.0"
edition = "2021"
rust-version = "1.90"
license = "Apache-2.0"
description = "Measure what verifiable unlinkability costs at agent action rates"
repository = "https://github.com/Task-force-for-AI-agents-in-Healthcare/occultation"

[lib]
name = "occultation"
path = "src/lib.rs"

[[bin]]
name = "occultation"
path = "src/bin/occultation.rs"

[dependencies]
# BLS12-381. Pins ff/group 0.13, hence rand_core 0.6 below.
blstrs = "0.7"
group = "0.13"
ff = "0.13"
pairing = "0.23"
# ed25519-dalek 3.x needs rand_core 0.9 and will not compile alongside
# blstrs' rand_core 0.6. Pinned to 2.x deliberately; see README.
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand_core = "0.6"
rand_chacha = "0.3"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
clap = { version = "4", features = ["derive"] }
thiserror = "2"
anyhow = "1"
humantime = "2"
log = "0.4"
env_logger = "0.11"

[dev-dependencies]
criterion = "0.8"

[[bench]]
name = "primitives"
harness = false

[profile.release]
debug = true          # benchmarks are worth profiling
```

- [ ] **Step 2: Write the failing test**

Create `src/cost.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_measurement_always_carries_a_source() {
        let m = Measurement::new("x", ms(1), Source::MeasuredHere { iters: 100 });
        assert!(matches!(m.source, Source::MeasuredHere { iters: 100 }));
        let p = Measurement::new("y", ms(1), Source::Published { citation: "somewhere" });
        assert!(p.is_published(), "a published figure must announce itself");
    }

    #[test]
    fn a_published_figure_renders_the_word_published() {
        let p = Measurement::new(
            "BBS+ presentation",
            Duration::from_micros(13_800),
            Source::Published { citation: "desk study" },
        );
        let rendered = format!("{}", p.source);
        assert!(rendered.contains("PUBLISHED"), "got {rendered}");
        assert!(rendered.contains("desk study"), "the citation must survive");
    }

    /// The headline correction. The desk study assessed 13.8 ms and 4.2 ms
    /// separately against a 15 ms budget and called each acceptable. Summed,
    /// it misses by 3 ms.
    #[test]
    fn the_desk_study_naive_composition_misses_the_budget() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_naive.cost, p.verify_naive.cost);
        assert_eq!(c.total, Duration::from_micros(18_000));
        assert_eq!(c.verdict, BudgetVerdict::Misses { over: ms(3) });
    }

    /// Each half, taken alone, fits — which is exactly how the error was made.
    #[test]
    fn each_half_alone_fits_which_is_how_the_error_happened() {
        let p = CostProfile::desk_study();
        assert!(matches!(
            judge(p.present_naive.cost),
            BudgetVerdict::Fits { .. } | BudgetVerdict::Marginal { .. }
        ));
        assert!(matches!(judge(p.verify_naive.cost), BudgetVerdict::Fits { .. }));
    }

    /// With cached pairings the sum is 14.9 ms: under the limit with 100 µs
    /// left, which is not headroom. `Marginal` exists so the tool cannot
    /// report that as a pass.
    #[test]
    fn cached_pairings_alone_are_marginal_not_a_pass() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_naive.cost, p.verify_cached.cost);
        assert_eq!(c.total, Duration::from_micros(14_900));
        assert_eq!(c.verdict, BudgetVerdict::Marginal { headroom: Duration::from_micros(100) });
    }

    #[test]
    fn the_pool_plus_cached_pairings_fits_with_room() {
        let p = CostProfile::desk_study();
        let c = compose(p.present_pooled.cost, p.verify_cached.cost);
        assert_eq!(c.total, Duration::from_micros(3_900));
        assert_eq!(c.verdict, BudgetVerdict::Fits { headroom: Duration::from_micros(11_100) });
    }

    #[test]
    fn the_marginal_band_is_five_percent_of_the_budget() {
        // 750 µs headroom is the edge: inside is Marginal, outside is Fits.
        assert!(matches!(judge(BUDGET - Duration::from_micros(750)), BudgetVerdict::Marginal { .. }));
        assert!(matches!(judge(BUDGET - Duration::from_micros(751)), BudgetVerdict::Fits { .. }));
    }

    #[test]
    fn exactly_on_the_budget_is_marginal_not_a_miss() {
        assert_eq!(judge(BUDGET), BudgetVerdict::Marginal { headroom: Duration::ZERO });
    }

    #[test]
    fn every_desk_study_figure_is_published_not_measured() {
        let p = CostProfile::desk_study();
        for m in p.all() {
            assert!(m.is_published(), "{} claims to be measured here", m.label);
            assert!(!m.citation().unwrap().is_empty());
        }
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib cost`
Expected: FAIL — `cannot find type Measurement in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `src/cost.rs`:

```rust
use serde::Serialize;
use std::time::Duration;

/// The per-action latency budget from P05 and the desk study.
pub const BUDGET: Duration = Duration::from_millis(15);

/// Headroom below this fraction of the budget is reported as `Marginal`.
/// 5% of 15 ms is 750 µs. The desk study's cached-pairing composition leaves
/// 100 µs, and calling that a pass is the second half of its arithmetic error.
const MARGINAL_FRACTION: u32 = 20;

/// Where a number came from. Every `Measurement` carries one, because the
/// desk study's central failure was presenting figures from published
/// benchmarks of other people's hardware as if they characterised this stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Timed on this host, in this process, by `harness::measure`.
    MeasuredHere { iters: u32 },
    /// Read from a publication. Never measured here.
    Published { citation: &'static str },
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::MeasuredHere { iters } => write!(f, "measured here (n={iters})"),
            Source::Published { citation } => {
                write!(f, "PUBLISHED — {citation}; not measured on this stack")
            }
        }
    }
}

/// A cost, its label, and where it came from. There is no other constructor,
/// so a number cannot enter the tool anonymously.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Measurement {
    pub label: String,
    pub cost: Duration,
    pub source: Source,
}

impl Measurement {
    pub fn new(label: impl Into<String>, cost: Duration, source: Source) -> Self {
        Measurement { label: label.into(), cost, source }
    }

    pub fn is_published(&self) -> bool {
        matches!(self.source, Source::Published { .. })
    }

    pub fn citation(&self) -> Option<&'static str> {
        match self.source {
            Source::Published { citation } => Some(citation),
            Source::MeasuredHere { .. } => None,
        }
    }
}

/// The verdict on a latency against the budget.
///
/// `Marginal` is the variant that earns its keep. Without it, 14.9 ms against
/// a 15 ms budget reports as a pass, which is what the desk study concluded
/// and is the claim this tool exists to correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum BudgetVerdict {
    Misses { over: Duration },
    Marginal { headroom: Duration },
    Fits { headroom: Duration },
}

impl std::fmt::Display for BudgetVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetVerdict::Misses { over } => write!(f, "MISSES by {}", us(*over)),
            BudgetVerdict::Marginal { headroom } => {
                write!(f, "MARGINAL — {} of headroom, which is none", us(*headroom))
            }
            BudgetVerdict::Fits { headroom } => write!(f, "fits, {} spare", us(*headroom)),
        }
    }
}

pub fn us(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1e3)
}

pub fn judge(total: Duration) -> BudgetVerdict {
    if total > BUDGET {
        return BudgetVerdict::Misses { over: total - BUDGET };
    }
    let headroom = BUDGET - total;
    if headroom <= BUDGET / MARGINAL_FRACTION {
        BudgetVerdict::Marginal { headroom }
    } else {
        BudgetVerdict::Fits { headroom }
    }
}

/// A present-and-verify path judged as one path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Composed {
    pub present: Duration,
    pub verify: Duration,
    pub total: Duration,
    pub budget: Duration,
    pub verdict: BudgetVerdict,
}

/// Sum the two halves and judge the sum. The desk study judged the halves.
pub fn compose(present: Duration, verify: Duration) -> Composed {
    let total = present + verify;
    Composed { present, verify, total, budget: BUDGET, verdict: judge(total) }
}

const DESK: &str = "research/Accountable Unlinkable Agent Identity.md, \
                    \"Empirical Overhead and Execution Latency at Agent Action Rates\"";

/// A set of costs for one profile of the construction.
#[derive(Clone, Debug, Serialize)]
pub struct CostProfile {
    pub name: &'static str,
    pub ed25519_sign: Measurement,
    pub ed25519_verify: Measurement,
    pub present_naive: Measurement,
    pub present_pooled: Measurement,
    pub verify_naive: Measurement,
    pub verify_cached: Measurement,
}

impl CostProfile {
    /// The desk study's published figures, verbatim. Not measured here, and
    /// every entry says so. Reproducing this profile's arithmetic on any host
    /// is what makes the headline correction checkable by a third party.
    pub fn desk_study() -> Self {
        let p = |label: &str, micros: u64| {
            Measurement::new(label, Duration::from_micros(micros), Source::Published { citation: DESK })
        };
        CostProfile {
            name: "desk-study (published)",
            ed25519_sign: p("Ed25519 sign", 97),
            ed25519_verify: p("Ed25519 verify", 162),
            present_naive: p("BBS+ presentation", 13_800),
            present_pooled: p("BBS+ presentation, pre-computed pool", 2_800),
            verify_naive: p("BBS+ verification", 4_200),
            verify_cached: p("BBS+ verification, cached pairings", 1_100),
        }
    }

    pub fn all(&self) -> Vec<&Measurement> {
        vec![
            &self.ed25519_sign,
            &self.ed25519_verify,
            &self.present_naive,
            &self.present_pooled,
            &self.verify_naive,
            &self.verify_cached,
        ]
    }

    /// Sign plus verify, the like-for-like comparison against a composed
    /// BBS+ path.
    pub fn baseline_round_trip(&self) -> Duration {
        self.ed25519_sign.cost + self.ed25519_verify.cost
    }
}
```

Create `src/lib.rs`:

```rust
//! Measure what verifiable unlinkability costs at agent action rates.
//!
//! Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**.
//!
//! Read `README.md` before trusting any output of this crate: parts of it are
//! real cryptography, parts are real but not interoperable, and parts are
//! modelled and provide no security whatsoever.
#![forbid(unsafe_code)]

pub mod cost;

pub use cost::{compose, BudgetVerdict, Composed, CostProfile, Measurement, Source, BUDGET};
```

Create `src/bin/occultation.rs`:

```rust
fn main() -> anyhow::Result<()> {
    println!("occultation");
    Ok(())
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib cost`
Expected: PASS, 9 tests.

- [ ] **Step 6: Add CI and licences**

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test --all-targets
```

Fetch the Apache-2.0 text into `LICENSE`:

```bash
curl -sL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

Create `NOTICE`:

```
occultation
Copyright 2026 Advanced AI Society and the Proof-of-Control contributors

Licensed under the Apache License, Version 2.0. See LICENSE.

This product includes the paper in paper/, which is covered by the same
licence as the source.
```

Create `README.md`. The distinction leads; nothing precedes it but the one-line description.

```markdown
# occultation

Measures what verifiable unlinkability costs at agent action rates.

Supporting tool for **P05 — Accountable but Unlinkable Agent Identity**.

## What is real and what is modelled

Read this before trusting any number this tool prints.

### Modelled — no security whatsoever

**ECDAA** (`ModelledEcdaa`) and **threshold ElGamal escrow**
(`ModelledThresholdElGamal`) are stubs. They carry the correct interface and a
representative cost profile. They provide **no anonymity, no soundness, no
confidentiality, and no accountability.** They exist so that the cost of the
composed path can be estimated, and for nothing else. Using them for anything
that matters would be a serious mistake.

They require `--allow-modelled`. Without it the tool exits 3 and explains why.
With it, every invocation logs a warning and every number they produce is
printed with `MODELLED` beside it.

### Real but not interoperable

**BBS+** key generation, signing, verification, presentation and proof
verification are implemented over `blstrs` BLS12-381 against
`draft-irtf-cfrg-bbs-signatures`. This is genuine cryptography with genuine
security properties: forged signatures fail, tampered proofs fail, and
undisclosed attributes stay undisclosed. Each of those is asserted by test.

It is **not validated against the draft's test vectors**, so its wire encoding
will not interoperate with another BBS+ implementation. The cost profile is
what this tool is for; interoperability is not claimed.

### Real

The Ed25519 baseline, the BLS12-381 group and pairing arithmetic, the
pre-computation pool, the anonymity-set calculator, and the timing harness.

## Where the numbers come from

Every figure the tool prints is tagged. `measured here (n=…)` was timed on the
host that produced the output. `PUBLISHED — …` was read from a publication and
was **not** measured on this stack; the citation is printed with it. There is
no third state and no untagged number.

## Licence

Apache-2.0 throughout, code and paper alike. See `LICENSE` and `NOTICE`.
```

Create `.gitignore`:

```
/target
paper/*.pdf
paper/*.aux
paper/*.log
paper/*.out
paper/_minted*
```

- [ ] **Step 7: Verify the whole build is clean**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: no warnings, 9 tests pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add repo skeleton and the cost model

Every number carries a Source saying whether it was measured here or read
from a publication. BudgetVerdict has a Marginal band because 14.9 ms
against a 15 ms budget is not a pass, and reporting it as one is half of
the arithmetic error this tool exists to correct.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: The timing harness and the Ed25519 baseline

**Files:**
- Create: `src/harness.rs`, `src/baseline.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Source`, `Measurement` from Task 1.
- Produces: `harness::{Sample, measure}`. `measure(label, iters, f) -> Sample` where `Sample { label, iters, median, p95, p99, min, mean }` and `Sample::measurement() -> Measurement` tagged `Source::MeasuredHere`. `baseline::{Baseline, measure_baseline}` where `Baseline { sign: Sample, verify: Sample }` and `Baseline::round_trip() -> Duration` is `sign.median + verify.median`.

- [ ] **Step 1: Write the failing test**

Create `src/harness.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_reports_the_iteration_count_it_actually_ran() {
        let s = measure("noop", 50, || std::hint::black_box(1u64 + 1));
        assert_eq!(s.iters, 50);
        assert_eq!(s.label, "noop");
    }

    #[test]
    fn the_percentiles_are_ordered() {
        let s = measure("noop", 200, || std::hint::black_box(1u64 + 1));
        assert!(s.min <= s.median, "min {:?} > median {:?}", s.min, s.median);
        assert!(s.median <= s.p95);
        assert!(s.p95 <= s.p99);
    }

    #[test]
    fn a_measurable_cost_is_reported_as_nonzero() {
        // 2 ms of real sleeping, in four samples, cannot median to zero.
        let s = measure("sleep", 4, || std::thread::sleep(Duration::from_micros(500)));
        assert!(s.median >= Duration::from_micros(400), "got {:?}", s.median);
    }

    #[test]
    fn a_sample_converts_to_a_measured_here_measurement() {
        let s = measure("noop", 10, || std::hint::black_box(1u64 + 1));
        let m = s.measurement();
        assert!(!m.is_published(), "a timed sample is never a published figure");
        assert_eq!(m.cost, s.median, "the reported cost is the median");
        assert!(matches!(m.source, Source::MeasuredHere { iters: 10 }));
    }

    #[test]
    fn zero_iterations_is_an_error_not_a_divide_by_zero() {
        assert!(try_measure("noop", 0, || ()).is_err());
    }
}
```

Create `src/baseline.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baseline_signs_and_verifies_for_real() {
        let b = measure_baseline(7, 100);
        assert_eq!(b.sign.iters, 100);
        assert!(b.round_trip() > Duration::ZERO);
    }

    #[test]
    fn the_baseline_rejects_a_tampered_message() {
        // If this passed, the "baseline" would be timing a no-op and every
        // ratio in the tool would be nonsense.
        let (sk, vk) = baseline_keypair(7);
        let sig = sk.sign(b"agent action");
        assert!(vk.verify_strict(b"agent action", &sig).is_ok());
        assert!(vk.verify_strict(b"agent actiom", &sig).is_err());
    }

    #[test]
    fn the_same_seed_gives_the_same_key() {
        let (a, _) = baseline_keypair(7);
        let (b, _) = baseline_keypair(7);
        assert_eq!(a.to_bytes(), b.to_bytes(), "measurements must be rerunnable");
        let (c, _) = baseline_keypair(8);
        assert_ne!(a.to_bytes(), c.to_bytes());
    }

    #[test]
    fn verification_costs_more_than_signing() {
        // True of Ed25519 everywhere. If it inverts, the harness is measuring
        // the wrong closure.
        let b = measure_baseline(7, 500);
        assert!(b.verify.median > b.sign.median, "sign {:?} verify {:?}", b.sign.median, b.verify.median);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib harness baseline`
Expected: FAIL — `cannot find function measure in this scope`.

- [ ] **Step 3: Write the harness**

Prepend to `src/harness.rs`:

```rust
use crate::cost::{Measurement, Source};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("cannot measure `{label}` with {iters} iterations; need at least 1")]
    NoIterations { label: String, iters: u32 },
}

/// One timed closure: the distribution, not just a mean.
///
/// The median is the reported cost. A mean over a run that hit a scheduler
/// preemption is not the cost of the operation, and p99 is carried separately
/// so the pool's stall analysis has a tail to talk about.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub label: String,
    pub iters: u32,
    pub min: Duration,
    pub median: Duration,
    pub mean: Duration,
    pub p95: Duration,
    pub p99: Duration,
}

impl Sample {
    pub fn measurement(&self) -> Measurement {
        Measurement::new(self.label.clone(), self.median, Source::MeasuredHere { iters: self.iters })
    }
}

/// Warm up, then time `iters` individual invocations.
///
/// Panics only via `expect` on a programmer error (zero iterations); prefer
/// `try_measure` where the count comes from user input.
pub fn measure<T>(label: &str, iters: u32, f: impl FnMut() -> T) -> Sample {
    try_measure(label, iters, f).expect("iters > 0")
}

pub fn try_measure<T>(
    label: &str,
    iters: u32,
    mut f: impl FnMut() -> T,
) -> Result<Sample, HarnessError> {
    if iters == 0 {
        return Err(HarnessError::NoIterations { label: label.to_string(), iters });
    }

    // Warm up caches, branch predictors and any lazily initialised tables in
    // blst. Ten percent of the run, capped, and never zero.
    let warmup = (iters / 10).clamp(1, 50);
    for _ in 0..warmup {
        std::hint::black_box(f());
    }

    let mut times: Vec<Duration> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t = Instant::now();
        std::hint::black_box(f());
        times.push(t.elapsed());
    }
    times.sort_unstable();

    let pick = |q: f64| -> Duration {
        let i = ((times.len() as f64 - 1.0) * q).round() as usize;
        times[i]
    };
    let total: Duration = times.iter().sum();

    Ok(Sample {
        label: label.to_string(),
        iters,
        min: times[0],
        median: pick(0.50),
        mean: total / iters,
        p95: pick(0.95),
        p99: pick(0.99),
    })
}
```

- [ ] **Step 4: Write the baseline**

Prepend to `src/baseline.rs`:

```rust
use crate::harness::{measure, Sample};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::time::Duration;

/// The message every baseline measurement signs. Ed25519 hashes internally,
/// so the length barely matters; it is fixed so runs are comparable.
pub const BASELINE_MESSAGE: &[u8] = b"occultation baseline: one agent action";

/// A deterministic keypair. Seeded so a benchmark can be rerun to the same
/// numbers, which `thread_rng` would make impossible.
pub fn baseline_keypair(seed: u64) -> (SigningKey, VerifyingKey) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// What the standard assumes today: Ed25519 sign and verify.
#[derive(Clone, Debug, Serialize)]
pub struct Baseline {
    pub sign: Sample,
    pub verify: Sample,
}

impl Baseline {
    /// Sign plus verify — the like-for-like comparison against a composed
    /// present-and-verify path. Comparing a BBS+ round trip against Ed25519
    /// verification alone would flatter the anonymous scheme by a factor of
    /// two.
    pub fn round_trip(&self) -> Duration {
        self.sign.median + self.verify.median
    }
}

pub fn measure_baseline(seed: u64, iters: u32) -> Baseline {
    let (sk, vk) = baseline_keypair(seed);
    let sig = sk.sign(BASELINE_MESSAGE);
    Baseline {
        sign: measure("Ed25519 sign", iters, || sk.sign(BASELINE_MESSAGE)),
        verify: measure("Ed25519 verify", iters, || {
            vk.verify_strict(BASELINE_MESSAGE, &sig).expect("baseline signature verifies")
        }),
    }
}
```

Note for the implementer: `verify_strict` needs `use ed25519_dalek::Verifier` only for the non-strict `verify`; `verify_strict` is an inherent method on `VerifyingKey`. Add whichever import the compiler asks for and no more.

Update `src/lib.rs`:

```rust
pub mod baseline;
pub mod cost;
pub mod harness;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib harness baseline`
Expected: PASS, 9 tests.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the timing harness and the Ed25519 baseline

The harness reports a distribution rather than a mean, seeds its RNG so a
run can be reproduced, and tags every sample as measured-here. The
baseline test asserts a tampered message fails, because a baseline that
verifies nothing would make every ratio in the tool meaningless.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: The modelled boundary

**Files:**
- Create: `src/modelled.rs`, `src/ecdaa.rs`, `src/escrow.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Measurement`, `Source` from Task 1.
- Produces: `modelled::{Provenance, AttestationVerdict, ModelledPermit, ModelledError, MODELLED_WARNING, AnonymousAttestation, EscrowTag, Attestation, Tag}`. `ecdaa::ModelledEcdaa::new(ModelledPermit) -> Self`. `escrow::ModelledThresholdElGamal::new(ModelledPermit, k: usize, n: usize) -> Result<Self, ModelledError>`.

This is the task the whole repository's credibility rests on. A stub that could be mistaken for a working ECDAA or a working escrow is worse than no stub at all. Four independent barriers, each asserted by test:

1. **A permit is required to construct one.** `ModelledPermit` has a private unit field, so the only way to get one is `ModelledPermit::from_flag(true)`, and the only caller that passes `true` is the CLI when `--allow-modelled` is present.
2. **`AttestationVerdict::Valid` is unreachable from a modelled implementation.** It returns `ModelledNoSecurity`. A caller matching on the verdict cannot accidentally treat a stub's output as a passing check, because the passing variant never appears.
3. **Every invocation logs a warning.** Not once per process — every time.
4. **Every value carries its provenance,** and the report layer (Task 7) renders `MODELLED` beside anything whose provenance is modelled.

- [ ] **Step 1: Write the failing test**

Create `src/modelled.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permit_cannot_be_had_without_the_flag() {
        assert!(ModelledPermit::from_flag(false).is_err());
        assert!(ModelledPermit::from_flag(true).is_ok());
    }

    #[test]
    fn the_permit_error_says_what_to_do_and_why() {
        let e = ModelledPermit::from_flag(false).unwrap_err();
        let s = format!("{e}");
        assert!(s.contains("--allow-modelled"), "must name the flag: {s}");
        assert!(s.contains("no security"), "must say what is missing: {s}");
    }

    #[test]
    fn the_warning_text_is_unambiguous() {
        let w = MODELLED_WARNING;
        assert!(w.contains("MODELLED"));
        assert!(w.contains("no security"));
        assert!(!w.to_lowercase().contains("simulat"), "'simulated' reads as 'nearly real'");
    }

    #[test]
    fn modelled_provenance_renders_the_word_modelled() {
        let p = Provenance::Modelled { component: "ECDAA", reason: "not implemented" };
        assert!(format!("{p}").contains("MODELLED"));
    }

    #[test]
    fn real_provenance_does_not_render_the_word_modelled() {
        let p = Provenance::Real { component: "BBS+ proof verification" };
        assert!(!format!("{p}").contains("MODELLED"));
    }

    #[test]
    fn a_modelled_verdict_is_not_equal_to_a_valid_one() {
        assert_ne!(AttestationVerdict::ModelledNoSecurity, AttestationVerdict::Valid);
        assert!(!AttestationVerdict::ModelledNoSecurity.is_valid());
        assert!(!AttestationVerdict::Invalid.is_valid());
        assert!(AttestationVerdict::Valid.is_valid());
    }
}
```

Create `src/ecdaa.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modelled::{AnonymousAttestation, AttestationVerdict, ModelledPermit, Provenance};

    fn stub() -> ModelledEcdaa {
        ModelledEcdaa::new(ModelledPermit::from_flag(true).unwrap())
    }

    #[test]
    fn it_declares_itself_modelled() {
        assert!(ModelledEcdaa::MODELLED);
        assert!(matches!(stub().provenance(), Provenance::Modelled { .. }));
    }

    /// The load-bearing test. A modelled attestation must never produce the
    /// verdict a real one produces, whatever it is handed — including its own
    /// honestly-produced output.
    #[test]
    fn it_can_never_return_valid() {
        let s = stub();
        let a = s.attest(b"measurement").unwrap();
        assert_eq!(s.verify(b"measurement", &a), AttestationVerdict::ModelledNoSecurity);
        assert_eq!(s.verify(b"different", &a), AttestationVerdict::ModelledNoSecurity);
        let mut tampered = a.clone();
        tampered.bytes[0] ^= 0xff;
        assert_eq!(s.verify(b"measurement", &tampered), AttestationVerdict::ModelledNoSecurity);
    }

    #[test]
    fn the_attestation_it_produces_is_labelled_modelled() {
        let a = stub().attest(b"m").unwrap();
        assert!(matches!(a.provenance, Provenance::Modelled { .. }));
    }

    /// The cost profile has to be representative or the composed bench is
    /// fiction. The stub does group work of the same order ECDAA would, so
    /// its cost is a stand-in rather than a guess — but it is still a
    /// stand-in, which is why it is gated.
    #[test]
    fn it_costs_something_of_the_right_order() {
        let s = stub();
        let t = std::time::Instant::now();
        s.attest(b"m").unwrap();
        let d = t.elapsed();
        assert!(d >= std::time::Duration::from_micros(20), "too cheap to be representative: {d:?}");
        assert!(d < std::time::Duration::from_millis(50), "implausibly slow: {d:?}");
    }
}
```

Create `src/escrow.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modelled::{EscrowTag, ModelledPermit, Provenance};

    fn stub(k: usize, n: usize) -> Result<ModelledThresholdElGamal, crate::modelled::ModelledError> {
        ModelledThresholdElGamal::new(ModelledPermit::from_flag(true).unwrap(), k, n)
    }

    #[test]
    fn it_declares_itself_modelled() {
        assert!(ModelledThresholdElGamal::MODELLED);
        assert!(matches!(stub(3, 5).unwrap().provenance(), Provenance::Modelled { .. }));
    }

    #[test]
    fn a_threshold_larger_than_the_committee_is_rejected() {
        assert!(stub(6, 5).is_err(), "6-of-5 can never open");
        assert!(stub(0, 5).is_err(), "0-of-5 opens unilaterally");
        assert!(stub(5, 5).is_ok());
    }

    /// The tag encrypts nothing. Asserting that the identity is *recoverable
    /// from the tag alone* is how the test pins "no confidentiality" rather
    /// than letting a reader assume the stub is doing ElGamal.
    #[test]
    fn the_tag_hides_nothing_and_the_test_says_so() {
        let s = stub(3, 5).unwrap();
        let tag = s.tag(b"did:web:agent-42").unwrap();
        assert!(
            tag.bytes.windows(16).any(|w| w == b"did:web:agent-42"),
            "the modelled tag carries the identity in the clear, on purpose"
        );
    }

    #[test]
    fn opening_below_the_threshold_still_returns_a_modelled_marker() {
        let s = stub(3, 5).unwrap();
        let tag = s.tag(b"did:web:agent-42").unwrap();
        // A real escrow would refuse. The stub refuses too — but its success
        // path is a marker, not an identity, so nothing downstream can treat
        // a modelled opening as an accountable one.
        assert!(s.open(&tag, 2).is_err(), "2 shares is below 3-of-5");
        let opened = s.open(&tag, 3).unwrap();
        assert!(opened.contains("MODELLED"), "got {opened}");
    }

    #[test]
    fn the_tag_is_labelled_modelled() {
        let tag = stub(3, 5).unwrap().tag(b"x").unwrap();
        assert!(matches!(tag.provenance, Provenance::Modelled { .. }));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib modelled ecdaa escrow`
Expected: FAIL — `cannot find type ModelledPermit in this scope`.

- [ ] **Step 3: Write the boundary**

Prepend to `src/modelled.rs`:

```rust
use serde::Serialize;

/// Printed by the binary before any modelled code runs, and logged by every
/// modelled invocation.
pub const MODELLED_WARNING: &str = "\
WARNING: MODELLED COMPONENT IN USE. ECDAA and threshold ElGamal escrow are
stubs. They provide no anonymity, no soundness, no confidentiality and no
accountability. Their cost profile is representative; nothing else about them
is. Any result depending on them is an estimate of cost, not evidence of
security.";

#[derive(Debug, thiserror::Error)]
pub enum ModelledError {
    #[error(
        "this path runs a modelled component, which provides no security; \
         pass --allow-modelled to run it anyway"
    )]
    PermitRequired,
    #[error("a {k}-of-{n} committee is not openable ({reason})")]
    BadThreshold { k: usize, n: usize, reason: &'static str },
}

/// Whether a value came from real cryptography or from a stub.
///
/// Carried on every value that crosses the boundary, so the report layer can
/// label it without knowing which implementation produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Real { component: &'static str },
    Modelled { component: &'static str, reason: &'static str },
}

impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provenance::Real { component } => write!(f, "{component}"),
            Provenance::Modelled { component, reason } => {
                write!(f, "{component} [MODELLED — no security: {reason}]")
            }
        }
    }
}

/// Proof that the operator explicitly asked to run code that provides no
/// security.
///
/// The unit field is private, so `from_flag` is the only way to obtain one and
/// a modelled constructor is the only thing that consumes one. The gate cannot
/// be bypassed by a caller forgetting to check a boolean, because there is no
/// boolean to forget.
#[derive(Clone, Copy, Debug)]
pub struct ModelledPermit(());

impl ModelledPermit {
    pub fn from_flag(allow_modelled: bool) -> Result<Self, ModelledError> {
        if allow_modelled {
            Ok(ModelledPermit(()))
        } else {
            Err(ModelledError::PermitRequired)
        }
    }
}

/// The result of checking an attestation.
///
/// `Valid` is deliberately unreachable from any modelled implementation. A
/// caller writing `if verdict.is_valid()` gets `false` from a stub, and a
/// caller matching exhaustively is forced to handle `ModelledNoSecurity`
/// explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    Invalid,
    ModelledNoSecurity,
}

impl AttestationVerdict {
    pub fn is_valid(self) -> bool {
        matches!(self, AttestationVerdict::Valid)
    }
}

/// An anonymous platform attestation.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub bytes: Vec<u8>,
    pub provenance: Provenance,
}

/// An escrow tag binding an action to a recoverable identity.
#[derive(Clone, Debug)]
pub struct Tag {
    pub bytes: Vec<u8>,
    pub provenance: Provenance,
}

/// Prove membership in a valid TEE group without emitting a platform
/// identifier. P05's hardware attestation layer; ECDAA in the construction.
///
/// The only implementation in this crate is modelled.
pub trait AnonymousAttestation {
    /// Whether this implementation provides security. Checked by test for
    /// every implementation in the crate.
    const MODELLED: bool;

    fn provenance(&self) -> Provenance;
    fn attest(&self, measurement: &[u8]) -> Result<Attestation, ModelledError>;
    fn verify(&self, measurement: &[u8], attestation: &Attestation) -> AttestationVerdict;
}

/// Bind an action to an identity recoverable only by a k-of-n quorum.
/// P05's accountability layer; threshold ElGamal in the construction.
///
/// The only implementation in this crate is modelled.
pub trait EscrowTag {
    const MODELLED: bool;

    fn provenance(&self) -> Provenance;
    fn tag(&self, identity: &[u8]) -> Result<Tag, ModelledError>;
    /// Recover the identity given `shares` cooperating nodes.
    fn open(&self, tag: &Tag, shares: usize) -> Result<String, ModelledError>;
}
```

- [ ] **Step 4: Write the ECDAA stub**

Prepend to `src/ecdaa.rs`:

```rust
use crate::modelled::{
    AnonymousAttestation, Attestation, AttestationVerdict, ModelledError, ModelledPermit,
    Provenance, MODELLED_WARNING,
};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

const WHY: &str = "ECDAA is not implemented; this is a cost stand-in";

/// A stand-in for ECDAA. **Provides no security whatsoever.**
///
/// It performs three G1 scalar multiplications and a hash, which is the shape
/// and roughly the cost of an ECDAA join-and-sign, so the composed cost
/// estimate is not a guess. It does not prove group membership, does not hide
/// a platform identifier, and its `verify` accepts nothing — it cannot return
/// `Valid`.
///
/// Constructing one requires a `ModelledPermit`, which only `--allow-modelled`
/// produces.
pub struct ModelledEcdaa {
    _permit: ModelledPermit,
}

impl ModelledEcdaa {
    pub fn new(permit: ModelledPermit) -> Self {
        ModelledEcdaa { _permit: permit }
    }
}

impl AnonymousAttestation for ModelledEcdaa {
    const MODELLED: bool = true;

    fn provenance(&self) -> Provenance {
        Provenance::Modelled { component: "ECDAA", reason: WHY }
    }

    fn attest(&self, measurement: &[u8]) -> Result<Attestation, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        // Representative work: the group operations an ECDAA signature would
        // perform. The output is not a proof of anything.
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from_le_bytes(
            Sha256::digest(measurement)[..8].try_into().expect("8 bytes"),
        ));
        let mut acc = G1Projective::identity();
        for _ in 0..3 {
            acc += G1Projective::generator() * Scalar::random(&mut rng);
        }
        let mut bytes = acc.to_compressed().to_vec();
        bytes.extend_from_slice(&Sha256::digest(measurement));
        Ok(Attestation { bytes, provenance: self.provenance() })
    }

    fn verify(&self, _measurement: &[u8], _attestation: &Attestation) -> AttestationVerdict {
        log::warn!("{MODELLED_WARNING}");
        // There is no check to perform. Returning `Valid` here — for any
        // input, including well-formed output of `attest` — would make a stub
        // indistinguishable from a working ECDAA verifier at the call site.
        AttestationVerdict::ModelledNoSecurity
    }
}
```

- [ ] **Step 5: Write the escrow stub**

Prepend to `src/escrow.rs`:

```rust
use crate::modelled::{
    EscrowTag, ModelledError, ModelledPermit, Provenance, Tag, MODELLED_WARNING,
};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const WHY: &str = "threshold ElGamal and DLEQ are not implemented; \
                   the tag carries the identity in the clear";

/// A stand-in for k-of-n threshold ElGamal escrow with DLEQ proofs of correct
/// opening. **Provides no security whatsoever.**
///
/// The tag **contains the identity in plaintext**. That is deliberate: a stub
/// that appeared to encrypt would invite someone to trust it. It performs the
/// group operations a real tag construction plus DLEQ proof would, so its cost
/// is representative, and nothing else about it is.
///
/// Constructing one requires a `ModelledPermit`.
pub struct ModelledThresholdElGamal {
    _permit: ModelledPermit,
    k: usize,
    n: usize,
}

impl ModelledThresholdElGamal {
    pub fn new(permit: ModelledPermit, k: usize, n: usize) -> Result<Self, ModelledError> {
        if k == 0 {
            return Err(ModelledError::BadThreshold { k, n, reason: "any single node could open" });
        }
        if k > n {
            return Err(ModelledError::BadThreshold { k, n, reason: "more shares than nodes" });
        }
        Ok(ModelledThresholdElGamal { _permit: permit, k, n })
    }

    pub fn threshold(&self) -> (usize, usize) {
        (self.k, self.n)
    }
}

impl EscrowTag for ModelledThresholdElGamal {
    const MODELLED: bool = true;

    fn provenance(&self) -> Provenance {
        Provenance::Modelled { component: "threshold ElGamal escrow", reason: WHY }
    }

    fn tag(&self, identity: &[u8]) -> Result<Tag, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        // Representative work: a real tag is two G1 elements plus a DLEQ proof,
        // which is four scalar multiplications and change.
        let mut rng = ChaCha20Rng::seed_from_u64(0xE5C0);
        let mut acc = G1Projective::identity();
        for _ in 0..4 {
            acc += G1Projective::generator() * Scalar::random(&mut rng);
        }
        let mut bytes = b"MODELLED-ESCROW-TAG:".to_vec();
        bytes.extend_from_slice(identity); // in the clear, on purpose
        bytes.extend_from_slice(&acc.to_compressed());
        Ok(Tag { bytes, provenance: self.provenance() })
    }

    fn open(&self, tag: &Tag, shares: usize) -> Result<String, ModelledError> {
        log::warn!("{MODELLED_WARNING}");
        if shares < self.k {
            return Err(ModelledError::BadThreshold {
                k: self.k,
                n: self.n,
                reason: "fewer cooperating shares than the threshold",
            });
        }
        let _ = tag;
        // Not the identity. A caller that treats this as an accountable
        // opening gets a string that says it is not one.
        Ok(format!(
            "MODELLED opening ({}-of-{}): no identity was recovered, because nothing was escrowed",
            self.k, self.n
        ))
    }
}
```

- [ ] **Step 6: Wire the modules and run**

Update `src/lib.rs`:

```rust
pub mod baseline;
pub mod cost;
pub mod ecdaa;
pub mod escrow;
pub mod harness;
pub mod modelled;
```

Run: `cargo test --lib modelled ecdaa escrow`
Expected: PASS, 15 tests.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the modelled boundary for ECDAA and threshold escrow

Four independent barriers against a stub being mistaken for the real
thing: a permit is required to construct one, AttestationVerdict::Valid is
unreachable from a modelled implementation, every invocation logs a
warning, and every value carries its provenance. The escrow tag carries
the identity in plaintext on purpose — a stub that appeared to encrypt
would invite someone to trust it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: BLS12-381 primitives — hashing, generators, prepared pairings

**Files:**
- Create: `src/bls.rs`
- Modify: `src/lib.rs`, `Cargo.toml`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces: `bls::{BlsError, expand_message_xmd, hash_to_scalar, octets, create_generators, Generators, PreparedIssuer, API_ID, neg_p2}`. `Generators { p1: G1Projective, q1: G1Projective, h: Vec<G1Projective> }` with `Generators::create(count: usize) -> Generators` and `Generators::b(&self, domain: Scalar, msgs: &[Scalar]) -> Result<G1Projective, BlsError>`. `PreparedIssuer::new(pk: &G2Projective) -> PreparedIssuer` holding `G2Prepared` for `W` and for `-P2`, which is the cached-pairing pre-computation the desk study describes.

`blstrs` has no `hash_to_scalar` and no wide reduction, so both are built here. The `expand_message_xmd` test vectors below are taken from the CFRG hash-to-curve working group's own vector file and **have been executed against this exact implementation** — they pass. Do not paraphrase them; if a value here disagrees with RFC 9380 Appendix K.1, the RFC wins and the plan is wrong.

- [ ] **Step 1: Add the dev-dependency**

Add to `Cargo.toml`:

```toml
[dev-dependencies]
criterion = "0.8"
hex = "0.4"
```

- [ ] **Step 2: Write the failing test**

Create `src/bls.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9380 Appendix K.1 — expand_message_xmd(SHA-256), 128-bit security.
    /// Verify these against the RFC before trusting them; the RFC is
    /// authoritative and this plan is not.
    const RFC9380_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    #[test]
    fn expand_message_xmd_matches_rfc9380_appendix_k1() {
        let cases: [(&[u8], usize, &str); 6] = [
            (b"", 0x20, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
            (b"abc", 0x20, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
            (b"abcdef0123456789", 0x20,
             "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
            (b"", 0x80,
             "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d1215877\
              13a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658\
              e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4\
              286b004ceb5ee6b9a7fa5b646c993f0ced"),
            (b"abc", 0x80,
             "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163\
              d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7\
              ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec\
              65e8afc50303a22c0f99b0509b4c895f40"),
            (b"abcdef0123456789", 0x80,
             "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635c\
              d1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef6\
              53cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2\
              c9d9eb20c7e3f6edc5a60629178d9478df"),
        ];
        for (msg, len, want) in cases {
            // The literals above are line-wrapped with `\` continuations, so
            // strip whitespace before comparing.
            let want: String = want.chars().filter(|c| !c.is_whitespace()).collect();
            let got = hex::encode(expand_message_xmd(msg, RFC9380_DST, len).unwrap());
            assert_eq!(got, want, "msg={:?} len={len}", String::from_utf8_lossy(msg));
        }
    }

    #[test]
    fn expand_message_xmd_rejects_impossible_lengths() {
        assert!(expand_message_xmd(b"m", &[0u8; 256], 32).is_err(), "DST over 255 bytes");
        assert!(expand_message_xmd(b"m", RFC9380_DST, 65_536).is_err(), "output over 65535");
        assert!(expand_message_xmd(b"m", RFC9380_DST, 0).is_ok(), "zero length is legal");
    }

    #[test]
    fn hash_to_scalar_is_deterministic_and_nonzero() {
        let a = hash_to_scalar(b"message", b"DST").unwrap();
        let b = hash_to_scalar(b"message", b"DST").unwrap();
        let c = hash_to_scalar(b"message", b"OTHER-DST").unwrap();
        let d = hash_to_scalar(b"other", b"DST").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "the DST must separate domains");
        assert_ne!(a, d);
        assert_ne!(a, Scalar::ZERO);
    }

    #[test]
    fn reducing_a_small_canonical_value_agrees_with_from_bytes_be() {
        // 32 zero bytes ending in 5 is 5, well below r, so the Horner
        // reduction and blstrs' canonical decoder must agree exactly.
        let mut be = [0u8; 32];
        be[31] = 5;
        assert_eq!(reduce_be_bytes(&be), Scalar::from_bytes_be(&be).unwrap());
        assert_eq!(reduce_be_bytes(&be), Scalar::from(5u64));
    }

    #[test]
    fn reducing_an_oversized_value_wraps_rather_than_failing() {
        // 48 bytes of 0xff is far above r. Canonical decoding cannot express
        // it; Horner reduction must, because that is the whole point.
        let big = [0xffu8; 48];
        let s = reduce_be_bytes(&big);
        assert_ne!(s, Scalar::ZERO);
        // Reducing a value and reducing it with leading zeros prepended must
        // give the same field element.
        let mut padded = vec![0u8; 16];
        padded.extend_from_slice(&big);
        assert_eq!(reduce_be_bytes(&padded), s);
    }

    #[test]
    fn octets_is_unambiguous_across_different_splits() {
        // Without length prefixes, ("ab","c") and ("a","bc") would collide,
        // and a challenge hash over a colliding encoding is not binding.
        assert_ne!(octets(&[b"ab", b"c"]), octets(&[b"a", b"bc"]));
        assert_eq!(octets(&[b"ab", b"c"]), octets(&[b"ab", b"c"]));
    }

    #[test]
    fn generators_are_distinct_deterministic_and_not_the_identity() {
        let g = Generators::create(5);
        assert_eq!(g.h.len(), 5);
        let again = Generators::create(5);
        assert_eq!(g.p1, again.p1, "generators must be reproducible");
        assert_eq!(g.h, again.h);

        let mut all = vec![g.p1, g.q1];
        all.extend(g.h.iter().copied());
        for (i, x) in all.iter().enumerate() {
            assert!(bool::from(!x.is_identity()), "generator {i} is the identity");
            for (j, y) in all.iter().enumerate().skip(i + 1) {
                assert_ne!(x, y, "generators {i} and {j} collide");
            }
        }
    }

    #[test]
    fn generators_of_different_counts_share_a_prefix() {
        // H_0 must not change when the credential gains an attribute, or a
        // signature over 3 messages could not be verified by code built for 5.
        let three = Generators::create(3);
        let five = Generators::create(5);
        assert_eq!(three.p1, five.p1);
        assert_eq!(three.q1, five.q1);
        assert_eq!(three.h[..], five.h[..3]);
    }

    #[test]
    fn b_rejects_the_wrong_number_of_messages() {
        let g = Generators::create(3);
        let d = Scalar::from(7u64);
        assert!(g.b(d, &[Scalar::from(1u64); 3]).is_ok());
        assert!(g.b(d, &[Scalar::from(1u64); 2]).is_err(), "too few messages");
        assert!(g.b(d, &[Scalar::from(1u64); 4]).is_err(), "too many messages");
    }

    #[test]
    fn a_prepared_issuer_gives_the_same_pairing_as_an_unprepared_one() {
        // The cached-pairing optimization must not change the answer. If it
        // did, `bench --composed` would be comparing two different functions.
        use pairing::{MillerLoopResult, MultiMillerLoop};
        let x = Scalar::from(42u64);
        let w = G2Projective::generator() * x;
        let a = G1Projective::generator() * Scalar::from(9u64);
        let prepared = PreparedIssuer::new(&w);

        let cached = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &prepared.w),
            (&a.to_affine(), &prepared.neg_p2),
        ])
        .final_exponentiation();

        let fresh = Bls12::multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(w.to_affine())),
            (&a.to_affine(), &G2Prepared::from(neg_p2().to_affine())),
        ])
        .final_exponentiation();

        assert_eq!(cached, fresh);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib bls`
Expected: FAIL — `cannot find function expand_message_xmd in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `src/bls.rs`:

```rust
use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use sha2::{Digest, Sha256};

/// Ciphersuite identifier. Structurally in the shape the BBS draft uses, but
/// this implementation is **not** validated against the draft's test vectors
/// and will not interoperate. See the README.
pub const API_ID: &[u8] = b"OCCULTATION_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    #[error("domain separation tag is {0} bytes; RFC 9380 allows at most 255")]
    DstTooLong(usize),
    #[error("cannot expand to {0} bytes; RFC 9380 allows at most 65535")]
    ExpandTooLong(usize),
    #[error("expected {expected} messages, got {got}")]
    MessageCount { expected: usize, got: usize },
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256.
///
/// Present because `blstrs` exposes hash-to-curve but not the expander, and
/// BBS+ needs the expander to derive scalars.
pub fn expand_message_xmd(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Vec<u8>, BlsError> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const S_IN_BYTES: usize = 64; // SHA-256 block

    if dst.len() > 255 {
        return Err(BlsError::DstTooLong(dst.len()));
    }
    if len_in_bytes > 65_535 {
        return Err(BlsError::ExpandTooLong(len_in_bytes));
    }
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    if ell > 255 {
        return Err(BlsError::ExpandTooLong(len_in_bytes));
    }

    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut h = Sha256::new();
    h.update([0u8; S_IN_BYTES]); // Z_pad
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes()); // l_i_b_str
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_i = h.finalize();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_i);
    for i in 2..=ell {
        let mut strxor = [0u8; B_IN_BYTES];
        for (k, s) in strxor.iter_mut().enumerate() {
            *s = b_0[k] ^ b_i[k];
        }
        let mut h = Sha256::new();
        h.update(strxor);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_i = h.finalize();
        out.extend_from_slice(&b_i);
    }
    out.truncate(len_in_bytes);
    Ok(out)
}

/// Reduce a big-endian byte string mod r by Horner's rule.
///
/// `blstrs` exposes no wide reduction — `Scalar::from_bytes_be` rejects
/// anything non-canonical — and this crate forbids `unsafe`, so raw `blst`
/// FFI is out. Forty-eight field multiply-adds cost tens of nanoseconds and
/// are exactly correct.
pub fn reduce_be_bytes(bytes: &[u8]) -> Scalar {
    let radix = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for b in bytes {
        acc = acc * radix + Scalar::from(*b as u64);
    }
    acc
}

/// Hash a message to a scalar. 48 bytes of expansion gives a reduction bias
/// below 2^-128, which is the margin the BBS draft asks for.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Scalar, BlsError> {
    Ok(reduce_be_bytes(&expand_message_xmd(msg, dst, 48)?))
}

/// Length-prefixed concatenation.
///
/// Plain concatenation would let two different inputs produce the same bytes,
/// and a Fiat-Shamir challenge over an ambiguous encoding is not binding.
pub fn octets(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// The public generators a credential is signed under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generators {
    /// The base point.
    pub p1: G1Projective,
    /// The domain generator.
    pub q1: G1Projective,
    /// One per message.
    pub h: Vec<G1Projective>,
}

impl Generators {
    /// Deterministic, and stable under a change of `count`: `h[0]` is the same
    /// point whether you asked for three generators or five. Otherwise adding
    /// an attribute to a credential would invalidate every signature that
    /// existed before it.
    pub fn create(count: usize) -> Self {
        let dst = [API_ID, b"SIG_GENERATOR_DST_"].concat();
        let at = |label: &[u8]| G1Projective::hash_to_curve(label, &dst, &[]);
        Generators {
            p1: at(b"BP"),
            q1: at(b"Q1"),
            h: (0..count).map(|i| at(&octets(&[b"H", &(i as u64).to_be_bytes()]))).collect(),
        }
    }

    /// `B = P1 + Q1*domain + sum(H_i * m_i)`, the commitment a signature is
    /// taken over. One multi-exponentiation rather than a loop of scalar
    /// multiplications, because this is on the measured path.
    pub fn b(&self, domain: Scalar, msgs: &[Scalar]) -> Result<G1Projective, BlsError> {
        if msgs.len() != self.h.len() {
            return Err(BlsError::MessageCount { expected: self.h.len(), got: msgs.len() });
        }
        let mut points = Vec::with_capacity(msgs.len() + 2);
        let mut scalars = Vec::with_capacity(msgs.len() + 2);
        points.push(self.p1);
        scalars.push(Scalar::ONE);
        points.push(self.q1);
        scalars.push(domain);
        points.extend(self.h.iter().copied());
        scalars.extend(msgs.iter().copied());
        Ok(G1Projective::multi_exp(&points, &scalars))
    }

    pub fn len(&self) -> usize {
        self.h.len()
    }

    pub fn is_empty(&self) -> bool {
        self.h.is_empty()
    }
}

/// `-P2`, the negated G2 generator, used on the right of every pairing check.
pub fn neg_p2() -> G2Projective {
    -G2Projective::generator()
}

/// A relying party's cached pairing pre-computation for one registered issuer.
///
/// This is the optimization the desk study calls "cached pairing
/// pre-computations": both G2 inputs to proof verification are fixed per
/// issuer, so the Miller loop's line-function coefficients can be computed
/// once. Note that it applies to **proof verification** and not to signature
/// verification, whose second G2 input is `W + P2*e` and therefore depends on
/// the signature.
pub struct PreparedIssuer {
    pub w: G2Prepared,
    pub neg_p2: G2Prepared,
}

impl PreparedIssuer {
    pub fn new(pk: &G2Projective) -> Self {
        PreparedIssuer {
            w: G2Prepared::from(pk.to_affine()),
            neg_p2: G2Prepared::from(neg_p2().to_affine()),
        }
    }
}

/// Re-exported so callers do not have to depend on `pairing` directly.
pub type Engine = Bls12;
```

Update `src/lib.rs` to add `pub mod bls;`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib bls`
Expected: PASS, 9 tests. In particular `expand_message_xmd_matches_rfc9380_appendix_k1` must pass on all six vectors; if it does not, the bug is in the implementation, not the vectors.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add BLS12-381 hashing, generators and prepared pairings

expand_message_xmd is checked against all six RFC 9380 Appendix K.1
vectors. blstrs has no wide scalar reduction and this crate forbids
unsafe, so hash-to-scalar reduces by Horner's rule in the field.
PreparedIssuer is the cached pairing pre-computation, and it applies to
proof verification rather than signature verification because only the
former's G2 inputs are fixed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: BBS+ keys, signing and verification

**Files:**
- Create: `src/bbs/mod.rs`, `src/bbs/keys.rs`, `src/bbs/sign.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Generators`, `hash_to_scalar`, `octets`, `neg_p2`, `API_ID`, `BlsError` (Task 4).
- Produces: `bbs::{BbsError, SecretKey, PublicKey, KeyPair, Signature, message_to_scalar, calculate_domain, sign, verify}`. `KeyPair::generate(seed: u64) -> KeyPair` with `.sk: SecretKey`, `.pk: PublicKey`. `sign(&SecretKey, &PublicKey, &Generators, header: &[u8], msgs: &[Scalar]) -> Result<Signature, BbsError>`. `verify(&PublicKey, &Generators, header: &[u8], msgs: &[Scalar], &Signature) -> Result<bool, BbsError>`.

Real cryptography. The negative tests are the point: a scheme whose `verify` returns `true` unconditionally would produce exactly the same benchmark numbers as a correct one, so the tests have to prove the arithmetic binds.

- [ ] **Step 1: Write the failing test**

Create `src/bbs/sign.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bls::Generators;

    const HEADER: &[u8] = b"occultation test header";

    fn fixture(n: usize) -> (KeyPair, Generators, Vec<Scalar>) {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(n);
        let msgs: Vec<Scalar> = (0..n)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        (kp, gens, msgs)
    }

    #[test]
    fn a_signature_verifies() {
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tampered_message_fails() {
        let (kp, gens, mut msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        msgs[2] += Scalar::ONE;
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tampered_header_fails() {
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(!verify(&kp.pk, &gens, b"a different header", &msgs, &sig).unwrap());
    }

    #[test]
    fn another_issuers_key_fails() {
        let (kp, gens, msgs) = fixture(5);
        let other = KeyPair::generate(8);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert!(!verify(&other.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_forged_signature_element_fails() {
        let (kp, gens, msgs) = fixture(5);
        let mut sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        sig.a += G1Projective::generator();
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn a_tweaked_e_fails() {
        let (kp, gens, msgs) = fixture(5);
        let mut sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        sig.e += Scalar::ONE;
        assert!(!verify(&kp.pk, &gens, HEADER, &msgs, &sig).unwrap());
    }

    #[test]
    fn signing_the_wrong_number_of_messages_is_an_error() {
        let (kp, gens, msgs) = fixture(5);
        assert!(sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs[..3]).is_err());
    }

    #[test]
    fn the_domain_binds_the_generator_count() {
        // A signature over 5 messages must not verify against generators built
        // for a different length, even on the same first five messages.
        let (kp, gens, msgs) = fixture(5);
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        let wider = Generators::create(6);
        let mut wider_msgs = msgs.clone();
        wider_msgs.push(Scalar::ZERO);
        assert!(!verify(&kp.pk, &wider, HEADER, &wider_msgs, &sig).unwrap());
    }

    #[test]
    fn signing_is_deterministic_for_the_same_inputs() {
        let (kp, gens, msgs) = fixture(3);
        let a = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        let b = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        assert_eq!(a.e, b.e);
        assert_eq!(a.a, b.a);
    }
}
```

Create `src/bbs/keys.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_a_keypair() {
        assert_eq!(KeyPair::generate(7).pk.0, KeyPair::generate(7).pk.0);
        assert_ne!(KeyPair::generate(7).pk.0, KeyPair::generate(8).pk.0);
    }

    #[test]
    fn the_public_key_is_the_secret_key_times_the_generator() {
        let kp = KeyPair::generate(7);
        assert_eq!(kp.pk.0, G2Projective::generator() * kp.sk.0);
    }

    #[test]
    fn the_secret_key_is_never_zero() {
        for seed in 0..32u64 {
            assert_ne!(KeyPair::generate(seed).sk.0, Scalar::ZERO);
        }
    }

    #[test]
    fn a_public_key_serializes_to_ninety_six_bytes() {
        assert_eq!(KeyPair::generate(7).pk.to_bytes().len(), 96);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib bbs`
Expected: FAIL — `cannot find type KeyPair in this scope`.

- [ ] **Step 3: Write the keys**

Prepend to `src/bbs/keys.rs`:

```rust
use blstrs::{G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// An issuer's signing key.
#[derive(Clone, Debug)]
pub struct SecretKey(pub Scalar);

/// An issuer's public key, `W = P2 * x`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_affine().to_compressed().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl KeyPair {
    /// Deterministic from a seed, so every measurement is rerunnable.
    ///
    /// A zero secret key would make the public key the identity and every
    /// signature unforgeable-by-anyone rather than by-nobody, so resample.
    /// The loop runs once with overwhelming probability.
    pub fn generate(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let x = loop {
            let candidate = Scalar::random(&mut rng);
            if candidate != Scalar::ZERO {
                break candidate;
            }
        };
        KeyPair { sk: SecretKey(x), pk: PublicKey(G2Projective::generator() * x) }
    }
}
```

- [ ] **Step 4: Write signing and verification**

Prepend to `src/bbs/sign.rs`:

```rust
use crate::bbs::keys::{PublicKey, SecretKey};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, octets, Generators, API_ID};
use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};

/// A BBS+ signature: one G1 element and one scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub a: G1Projective,
    pub e: Scalar,
}

fn h2s_dst() -> Vec<u8> {
    [API_ID, b"H2S_"].concat()
}

/// Map an attribute's bytes into the scalar field.
pub fn message_to_scalar(msg: &[u8]) -> Result<Scalar, BbsError> {
    Ok(hash_to_scalar(msg, &[API_ID, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat())?)
}

/// Bind the public key, the generator set and the header into one scalar, so a
/// signature cannot be replayed under a different credential shape.
pub fn calculate_domain(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
) -> Result<Scalar, BbsError> {
    let mut parts: Vec<Vec<u8>> = vec![
        pk.to_bytes(),
        (gens.len() as u64).to_be_bytes().to_vec(),
        gens.p1.to_affine().to_compressed().to_vec(),
        gens.q1.to_affine().to_compressed().to_vec(),
    ];
    for h in &gens.h {
        parts.push(h.to_affine().to_compressed().to_vec());
    }
    parts.push(API_ID.to_vec());
    parts.push(header.to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(hash_to_scalar(&octets(&refs), &[API_ID, b"H2S_DOMAIN_"].concat())?)
}

/// Sign `msgs` under `sk`.
///
/// `e` is derived deterministically from the key, the messages and the domain,
/// as the draft does. Determinism matters here beyond hygiene: a measurement
/// that changes its inputs between runs is not reproducible.
pub fn sign(
    sk: &SecretKey,
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    msgs: &[Scalar],
) -> Result<Signature, BbsError> {
    let domain = calculate_domain(pk, gens, header)?;

    let mut parts: Vec<Vec<u8>> = vec![sk.0.to_bytes_be().to_vec()];
    for m in msgs {
        parts.push(m.to_bytes_be().to_vec());
    }
    parts.push(domain.to_bytes_be().to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let e = hash_to_scalar(&octets(&refs), &h2s_dst())?;

    let b = gens.b(domain, msgs)?;
    // A = B * 1/(x + e). `x + e == 0` has negligible probability but is not
    // impossible, and unwrapping a CtOption on it would be a panic on input.
    let denom = sk.0 + e;
    let inv = Option::<Scalar>::from(denom.invert()).ok_or(BbsError::DegenerateKey)?;
    Ok(Signature { a: b * inv, e })
}

/// `e(A, W + P2*e) * e(B, -P2) == 1`.
///
/// Note what is *not* cacheable here: the second G2 input is `W + P2*e`, which
/// depends on the signature, so a per-issuer `G2Prepared` does not help
/// signature verification. It helps proof verification, where both G2 inputs
/// are fixed.
pub fn verify(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    msgs: &[Scalar],
    sig: &Signature,
) -> Result<bool, BbsError> {
    let domain = calculate_domain(pk, gens, header)?;
    let b = gens.b(domain, msgs)?;

    let lhs_g2 = (pk.0 + G2Projective::generator() * sig.e).to_affine();
    let prep_lhs = G2Prepared::from(lhs_g2);
    let prep_rhs = G2Prepared::from(crate::bls::neg_p2().to_affine());

    let result = Bls12::multi_miller_loop(&[
        (&sig.a.to_affine(), &prep_lhs),
        (&b.to_affine(), &prep_rhs),
    ])
    .final_exponentiation();

    Ok(result == Gt::identity())
}
```

- [ ] **Step 5: Write the module root**

Create `src/bbs/mod.rs`:

```rust
//! BBS+ over BLS12-381.
//!
//! **Real cryptography, not interoperable.** The algebra is genuine: forged
//! signatures fail, tampered proofs fail, and undisclosed attributes stay
//! undisclosed, each asserted by test. The encoding of generators, domain and
//! challenge is our own domain-separated construction and has **not** been
//! validated against the test vectors in `draft-irtf-cfrg-bbs-signatures`, so
//! output will not interoperate with another BBS+ implementation.
//!
//! The cost profile is what this module exists to produce. Interoperability is
//! not claimed anywhere and must not be inferred.

pub mod keys;
pub mod proof;
pub mod sign;

pub use keys::{KeyPair, PublicKey, SecretKey};
pub use sign::{calculate_domain, message_to_scalar, sign, verify, Signature};

#[derive(Debug, thiserror::Error)]
pub enum BbsError {
    #[error(transparent)]
    Bls(#[from] crate::bls::BlsError),
    #[error("the signing key and signature scalar sum to zero; regenerate the key")]
    DegenerateKey,
    #[error("disclosed index {index} is out of range for a {len}-attribute credential")]
    IndexOutOfRange { index: usize, len: usize },
    #[error("disclosed indexes must be sorted and distinct; {0} repeats or goes backwards")]
    UnsortedIndexes(usize),
    #[error("expected {expected} undisclosed responses, got {got}")]
    ResponseCount { expected: usize, got: usize },
    #[error("a blinding scalar was zero and cannot be inverted")]
    ZeroBlinding,
}
```

Update `src/lib.rs` to add `pub mod bbs;`.

**Note for the implementer:** `src/bbs/proof.rs` does not exist until Task 6. Add `pub mod proof;` to `mod.rs` in Task 6, not now, or create the file empty in this task — either is fine, but `cargo test` must pass at the end of this task.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib bbs`
Expected: PASS, 13 tests.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add BBS+ key generation, signing and verification

Real BBS+ over BLS12-381: A = B/(x+e), verified by
e(A, W + P2*e) * e(B, -P2) == 1. Six negative tests, because a verify that
returned true unconditionally would produce identical benchmark numbers to
a correct one.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: BBS+ presentation and proof verification

**Files:**
- Create: `src/bbs/proof.rs`
- Modify: `src/bbs/mod.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 4–5.
- Produces: `bbs::proof::{ProofScalars, Proof, prove, prove_with_scalars, verify_proof, verify_proof_prepared}`.
  - `ProofScalars { r1, r2, e_tilde, r1_tilde, r3_tilde, m_tilde: Vec<Scalar> }` with `ProofScalars::random(rng: &mut ChaCha20Rng, undisclosed: usize) -> ProofScalars`.
  - `prove_with_scalars(&PublicKey, &Generators, header, ph, &Signature, msgs, disclosed: &[usize], &ProofScalars) -> Result<Proof, BbsError>` — the low-level entry the pool wraps in Task 9.
  - `prove(...same minus scalars..., rng) -> Result<Proof, BbsError>` — draws fresh scalars.
  - `verify_proof(&PublicKey, &Generators, header, ph, disclosed: &[(usize, Scalar)], &Proof) -> Result<bool, BbsError>`.
  - `verify_proof_prepared(&PreparedIssuer, ...same...) -> Result<bool, BbsError>` — identical answer, cached pairing.

**The algebra, so a reviewer can check it rather than trust it.** With signature `(A, e)` on `B = P1 + Q1·domain + Σ H_i·m_i`:

```
D    = B · r2
Abar = A · (r1·r2)
Bbar = D · r1 − Abar · e            [ = r1·r2·(B − A·e) ]
```

`e(Abar, W) · e(Bbar, −P2) = 1` holds exactly when `A·(x+e) = B`, which is the signature equation, so the pairing check carries over to the randomized elements. `r1` and `r2` are fresh per presentation, so `Abar` and `D` are fresh group elements and two presentations of one credential are unlinkable. The Schnorr layer proves knowledge of `e`, `r1`, `r3 = r2⁻¹` and the undisclosed `m_j` against commitments `T1`, `T2`; the verifier reconstructs both and recomputes the challenge.

**Both G2 inputs to the proof pairing check are fixed per issuer** — `W` and `−P2`. That is what makes `PreparedIssuer` applicable here and not to signature verification.

- [ ] **Step 1: Write the failing test**

Create `src/bbs/proof.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bbs::sign::{message_to_scalar, sign};
    use crate::bls::{Generators, PreparedIssuer};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const HEADER: &[u8] = b"occultation test header";
    const PH: &[u8] = b"presentation nonce 1";

    struct Fixture {
        kp: KeyPair,
        gens: Generators,
        msgs: Vec<Scalar>,
        sig: crate::bbs::Signature,
    }

    fn fixture(n: usize) -> Fixture {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(n);
        let msgs: Vec<Scalar> = (0..n)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        let sig = sign(&kp.sk, &kp.pk, &gens, HEADER, &msgs).unwrap();
        Fixture { kp, gens, msgs, sig }
    }

    fn disclosed_pairs(f: &Fixture, idx: &[usize]) -> Vec<(usize, Scalar)> {
        idx.iter().map(|&i| (i, f.msgs[i])).collect()
    }

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn a_presentation_verifies() {
        let f = fixture(5);
        let disclosed = [1usize, 3];
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &mut rng(1))
            .unwrap();
        assert!(verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &disclosed_pairs(&f, &disclosed), &p)
            .unwrap());
    }

    #[test]
    fn disclosing_nothing_verifies() {
        let f = fixture(5);
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[], &mut rng(1)).unwrap();
        assert!(verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &[], &p).unwrap());
        assert_eq!(p.m_hat.len(), 5, "one response per undisclosed attribute");
    }

    #[test]
    fn disclosing_everything_verifies() {
        let f = fixture(3);
        let disclosed = [0usize, 1, 2];
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &mut rng(1))
            .unwrap();
        assert!(verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &disclosed_pairs(&f, &disclosed), &p)
            .unwrap());
        assert!(p.m_hat.is_empty());
    }

    /// Unlinkability, at the level this tool can assert it: two presentations
    /// of one credential share no group element.
    #[test]
    fn two_presentations_of_one_credential_share_no_element() {
        let f = fixture(5);
        let a = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(1)).unwrap();
        let b = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(2)).unwrap();
        assert_ne!(a.a_bar, b.a_bar);
        assert_ne!(a.b_bar, b.b_bar);
        assert_ne!(a.d, b.d);
        assert_ne!(a.challenge, b.challenge);
    }

    #[test]
    fn claiming_an_undisclosed_attribute_fails() {
        // The verifier is told attribute 0 was disclosed as attribute 0's real
        // value, but the prover never disclosed it. The index sets disagree,
        // so the challenge does not reproduce.
        let f = fixture(5);
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(1)).unwrap();
        let lying = disclosed_pairs(&f, &[0, 1]);
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &lying, &p).unwrap());
    }

    #[test]
    fn a_wrong_disclosed_value_fails() {
        let f = fixture(5);
        let disclosed = [1usize, 3];
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &mut rng(1))
            .unwrap();
        let mut lying = disclosed_pairs(&f, &disclosed);
        lying[0].1 += Scalar::ONE;
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &lying, &p).unwrap());
    }

    #[test]
    fn a_tampered_response_fails() {
        let f = fixture(5);
        let disclosed = [1usize];
        let mut p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &mut rng(1))
            .unwrap();
        p.m_hat[0] += Scalar::ONE;
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &disclosed_pairs(&f, &disclosed), &p)
            .unwrap());
    }

    #[test]
    fn a_tampered_group_element_fails() {
        let f = fixture(5);
        let mut p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(1))
            .unwrap();
        p.a_bar += G1Projective::generator();
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &disclosed_pairs(&f, &[1]), &p)
            .unwrap());
    }

    #[test]
    fn a_different_presentation_header_fails() {
        // Replaying a presentation against a second relying party's nonce is
        // the attack `ph` exists to stop.
        let f = fixture(5);
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(1)).unwrap();
        assert!(!verify_proof(
            &f.kp.pk, &f.gens, HEADER, b"presentation nonce 2", &disclosed_pairs(&f, &[1]), &p
        )
        .unwrap());
    }

    #[test]
    fn another_issuers_key_fails() {
        let f = fixture(5);
        let other = KeyPair::generate(8);
        let p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1], &mut rng(1)).unwrap();
        assert!(!verify_proof(&other.pk, &f.gens, HEADER, PH, &disclosed_pairs(&f, &[1]), &p)
            .unwrap());
    }

    #[test]
    fn an_identity_a_bar_is_rejected() {
        // Abar = identity satisfies the pairing equation for any Bbar = identity
        // and must be rejected explicitly, not left to the Schnorr layer.
        let f = fixture(3);
        let mut p = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[], &mut rng(1))
            .unwrap();
        p.a_bar = G1Projective::identity();
        assert!(!verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &[], &p).unwrap());
    }

    #[test]
    fn out_of_range_and_unsorted_indexes_are_errors_not_panics() {
        let f = fixture(3);
        assert!(prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[9], &mut rng(1)).is_err());
        assert!(prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[1, 1], &mut rng(1))
            .is_err());
        assert!(prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[2, 0], &mut rng(1))
            .is_err());
    }

    /// The cached-pairing path must agree with the uncached one on every
    /// answer, or `bench --composed` would be timing two different functions
    /// and calling the difference an optimization.
    #[test]
    fn the_prepared_verifier_agrees_with_the_plain_one() {
        let f = fixture(5);
        let prepared = PreparedIssuer::new(&f.kp.pk.0);
        let disclosed = [1usize, 3];
        let pairs = disclosed_pairs(&f, &disclosed);

        let good = prove(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &disclosed, &mut rng(1))
            .unwrap();
        assert_eq!(
            verify_proof(&f.kp.pk, &f.gens, HEADER, PH, &pairs, &good).unwrap(),
            verify_proof_prepared(&prepared, &f.kp.pk, &f.gens, HEADER, PH, &pairs, &good).unwrap()
        );

        let mut bad = good.clone();
        bad.b_bar += G1Projective::generator();
        assert!(!verify_proof_prepared(&prepared, &f.kp.pk, &f.gens, HEADER, PH, &pairs, &bad)
            .unwrap());
    }

    #[test]
    fn the_same_scalars_and_inputs_give_the_same_proof() {
        // prove_with_scalars must be a pure function of its inputs — the pool
        // in Task 9 depends on it.
        let f = fixture(4);
        let s = ProofScalars::random(&mut rng(11), 3);
        let a = prove_with_scalars(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[2], &s)
            .unwrap();
        let b = prove_with_scalars(&f.kp.pk, &f.gens, HEADER, PH, &f.sig, &f.msgs, &[2], &s)
            .unwrap();
        assert_eq!(a.a_bar, b.a_bar);
        assert_eq!(a.challenge, b.challenge);
        assert_eq!(a.m_hat, b.m_hat);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib proof`
Expected: FAIL — `cannot find type ProofScalars in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/bbs/proof.rs`:

```rust
use crate::bbs::keys::PublicKey;
use crate::bbs::sign::{calculate_domain, Signature};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, octets, Generators, PreparedIssuer, API_ID};
use blstrs::{Bls12, G1Projective, G2Prepared, Gt, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use rand_chacha::ChaCha20Rng;

/// The random scalars one presentation consumes.
///
/// This is exactly what the pre-computation pool holds, and exactly what must
/// never be used twice: two presentations sharing these scalars share `Abar`
/// and `D` (so they are linkable) and expose `e` and every undisclosed message
/// to anyone who sees both transcripts. See `pool.rs`.
#[derive(Clone, Debug)]
pub struct ProofScalars {
    pub r1: Scalar,
    pub r2: Scalar,
    pub e_tilde: Scalar,
    pub r1_tilde: Scalar,
    pub r3_tilde: Scalar,
    /// One per undisclosed message, in ascending index order.
    pub m_tilde: Vec<Scalar>,
}

impl ProofScalars {
    /// `r2` is inverted during finalization, so a zero draw is resampled. The
    /// loop runs once with overwhelming probability, and the alternative is
    /// unwrapping a `CtOption` that can be `None`.
    pub fn random(rng: &mut ChaCha20Rng, undisclosed: usize) -> Self {
        let mut nonzero = |rng: &mut ChaCha20Rng| loop {
            let s = Scalar::random(&mut *rng);
            if s != Scalar::ZERO {
                break s;
            }
        };
        ProofScalars {
            r1: nonzero(rng),
            r2: nonzero(rng),
            e_tilde: Scalar::random(&mut *rng),
            r1_tilde: Scalar::random(&mut *rng),
            r3_tilde: Scalar::random(&mut *rng),
            m_tilde: (0..undisclosed).map(|_| Scalar::random(&mut *rng)).collect(),
        }
    }
}

/// A presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub e_hat: Scalar,
    pub r1_hat: Scalar,
    pub r3_hat: Scalar,
    /// One response per undisclosed message, in ascending index order.
    pub m_hat: Vec<Scalar>,
    pub challenge: Scalar,
}

/// Indexes must be sorted, distinct and in range. Checked rather than assumed,
/// because an out-of-range index would otherwise index a slice and panic.
fn check_indexes(disclosed: &[usize], len: usize) -> Result<Vec<usize>, BbsError> {
    let mut previous: Option<usize> = None;
    for &i in disclosed {
        if i >= len {
            return Err(BbsError::IndexOutOfRange { index: i, len });
        }
        if let Some(p) = previous {
            if i <= p {
                return Err(BbsError::UnsortedIndexes(i));
            }
        }
        previous = Some(i);
    }
    Ok((0..len).filter(|i| !disclosed.contains(i)).collect())
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    a_bar: &G1Projective,
    b_bar: &G1Projective,
    d: &G1Projective,
    t1: &G1Projective,
    t2: &G1Projective,
    domain: Scalar,
    disclosed: &[(usize, Scalar)],
    ph: &[u8],
) -> Result<Scalar, BbsError> {
    let mut parts: Vec<Vec<u8>> = vec![(disclosed.len() as u64).to_be_bytes().to_vec()];
    for (i, m) in disclosed {
        parts.push((*i as u64).to_be_bytes().to_vec());
        parts.push(m.to_bytes_be().to_vec());
    }
    for p in [a_bar, b_bar, d, t1, t2] {
        parts.push(p.to_affine().to_compressed().to_vec());
    }
    parts.push(domain.to_bytes_be().to_vec());
    parts.push(ph.to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    Ok(hash_to_scalar(&octets(&refs), &[API_ID, b"H2S_CHALLENGE_"].concat())?)
}

/// Present a credential, disclosing `disclosed` and hiding the rest, using
/// caller-supplied scalars.
///
/// This is the entry point the pre-computation pool wraps. It is a pure
/// function of its arguments, which is what makes the pool's items meaningful
/// — and what makes reusing one catastrophic.
#[allow(clippy::too_many_arguments)]
pub fn prove_with_scalars(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    sig: &Signature,
    msgs: &[Scalar],
    disclosed: &[usize],
    s: &ProofScalars,
) -> Result<Proof, BbsError> {
    let undisclosed = check_indexes(disclosed, gens.len())?;
    if s.m_tilde.len() != undisclosed.len() {
        return Err(BbsError::ResponseCount {
            expected: undisclosed.len(),
            got: s.m_tilde.len(),
        });
    }

    let domain = calculate_domain(pk, gens, header)?;
    let b = gens.b(domain, msgs)?;

    let d = b * s.r2;
    let a_bar = sig.a * (s.r1 * s.r2);
    let b_bar = d * s.r1 - a_bar * sig.e;

    let t1 = a_bar * s.e_tilde + d * s.r1_tilde;
    let mut points = vec![d];
    let mut scalars = vec![s.r3_tilde];
    for (k, &j) in undisclosed.iter().enumerate() {
        points.push(gens.h[j]);
        scalars.push(s.m_tilde[k]);
    }
    let t2 = G1Projective::multi_exp(&points, &scalars);

    let disclosed_pairs: Vec<(usize, Scalar)> =
        disclosed.iter().map(|&i| (i, msgs[i])).collect();
    let c = challenge(&a_bar, &b_bar, &d, &t1, &t2, domain, &disclosed_pairs, ph)?;

    let r3 = Option::<Scalar>::from(s.r2.invert()).ok_or(BbsError::ZeroBlinding)?;
    Ok(Proof {
        a_bar,
        b_bar,
        d,
        e_hat: s.e_tilde + sig.e * c,
        r1_hat: s.r1_tilde - s.r1 * c,
        r3_hat: s.r3_tilde - r3 * c,
        m_hat: undisclosed.iter().enumerate().map(|(k, &j)| s.m_tilde[k] + msgs[j] * c).collect(),
        challenge: c,
    })
}

/// Present a credential with freshly drawn scalars.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    sig: &Signature,
    msgs: &[Scalar],
    disclosed: &[usize],
    rng: &mut ChaCha20Rng,
) -> Result<Proof, BbsError> {
    let undisclosed = check_indexes(disclosed, gens.len())?;
    let s = ProofScalars::random(rng, undisclosed.len());
    prove_with_scalars(pk, gens, header, ph, sig, msgs, disclosed, &s)
}

/// Reconstruct the commitments and the challenge. Shared by both verifiers.
fn recompute(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    let indexes: Vec<usize> = disclosed.iter().map(|(i, _)| *i).collect();
    let undisclosed = check_indexes(&indexes, gens.len())?;
    if p.m_hat.len() != undisclosed.len() {
        return Err(BbsError::ResponseCount { expected: undisclosed.len(), got: p.m_hat.len() });
    }

    let domain = calculate_domain(pk, gens, header)?;

    let t1 = p.b_bar * p.challenge + p.a_bar * p.e_hat + p.d * p.r1_hat;

    // Bv covers only the disclosed attributes; the undisclosed ones enter
    // through their responses.
    let mut bv_points = vec![gens.p1, gens.q1];
    let mut bv_scalars = vec![Scalar::ONE, domain];
    for (i, m) in disclosed {
        bv_points.push(gens.h[*i]);
        bv_scalars.push(*m);
    }
    let bv = G1Projective::multi_exp(&bv_points, &bv_scalars);

    let mut t2_points = vec![bv, p.d];
    let mut t2_scalars = vec![p.challenge, p.r3_hat];
    for (k, &j) in undisclosed.iter().enumerate() {
        t2_points.push(gens.h[j]);
        t2_scalars.push(p.m_hat[k]);
    }
    let t2 = G1Projective::multi_exp(&t2_points, &t2_scalars);

    let c = challenge(&p.a_bar, &p.b_bar, &p.d, &t1, &t2, domain, disclosed, ph)?;
    Ok(c == p.challenge)
}

/// `e(Abar, W) * e(Bbar, -P2) == 1`, with the G2 inputs prepared on the spot.
pub fn verify_proof(
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    let prepared = PreparedIssuer::new(&pk.0);
    verify_proof_prepared(&prepared, pk, gens, header, ph, disclosed, p)
}

/// The same check with a per-issuer `G2Prepared` supplied by the caller.
///
/// This is the desk study's "cached pairing pre-computation". Measure the
/// difference; do not assume it.
#[allow(clippy::too_many_arguments)]
pub fn verify_proof_prepared(
    prepared: &PreparedIssuer,
    pk: &PublicKey,
    gens: &Generators,
    header: &[u8],
    ph: &[u8],
    disclosed: &[(usize, Scalar)],
    p: &Proof,
) -> Result<bool, BbsError> {
    // The identity satisfies the pairing equation trivially, so reject it
    // before doing any work.
    if bool::from(p.a_bar.is_identity()) {
        return Ok(false);
    }
    if !recompute(pk, gens, header, ph, disclosed, p)? {
        return Ok(false);
    }
    let result = Bls12::multi_miller_loop(&[
        (&p.a_bar.to_affine(), &prepared.w),
        (&p.b_bar.to_affine(), &prepared.neg_p2),
    ])
    .final_exponentiation();
    Ok(result == Gt::identity())
}

/// Kept so `G2Prepared` is nameable from this module's tests without an extra
/// import in every one.
pub type Prepared = G2Prepared;
```

Note: `verify_proof` constructing a `PreparedIssuer` on every call means the plain path pays the `G2Prepared::from` cost twice per verification, which is exactly the uncached path we want to measure in Task 7. That is intentional, not an oversight.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib proof`
Expected: PASS, 14 tests.

If `a_presentation_verifies` fails, the algebra is wrong somewhere and no later task can proceed. Check in this order: (1) does `verify` from Task 5 still pass — if not, `B` or `domain` changed; (2) does `recompute` return `true` — if not, the Schnorr layer is wrong and the pairing is fine; (3) if `recompute` is true and the pairing fails, `Bbar` is wrong. Do not "fix" it by loosening an assertion.

- [ ] **Step 5: Run the whole suite and lint**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add BBS+ presentation and proof verification

Selective disclosure with fresh blinding per presentation: two showings of
one credential share no group element, asserted by test. Eleven negative
tests cover claiming an undisclosed attribute, replaying under a second
relying party's nonce, and an identity Abar, which satisfies the pairing
equation trivially and has to be rejected before the Schnorr layer.

Both G2 inputs to the proof pairing are fixed per issuer, so the cached
verifier is available here and not for signature verification.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: The report layer and `occultation bench`

**Files:**
- Create: `src/report.rs`, `src/bench.rs`
- Modify: `src/lib.rs`, `src/bin/occultation.rs`

**Interfaces:**
- Consumes: `harness`, `baseline`, `cost`, `bls`, `bbs`, `modelled`, `ecdaa`, `escrow`.
- Produces: `report::{Row, Table, Format}` with `Table::render(&self) -> String` and `Table::to_json(&self) -> serde_json::Value`; `bench::{BenchOptions, run_bench, PrimitiveCosts}`. CLI: `occultation bench [--iters N] [--seed N] [--attributes N] [--disclose N] [--allow-modelled] [--format table|json]`.

The report layer is where the two labelling rules become visible: a row whose source is `Published` prints `PUBLISHED`, and a row whose provenance is `Modelled` prints `MODELLED`. Every command renders through it, so neither label can be forgotten in one command and remembered in another.

- [ ] **Step 1: Write the failing test**

Create `src/report.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::Source;
    use crate::modelled::Provenance;
    use std::time::Duration;

    fn real_row() -> Row {
        Row::real("BBS+ verify", Duration::from_micros(500), Source::MeasuredHere { iters: 100 })
    }

    fn modelled_row() -> Row {
        Row::new(
            "escrow tag + DLEQ",
            Duration::from_micros(300),
            Source::MeasuredHere { iters: 100 },
            Provenance::Modelled { component: "escrow", reason: "stub" },
        )
    }

    #[test]
    fn a_modelled_row_renders_the_word_modelled() {
        let t = Table::new("costs").with(modelled_row());
        assert!(t.render().contains("MODELLED"), "{}", t.render());
    }

    #[test]
    fn a_real_measured_row_does_not_say_modelled_or_published() {
        let out = Table::new("costs").with(real_row()).render();
        assert!(!out.contains("MODELLED"), "{out}");
        assert!(!out.contains("PUBLISHED"), "{out}");
    }

    #[test]
    fn a_published_row_renders_the_word_published_and_its_citation() {
        let row = Row::real(
            "BBS+ presentation",
            Duration::from_micros(13_800),
            Source::Published { citation: "the desk study" },
        );
        let out = Table::new("costs").with(row).render();
        assert!(out.contains("PUBLISHED"), "{out}");
        assert!(out.contains("the desk study"), "{out}");
    }

    #[test]
    fn a_ratio_is_rendered_against_the_baseline() {
        let t = Table::new("costs")
            .with(real_row().against(Duration::from_micros(25)))
            .render();
        assert!(t.contains("20.0"), "500 us against a 25 us baseline is 20x: {t}");
    }

    #[test]
    fn a_zero_baseline_does_not_divide_by_zero() {
        let r = real_row().against(Duration::ZERO);
        assert!(r.ratio.is_none(), "a zero baseline has no meaningful ratio");
        assert!(!Table::new("c").with(r).render().contains("inf"));
    }

    #[test]
    fn json_carries_the_source_and_provenance_as_data_not_prose() {
        let v = Table::new("costs").with(modelled_row()).to_json();
        let row = &v["rows"][0];
        assert_eq!(row["provenance"]["kind"], "modelled");
        assert_eq!(row["source"]["kind"], "measured_here");
        assert_eq!(row["label"], "escrow tag + DLEQ");
        assert!(row["cost_us"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn a_table_notes_every_modelled_component_in_its_footer() {
        let out = Table::new("costs").with(real_row()).with(modelled_row()).render();
        assert!(
            out.contains("no security"),
            "a table containing a modelled row must warn in prose too: {out}"
        );
    }

    #[test]
    fn a_table_with_no_modelled_rows_has_no_warning_footer() {
        let out = Table::new("costs").with(real_row()).render();
        assert!(!out.contains("no security"), "{out}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib report`
Expected: FAIL — `cannot find type Row in this scope`.

- [ ] **Step 3: Write the report layer**

Prepend to `src/report.rs`:

```rust
use crate::cost::Source;
use crate::modelled::Provenance;
use serde_json::json;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "table" => Ok(Format::Table),
            "json" => Ok(Format::Json),
            other => Err(format!("unknown format `{other}`; expected `table` or `json`")),
        }
    }
}

/// One measured or published cost.
#[derive(Clone, Debug)]
pub struct Row {
    pub label: String,
    pub cost: Duration,
    pub source: Source,
    pub provenance: Provenance,
    /// Multiple of the Ed25519 baseline, when a baseline is available.
    pub ratio: Option<f64>,
}

impl Row {
    pub fn new(
        label: impl Into<String>,
        cost: Duration,
        source: Source,
        provenance: Provenance,
    ) -> Self {
        Row { label: label.into(), cost, source, provenance, ratio: None }
    }

    pub fn real(label: impl Into<String>, cost: Duration, source: Source) -> Self {
        let label = label.into();
        let component: &'static str = Box::leak(label.clone().into_boxed_str());
        Row::new(label, cost, source, Provenance::Real { component })
    }

    /// Attach the multiple of a baseline. A zero baseline yields `None` rather
    /// than an infinity, because printing `inf` in a results table is worse
    /// than printing nothing.
    pub fn against(mut self, baseline: Duration) -> Self {
        self.ratio = if baseline.is_zero() {
            None
        } else {
            Some(self.cost.as_secs_f64() / baseline.as_secs_f64())
        };
        self
    }

    pub fn is_modelled(&self) -> bool {
        matches!(self.provenance, Provenance::Modelled { .. })
    }
}

#[derive(Clone, Debug)]
pub struct Table {
    pub title: String,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}

impl Table {
    pub fn new(title: impl Into<String>) -> Self {
        Table { title: title.into(), rows: Vec::new(), notes: Vec::new() }
    }

    pub fn with(mut self, row: Row) -> Self {
        self.rows.push(row);
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn render(&self) -> String {
        let mut out = format!("{}\n\n", self.title);
        out.push_str(&format!(
            "{:<40} {:>12} {:>10}  {}\n",
            "OPERATION", "COST", "xED25519", "PROVENANCE"
        ));
        for r in &self.rows {
            let ratio = match r.ratio {
                Some(x) => format!("{x:.1}"),
                None => "-".to_string(),
            };
            // Both labels come from Display impls, so a new Source or
            // Provenance variant cannot silently render as blank.
            let tag = match (&r.provenance, &r.source) {
                (Provenance::Modelled { .. }, s) => format!("{} · {s}", r.provenance),
                (_, s) => format!("{s}"),
            };
            out.push_str(&format!(
                "{:<40} {:>9.3} ms {:>10}  {}\n",
                r.label,
                r.cost.as_secs_f64() * 1e3,
                ratio,
                tag
            ));
        }
        for n in &self.notes {
            out.push_str(&format!("\n{n}\n"));
        }
        if self.rows.iter().any(Row::is_modelled) {
            out.push_str(
                "\nRows marked MODELLED come from stubs that provide no security. \
                 Their cost is representative; nothing else about them is.\n",
            );
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "title": self.title,
            "notes": self.notes,
            "rows": self.rows.iter().map(|r| json!({
                "label": r.label,
                "cost_us": r.cost.as_secs_f64() * 1e6,
                "source": r.source,
                "provenance": r.provenance,
                "ratio_to_ed25519": r.ratio,
            })).collect::<Vec<_>>(),
        })
    }
}
```

**Note on `Row::real`:** `Box::leak` is used to satisfy `Provenance`'s `&'static str` field from a runtime label. That is a deliberate small leak, bounded by the number of rows a single command prints. If a reviewer objects, the alternative is changing `Provenance` to own its strings; either is acceptable, but do not silently switch to a placeholder like `"real"` that loses the component name.

- [ ] **Step 4: Write the bench module**

Create `src/bench.rs`:

```rust
use crate::baseline::{measure_baseline, Baseline};
use crate::bbs::keys::KeyPair;
use crate::bbs::proof::{prove, verify_proof, verify_proof_prepared, ProofScalars};
use crate::bbs::sign::{message_to_scalar, sign, verify};
use crate::bbs::BbsError;
use crate::bls::{hash_to_scalar, Generators, PreparedIssuer, API_ID};
use crate::cost::Source;
use crate::harness::{measure, Sample};
use crate::modelled::{
    AnonymousAttestation, EscrowTag, ModelledError, ModelledPermit, Provenance,
};
use crate::report::{Row, Table};
use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BenchOptions {
    pub iters: u32,
    pub seed: u64,
    /// Attributes in the credential.
    pub attributes: usize,
    /// How many of them a presentation discloses.
    pub disclose: usize,
    pub allow_modelled: bool,
}

impl Default for BenchOptions {
    fn default() -> Self {
        // Ten attributes with two disclosed is the shape P05 describes: an
        // agent proving authorization scope while revealing almost nothing.
        BenchOptions { iters: 100, seed: 7, attributes: 10, disclose: 2, allow_modelled: false }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error(transparent)]
    Bbs(#[from] BbsError),
    #[error(transparent)]
    Modelled(#[from] ModelledError),
    #[error("cannot disclose {disclose} of {attributes} attributes")]
    BadDisclosure { disclose: usize, attributes: usize },
}

/// Everything `bench` measures, kept as structured samples so `bench
/// --composed` can reuse them without re-timing.
#[derive(Debug)]
pub struct PrimitiveCosts {
    pub baseline: Baseline,
    pub g1_mul: Sample,
    pub hash_to_scalar: Sample,
    pub bbs_sign: Sample,
    pub bbs_verify: Sample,
    pub present: Sample,
    pub verify_proof_uncached: Sample,
    pub verify_proof_cached: Sample,
    pub modelled_ecdaa_attest: Option<Sample>,
    pub modelled_escrow_tag: Option<Sample>,
}

pub fn run_bench(opts: &BenchOptions) -> Result<PrimitiveCosts, BenchError> {
    if opts.disclose > opts.attributes {
        return Err(BenchError::BadDisclosure {
            disclose: opts.disclose,
            attributes: opts.attributes,
        });
    }

    let baseline = measure_baseline(opts.seed, opts.iters);

    let kp = KeyPair::generate(opts.seed);
    let gens = Generators::create(opts.attributes);
    let msgs: Vec<Scalar> = (0..opts.attributes)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()))
        .collect::<Result<_, _>>()?;
    let header = b"occultation bench";
    let ph = b"occultation bench nonce";
    let disclosed: Vec<usize> = (0..opts.disclose).collect();
    let disclosed_pairs: Vec<(usize, Scalar)> = disclosed.iter().map(|&i| (i, msgs[i])).collect();

    let sig = sign(&kp.sk, &kp.pk, &gens, header, &msgs)?;
    let mut rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let proof = prove(&kp.pk, &gens, header, ph, &sig, &msgs, &disclosed, &mut rng)?;
    let prepared = PreparedIssuer::new(&kp.pk.0);

    let s = Scalar::random(&mut ChaCha20Rng::seed_from_u64(opts.seed));
    let g1_mul = measure("G1 scalar multiplication", opts.iters, || {
        G1Projective::generator() * s
    });
    let h2s = measure("hash_to_scalar", opts.iters, || {
        hash_to_scalar(b"an agent action", API_ID).expect("fixed-length DST")
    });

    let bbs_sign = measure("BBS+ sign (issuer)", opts.iters, || {
        sign(&kp.sk, &kp.pk, &gens, header, &msgs).expect("valid inputs")
    });
    let bbs_verify = measure("BBS+ signature verify (holder)", opts.iters, || {
        verify(&kp.pk, &gens, header, &msgs, &sig).expect("valid inputs")
    });

    let mut prove_rng = ChaCha20Rng::seed_from_u64(opts.seed);
    let present = measure("BBS+ presentation", opts.iters, || {
        prove(&kp.pk, &gens, header, ph, &sig, &msgs, &disclosed, &mut prove_rng)
            .expect("valid inputs")
    });
    let verify_proof_uncached = measure("BBS+ proof verify", opts.iters, || {
        verify_proof(&kp.pk, &gens, header, ph, &disclosed_pairs, &proof).expect("valid inputs")
    });
    let verify_proof_cached = measure("BBS+ proof verify, cached pairings", opts.iters, || {
        verify_proof_prepared(&prepared, &kp.pk, &gens, header, ph, &disclosed_pairs, &proof)
            .expect("valid inputs")
    });

    // Modelled components are only executed with a permit. Note that this is
    // the *execution* gate: `bench --composed` can still do arithmetic over
    // the desk study's published escrow figure without one, because reading a
    // number out of a paper is not running a stub.
    let (modelled_ecdaa_attest, modelled_escrow_tag) = if opts.allow_modelled {
        let permit = ModelledPermit::from_flag(true)?;
        let ecdaa = crate::ecdaa::ModelledEcdaa::new(permit);
        let escrow = crate::escrow::ModelledThresholdElGamal::new(permit, 3, 5)?;
        (
            Some(measure("ECDAA attest", opts.iters, || {
                ecdaa.attest(b"measurement").expect("stub cannot fail")
            })),
            Some(measure("escrow tag + DLEQ", opts.iters, || {
                escrow.tag(b"did:web:agent-42").expect("stub cannot fail")
            })),
        )
    } else {
        (None, None)
    };

    Ok(PrimitiveCosts {
        baseline,
        g1_mul,
        hash_to_scalar: h2s,
        bbs_sign,
        bbs_verify,
        present,
        verify_proof_uncached,
        verify_proof_cached,
        modelled_ecdaa_attest,
        modelled_escrow_tag,
    })
}

impl PrimitiveCosts {
    /// The comparison the paper reports: every primitive against an Ed25519
    /// sign-and-verify round trip, not against verification alone.
    pub fn table(&self) -> Table {
        let b = self.baseline.round_trip();
        let src = |s: &Sample| Source::MeasuredHere { iters: s.iters };
        let mut t = Table::new("Primitive costs against the Ed25519 baseline")
            .with(Row::real(self.baseline.sign.label.clone(), self.baseline.sign.median, src(&self.baseline.sign)).against(b))
            .with(Row::real(self.baseline.verify.label.clone(), self.baseline.verify.median, src(&self.baseline.verify)).against(b))
            .with(Row::real("Ed25519 sign + verify (baseline)", b, src(&self.baseline.sign)).against(b))
            .with(Row::real(self.g1_mul.label.clone(), self.g1_mul.median, src(&self.g1_mul)).against(b))
            .with(Row::real(self.hash_to_scalar.label.clone(), self.hash_to_scalar.median, src(&self.hash_to_scalar)).against(b))
            .with(Row::real(self.bbs_sign.label.clone(), self.bbs_sign.median, src(&self.bbs_sign)).against(b))
            .with(Row::real(self.bbs_verify.label.clone(), self.bbs_verify.median, src(&self.bbs_verify)).against(b))
            .with(Row::real(self.present.label.clone(), self.present.median, src(&self.present)).against(b))
            .with(Row::real(self.verify_proof_uncached.label.clone(), self.verify_proof_uncached.median, src(&self.verify_proof_uncached)).against(b))
            .with(Row::real(self.verify_proof_cached.label.clone(), self.verify_proof_cached.median, src(&self.verify_proof_cached)).against(b));

        for (sample, component) in [
            (&self.modelled_ecdaa_attest, "ECDAA"),
            (&self.modelled_escrow_tag, "threshold ElGamal escrow"),
        ] {
            if let Some(s) = sample {
                t = t.with(
                    Row::new(
                        s.label.clone(),
                        s.median,
                        Source::MeasuredHere { iters: s.iters },
                        Provenance::Modelled { component, reason: "stub; cost stand-in only" },
                    )
                    .against(b),
                );
            }
        }

        if self.modelled_ecdaa_attest.is_none() {
            t = t.note(
                "ECDAA and escrow are not shown: they are modelled and require \
                 --allow-modelled to execute.",
            );
        }
        t
    }

    /// What `bench --composed` needs from a measured run.
    pub fn composed_halves(&self) -> (Duration, Duration, Duration) {
        (self.present.median, self.verify_proof_uncached.median, self.verify_proof_cached.median)
    }
}

/// Kept so the bench module compiles when `ProofScalars` is unused above; the
/// pool in Task 9 imports it from here.
pub use crate::bbs::proof::ProofScalars as BenchProofScalars;
```

- [ ] **Step 5: Wire the CLI**

Replace `src/bin/occultation.rs`:

```rust
use anyhow::Result;
use clap::{Parser, Subcommand};
use occultation::bench::{run_bench, BenchOptions};
use occultation::modelled::MODELLED_WARNING;
use occultation::report::Format;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "occultation",
    version,
    about = "Measure what verifiable unlinkability costs at agent action rates"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Primitive costs against the Ed25519 baseline
    Bench {
        /// Assess presentation AND verification against the 15 ms budget
        #[arg(long)]
        composed: bool,
        #[arg(long, default_value_t = 100)]
        iters: u32,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value_t = 10)]
        attributes: usize,
        #[arg(long, default_value_t = 2)]
        disclose: usize,
        /// Run components that provide no security
        #[arg(long)]
        allow_modelled: bool,
        #[arg(long, default_value = "table")]
        format: Format,
    },
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    match run() {
        Ok(code) => code,
        // `{e}` not `{e:#}` — the library error types already interpolate
        // their own source, so the alternate formatter prints every cause
        // twice.
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Bench { composed, iters, seed, attributes, disclose, allow_modelled, format } => {
            if allow_modelled {
                eprintln!("{MODELLED_WARNING}\n");
            }
            let opts = BenchOptions { iters, seed, attributes, disclose, allow_modelled };
            let costs = run_bench(&opts)?;
            let table = costs.table();
            match format {
                Format::Table => println!("{}", table.render()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&table.to_json())?),
            }
            let _ = composed; // wired in Task 8
            Ok(ExitCode::SUCCESS)
        }
    }
}
```

Update `src/lib.rs` to add `pub mod bench;` and `pub mod report;`.

- [ ] **Step 6: Run it and look at the numbers**

```bash
cargo test
cargo run --release -- bench
cargo run --release -- bench --allow-modelled
```

Expected: the first table has no `MODELLED` rows and carries the note explaining why; the second has two, each tagged, with the footer warning. Sanity-check the shape of the output before moving on: BBS+ presentation should land in the hundreds of microseconds to low milliseconds and be one to two orders of magnitude above the Ed25519 round trip. If presentation comes out *faster* than an Ed25519 verify, something is being optimized away — check that `measure` is black-boxing its result.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the report layer and `occultation bench`

Every command renders through one table type, so the PUBLISHED and
MODELLED labels cannot be applied in one command and forgotten in
another. Ratios are against an Ed25519 sign-and-verify round trip rather
than verification alone, which would flatter the anonymous scheme by two.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `bench --composed` — the headline correction

**Files:**
- Create: `tests/acceptance.rs`
- Modify: `src/bench.rs`, `src/bin/occultation.rs`

**Interfaces:**
- Consumes: `cost::{compose, CostProfile, BudgetVerdict}`, `bench::PrimitiveCosts`.
- Produces: `bench::{ComposedRow, ComposedReport, composed_report}`. `composed_report(&PrimitiveCosts) -> ComposedReport` holding the desk-study rows and the measured rows, each with a `BudgetVerdict`. `ComposedReport::render()` and `::to_json()`. CLI: `occultation bench --composed`.

**This is acceptance test 1 and it needs stating precisely, because a naive reading of it is not satisfiable.**

The desk study's numbers are 13.8 ms presentation and 4.2 ms verification. Composed, that is 18 ms and it misses the 15 ms budget. Those numbers came from published benchmarks of other people's hardware. Measured on this stack, a real BBS+ present-and-verify is roughly an order of magnitude cheaper and **does not exceed 15 ms**, so asserting a measured wall-clock over 15 ms would be asserting something false, and asserting it on wall-clock at all would make the test host-dependent.

So the report has two halves and the acceptance test pins the deterministic one:

- **Desk-study rows** — arithmetic over published figures, identical on every host. `naive` misses; `cached pairings only` is marginal; `pool + cached` fits. **This is what acceptance test 1 asserts**, and it is what a third party reproduces.
- **Measured rows** — the same three compositions using this host's numbers, with an honest note that they differ from the published ones and by how much. Asserted only on host-independent properties: the composed total equals the sum of its halves, and it is reported as one verdict rather than two.

The correction survives the discrepancy intact, because it was never a claim about absolute speed. It is a claim about a composition error: two costs on one path were assessed separately against a budget the path as a whole has to meet. That error is in the arithmetic, not in the hardware.

- [ ] **Step 1: Write the failing test**

Append to `src/bench.rs`:

```rust
#[cfg(test)]
mod composed_tests {
    use super::*;
    use crate::cost::{BudgetVerdict, BUDGET};

    fn costs() -> PrimitiveCosts {
        // Few iterations: these tests assert structure, not speed.
        run_bench(&BenchOptions { iters: 5, ..Default::default() }).unwrap()
    }

    #[test]
    fn the_report_carries_both_profiles() {
        let r = composed_report(&costs());
        assert!(r.desk_study.iter().all(|row| row.published));
        assert!(r.measured.iter().all(|row| !row.published));
        assert_eq!(r.desk_study.len(), 3, "naive, cached-only, pool+cached");
        assert_eq!(r.measured.len(), 3);
    }

    #[test]
    fn the_desk_study_naive_row_misses_the_budget() {
        let r = composed_report(&costs());
        let naive = &r.desk_study[0];
        assert_eq!(naive.composed.total, Duration::from_micros(18_000));
        assert_eq!(naive.composed.verdict, BudgetVerdict::Misses { over: Duration::from_millis(3) });
    }

    #[test]
    fn every_row_total_is_the_sum_of_its_halves() {
        // The whole point: nothing is judged against the budget except a sum.
        let r = composed_report(&costs());
        for row in r.desk_study.iter().chain(r.measured.iter()) {
            assert_eq!(
                row.composed.total,
                row.composed.present + row.composed.verify,
                "{} was judged on something other than its sum",
                row.label
            );
            assert_eq!(row.composed.budget, BUDGET);
        }
    }

    #[test]
    fn the_rendered_report_never_shows_a_half_path_verdict() {
        // A verdict beside a presentation-only or verification-only figure is
        // exactly the mistake being corrected. There must be one verdict per
        // composed row and no more.
        let out = composed_report(&costs()).render();
        let verdicts = out.matches("MISSES").count()
            + out.matches("MARGINAL").count()
            + out.matches("fits,").count();
        assert_eq!(verdicts, 6, "one verdict per composed row, no others:\n{out}");
    }

    #[test]
    fn the_report_states_the_correction_in_prose() {
        let out = composed_report(&costs()).render();
        assert!(out.contains("separately"), "must name the error: {out}");
        assert!(out.contains("18.00 ms"), "must show the sum: {out}");
    }

    #[test]
    fn the_measured_profile_is_labelled_as_diverging_from_the_published_one() {
        let out = composed_report(&costs()).render();
        assert!(out.contains("measured here"));
        assert!(out.contains("PUBLISHED"));
        assert!(
            out.contains("differ"),
            "the report must say the two profiles disagree, not print them silently: {out}"
        );
    }

    #[test]
    fn the_measured_composed_cost_is_a_large_multiple_of_the_baseline() {
        // Host-independent form of "unlinkability is expensive". The desk
        // study says ~70x unoptimized; anything above 10x reproduces the
        // qualitative claim without pinning a wall clock.
        let c = costs();
        let r = composed_report(&c);
        let ratio = r.measured[0].composed.total.as_secs_f64()
            / c.baseline.round_trip().as_secs_f64();
        assert!(ratio > 10.0, "composed BBS+ was only {ratio:.1}x Ed25519");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib composed`
Expected: FAIL — `cannot find function composed_report in this scope`.

- [ ] **Step 3: Write the implementation**

Append to `src/bench.rs` (above the test module):

```rust
use crate::cost::{compose, us, Composed, CostProfile};

/// One composition of a present-and-verify path, judged as a whole.
#[derive(Debug)]
pub struct ComposedRow {
    pub label: String,
    pub composed: Composed,
    /// True when both halves came from a publication rather than this host.
    pub published: bool,
    pub note: Option<String>,
}

#[derive(Debug)]
pub struct ComposedReport {
    pub desk_study: Vec<ComposedRow>,
    pub measured: Vec<ComposedRow>,
    pub baseline_round_trip: Duration,
    pub measured_ratio: f64,
}

/// Compose the desk study's published figures and this host's measured ones.
///
/// Three compositions each: the naive path, the path with cached pairings
/// only, and the path with both a pre-computation pool and cached pairings.
pub fn composed_report(costs: &PrimitiveCosts) -> ComposedReport {
    let d = CostProfile::desk_study();
    let desk_study = vec![
        ComposedRow {
            label: "naive (no pool, no cached pairings)".into(),
            composed: compose(d.present_naive.cost, d.verify_naive.cost),
            published: true,
            note: Some(
                "13.8 ms and 4.2 ms were each assessed separately against the \
                 15 ms budget and each looked acceptable."
                    .into(),
            ),
        },
        ComposedRow {
            label: "cached pairings only".into(),
            composed: compose(d.present_naive.cost, d.verify_cached.cost),
            published: true,
            note: Some(
                "Under the limit with 100 us to spare, which leaves nothing for \
                 application work, network time or evidence writing."
                    .into(),
            ),
        },
        ComposedRow {
            label: "pre-computation pool + cached pairings".into(),
            composed: compose(d.present_pooled.cost, d.verify_cached.cost),
            published: true,
            note: Some(
                "The only composition that fits. Pre-computation is load-bearing, \
                 not an optimization."
                    .into(),
            ),
        },
    ];

    let (present, verify_uncached, verify_cached) = costs.composed_halves();
    // A pooled presentation removes the group operations from the online path,
    // leaving the challenge hash and the field-arithmetic responses. Task 9
    // measures that directly; here it is the presentation minus its group
    // work, approximated by the hash cost, and labelled as an estimate.
    let pooled_estimate = costs.hash_to_scalar.median * 2;
    let measured = vec![
        ComposedRow {
            label: "naive (no pool, no cached pairings)".into(),
            composed: compose(present, verify_uncached),
            published: false,
            note: None,
        },
        ComposedRow {
            label: "cached pairings only".into(),
            composed: compose(present, verify_cached),
            published: false,
            note: None,
        },
        ComposedRow {
            label: "pre-computation pool (estimated) + cached pairings".into(),
            composed: compose(pooled_estimate, verify_cached),
            published: false,
            note: Some("Pooled presentation is estimated here; `occultation pool` measures it.".into()),
        },
    ];

    let baseline_round_trip = costs.baseline.round_trip();
    let measured_ratio = if baseline_round_trip.is_zero() {
        f64::NAN
    } else {
        measured[0].composed.total.as_secs_f64() / baseline_round_trip.as_secs_f64()
    };

    ComposedReport { desk_study, measured, baseline_round_trip, measured_ratio }
}

impl ComposedReport {
    pub fn render(&self) -> String {
        let mut out = String::from("The composed present-and-verify path against a 15 ms budget\n\n");

        out.push_str("PUBLISHED — desk study figures, not measured on this stack\n");
        out.push_str(&Self::rows(&self.desk_study));
        out.push_str(
            "\nThe correction: presentation and verification were assessed \
             separately against\nthe budget and each looked acceptable. Their sum is \
             18.00 ms, which is over.\n",
        );

        out.push_str("\nmeasured here\n");
        out.push_str(&Self::rows(&self.measured));
        out.push_str(&format!(
            "\nMeasured and published figures differ substantially — this host's \
             primitives are\nfaster than the ones the desk study cites. The composition \
             error is unaffected:\nit is an error in arithmetic, not in hardware. \
             Composed BBS+ costs {:.0}x an\nEd25519 sign-and-verify round trip of {} here.\n",
            self.measured_ratio,
            us(self.baseline_round_trip)
        ));
        out
    }

    fn rows(rows: &[ComposedRow]) -> String {
        let mut out = format!(
            "  {:<46} {:>10} {:>10} {:>10}  {}\n",
            "COMPOSITION", "PRESENT", "VERIFY", "TOTAL", "VERDICT"
        );
        for r in rows {
            out.push_str(&format!(
                "  {:<46} {:>10} {:>10} {:>10}  {}\n",
                r.label,
                us(r.composed.present),
                us(r.composed.verify),
                us(r.composed.total),
                r.composed.verdict
            ));
            if let Some(n) = &r.note {
                out.push_str(&format!("      {n}\n"));
            }
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        let rows = |rs: &[ComposedRow]| {
            rs.iter()
                .map(|r| {
                    serde_json::json!({
                        "label": r.label,
                        "published": r.published,
                        "composed": r.composed,
                        "note": r.note,
                    })
                })
                .collect::<Vec<_>>()
        };
        serde_json::json!({
            "budget_us": crate::cost::BUDGET.as_secs_f64() * 1e6,
            "desk_study": rows(&self.desk_study),
            "measured": rows(&self.measured),
            "baseline_round_trip_us": self.baseline_round_trip.as_secs_f64() * 1e6,
            "measured_ratio_to_baseline": self.measured_ratio,
        })
    }
}
```

- [ ] **Step 4: Wire the flag**

In `src/bin/occultation.rs`, replace `let _ = composed;` and the surrounding rendering with:

```rust
            let costs = run_bench(&opts)?;
            if composed {
                let report = occultation::bench::composed_report(&costs);
                match format {
                    Format::Table => println!("{}", report.render()),
                    Format::Json => {
                        println!("{}", serde_json::to_string_pretty(&report.to_json())?)
                    }
                }
            } else {
                let table = costs.table();
                match format {
                    Format::Table => println!("{}", table.render()),
                    Format::Json => println!("{}", serde_json::to_string_pretty(&table.to_json())?),
                }
            }
            Ok(ExitCode::SUCCESS)
```

- [ ] **Step 5: Write acceptance test 1**

Create `tests/acceptance.rs`:

```rust
use occultation::bench::{composed_report, run_bench, BenchOptions};
use occultation::cost::{BudgetVerdict, BUDGET};
use std::time::Duration;

/// Acceptance test 1, part 1 — the paper's headline correction.
///
/// Asserted against the desk study's published figures rather than this host's
/// wall clock, because the claim is about a composition error and must
/// reproduce identically on any machine. See the plan's Task 8 for why a
/// measured-wall-clock form of this assertion would be host-dependent and, on
/// current hardware, false.
#[test]
fn the_composed_path_misses_the_budget_without_pre_computation() {
    let costs = run_bench(&BenchOptions { iters: 5, ..Default::default() }).unwrap();
    let report = composed_report(&costs);

    let naive = &report.desk_study[0];
    assert!(naive.published);
    assert_eq!(naive.composed.present, Duration::from_micros(13_800));
    assert_eq!(naive.composed.verify, Duration::from_micros(4_200));
    assert_eq!(naive.composed.total, Duration::from_micros(18_000));
    assert!(
        naive.composed.total > BUDGET,
        "18 ms must exceed the 15 ms budget"
    );
    assert_eq!(naive.composed.verdict, BudgetVerdict::Misses { over: Duration::from_millis(3) });
}

/// Acceptance test 1, part 2 — with pre-computation it fits.
#[test]
fn the_composed_path_fits_the_budget_with_pre_computation() {
    let costs = run_bench(&BenchOptions { iters: 5, ..Default::default() }).unwrap();
    let report = composed_report(&costs);

    let pooled = &report.desk_study[2];
    assert_eq!(pooled.composed.total, Duration::from_micros(3_900));
    assert!(pooled.composed.total < BUDGET);
    assert_eq!(
        pooled.composed.verdict,
        BudgetVerdict::Fits { headroom: Duration::from_micros(11_100) }
    );
}

/// The half-measure in between, and the reason `Marginal` exists. Cached
/// pairings alone bring the sum to 14.9 ms: under the limit, with 100 us
/// left, which is not headroom.
#[test]
fn cached_pairings_alone_are_marginal_rather_than_a_pass() {
    let costs = run_bench(&BenchOptions { iters: 5, ..Default::default() }).unwrap();
    let report = composed_report(&costs);
    let cached = &report.desk_study[1];
    assert_eq!(cached.composed.total, Duration::from_micros(14_900));
    assert_eq!(
        cached.composed.verdict,
        BudgetVerdict::Marginal { headroom: Duration::from_micros(100) }
    );
}

/// The property that must hold for measured numbers too, on any host: the
/// budget is applied to a sum, never to a half.
#[test]
fn no_verdict_is_ever_issued_against_half_a_path() {
    let costs = run_bench(&BenchOptions { iters: 5, ..Default::default() }).unwrap();
    let report = composed_report(&costs);
    for row in report.desk_study.iter().chain(report.measured.iter()) {
        assert_eq!(row.composed.total, row.composed.present + row.composed.verify);
    }
}
```

- [ ] **Step 6: Run everything**

```bash
cargo test
cargo run --release -- bench --composed
```

Expected: tests pass; the output shows two blocks, the published one reporting `MISSES by 3.00 ms` on the naive row and `MARGINAL` on the cached row, and the measured one reporting this host's numbers with the divergence stated.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add `bench --composed` and the headline correction

The desk study assessed 13.8 ms presentation and 4.2 ms verification
separately against a 15 ms budget and called each acceptable. Summed, that
is 18 ms and it misses. With cached pairings it is 14.9 ms, which the tool
reports as MARGINAL rather than a pass, because 100 us of headroom leaves
nothing for the application.

Acceptance test 1 asserts this against the published figures, which
reproduce on any host. Measured figures on this stack are roughly an order
of magnitude smaller and are reported beside them, with the divergence
stated. The correction is unaffected: it is an error in arithmetic, not in
hardware.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: The pre-computation pool — stall, never reuse

**Files:**
- Create: `src/pool.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `bbs::proof::{ProofScalars, prove_with_scalars}`, `harness`.
- Produces: `pool::{PoolItem, PrecomputationPool, PoolError, BurstConfig, BurstReport, simulate_burst}`.
  - `PoolItem` — **not `Clone`, not `Copy`.** `PoolItem::consume<R>(self, f: impl FnOnce(&ProofScalars) -> R) -> R` moves the item in, lends its scalars for the duration of one call, and drops them. `PoolItem::fingerprint(&self) -> [u8; 32]`.
  - `PrecomputationPool::new(capacity, undisclosed, seed)`, `.fill()`, `.refill_one() -> bool`, `.acquire() -> Option<PoolItem>`, `.len()`, `.capacity()`, `.produced()`, `.issued()`, `.exhaustions()`.
  - `simulate_burst(&BurstConfig) -> Result<BurstReport, PoolError>`.

**This task carries a security invariant, and the invariant is not a preference.** P05 names two behaviours on exhaustion — stall, or reuse — and calls both unacceptable. Reuse is worse than unacceptable: it is silently catastrophic, and the tool must make it unrepresentable rather than merely discouraged. There is no reuse flag, no configuration key, and no `--allow-reuse`. Do not add one, and reject a review comment asking for one.

**Why reuse is catastrophic, and not merely "linkable".** Two presentations sharing one `ProofScalars` share `Abar` and `D`, so a relying party links them on sight. Worse, the two transcripts have different challenges over the same commitments, so the witness falls out by subtraction:

```
e     = (ê₁ − ê₂) / (c₁ − c₂)
m_j   = (m̂_j₁ − m̂_j₂) / (c₁ − c₂)
```

Every undisclosed attribute and the signature's `e` are recovered by anyone who sees both. A test demonstrates this by actually performing the extraction, so the consequence is a measured fact in the repository rather than a warning in a comment.

- [ ] **Step 1: Write the failing test**

Create `src/pool.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs::keys::KeyPair;
    use crate::bbs::proof::{prove_with_scalars, verify_proof};
    use crate::bbs::sign::{message_to_scalar, sign};
    use crate::bls::Generators;
    use ff::Field;
    use std::collections::HashSet;

    /// Compile-time guard: `PoolItem` must never gain `Clone`.
    ///
    /// Autoref specialization — the by-value impl needs one autoref and the
    /// `&Probe<T>` impl needs two, so Rust picks the first when `T: Clone` and
    /// falls back otherwise. If this becomes a maintenance burden, delete it
    /// and keep the behavioural tests below, but do not delete it *and* add
    /// `#[derive(Clone)]`.
    mod clone_probe {
        use std::marker::PhantomData;
        pub struct Probe<T>(pub PhantomData<T>);
        pub trait IsClone {
            fn probe(&self) -> bool;
        }
        impl<T: Clone> IsClone for Probe<T> {
            fn probe(&self) -> bool {
                true
            }
        }
        pub trait NotClone {
            fn probe(&self) -> bool;
        }
        impl<T> NotClone for &Probe<T> {
            fn probe(&self) -> bool {
                false
            }
        }
    }

    #[test]
    fn pool_items_are_not_clonable() {
        use clone_probe::{IsClone, NotClone};
        use std::marker::PhantomData;
        let item = clone_probe::Probe::<PoolItem>(PhantomData);
        assert!(!(&item).probe(), "PoolItem gained Clone; blinding reuse is now representable");
        // Control: the probe does detect Clone when it is present.
        let control = clone_probe::Probe::<u64>(PhantomData);
        assert!((&control).probe());
    }

    #[test]
    fn an_empty_pool_hands_back_nothing_rather_than_something_old() {
        let mut p = PrecomputationPool::new(2, 3, 7);
        p.fill();
        assert!(p.acquire().is_some());
        assert!(p.acquire().is_some());
        assert!(p.acquire().is_none(), "an exhausted pool must yield None, never a used item");
        assert_eq!(p.exhaustions(), 1);
    }

    #[test]
    fn every_item_a_pool_ever_issues_is_distinct() {
        let mut p = PrecomputationPool::new(8, 3, 7);
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..500 {
            p.fill();
            let item = p.acquire().expect("just filled");
            assert!(seen.insert(item.fingerprint()), "a blinding factor was issued twice");
        }
        assert_eq!(seen.len(), 500);
        assert_eq!(p.issued(), 500);
    }

    #[test]
    fn refilling_a_full_pool_produces_nothing() {
        let mut p = PrecomputationPool::new(3, 1, 7);
        p.fill();
        assert_eq!(p.len(), 3);
        assert!(!p.refill_one(), "a full pool must not grow past capacity");
        assert_eq!(p.produced(), 3);
    }

    #[test]
    fn a_zero_capacity_pool_is_an_error_not_a_permanent_stall() {
        assert!(PrecomputationPool::try_new(0, 1, 7).is_err());
    }

    /// The demonstration. This is what the type system prevents, shown by
    /// bypassing the pool and calling the low-level prover twice with one set
    /// of scalars.
    #[test]
    fn reusing_one_set_of_scalars_leaks_the_signature_and_every_hidden_attribute() {
        let kp = KeyPair::generate(7);
        let gens = Generators::create(4);
        let msgs: Vec<Scalar> = (0..4)
            .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
            .collect();
        let sig = sign(&kp.sk, &kp.pk, &gens, b"h", &msgs).unwrap();
        let disclosed = [0usize];
        let pairs: Vec<(usize, Scalar)> = vec![(0, msgs[0])];

        // One set of scalars, two presentations to two relying parties.
        let s = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(99), 3);
        let p1 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-one", &sig, &msgs, &disclosed, &s)
            .unwrap();
        let p2 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-two", &sig, &msgs, &disclosed, &s)
            .unwrap();

        // Both are individually valid, so neither relying party sees a problem.
        assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-one", &pairs, &p1).unwrap());
        assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-two", &pairs, &p2).unwrap());

        // Linkage, on sight.
        assert_eq!(p1.a_bar, p2.a_bar, "reuse makes two showings trivially linkable");
        assert_eq!(p1.d, p2.d);

        // And the witness falls out by subtraction.
        let dc = Option::<Scalar>::from((p1.challenge - p2.challenge).invert()).unwrap();
        let recovered_e = (p1.e_hat - p2.e_hat) * dc;
        assert_eq!(recovered_e, sig.e, "the signature scalar is recoverable");

        // Undisclosed attributes 1, 2 and 3, in order.
        for (k, j) in [1usize, 2, 3].into_iter().enumerate() {
            let recovered = (p1.m_hat[k] - p2.m_hat[k]) * dc;
            assert_eq!(recovered, msgs[j], "hidden attribute {j} is recoverable");
        }
    }

    #[test]
    fn a_burst_below_the_refill_rate_never_stalls() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000), // 1000 items/s
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 100.0, // well under refill
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();
        assert!(!r.exhausted, "a pool refilling faster than it drains cannot exhaust");
        assert_eq!(r.stalled, 0);
        assert_eq!(r.stall_max, Duration::ZERO);
    }

    #[test]
    fn a_burst_above_the_refill_rate_exhausts_and_stalls() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000), // 1000 items/s
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0, // four times refill
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();
        assert!(r.exhausted);
        assert!(r.stalled > 0);
        assert!(r.stall_max > Duration::ZERO);
        assert_eq!(r.reuse_events, 0, "the pool must stall, never reuse");
        assert_eq!(r.distinct_blinding_factors, r.requests, "every request got a fresh item");
    }

    #[test]
    fn the_stall_grows_through_a_sustained_burst() {
        // The side channel: latency is not merely worse under load, it climbs,
        // so an observer can read burst length off response times.
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0,
            duration: Duration::from_secs(2),
            seed: 7,
        };
        let r = simulate_burst(&cfg).unwrap();
        assert!(r.latency_max > r.latency_p50 * 10, "amplification {}", r.amplification);
        assert!(r.amplification > 10.0);
    }

    #[test]
    fn the_simulation_is_deterministic() {
        let cfg = BurstConfig {
            capacity: 16,
            refill_cost: Duration::from_micros(800),
            online_cost: Duration::from_micros(40),
            burst_rate_hz: 3_000.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        let a = simulate_burst(&cfg).unwrap();
        let b = simulate_burst(&cfg).unwrap();
        assert_eq!(a.requests, b.requests);
        assert_eq!(a.stalled, b.stalled);
        assert_eq!(a.stall_total, b.stall_total);
        assert_eq!(a.latency_p99, b.latency_p99);
    }

    #[test]
    fn a_nonpositive_burst_rate_is_an_error_not_an_infinite_loop() {
        let base = BurstConfig {
            capacity: 8,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 0.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        assert!(simulate_burst(&base).is_err());
        assert!(simulate_burst(&BurstConfig { burst_rate_hz: -5.0, ..base.clone() }).is_err());
        assert!(simulate_burst(&BurstConfig { burst_rate_hz: f64::NAN, ..base.clone() }).is_err());
        assert!(simulate_burst(&BurstConfig {
            refill_cost: Duration::ZERO,
            ..base.clone()
        })
        .is_err());
    }

    #[test]
    fn an_absurd_request_count_is_refused_rather_than_allocated() {
        let cfg = BurstConfig {
            capacity: 8,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 1e9,
            duration: Duration::from_secs(3_600),
            seed: 7,
        };
        assert!(simulate_burst(&cfg).is_err(), "3.6e12 requests must not be attempted");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib pool`
Expected: FAIL — `cannot find type PoolItem in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/pool.rs`:

```rust
use crate::bbs::proof::ProofScalars;
use blstrs::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

/// Above this many simulated requests the run is refused rather than
/// allocated. A burst description that implies billions of actions is a typo,
/// and turning it into an out-of-memory kill helps nobody.
const MAX_REQUESTS: usize = 20_000_000;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("a pool needs capacity of at least 1, got {0}")]
    ZeroCapacity(usize),
    #[error("burst rate must be a positive number of requests per second, got {0}")]
    BadBurstRate(f64),
    #[error("refill cost must be greater than zero")]
    ZeroRefillCost,
    #[error("that burst implies {0} requests, above the {MAX_REQUESTS} limit; shorten --duration or lower --burst")]
    TooManyRequests(u128),
}

/// One pre-computed presentation's worth of blinding.
///
/// **Not `Clone` and not `Copy`, deliberately.** `consume` takes `self` by
/// value, lends the scalars for exactly one call and drops them. There is no
/// way through this API to present twice from one item, which is the point:
/// blinding reuse silently voids the unlinkability property the whole of P05
/// is about, and it also hands an observer of two transcripts the signature
/// scalar and every undisclosed attribute. See the test
/// `reusing_one_set_of_scalars_leaks_the_signature_and_every_hidden_attribute`.
pub struct PoolItem {
    scalars: ProofScalars,
    serial: u64,
}

impl PoolItem {
    /// Use this item, once.
    pub fn consume<R>(self, f: impl FnOnce(&ProofScalars) -> R) -> R {
        f(&self.scalars)
    }

    /// A stable identifier for the item's blinding, for the uniqueness audit.
    /// Derived from `r1`, which is the scalar whose repetition would be
    /// immediately observable as a repeated `Abar`.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.scalars.r1.to_bytes_be()
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }
}

/// A pool of pre-computed blinding, refilled by an idle-time worker.
///
/// On exhaustion `acquire` returns `None`. The caller stalls. It never returns
/// a previously issued item, and there is no configuration under which it
/// would.
pub struct PrecomputationPool {
    capacity: usize,
    items: VecDeque<PoolItem>,
    rng: ChaCha20Rng,
    undisclosed: usize,
    next_serial: u64,
    produced: u64,
    issued: u64,
    exhaustions: u64,
}

impl PrecomputationPool {
    pub fn try_new(capacity: usize, undisclosed: usize, seed: u64) -> Result<Self, PoolError> {
        if capacity == 0 {
            return Err(PoolError::ZeroCapacity(capacity));
        }
        Ok(PrecomputationPool {
            capacity,
            items: VecDeque::with_capacity(capacity),
            rng: ChaCha20Rng::seed_from_u64(seed),
            undisclosed,
            next_serial: 0,
            produced: 0,
            issued: 0,
            exhaustions: 0,
        })
    }

    /// Convenience for tests and callers that have already validated capacity.
    pub fn new(capacity: usize, undisclosed: usize, seed: u64) -> Self {
        Self::try_new(capacity, undisclosed, seed).expect("capacity >= 1")
    }

    /// Produce one item. Returns false when the pool is already full.
    pub fn refill_one(&mut self) -> bool {
        if self.items.len() >= self.capacity {
            return false;
        }
        let scalars = ProofScalars::random(&mut self.rng, self.undisclosed);
        self.items.push_back(PoolItem { scalars, serial: self.next_serial });
        self.next_serial += 1;
        self.produced += 1;
        true
    }

    pub fn fill(&mut self) {
        while self.refill_one() {}
    }

    /// Take an item, or `None` if there are none.
    ///
    /// `None` means stall. It does not mean "reuse the last one".
    pub fn acquire(&mut self) -> Option<PoolItem> {
        match self.items.pop_front() {
            Some(item) => {
                self.issued += 1;
                Some(item)
            }
            None => {
                self.exhaustions += 1;
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn produced(&self) -> u64 {
        self.produced
    }

    pub fn issued(&self) -> u64 {
        self.issued
    }

    pub fn exhaustions(&self) -> u64 {
        self.exhaustions
    }
}

#[derive(Clone, Debug)]
pub struct BurstConfig {
    pub capacity: usize,
    /// Wall-clock cost of pre-computing one item inside the TEE.
    pub refill_cost: Duration,
    /// Wall-clock cost of finishing a presentation once an item is in hand.
    pub online_cost: Duration,
    pub burst_rate_hz: f64,
    pub duration: Duration,
    pub seed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BurstReport {
    pub requests: usize,
    pub served_immediately: usize,
    pub stalled: usize,
    pub exhausted: bool,
    pub refill_rate_hz: f64,
    pub burst_rate_hz: f64,
    pub stall_total: Duration,
    pub stall_max: Duration,
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub latency_p99: Duration,
    pub latency_max: Duration,
    /// `latency_max / latency_p50`. How far a busy agent's response time
    /// departs from its idle one — the size of the timing side channel.
    pub amplification: f64,
    pub distinct_blinding_factors: usize,
    /// Always zero. Present so the report says so out loud, and computed from
    /// the issued fingerprints rather than asserted, so it would catch a pool
    /// that started handing items out twice.
    pub reuse_events: usize,
}

/// Run a burst against a pool.
///
/// Refill is modelled as one worker producing at `1/refill_cost`, capped at
/// `capacity`, using a fluid approximation of the queue level. Item issuance
/// is not approximated: every served request takes a real `PoolItem` with real
/// scalars, so the uniqueness audit measures the actual pool rather than the
/// model of it.
pub fn simulate_burst(cfg: &BurstConfig) -> Result<BurstReport, PoolError> {
    if !cfg.burst_rate_hz.is_finite() || cfg.burst_rate_hz <= 0.0 {
        return Err(PoolError::BadBurstRate(cfg.burst_rate_hz));
    }
    if cfg.refill_cost.is_zero() {
        return Err(PoolError::ZeroRefillCost);
    }
    let implied = (cfg.duration.as_secs_f64() * cfg.burst_rate_hz).ceil();
    if !implied.is_finite() || implied > MAX_REQUESTS as f64 {
        return Err(PoolError::TooManyRequests(implied as u128));
    }
    let requests = implied as usize;

    let mut pool = PrecomputationPool::try_new(cfg.capacity, 8, cfg.seed)?;
    pool.fill();

    let refill_rate = 1.0 / cfg.refill_cost.as_secs_f64();
    let interval = 1.0 / cfg.burst_rate_hz;
    let capacity = cfg.capacity as f64;

    // Items available, as a real number. Starts full.
    let mut level = capacity;
    let mut last_t = 0.0f64;

    let mut latencies: Vec<Duration> = Vec::with_capacity(requests);
    let mut stalls: Vec<Duration> = Vec::with_capacity(requests);
    let mut fingerprints: HashSet<[u8; 32]> = HashSet::with_capacity(requests);
    let mut served_immediately = 0usize;
    let mut stalled = 0usize;

    for k in 0..requests {
        let t = k as f64 * interval;
        level = (level + (t - last_t) * refill_rate).min(capacity);
        last_t = t;

        let stall_secs = if level >= 1.0 {
            level -= 1.0;
            served_immediately += 1;
            0.0
        } else {
            // Wait for the worker to finish the item in progress.
            let wait = (1.0 - level) / refill_rate;
            level = 0.0;
            last_t = t + wait;
            stalled += 1;
            wait
        };

        // Real item, real scalars, real fingerprint.
        pool.fill();
        let item = pool.acquire().expect("just filled");
        fingerprints.insert(item.fingerprint());

        let stall = Duration::from_secs_f64(stall_secs);
        stalls.push(stall);
        latencies.push(cfg.online_cost + stall);
    }

    latencies.sort_unstable();
    let pick = |q: f64| -> Duration {
        if latencies.is_empty() {
            Duration::ZERO
        } else {
            latencies[(((latencies.len() - 1) as f64) * q).round() as usize]
        }
    };
    let p50 = pick(0.50);
    let latency_max = latencies.last().copied().unwrap_or_default();

    Ok(BurstReport {
        requests,
        served_immediately,
        stalled,
        exhausted: stalled > 0,
        refill_rate_hz: refill_rate,
        burst_rate_hz: cfg.burst_rate_hz,
        stall_total: stalls.iter().sum(),
        stall_max: stalls.iter().copied().max().unwrap_or_default(),
        latency_p50: p50,
        latency_p95: pick(0.95),
        latency_p99: pick(0.99),
        latency_max,
        amplification: if p50.is_zero() {
            1.0
        } else {
            latency_max.as_secs_f64() / p50.as_secs_f64()
        },
        distinct_blinding_factors: fingerprints.len(),
        reuse_events: requests - fingerprints.len(),
    })
}
```

Add the missing test imports at the top of the `tests` module: `use blstrs::Scalar; use rand_chacha::ChaCha20Rng; use rand_core::SeedableRng; use std::time::Duration;`.

Update `src/lib.rs` to add `pub mod pool;`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib pool`
Expected: PASS, 12 tests. `reusing_one_set_of_scalars_leaks_the_signature_and_every_hidden_attribute` passing is the important one — it means the extraction really works, which is why the pool's API forbids it.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add the pre-computation pool: stall, never reuse

PoolItem is not Clone and is consumed by value, so presenting twice from
one item is unrepresentable through the public API. There is no reuse
flag and there must not be one.

A test performs the extraction that reuse enables: two presentations
sharing one set of scalars are individually valid, are linkable on sight,
and yield the signature scalar and every undisclosed attribute by
subtraction. Reuse does not merely weaken unlinkability; it hands over
the credential.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: `occultation pool` and acceptance test 2

**Files:**
- Modify: `src/pool.rs`, `src/bin/occultation.rs`, `tests/acceptance.rs`

**Interfaces:**
- Consumes: `pool::{BurstConfig, BurstReport, simulate_burst}`, `bench::run_bench`.
- Produces: `pool::BurstReport::{render, to_json}`. CLI: `occultation pool --burst <rate> [--duration 10s] [--capacity 64] [--refill <duration>] [--online <duration>] [--max-stall <duration>] [--seed N] [--format table|json]`. Exit 1 when `--max-stall` is exceeded.

Refill and online costs default to values measured on this host rather than invented: refill is one presentation's group work, approximated by the measured presentation cost; online is the measured cost minus that, approximated by two hash-to-scalar operations. Both defaults are stated in the output, so a reader can see they are measured rather than assumed.

- [ ] **Step 1: Write the failing test**

Append to `src/pool.rs`'s test module:

```rust
    #[test]
    fn the_report_names_the_two_behaviours_and_says_which_one_it_chose() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        let out = simulate_burst(&cfg).unwrap().render();
        assert!(out.contains("EXHAUSTED"), "{out}");
        assert!(out.contains("stall"), "{out}");
        assert!(out.contains("reuse"), "the report must address reuse explicitly: {out}");
        assert!(out.contains("0"), "reuse events must be reported as a number: {out}");
    }

    #[test]
    fn a_healthy_run_reports_no_exhaustion() {
        let cfg = BurstConfig {
            capacity: 32,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 100.0,
            duration: Duration::from_secs(1),
            seed: 7,
        };
        let out = simulate_burst(&cfg).unwrap().render();
        assert!(!out.contains("EXHAUSTED"), "{out}");
    }

    #[test]
    fn json_reports_reuse_events_as_a_field() {
        let cfg = BurstConfig {
            capacity: 8,
            refill_cost: Duration::from_micros(1_000),
            online_cost: Duration::from_micros(50),
            burst_rate_hz: 4_000.0,
            duration: Duration::from_millis(500),
            seed: 7,
        };
        let v = simulate_burst(&cfg).unwrap().to_json();
        assert_eq!(v["reuse_events"], 0);
        assert_eq!(v["exhausted"], true);
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib pool`
Expected: FAIL — no method named `render` on `BurstReport`.

- [ ] **Step 3: Write the rendering**

Append to `src/pool.rs`:

```rust
impl BurstReport {
    pub fn render(&self) -> String {
        let ms = |d: Duration| format!("{:.3} ms", d.as_secs_f64() * 1e3);
        let mut out = String::from("Pre-computation pool under burst\n\n");
        out.push_str(&format!(
            "  burst rate           {:.0} presentations/s\n  refill rate          {:.0} items/s\n",
            self.burst_rate_hz, self.refill_rate_hz
        ));
        out.push_str(&format!(
            "  requests             {}\n  served from pool     {}\n  stalled              {}\n",
            self.requests, self.served_immediately, self.stalled
        ));
        if self.exhausted {
            out.push_str("\n  POOL EXHAUSTED\n");
        }
        out.push_str(&format!(
            "\n  latency p50          {}\n  latency p95          {}\n  latency p99          {}\n  \
             latency max          {}\n  amplification        {:.1}x\n  total stall          {}\n  \
             worst stall          {}\n",
            ms(self.latency_p50),
            ms(self.latency_p95),
            ms(self.latency_p99),
            ms(self.latency_max),
            self.amplification,
            ms(self.stall_total),
            ms(self.stall_max),
        ));
        out.push_str(&format!(
            "\n  distinct blinding factors issued   {}\n  blinding-factor reuse events       {}\n",
            self.distinct_blinding_factors, self.reuse_events
        ));
        out.push_str(
            "\nOn exhaustion there are two available behaviours. This tool stalls. It does not\n\
             reuse, and reuse is not configurable: two presentations sharing one blinding\n\
             factor are linkable on sight, and an observer of both transcripts recovers the\n\
             signature scalar and every undisclosed attribute by subtraction.\n\n\
             Stalling is not free either. The amplification figure above is the size of the\n\
             timing side channel: how far a busy agent's response time departs from its idle\n\
             one, and therefore how much of its load an observer can read off latency alone.\n",
        );
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("BurstReport is serializable")
    }
}
```

`Duration` serializes as `{secs, nanos}` by default, which is awkward to read. Add `#[serde(serialize_with = ...)]` helpers converting each `Duration` field to microseconds as `f64`, or change the fields' serialization with a small module — either is fine, but the JSON must carry microseconds as numbers, and a test should assert `v["stall_max_us"].is_number()` once the shape is chosen. Pick one shape and keep it consistent with `report.rs`'s `cost_us`.

- [ ] **Step 4: Add the CLI subcommand**

Add to `Cmd` in `src/bin/occultation.rs`:

```rust
    /// Pre-computation pool under load
    Pool {
        /// Presentations per second during the burst
        #[arg(long)]
        burst: f64,
        #[arg(long, default_value = "10s")]
        duration: humantime::Duration,
        #[arg(long, default_value_t = 64)]
        capacity: usize,
        /// Cost of pre-computing one pool item; defaults to a measured presentation
        #[arg(long)]
        refill: Option<humantime::Duration>,
        /// Cost of finishing a presentation from a pool item; defaults to measured
        #[arg(long)]
        online: Option<humantime::Duration>,
        /// Exit 1 if the worst stall exceeds this
        #[arg(long)]
        max_stall: Option<humantime::Duration>,
        #[arg(long, default_value_t = 7)]
        seed: u64,
        #[arg(long, default_value = "table")]
        format: Format,
    },
```

And to `run()`:

```rust
        Cmd::Pool { burst, duration, capacity, refill, online, max_stall, seed, format } => {
            // Defaults come from this host, not from a guess. Measuring costs a
            // second; inventing a refill cost would make the whole simulation
            // fiction.
            let (refill_cost, online_cost) = match (refill, online) {
                (Some(r), Some(o)) => (r.into(), o.into()),
                (r, o) => {
                    let costs = run_bench(&BenchOptions { iters: 30, seed, ..Default::default() })?;
                    (
                        r.map(Into::into).unwrap_or(costs.present.median),
                        o.map(Into::into).unwrap_or(costs.hash_to_scalar.median * 2),
                    )
                }
            };
            let cfg = occultation::pool::BurstConfig {
                capacity,
                refill_cost,
                online_cost,
                burst_rate_hz: burst,
                duration: duration.into(),
                seed,
            };
            let report = occultation::pool::simulate_burst(&cfg)?;
            match format {
                Format::Table => println!("{}", report.render()),
                Format::Json => println!("{}", serde_json::to_string_pretty(&report.to_json())?),
            }
            if let Some(limit) = max_stall {
                if report.stall_max > limit.into() {
                    eprintln!(
                        "VIOLATION: worst stall {:?} exceeds --max-stall {:?}",
                        report.stall_max,
                        Duration::from(limit)
                    );
                    return Ok(ExitCode::from(1));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
```

- [ ] **Step 5: Write acceptance test 2**

Append to `tests/acceptance.rs`:

```rust
use occultation::bbs::keys::KeyPair;
use occultation::bbs::proof::{prove_with_scalars, verify_proof};
use occultation::bbs::sign::{message_to_scalar, sign};
use occultation::bls::Generators;
use occultation::pool::{simulate_burst, BurstConfig, PrecomputationPool};
use std::collections::HashSet;

/// Acceptance test 2 — the pool exhausts under burst, and stalls rather than
/// reusing.
#[test]
fn a_burst_above_the_refill_rate_exhausts_and_stalls_without_reusing() {
    let cfg = BurstConfig {
        capacity: 64,
        refill_cost: Duration::from_micros(700), // ~1430 items/s
        online_cost: Duration::from_micros(60),
        burst_rate_hz: 5_000.0, // well above refill
        duration: Duration::from_secs(2),
        seed: 7,
    };
    let r = simulate_burst(&cfg).unwrap();

    assert!(r.exhausted, "5000/s against ~1430/s refill must exhaust the pool");
    assert!(r.stalled > 0, "exhaustion must produce stalls");
    assert!(r.stall_max > Duration::ZERO);

    // The invariant. Not a preference, not a tuning choice.
    assert_eq!(r.reuse_events, 0, "the pool reused a blinding factor");
    assert_eq!(
        r.distinct_blinding_factors, r.requests,
        "every one of {} requests must have had its own blinding",
        r.requests
    );

    // And the cost of stalling, which is the finding: latency under load is a
    // side channel, not merely a slowdown.
    assert!(r.amplification > 5.0, "amplification was only {:.1}x", r.amplification);
}

/// The invariant again, at the level of the pool itself rather than the
/// simulation: an exhausted pool yields nothing rather than something used.
#[test]
fn an_exhausted_pool_yields_nothing_rather_than_a_used_item() {
    let mut pool = PrecomputationPool::new(4, 3, 7);
    pool.fill();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for _ in 0..4 {
        seen.insert(pool.acquire().expect("pool was filled").fingerprint());
    }
    assert_eq!(seen.len(), 4);
    assert!(pool.acquire().is_none(), "an exhausted pool must stall its caller");
    assert_eq!(pool.exhaustions(), 1);
}

/// Why the invariant is an invariant. Reuse is not a degradation of
/// unlinkability; it discloses the credential.
#[test]
fn reuse_would_hand_over_the_signature_and_every_hidden_attribute() {
    use blstrs::Scalar;
    use ff::Field;
    use occultation::bbs::proof::ProofScalars;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let kp = KeyPair::generate(7);
    let gens = Generators::create(4);
    let msgs: Vec<Scalar> = (0..4)
        .map(|i| message_to_scalar(format!("attribute-{i}").as_bytes()).unwrap())
        .collect();
    let sig = sign(&kp.sk, &kp.pk, &gens, b"h", &msgs).unwrap();
    let pairs = vec![(0usize, msgs[0])];

    let s = ProofScalars::random(&mut ChaCha20Rng::seed_from_u64(99), 3);
    let p1 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-one", &sig, &msgs, &[0], &s).unwrap();
    let p2 = prove_with_scalars(&kp.pk, &gens, b"h", b"rp-two", &sig, &msgs, &[0], &s).unwrap();

    assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-one", &pairs, &p1).unwrap());
    assert!(verify_proof(&kp.pk, &gens, b"h", b"rp-two", &pairs, &p2).unwrap());

    let dc = Option::<Scalar>::from((p1.challenge - p2.challenge).invert()).unwrap();
    assert_eq!((p1.e_hat - p2.e_hat) * dc, sig.e);
    for (k, j) in [1usize, 2, 3].into_iter().enumerate() {
        assert_eq!((p1.m_hat[k] - p2.m_hat[k]) * dc, msgs[j]);
    }
}
```

- [ ] **Step 6: Run everything**

```bash
cargo test
cargo run --release -- pool --burst 5000 --duration 2s
cargo run --release -- pool --burst 100 --duration 2s
```

Expected: the first reports `POOL EXHAUSTED` with a large amplification and zero reuse events; the second reports no exhaustion.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add `occultation pool` and the exhaustion acceptance test

Under a burst above the refill rate the pool exhausts, stalls, and issues
a distinct blinding factor for every single request — asserted, not
assumed. The report states both available behaviours, says which one was
chosen, and reports the amplification figure, which is the size of the
timing side channel that stalling buys in exchange.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---
