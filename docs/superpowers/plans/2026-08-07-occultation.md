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
