# parallax-proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `parallax` from a description tool into a verification tool — verify a real Intel TDX quote, derive the residual trust set from the verification steps actually performed, and gate a reverse proxy on it.

**Architecture:** A new `verify` module drives `dcap-qvl` (pure Rust) against a real captured quote and its collateral, with an injected clock so tests run offline and deterministically. A `derive` module turns the verification outcome into the same `TrustSet` type the existing calculus produces, and a cross-check test asserts the two routes agree. Only then is the proxy wired on top, reusing the existing policy engine and manifest emitter unchanged.

**Tech Stack:** Rust 2021, `dcap-qvl` 0.6, `x509-parser`, `rustls` + `tokio-rustls`, `hyper` 1, `tokio`, `reqwest` (collateral), plus the existing `serde`/`toml`/`clap`/`thiserror`/`anyhow`.

## Global Constraints

- Rust edition **2021**, `rust-version = "1.90"`. `cargo clippy --all-targets -- -D warnings` must pass; warnings are errors.
- Library errors use `thiserror`; binaries use `anyhow`. Errors print with `{e}`, never `{e:#}` — the library types already interpolate their own source.
- **No panics on malformed input.** This code parses hostile bytes from the network by definition. Every parser returns `Result`. No `unwrap`, `expect`, slice indexing, or unchecked integer conversion on anything that came off a socket or out of a file.
- **Fail closed.** Any verification failure, collateral failure, or policy violation refuses the connection. There is no allow-on-error mode.
- **Time is always injected, never read from the system clock**, in every function that can be reached from a test. `dcap-qvl::verify` already takes `now_secs: u64`; carry that discipline through our own code.
- Exit codes: `0` clean, `1` policy violation, `2` bad input or configuration.
- Reuse `Latency`, `Assumption`, `Impact`, `TrustSet`, `policy::evaluate`, and `manifest::manifest` **unchanged**. If a change to one seems necessary, stop and report it rather than editing.
- `TrustSet` has a hand-written subset `PartialOrd` and deliberately no `Ord`. Never use `<`/`<=` on it; use `is_subset`/`is_superset` or `compare`.
- Every commit message ends with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

## Verified upstream facts (do not re-litigate)

Established by reading `dcap-qvl` 0.6.1's source before this plan was written:

- `dcap_qvl::verify::verify(raw_quote: &[u8], collateral: &QuoteCollateralV3, now_secs: u64) -> Result<VerifiedReport>`
- `VerifiedReport { status: String, advisory_ids: Vec<String>, report: Report, ppid: Vec<u8>, qe_status: TcbStatusWithAdvisory, platform_status: TcbStatusWithAdvisory }`
- `qe_status` and `platform_status` are **separate**, which is what makes per-party attribution possible.
- `Report` is an enum; the TDX arm carries `TDReport10 { mr_td: [u8; 48], rt_mr0..rt_mr3: [u8; 48], report_data: [u8; 64], .. }`.
- `QuoteVerifier::new(root_ca_der: Vec<u8>)` allows a custom root; the crate ships `TrustedRootCA.der`. `allow_debug` and `allow_service_td` default to `false`.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/verify/mod.rs` | module wiring; `VerificationOutcome` |
| `src/verify/quote.rs` | extract the quote from an X.509 extension; parse `report_data`/`mr_td` |
| `src/verify/chain.rs` | drive `dcap-qvl`; map its errors to ours |
| `src/verify/binding.rs` | `report_data == SHA256(cert public key)` |
| `src/verify/refvals.rs` | compare `mr_td` against configured reference values |
| `src/derive.rs` | `VerificationOutcome` → `TrustSet` |
| `src/collateral/mod.rs` | fetch from PCS/PCCS, cache with TTL |
| `src/proxy/mod.rs` | listener, upstream dialler, forwarding, gate |
| `src/bin/parallax-proxy.rs` | CLI and config |
| `tests/fixtures/gcp-c3-tdx/` | a real captured quote and its collateral |

---

### Task 1: Capture a real TDX quote and its collateral

**Files:**
- Create: `scripts/capture-fixture.sh`, `tests/fixtures/gcp-c3-tdx/{quote.bin,collateral.json,captured-at,PROVENANCE.md}`

**Interfaces:**
- Consumes: nothing.
- Produces: a fixture directory every later task verifies against. `captured-at` holds an RFC 3339 timestamp; `collateral.json` is a serialized `dcap_qvl::QuoteCollateralV3`.

This task needs a real TDX machine once. `ov-poc-standard/impl/tdx/run_on_gcp.sh` provisions a GCP C3 instance with `--confidential-compute-type=TDX` and deletes it afterwards, for a few tens of cents.

- [ ] **Step 1: Write the capture script**

Create `scripts/capture-fixture.sh`:

```bash
#!/usr/bin/env bash
# Capture a real TDX quote and its Intel collateral, once, for offline tests.
#
# Run this ON a TDX guest (GCP C3 with --confidential-compute-type=TDX, or
# equivalent). It writes a fixture directory that CI then verifies against
# forever, with the verification clock pinned to the capture time.
set -euo pipefail

OUT="${1:?usage: capture-fixture.sh <output-dir>}"
mkdir -p "$OUT"

# configfs-tsm is the vendor-neutral interface (Linux 6.7+). The same one
# ov-poc-standard/impl/poc/tdx.py uses.
TSM=/sys/kernel/config/tsm/report/parallax
[ -d /sys/kernel/config/tsm/report ] || { echo "no configfs-tsm; not a TDX guest?" >&2; exit 2; }

mkdir -p "$TSM"
# 64 bytes of report_data. For the fixture we use a fixed, obviously-fake
# value; Task 4 tests the real key binding separately.
printf '%064d' 0 > "$TSM/inblob"
cat "$TSM/outblob" > "$OUT/quote.bin"
rmdir "$TSM"

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/captured-at"
echo "wrote $OUT/quote.bin ($(stat -c%s "$OUT/quote.bin") bytes)"
echo "now fetch collateral with: cargo run --bin fetch-collateral -- $OUT"
```

`chmod +x scripts/capture-fixture.sh`

- [ ] **Step 2: Capture the quote**

Run `ov-poc-standard/impl/tdx/run_on_gcp.sh` to get a TDX instance, copy the
script over, run it, and copy `quote.bin` and `captured-at` back.

If no TDX machine is obtainable, **stop and report BLOCKED**. Do not synthesise
a quote — a verifier tested against our own fiction is exactly what this project
must not ship.

- [ ] **Step 3: Fetch the matching collateral**

Add a small helper binary `src/bin/fetch-collateral.rs`:

```rust
//! One-off: fetch the Intel collateral matching a captured quote and freeze it
//! next to the quote, so verification is testable offline.
use anyhow::{Context, Result};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let dir = PathBuf::from(std::env::args().nth(1).context("usage: fetch-collateral <dir>")?);
    let quote = std::fs::read(dir.join("quote.bin")).context("reading quote.bin")?;

    let collateral = dcap_qvl::collateral::get_collateral_for_fmspc_from_quote(&quote)
        .await
        .context("fetching collateral from Intel PCS")?;

    std::fs::write(dir.join("collateral.json"), serde_json::to_vec_pretty(&collateral)?)?;
    println!("wrote {}/collateral.json", dir.display());
    Ok(())
}
```

Check `dcap-qvl`'s `collateral` module for the exact fetch function name and
signature before writing this — the crate's API is the authority, not this
plan. If the name differs, use the real one and note it in your report.

- [ ] **Step 4: Record provenance**

Create `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`:

```markdown
# Fixture provenance

A **real** Intel TDX quote and the Intel collateral that was current when it
was captured. Not synthesised.

| | |
| --- | --- |
| Captured from | GCP C3 instance, `--confidential-compute-type=TDX` |
| Interface | Linux configfs-tsm (`/sys/kernel/config/tsm/report`) |
| Captured at | see `captured-at` |
| `report_data` | 64 zero bytes — a deliberate placeholder. The real key binding is tested separately in `verify::binding`. |

## Why the clock is pinned

CRLs and TCB info carry validity windows. Verified against the system clock,
this fixture stops verifying a few weeks after capture and CI turns red for a
reason that has nothing to do with the code. Tests therefore pass `captured-at`
as `now_secs`.

**When the opt-in live test fails**, Intel's collateral format or the TCB
baseline has moved. That is information, not a broken build: recapture with
`scripts/capture-fixture.sh` and commit the new fixture.
```

- [ ] **Step 5: Commit**

```bash
git add scripts/capture-fixture.sh src/bin/fetch-collateral.rs tests/fixtures/
git commit -m "$(cat <<'EOF'
Capture a real TDX quote and its collateral as a test fixture

Real, from a GCP C3 confidential VM over configfs-tsm — not synthesised,
because a verifier tested against our own fiction proves nothing. The
collateral is frozen alongside it and the verification clock is pinned to
the capture time, so CRL and TCB validity windows do not rot the build.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Verify the captured quote

**Files:**
- Create: `src/verify/mod.rs`, `src/verify/chain.rs`
- Modify: `src/lib.rs`, `Cargo.toml`

**Interfaces:**
- Consumes: the Task 1 fixture.
- Produces:
  - `pub struct VerificationOutcome { pub tcb_status: String, pub qe_status: String, pub platform_status: String, pub advisory_ids: Vec<String>, pub mr_td: [u8; 48], pub rt_mrs: [[u8; 48]; 4], pub report_data: [u8; 64], pub collateral_refresh: Latency, pub root_ca: RootCa }`
  - `pub enum RootCa { IntelProduction, Custom(String) }`
  - `pub fn verify_quote(quote: &[u8], collateral: &QuoteCollateralV3, now_secs: u64, root: &RootCa) -> Result<VerificationOutcome, VerifyError>`

- [ ] **Step 1: Add dependencies**

```toml
dcap-qvl = "0.6"
hex = "0.4"
```

- [ ] **Step 2: Write the failing test**

Create `src/verify/chain.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, dcap_qvl::QuoteCollateralV3, u64) {
        let dir = std::path::Path::new("tests/fixtures/gcp-c3-tdx");
        let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
        let collateral: dcap_qvl::QuoteCollateralV3 =
            serde_json::from_slice(&std::fs::read(dir.join("collateral.json")).expect("collateral"))
                .expect("collateral parses");
        let stamp = std::fs::read_to_string(dir.join("captured-at")).expect("captured-at");
        let now = humantime::parse_rfc3339(stamp.trim())
            .expect("captured-at is RFC 3339")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        (quote, collateral, now)
    }

    #[test]
    fn a_real_quote_verifies_at_its_capture_time() {
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction).expect("verifies");
        assert_eq!(out.mr_td.len(), 48);
        assert!(!out.tcb_status.is_empty());
    }

    #[test]
    fn qe_and_platform_status_are_reported_separately() {
        // The whole per-party attribution rests on these being distinct
        // signals rather than one boolean.
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction).unwrap();
        assert!(!out.qe_status.is_empty());
        assert!(!out.platform_status.is_empty());
    }

    #[test]
    fn a_truncated_quote_errors_and_does_not_panic() {
        let (q, c, now) = fixture();
        assert!(verify_quote(&q[..q.len() / 2], &c, now, &RootCa::IntelProduction).is_err());
    }

    #[test]
    fn an_empty_quote_errors_and_does_not_panic() {
        let (_, c, now) = fixture();
        assert!(verify_quote(&[], &c, now, &RootCa::IntelProduction).is_err());
    }

    #[test]
    fn verification_far_in_the_future_fails_on_expired_collateral() {
        // Ten years on, the CRLs and TCB info in the fixture are long expired.
        // This is the test that proves the clock is genuinely injected.
        let (q, c, now) = fixture();
        assert!(verify_quote(&q, &c, now + 10 * 365 * 24 * 3600, &RootCa::IntelProduction).is_err());
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib verify::chain`
Expected: FAIL — `cannot find function verify_quote in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `src/verify/chain.rs`:

```rust
use crate::latency::Latency;
use dcap_qvl::quote::Report;
use dcap_qvl::QuoteCollateralV3;

/// Which root of trust the chain was validated against. This is itself a
/// trust assumption — a custom root means trusting whoever chose it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootCa {
    IntelProduction,
    Custom(String),
}

/// What verification established, and — just as importantly — what it
/// assumed in order to establish it. Every field here becomes an assumption
/// in `derive`.
#[derive(Clone, Debug)]
pub struct VerificationOutcome {
    pub tcb_status: String,
    pub qe_status: String,
    pub platform_status: String,
    pub advisory_ids: Vec<String>,
    pub mr_td: [u8; 48],
    pub rt_mrs: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    /// How long collateral may be stale. Becomes the PCS assumption's bound.
    pub collateral_refresh: Latency,
    pub root_ca: RootCa,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("quote verification failed: {0}")]
    Rejected(String),
    #[error("quote is not a TDX report; parallax verifies TDX only")]
    NotTdx,
}

pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    root: &RootCa,
    collateral_refresh: Latency,
) -> Result<VerificationOutcome, VerifyError> {
    let verified = dcap_qvl::verify::verify(quote, collateral, now_secs)
        .map_err(|e| VerifyError::Rejected(format!("{e:?}")))?;

    let td = match &verified.report {
        Report::TD10(r) => r,
        _ => return Err(VerifyError::NotTdx),
    };

    Ok(VerificationOutcome {
        tcb_status: verified.status.clone(),
        qe_status: format!("{:?}", verified.qe_status),
        platform_status: format!("{:?}", verified.platform_status),
        advisory_ids: verified.advisory_ids.clone(),
        mr_td: td.mr_td,
        rt_mrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        report_data: td.report_data,
        collateral_refresh,
        root_ca: root.clone(),
    })
}
```

The `Report` enum's TDX variant name and the `QuoteVerifier` path for a custom
root must be checked against the installed crate source before you write this —
`Report::TD10` is this plan's best reading, not a guarantee. Use whatever the
crate actually defines and say so in your report. Note the signature gains
`collateral_refresh`; update the tests' call sites to pass
`Latency::parse("12h").unwrap()`.

Create `src/verify/mod.rs`:

```rust
pub mod chain;

pub use chain::{verify_quote, RootCa, VerificationOutcome, VerifyError};
```

Add `pub mod verify;` to `src/lib.rs`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib verify`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Verify a real TDX quote against frozen collateral

dcap-qvl takes an explicit now_secs, so the whole verification is testable
offline at a pinned clock. VerifiedReport reports QE and platform TCB
status separately, which is what makes per-party attribution possible in
the next task.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Derive the trust set from the verification

**Files:**
- Create: `src/derive.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `VerificationOutcome` (Task 2), `Assumption`/`Impact`/`TrustSet`/`Latency` (existing).
- Produces: `pub struct DeriveConfig { pub reference_values: Vec<[u8; 48]>, pub verifier_id: String, pub cache_ttl: Latency }` and `pub fn derive(o: &VerificationOutcome, cfg: &DeriveConfig) -> TrustSet`.

This is the task the whole design rests on: verification and enumeration are
the same act.

- [ ] **Step 1: Write the failing test**

Create `src/derive.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{RootCa, VerificationOutcome};

    fn outcome() -> VerificationOutcome {
        VerificationOutcome {
            tcb_status: "UpToDate".into(),
            qe_status: "UpToDate".into(),
            platform_status: "UpToDate".into(),
            advisory_ids: vec![],
            mr_td: [0xAB; 48],
            rt_mrs: [[0u8; 48]; 4],
            report_data: [0u8; 64],
            collateral_refresh: Latency::Bounded(43_200),
            root_ca: RootCa::IntelProduction,
        }
    }

    fn cfg(refvals: Vec<[u8; 48]>) -> DeriveConfig {
        DeriveConfig {
            reference_values: refvals,
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
        }
    }

    #[test]
    fn with_reference_values_the_set_names_five_attestation_parties() {
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        for cap in [
            "silicon_and_microcode_integrity",
            "accurate_collateral_issuance",
            "quote_signing_honesty",
            "measurement_injection_resistance",
            "golden_value_correctness",
        ] {
            assert!(
                t.0.iter().any(|a| a.capability == cap),
                "missing {cap}"
            );
        }
    }

    #[test]
    fn without_reference_values_the_publisher_assumption_is_absent() {
        // Nothing was compared, so nothing was assumed. This is the whole
        // practical point: you proved some code ran in a genuine TD, not
        // that it is yours.
        let t = derive(&outcome(), &cfg(vec![]));
        assert!(!t.0.iter().any(|a| a.capability == "golden_value_correctness"));
    }

    #[test]
    fn only_the_collateral_authority_is_detectable() {
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        let bounded: Vec<&str> = t
            .0
            .iter()
            .filter(|a| a.latency != Latency::Never)
            .map(|a| a.capability.as_str())
            .collect();
        assert_eq!(bounded, vec!["accurate_collateral_issuance", "serves_current_collateral"]);
    }

    #[test]
    fn the_proxy_declares_its_own_contribution() {
        // A tool that enumerates everyone else's assumptions and omits its
        // own is committing the overclaim this project exists to attack.
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        assert!(t.0.iter().any(|a| a.capability == "sound_quote_verification"));
        assert!(t.0.iter().any(|a| a.capability == "forwards_only_what_it_verified"));
    }

    #[test]
    fn a_custom_root_is_an_extra_assumption() {
        let mut o = outcome();
        o.root_ca = RootCa::Custom("did:web:test-root.example".into());
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(t.0.iter().any(|a| a.principal == "did:web:test-root.example"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib derive`
Expected: FAIL — `cannot find function derive in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/derive.rs`:

```rust
use crate::latency::Latency;
use crate::trust::{Assumption, Impact, TrustSet};
use crate::verify::{RootCa, VerificationOutcome};

/// Configuration that decides which assumptions verification actually made.
pub struct DeriveConfig {
    /// Empty means MRTD was never compared — so no publisher is trusted,
    /// because nothing was checked.
    pub reference_values: Vec<[u8; 48]>,
    /// Identifies the verifier implementation, which is itself trusted.
    pub verifier_id: String,
    pub cache_ttl: Latency,
}

fn a(principal: &str, capability: &str, latency: Latency, impact: Impact, mech: &str) -> Assumption {
    Assumption {
        principal: principal.to_string(),
        capability: capability.to_string(),
        latency,
        impact,
        mechanism: mech.to_string(),
    }
}

/// Turn what verification established into what it assumed.
///
/// Each step of `verify_quote` establishes a fact conditional on somebody's
/// honesty. That party is a member of the residual trust set, and this is
/// where the correspondence is made explicit.
pub fn derive(o: &VerificationOutcome, cfg: &DeriveConfig) -> TrustSet {
    let m = "tdx_attestation(verified)";
    let mut t = TrustSet::default();
    let mut push = |x: Assumption| {
        t.0.insert(x);
    };

    // The chain validated to a root. Whoever owns that root is trusted for
    // the silicon behind it.
    let (root_principal, root_cap) = match &o.root_ca {
        RootCa::IntelProduction => ("did:web:intel.com", "silicon_and_microcode_integrity"),
        RootCa::Custom(id) => (id.as_str(), "silicon_and_microcode_integrity"),
    };
    push(a(root_principal, root_cap, Latency::Never, Impact::Soundness, m));

    // Collateral was fetched and was current — bounded by its refresh window.
    push(a(
        "did:web:pcs.intel.com",
        "accurate_collateral_issuance",
        o.collateral_refresh.clone(),
        Impact::Revocation,
        m,
    ));

    // QE identity checked out.
    push(a("urn:qe:tdx", "quote_signing_honesty", Latency::Never, Impact::Soundness, m));

    // RTMRs were present and well-formed; the host measured the firmware.
    push(a(
        "urn:host:unattributed",
        "measurement_injection_resistance",
        Latency::Never,
        Impact::Soundness,
        m,
    ));

    // Only if reference values were configured was the measurement compared
    // to anything. No comparison, no assumption.
    if !cfg.reference_values.is_empty() {
        push(a(
            "urn:reference-values:configured",
            "golden_value_correctness",
            Latency::Never,
            Impact::Soundness,
            m,
        ));
    }

    // The proxy's own contribution.
    let p = "proxy";
    push(a(&cfg.verifier_id, "sound_quote_verification", Latency::Never, Impact::Soundness, p));
    push(a(
        "urn:parallax:collateral-cache",
        "serves_current_collateral",
        cfg.cache_ttl.clone(),
        Impact::Revocation,
        p,
    ));
    push(a(
        "urn:parallax:proxy",
        "forwards_only_what_it_verified",
        Latency::Never,
        Impact::Soundness,
        p,
    ));

    t
}
```

Add `pub mod derive;` to `src/lib.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib derive`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Derive the trust set from what verification actually checked

Each verification step establishes a fact conditional on somebody's
honesty, so the step and the assumption are the same thing seen from two
sides. The reference-value assumption is conditional on configuration:
verify without reference values and nothing was compared, so nothing was
assumed -- and what you proved is weaker than you think.

The proxy also declares its own contribution, because a tool that
enumerates everyone else's assumptions and omits its own commits the
overclaim this project exists to attack.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Cross-check the two routes to the same answer

**Files:**
- Create: `tests/cross_check.rs`, `examples/verified-tdx.toml`

**Interfaces:**
- Consumes: `derive` (Task 3), `solve`/`Deployment` (existing).
- Produces: nothing new; this is the guard.

The existing calculus computes a TDX trust set from a written description. Task 3
computes one from a live quote. **They must agree**, and this is a narrow but
real instance of the independent-encoding experiment the paper proposes and
admits it has not run.

- [ ] **Step 1: Write the deployment that mirrors the derived set**

Create `examples/verified-tdx.toml`, declaring a `tee_attestation` mechanism
whose five principals are the same five identifiers `derive` emits
(`did:web:intel.com`, `did:web:pcs.intel.com`, `urn:qe:tdx`,
`urn:host:unattributed`, `urn:reference-values:configured`), with
`collateral_refresh = "12h"` and `claim = "execution_valid"`. Declare a
`[[principal]]` for each, since validation is strict.

- [ ] **Step 2: Write the failing test**

Create `tests/cross_check.rs`:

```rust
use parallax::derive::{derive, DeriveConfig};
use parallax::deployment::Deployment;
use parallax::latency::Latency;
use parallax::solve::solve;
use parallax::verify::{RootCa, VerificationOutcome};
use std::collections::BTreeSet;
use std::path::Path;

fn outcome() -> VerificationOutcome {
    VerificationOutcome {
        tcb_status: "UpToDate".into(),
        qe_status: "UpToDate".into(),
        platform_status: "UpToDate".into(),
        advisory_ids: vec![],
        mr_td: [0xAB; 48],
        rt_mrs: [[0u8; 48]; 4],
        report_data: [0u8; 64],
        collateral_refresh: Latency::Bounded(43_200),
        root_ca: RootCa::IntelProduction,
    }
}

/// Two independent routes to the same trust set: one from a written
/// deployment description, one from a live verification. If they disagree,
/// one of them is wrong and we want to know which.
#[test]
fn deriving_from_a_quote_agrees_with_solving_a_description() {
    let d = Deployment::load(Path::new("examples/verified-tdx.toml")).unwrap();
    let solved = solve(&d).unwrap();

    let derived = derive(
        &outcome(),
        &DeriveConfig {
            reference_values: vec![[0xAB; 48]],
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
        },
    );

    // Compare the attestation half only: `derive` additionally reports the
    // proxy's own assumptions, which no written description contains.
    let attestation_only: BTreeSet<(String, String)> = derived
        .0
        .iter()
        .filter(|a| a.mechanism != "proxy")
        .map(|a| (a.principal.clone(), a.capability.clone()))
        .collect();

    let from_description: BTreeSet<(String, String)> = solved
        .0
        .iter()
        .map(|a| (a.principal.clone(), a.capability.clone()))
        .collect();

    assert_eq!(
        attestation_only, from_description,
        "the two routes disagree; one of them is wrong"
    );
}

/// The proxy's own assumptions are exactly what the written description
/// cannot know about.
#[test]
fn the_proxy_adds_three_assumptions_no_description_contains() {
    let derived = derive(
        &outcome(),
        &DeriveConfig {
            reference_values: vec![[0xAB; 48]],
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
        },
    );
    assert_eq!(derived.0.iter().filter(|a| a.mechanism == "proxy").count(), 3);
}
```

- [ ] **Step 3: Run it and reconcile**

Run: `cargo test --test cross_check`

Expected: FAIL on the first run, because the capability strings or principal
identifiers will not line up exactly. **Reconcile by changing whichever side is
wrong on the merits** — do not edit the test until it passes. If `derive`'s
identifiers are arbitrary where `mechanism.rs`'s are considered, change
`derive`. If the example file is wrong, change the file. Record which you
changed and why in your report; a disagreement here is a finding about the
calculus, which is the entire point of the test.

- [ ] **Step 4: Run the full suite**

Run: `cargo test`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Cross-check the derived trust set against the solved one

The calculus computes a TDX trust set from a written description; the
verifier computes one from a live quote. They must agree, and now a test
says so. This is a narrow instance of the independent-encoding experiment
the paper proposes and admits it has not run -- two routes to the same
answer, with any divergence a finding about the calculus rather than a bug
to quietly fix.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Extract the quote from an RA-TLS certificate and check the key binding

**Files:**
- Create: `src/verify/quote.rs`, `src/verify/binding.rs`
- Modify: `src/verify/mod.rs`, `Cargo.toml`

**Interfaces:**
- Consumes: nothing from Tasks 2–4.
- Produces:
  - `pub fn quote_from_cert(der: &[u8], oid: &str) -> Result<Vec<u8>, QuoteExtractError>`
  - `pub fn check_binding(report_data: &[u8; 64], cert_der: &[u8]) -> Result<(), BindingError>`

The binding is what stops a genuine quote being replayed in front of a
different key. Without it, verification proves a real TD exists somewhere, not
that you are talking to it.

- [ ] **Step 1: Add dependencies**

```toml
x509-parser = "0.16"
sha2 = "0.10"
```

- [ ] **Step 2: Write the failing tests**

Create `src/verify/binding.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A self-signed cert whose public key we know, generated at test time.
    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key).expect("self-signed");
        (cert.der().to_vec(), key.public_key_der())
    }

    fn report_data_for(pubkey_der: &[u8]) -> [u8; 64] {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&Sha256::digest(pubkey_der));
        rd
    }

    #[test]
    fn a_matching_binding_is_accepted() {
        let (cert, pubkey) = cert_and_key();
        assert!(check_binding(&report_data_for(&pubkey), &cert).is_ok());
    }

    #[test]
    fn a_quote_bound_to_a_different_key_is_rejected() {
        // This is the replay the binding exists to stop: a genuine quote
        // presented in front of somebody else's certificate.
        let (cert_a, _) = cert_and_key();
        let (_, pubkey_b) = cert_and_key();
        assert!(check_binding(&report_data_for(&pubkey_b), &cert_a).is_err());
    }

    #[test]
    fn all_zero_report_data_is_rejected() {
        let (cert, _) = cert_and_key();
        assert!(check_binding(&[0u8; 64], &cert).is_err());
    }

    #[test]
    fn a_malformed_certificate_errors_and_does_not_panic() {
        assert!(check_binding(&[0u8; 64], &[0xFF; 32]).is_err());
    }
}
```

Add `rcgen = "0.13"` to `[dev-dependencies]`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib verify::binding`
Expected: FAIL — `cannot find function check_binding in this scope`.

- [ ] **Step 4: Write the implementations**

Prepend to `src/verify/binding.rs`:

```rust
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("certificate did not parse: {0}")]
    BadCertificate(String),
    #[error("quote is not bound to this certificate's key; \
             a valid quote in front of the wrong key proves nothing")]
    Mismatch,
}

/// The quote's `report_data` must commit to the certificate's public key.
///
/// Without this, verification establishes only that *a* trust domain exists
/// somewhere — not that it is the peer you are talking to. An attacker can
/// take any genuine quote and present it with their own certificate.
pub fn check_binding(report_data: &[u8; 64], cert_der: &[u8]) -> Result<(), BindingError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| BindingError::BadCertificate(e.to_string()))?;
    let spki = cert.public_key().raw;
    let expected = Sha256::digest(spki);
    if report_data[..32] == expected[..] {
        Ok(())
    } else {
        Err(BindingError::Mismatch)
    }
}
```

Create `src/verify/quote.rs`:

```rust
/// The default OID carrying a TDX quote in an RA-TLS certificate. Gramine and
/// Intel's stacks use this; others differ, so it is configurable and a
/// mismatch must fail loudly naming what was looked for.
pub const DEFAULT_QUOTE_OID: &str = "1.2.840.113741.1337.6";

#[derive(Debug, thiserror::Error)]
pub enum QuoteExtractError {
    #[error("certificate did not parse: {0}")]
    BadCertificate(String),
    #[error("certificate carries no extension {oid}; \
             is this an RA-TLS certificate, and is the OID right?")]
    NoQuoteExtension { oid: String },
}

pub fn quote_from_cert(cert_der: &[u8], oid: &str) -> Result<Vec<u8>, QuoteExtractError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| QuoteExtractError::BadCertificate(e.to_string()))?;
    let wanted: x509_parser::der_parser::Oid = oid
        .parse()
        .map_err(|_| QuoteExtractError::NoQuoteExtension { oid: oid.to_string() })?;
    for ext in cert.extensions() {
        if ext.oid == wanted {
            return Ok(ext.value.to_vec());
        }
    }
    Err(QuoteExtractError::NoQuoteExtension { oid: oid.to_string() })
}
```

Add a test to `src/verify/quote.rs` asserting a certificate without the
extension produces `NoQuoteExtension` naming the OID, and that a malformed
certificate errors rather than panicking.

Update `src/verify/mod.rs` to declare and re-export both modules.

- [ ] **Step 5: Run the tests and commit**

Run: `cargo test --lib verify`

```bash
git add -A
git commit -m "$(cat <<'EOF'
Extract the quote from an RA-TLS certificate and bind it to the key

The binding is the part that matters. Verification alone proves a trust
domain exists somewhere; only report_data committing to the certificate's
public key proves it is the peer you are talking to. A genuine quote in
front of somebody else's certificate is the replay this rejects.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Collateral fetch and cache

**Files:**
- Create: `src/collateral/mod.rs`
- Modify: `src/lib.rs`, `Cargo.toml`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct CollateralSource { pub base_url: String, pub cache_ttl: Latency }` and `pub async fn fetch(&self, quote: &[u8], now_secs: u64) -> Result<QuoteCollateralV3, CollateralError>`, with an in-process cache keyed by FMSPC.

- [ ] **Step 1: Add dependencies**

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net", "io-util", "time"] }
```

- [ ] **Step 2: Write the failing test**

Tests must not hit the network by default. Cover: a cache hit within the TTL
returns without a fetch; a cache entry older than the TTL is refused; an
unreachable base URL produces an error, not a panic. Use an injected fetch
closure so the cache logic is testable offline:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_cache_entry_is_reused() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("00806f050000", 1000 + 3600, &Latency::Bounded(43_200)),
            Some(b"collateral".to_vec())
        );
    }

    #[test]
    fn a_stale_cache_entry_is_refused() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(cache.get("00806f050000", 1000 + 43_201, &Latency::Bounded(43_200)), None);
    }

    #[test]
    fn a_never_ttl_means_never_reuse() {
        // `Never` is not "cache forever" -- it is "no bound", which for a
        // cache means it cannot vouch for freshness at all.
        let mut cache = Cache::default();
        cache.put("f".into(), b"c".to_vec(), 1000);
        assert_eq!(cache.get("f", 1000, &Latency::Never), None);
    }
}
```

- [ ] **Step 3: Run, implement, run**

Implement `Cache` with `BTreeMap<String, (Vec<u8>, u64)>` and a `get` that
takes the current time and the TTL explicitly — no system clock. Then implement
`CollateralSource::fetch` using `dcap-qvl`'s collateral helper, populating the
cache. Run `cargo test --lib collateral`.

- [ ] **Step 4: Add the opt-in live test**

Create `tests/live_pcs.rs`:

```rust
/// Hits Intel's live PCS. Ignored by default; run in a scheduled CI job with
/// `cargo test --test live_pcs -- --ignored`.
///
/// When this fails, Intel's collateral format or TCB baseline has moved and
/// the committed fixture needs recapturing. That is information, not a broken
/// build.
#[tokio::test]
#[ignore]
async fn live_collateral_matches_the_fixture_shape() {
    let quote = std::fs::read("tests/fixtures/gcp-c3-tdx/quote.bin").expect("fixture");
    let src = parallax::collateral::CollateralSource::intel_production();
    let fetched = src.fetch(&quote, now()).await.expect("live fetch");
    // Shape, not contents: TCB info moves legitimately, the structure should not.
    assert!(!fetched.tcb_info.is_empty());
}
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Fetch and cache Intel collateral, with the clock injected

The cache TTL is a trust assumption with a detection bound, not an
optimisation: a stale cache is a revocation you have not noticed yet. A
`Never` TTL means the cache cannot vouch for freshness at all, so it is
refused rather than treated as cache-forever.

The live PCS test is opt-in. When it fails, Intel moved and the fixture
needs recapturing -- information, not a broken build.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: The proxy

**Files:**
- Create: `src/proxy/mod.rs`, `src/bin/parallax-proxy.rs`, `examples/proxy.toml`
- Modify: `Cargo.toml`, `src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 2–6, plus `policy::evaluate` and `manifest::manifest` unchanged.
- Produces: the `parallax-proxy` binary.

- [ ] **Step 1: Add dependencies and the binary target**

```toml
hyper = { version = "1", features = ["server", "client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
tokio-rustls = "0.26"
rustls = "0.23"

[[bin]]
name = "parallax-proxy"
path = "src/bin/parallax-proxy.rs"
```

- [ ] **Step 2: Write the gate, and test it without a network**

The decision logic must be a pure function so it is testable without sockets:

```rust
/// What the proxy decided, and why.
pub enum Decision {
    Allow { trust_set: TrustSet, warnings: Vec<String> },
    Refuse { reason: String },
}

pub fn decide(
    outcome: &VerificationOutcome,
    cfg: &DeriveConfig,
    policy: &Policy,
) -> Result<Decision, PolicyError>;
```

Tests: a clean outcome under a permissive policy allows; an outcome whose
derived set violates the policy refuses, and the reason names the violated
assumption; an outcome with no reference values allows **with a warning whose
text says what was not proved**; with `require_reference_values = true` the
same outcome refuses.

- [ ] **Step 3: Wire the proxy**

`src/proxy/mod.rs`: bind the listener; on each connection dial the upstream
over TLS, capture the peer certificate, extract the quote, verify, check the
binding, derive, decide. On `Allow`, forward bidirectionally. On `Refuse`,
return `502 Bad Gateway` with the reason in the body and log the manifest.

Every decision emits a Residual Trust Manifest via `manifest::manifest` to the
log sink — this is the auditor evidence C10.2.1 asks for and the automated
validator C10.3.3 describes.

- [ ] **Step 4: Integration test against a local RA-TLS server**

Stand up a test server in-process whose certificate carries the fixture quote in
the configured OID, point the proxy at it, and assert: a request is forwarded
when policy permits; the connection is refused with `502` and the assumption
named when policy forbids; a certificate with no quote extension is refused
naming the OID; a quote bound to a different key is refused.

- [ ] **Step 5: Write `examples/proxy.toml`**

```toml
upstream = "https://svc.internal:8443"
listen   = "127.0.0.1:8080"
policy   = "examples/policy-strict.toml"

[collateral]
source    = "https://api.trustedservices.intel.com/tdx/certification/v4"
cache_ttl = "12h"

[reference_values]
# Absent on purpose: with no reference values the proxy allows but warns that
# this attests some code ran in a genuine trust domain, not that it is yours.
mrtd = []
```

- [ ] **Step 6: Run everything and commit**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`

```bash
git add -A
git commit -m "$(cat <<'EOF'
Add parallax-proxy: gate traffic on what verification actually assumed

The decision is a pure function over the derived trust set, so the gate is
tested without sockets. Fail closed everywhere: any verification,
collateral or policy failure refuses, because a proxy that forwards when
it could not verify produces the appearance of a check.

Every decision emits a Residual Trust Manifest, which is the auditor
evidence C10.2.1 asks for and the automated validator C10.3.3 describes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Documentation and the standard mapping

**Files:**
- Modify: `README.md`, `docs/STANDARD-MAP.md`, `paper/README.md`

- [ ] **Step 1: README**

Add a section after "What parallax does" showing the proxy with real output,
including the no-reference-values warning, and stating plainly that the tool now
has two modes: describe a deployment, or verify a live one.

- [ ] **Step 2: Update the standard mapping**

In `docs/STANDARD-MAP.md`, move **C10.3.3** from "supported" to "implemented"
and add a row for **C10.2.1** noting that per-connection manifests are the
auditor evidence it asks for. Add the reference-value gap as a finding: a
verifier that checks a quote without reference values satisfies less of C8's
Tier 3 than its operator believes.

- [ ] **Step 3: "What is real and what is modelled"**

Update the README's section. Verification is now **real** — a real captured
quote, real Intel collateral, real chain validation. State what remains
modelled or absent: SGX and SEV-SNP are unsupported; the fixture's
`report_data` is a placeholder so the binding is tested separately; and the
proxy has been exercised against a local test server, not a production
deployment.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
Document the proxy and move C10.3.3 to implemented

Also records the reference-value gap as a finding against the standard: a
verifier that checks a quote without comparing the measurement to a
reference value satisfies less of Tier 3 than its operator believes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: real TDX verification (2), session binding (5), trust set derived from verification rather than a file (3), policy enforcement with the violated assumption named (7), the proxy's own contribution reported (3), the reference-value gap (3 and 7), fail-closed (7), per-connection manifests (7), fixtures with a pinned clock (1), the opt-in live PCS test (6), the cross-check against `solve` (4), and the documentation and standard-mapping updates (8).

**Deferred deliberately, and stated rather than implied.** The spec's non-goals hold: no SGX, no SEV-SNP, no transport other than RA-TLS, one upstream per instance, no policy hot-reload. Additionally, `derive` attributes the host assumption to a placeholder principal (`urn:host:unattributed`) because a quote does not name its cloud operator — a real deployment would configure that identifier, and Task 7's config should carry it.

**Type consistency.** `VerificationOutcome`, `RootCa`, `DeriveConfig`, `Decision`, `CollateralSource` and `Cache` are each defined once and referenced with matching signatures. Note the deliberate signature change in Task 2 Step 4: `verify_quote` gains a `collateral_refresh: Latency` parameter, and the tests written in Step 2 must be updated to match — this is called out in the task rather than left to be discovered.

**Two places the plan defers to the crate over itself**, both flagged in-task: the exact name of `dcap-qvl`'s collateral-fetch function (Task 1), and the `Report` enum's TDX variant name (Task 2). The plan states its best reading and instructs the implementer to use what the crate actually defines and report the difference.

**The riskiest task is Task 1**, and it is first on purpose: it needs real hardware once, and it BLOCKS rather than substituting a synthesised quote. Tasks 2–4 are worth doing even if the proxy is never built.

---

## Plan complete

Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, reviewed between tasks.

**2. Inline Execution** — executed in this session with batch checkpoints.
