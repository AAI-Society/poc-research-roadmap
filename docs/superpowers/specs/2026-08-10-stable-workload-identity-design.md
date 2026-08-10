# Stable workload identity for `parallax-attest`

**Status:** design, approved 2026-08-10.
**Repository:** `parallax` (`/Users/jimschwoebel/Desktop/parallax`), branch off `main` at `e1fdc44`.

## The problem

`parallax-attest` extends RTMR3 with `workload_measurement(image_digest)` so that a
quote attests to *what is running*, not merely that something runs in a TEE. A
verifier compares the resulting RTMR3 against a reference value the operator wrote
in advance. The scheme only works if the operator can name their workload with a
digest that is stable across time.

Today they cannot. `deploy/gcp/up.sh:79` builds the app image on the confidential VM
and measures `docker image inspect -f '{{.Id}}'`. Task 7 rebuilt that image from
byte-identical source and got a third distinct RTMR3
(`docs/WALKTHROUGH.md` §5), so the deployed instance matched neither committed
reference value.

**Root cause.** `.Id` is the digest of the image *config JSON*, and that JSON embeds
a `created` timestamp with nanosecond precision. It therefore changes on every build
regardless of content. Base-image tag drift (`python:3.12-alpine` is pinned by tag,
not by manifest digest) is a second, independent source of change, but the timestamp
alone is sufficient to guarantee instability. `up.sh`'s own comment records why it
chose `.Id`: `.RepoDigests` is empty for an image built locally and never pushed.

That is the crux. **The stable identity already exists — the demo never created
one.**

## The fix, in one sentence

Stop building on the VM. Publish the image to a registry once, deploy by its
immutable manifest digest, and derive the reference value from that digest.

Because the VM pulls rather than rebuilds, the image config is *transferred* rather
than regenerated, so the identity is stable by construction. Reproducible builds
stop being a prerequisite: the problem leaves the trust story instead of being
solved inside it.

## Goals

- An operator can obtain a workload digest that does not change unless the workload
  changes, and can derive a reference value from it before deploying.
- The demo demonstrates that workflow end to end on real hardware.
- The claim that the workflow is stable is backed by measurement, not assertion.

## Non-goals

- **Reproducible builds.** Explicitly out of scope; the design removes the need.
- **Verifying that the running container matches the configured digest.** Decided
  against: it would require giving the process that holds the attestation key access
  to the container runtime, and `docker.sock` is root-equivalent on the host. The
  trust boundary is documented instead (see "Trust boundary").
- **A trust-set principal for the attester** (the open I2 question from the
  whole-branch review) and **a `require_rtmr3` flag**. Both are real and neither is
  this change.
- **Config-format change.** `image_digest` keeps its current form. Accepting a full
  `repo@sha256:…` reference is ergonomics, not correctness, and can follow if
  operators trip over it.

## Architecture

```
operator's machine                 Artifact Registry              C3 VM
──────────────────                 ─────────────────              ─────
publish.sh
  docker build            ──push──> repo@sha256:MANIFEST ──pull──> byte-identical
  parallax reference-value                                         artifact
    -> [reference_values]                                          up.sh
                                                                     attest.toml
                                                                     image_digest
                                                                       = MANIFEST
```

The measured identity becomes "the artifact published to the registry" rather than
"the image this host built." That is stronger for an operator, and it does put the
registry in the picture — noted rather than hidden.

## Components

### `deploy/gcp/publish.sh` (new, runs off the VM)

Builds the app image, pushes it to Artifact Registry, and prints both the manifest
digest and the exact `up.sh` invocation to run. Also prints the
`[reference_values]` block by calling `parallax reference-value`, so the operator
never derives it by hand.

The manifest digest is read back after the push from
`docker image inspect -f '{{json .RepoDigests}}'`, and the script requires **exactly
one** entry matching the target repository. If there are none, or more than one and
they disagree, it fails. It must never fall back to `.Id` — that fallback is the
bug this design exists to remove.

`publish.sh` runs from a checkout, so it invokes the subcommand as
`cargo run --quiet --bin parallax -- reference-value …`. It does not require an
installed binary.

### `deploy/gcp/up.sh` (changed)

Takes an image reference instead of building one. It pulls by digest, renders
`attest.toml`, and **refuses a reference that is not digest-pinned** — a tag would
reintroduce exactly the drift being removed.

Its shell reimplementation of the measurement arithmetic (`up.sh:130-133`, currently
`xxd` + `sha384sum`) is deleted. Reference values now arrive from `publish.sh`.
This retires a deferred minor from the whole-branch review: that shell math was
cross-checked only on hardware, with nothing offline pinning it to the Rust.

### `deploy/gcp/provision.sh` (changed)

Gains the registry plumbing: create the Artifact Registry repository, grant the VM's
service account `artifactregistry.reader`, and run `gcloud auth configure-docker`
for the registry host. Every new resource is named `parallax-demo-*` and appears in
the teardown inventory with its exact deletion command, matching the discipline the
existing script already follows.

### `parallax reference-value` (new subcommand, default build)

```
parallax reference-value --image-digest sha256:<64 hex> [--mrtd <96 hex>]
```

Prints a pasteable block:

```toml
[reference_values]
mrtd  = ["c1ee9c16…70a5"]
rtmr3 = ["1d2860c8…3325"]
```

`rtmr3` is `ratls::expected_rtmr3(ratls::workload_measurement(digest_bytes))`.

MRTD is not derivable from an image — it measures firmware — so it is supplied with
`--mrtd` and echoed. **When `--mrtd` is omitted the `mrtd` array is emitted empty,
with a note on stderr saying where the value comes from.** It must never emit a
plausible-looking placeholder: an operator pasting a fabricated MRTD would get a
config that looks configured and checks nothing.

Lives alongside `solve` on the existing `src/bin/parallax.rs`.

### `ratls::parse_image_digest` (moved, not written)

Task 5 built a strict parser for the `sha256:` + exactly-64-hex form, using an
`is_ascii_hexdigit` allowlist rather than `u8::from_str_radix` — which accepts a
leading `+` and silently yields a different, valid digest. It currently lives in
`src/attest/serve.rs`, behind the `attest` feature.

`reference-value` is in the default build, so the parser moves to `src/ratls.rs` and
both callers use it. This is the same argument Task 2 made when it hoisted the
layout constants: a third digest parser is how the `+`-acceptance bug came to exist
in two places.

## Data flow

1. Operator runs `publish.sh`. Image is built and pushed; the manifest digest is
   read back from the registry.
2. `publish.sh` calls `parallax reference-value` with that digest and the platform
   MRTD, printing the `[reference_values]` block for the proxy config.
3. Operator runs `up.sh <registry>/<repo>@sha256:<manifest>` on the VM. It pulls the
   artifact and renders `attest.toml` with `image_digest` set to the manifest digest.
4. `parallax-attest` resolves the digest, computes `workload_measurement`, extends
   RTMR3, requests a quote, mints the certificate, and serves.
5. `parallax-proxy`, configured with the reference values from step 2, admits the
   connection.

Steps 4 and 5 are unchanged; this design only changes where the digest comes from.

## Error handling

- `up.sh` refuses a non-digest-pinned reference, naming the tag it was given.
- `publish.sh` fails if no repo digest is available after push, rather than falling
  back to `.Id`.
- `reference-value` rejects a malformed digest through the shared parser, with the
  same error shape the attester already produces.
- A pull failure on the VM fails before `attest.toml` is rendered, so the sidecar
  never starts against an image that is not present.

Existing fail-closed behaviour is untouched: if attestation is unavailable the
sidecar exits 2 without listening.

## A limitation that must be stated, not papered over

A registry manifest digest and a local image-config digest are **both 32-byte
SHA-256 values and are indistinguishable by form.** `reference-value` cannot tell an
operator they pasted the wrong one. What enforces the distinction is `up.sh`
refusing a reference that is not digest-pinned, and the documentation — not a check
in the tool. The docs must say so rather than implying a validation that does not
exist.

## Trust boundary

`parallax-attest` measures the digest its configuration declares. It does not verify
that the app container it fronts is that image; the deploy tooling asserts that.
The documentation states this plainly, because an attestation that silently means
"the operator claimed X" rather than "X is running" is exactly the kind of overclaim
this project exists to attack.

## Evidence and testing

**Local proof** (`scripts/publish-digest-stability.sh`, in the register of
`scripts/spike-rtmr.sh`) — no TDX, no GCP, transcript committed:

1. Build the app image twice from byte-identical source. Show the two `.Id` values
   differ, and diff the two image configs to establish that **`created` is the
   differing field.** This converts the app Dockerfile's current "most likely cause…
   this repository has not isolated which" into a measured statement.
2. Push once, pull by manifest digest twice. Show the image config is byte-identical,
   `.Id` identical, and the derived RTMR3 identical.

Claim 2 is the new one. The TDX half needs no re-measurement: Task 1 established on
real hardware that RTMR3 is a deterministic function of the digest, across boots.

**Unit tests:**

- `reference-value`'s output pinned against `ratls::expected_rtmr3` for the committed
  fixture digests, so the CLI and the library cannot drift — the gap the shell
  version had, closed properly.
- The moved `parse_image_digest` keeps its existing coverage, including the `+`,
  `-`, and whitespace rejection cases, and both call sites are exercised.

**Hardware:** one `c3-standard-4` run in `us-central1-a`, project `example-project`,
to re-capture the walkthrough on the new flow — accept, then a different published
image, then the refusal. Torn down after capture and verified against the
pre-provisioning baseline.

## Consequence for the committed fixture

`tests/fixtures/gcp-c3-bound/` remains valid as a *binding* artifact: its
`report_data` still commits to a key we hold and `check_binding` still accepts it.
But its RTMR3 came from a locally-built image, while `examples/gcp-c3.toml`'s
reference values will now come from a published one.

The whole-branch fix wave deliberately rewrote
`mrtd_and_rtmr3_match_examples_gcp_c3_toml` to *read* that config rather than
hardcode it, so changing the config breaks the pin.

**Decision: re-capture the fixture during the hardware run.** It is nearly free once
the VM is up, keeps a single coherent story, and weakening the test to MRTD-only
would remove the reason the pin is worth having.

## Documentation changes

- `docs/WALKTHROUGH.md` §5 stops being "a second real finding" and becomes the cause
  plus the fix. The finding stays — it is true, and it is why the design changed —
  relabelled as what the naive flow exposes.
- The walkthrough's up-front "what this does not prove" block and its "does not
  cover" accounting both gain the trust-boundary statement.
- `README.md`, `examples/gcp-c3.toml`, and `deploy/gcp/app/Dockerfile` updated; the
  Dockerfile's hedge replaced with the measured cause.
- `examples/gcp-c3.toml` must also stop naming a torn-down instance's ephemeral IP
  as though it were live — a separate slip the fix wave noted and this change
  touches the same file.
