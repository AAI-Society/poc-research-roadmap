# Parallax paper — the Feynman pass on §3 and §5

Repo: `/Users/jimschwoebel/Desktop/parallax`. Base `b02789a`. Only
`paper/main.tex`, `paper/README.md` and `tests/acceptance.rs` changed, plus
the rebuilt `paper/main.pdf`.

The brief: the paper already had the plain register, but it stated results
and pointed at tables where Feynman would work the example in front of the
reader and let the answer arrive as a consequence. So: derive first, ask the
obvious question at each step, land the tool as confirmation.

## §5 — Does It Actually Work?

**§5.1, the TDX set.** Replaced "the tool produces the five parties, it
does, here is the table" with the derivation. Open the file; it declares one
mechanism naming six things; apply the rule and get one assumption per name;
then ask of each one *how would I find out if it were false?* and watch four
of them give no answer. The count arrives at the end of that walk — as
macros — and *then* the tool runs, as confirmation of a whiteboard result.

The honesty paragraph that follows got sharper rather than weaker. The old
version said "it is worth being exact about what this does and does not
demonstrate." The new one says: if the derivation felt like a cheat, it was,
and the cheat is the result — we read the names straight out of the file in
step one, and so does the tool. Same concession, arriving as the reader's own
suspicion instead of as an authorial disclaimer.

**§5.2, the comparison matrix.** Now walks Σ₂ against Σ₄ by hand before the
matrix appears. Σ₂'s five we already have; Σ₄'s file declares two mechanisms,
carry them to the rules table and its five fall out. Then the containment
question asked in both directions — is Intel's silicon in Σ₄'s list (a
Groth16 verifier does not care which CPU made the proof), is the ceremony in
Σ₂'s (a TDX box does not have one) — so that `Incomparable` is an anticlimax
by the time the tool prints it. Table 4 then earns its place as "all of them,
and notice how few pairs the question can even be asked of."

**§5.3, the shared dependency.** Reframed as something built on purpose. You
have read Table 1, you do not want to rest on Intel alone, so you put a layer
under it with no CPU in it anywhere. Then: write down who you are trusting,
layer by layer, straight off the file — and the same `did:web:buildco.example`
appears in the TEE stanza's reference-value field and the ZK stanza's compiler
field. "Read the two lists again." The reader sees it before the paper points
at it. The credit-limiting paragraph (we built Σ₅, so the tool found what we
put there; the negative control exists; real deployments untested) is
unchanged.

**§5.4, latency and policy.** Opens by asking the reader to guess Σ₃'s
composed Δ before looking — Σ₃ being the one design in the set built
specifically to make misbehaviour visible, with real bounds on its anchoring
and its gossip. Then compose it: seven witnesses underneath, no mechanism
reports collusion, one member at ∞ takes the system to ∞. "The fifteen
minutes are still true. They simply do not survive the composition." The
policy half asks what clause a relying party would write first — *no silent
failure modes* — before showing that the clause rejects everything, and that
the 24-hour clause never bound anything at all.

## §3 — Writing It Down Precisely

Every symbol, equation and table row is byte-identical. Only the prose around
them changed, so that each definition arrives as the answer to a question
posed just before it:

- The section now opens on §1's unending argument (reviewer says build
  pipeline, vendor says covered) rather than on "here it is in symbols."
- **The judgment**: the sentence you want to write comes first — *this party
  must be honest about this thing, and you would find out within this long* —
  and P, C, L are what it needs in order to be sayable. The Never/∞ choice is
  derived from the quoting enclave's leaked key: writing it as a huge number
  of seconds "tells a specific lie, that patience is eventually rewarded."
  The impact and provenance components arrive as two things you find missing
  once you write a few tuples side by side.
- **The lattices**: latency's join is derived from the adversary's freedom to
  attack the unwatched layer. The trust-set order is derived from the
  question "when is one deployment more verifiable than the other?", with the
  partiality of inclusion landing as a consequence the reader has already
  agreed to rather than as an announcement.
- **Composition rules**: framed as one question asked once per mechanism.
  `anchoring` now asks what the conversion *cost* before naming the
  settlement assumption it ingests.
- **Delegation**: posed as why the set cannot be read off a file with a
  highlighter. **Provenance**: posed as the case that pays for the tag — a
  party appearing twice, two ways that could have happened.

## Left alone, deliberately

- §1, §2, §4, §6, §7, the Conclusion, the abstract, every caption's pinned
  sentence, Table 2 and all its rows.
- §3's `witness_quorum` discussion (all *n* named, the count arguable, the
  representation limitation). It is already an argument the reader is walked
  through, and it is load-bearing for §6.
- §5's opening three paragraphs: what is generated, what is typed, and that
  five self-written deployments plus one negative control are the entire
  evidence base. Untouched.
- Every honesty statement: the identities come from whoever wrote the file;
  the independent-encoding experiment is unrun; the completeness problem is
  the takeaway; the composition rules are not proved sound.

## Where the register fought the precision

1. **Sentence-initial macros render lowercase.** `\SigmaTwoAssumptions{}`
   expands to `five`, so "Five assumptions, one per name" — the beat the
   derivation is built toward — came out of tectonic as "five assumptions."
   Fixed by rewording so the count is never the first word ("That is five
   assumptions, one per name", "Count them up: five parties, four of them
   silent"). Caught by reading the built PDF, not the source; worth
   remembering for any future prose that states a generated count.
2. **The one number with no macro.** "The collateral gets refreshed every
   twelve hours" is typed. There is no generated macro for a deployment
   parameter, only for counts, and the derivation needs the sixth field to be
   nameable so the reader can watch it fail to be a party. It agrees with
   `examples/sigma2-tdx.toml` (`12h`) and with Table 1's `≈12h`. Same for
   Σ₄'s ten-minute posting interval and twelve-second finality, and Σ₃'s
   fifteen minutes and fifteen seconds.
3. **Counts of mechanisms are now macros in the new prose.** "It declares one
   mechanism" and "its file declares two mechanisms" use
   `\SigmaTwoMechanisms{}` and `\SigmaFourMechanisms{}` — these are exactly
   the family that has been typed wrong before.
4. **One typed count survived on purpose**: "besides the kind that stanza
   names six things." It describes a TOML stanza's fields, not tool output,
   and the enumeration a reader can count follows immediately. The existing
   §3 prose has the same shape ("declares five principal identifiers, a
   refresh interval and a mechanism kind").
5. **New guard anchor.** §5.1's derivation now states the headline count in
   the place a reader is most likely to believe it, so it got the same
   tripwire as the other four sites: `(" of them silent",
   "\\SigmaTwoUndetectable{}")` added to
   `the_headline_count_is_never_typed_into_the_paper`, and `paper/README.md`
   updated from "four existing sites" to five. Test count unchanged at 176 —
   this is one more anchor inside an existing test, not a new test.
6. **One typographic casualty.** Spelling the strict policy's two clauses
   inline as `\texttt{}` overran the line by 21pt; the caption already gives
   them verbatim, so the prose now says "those two clauses are
   `examples/policy-strict.toml`" and lets the caption carry the syntax.

## Verification

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` clean.
`cargo test`: 132 + 38 + 6 = 176 passed, 0 failed. `./scripts/regen-results.sh`
leaves `results/` with no diff. `tectonic -Z shell-escape main.tex` builds;
the only TeX warning is the pre-existing underfull hbox in Table 2, confirmed
identical on a build of `HEAD`'s `main.tex`. `grep -c '\placeholder{'` is 0.
`main.pdf` rebuilt and committed.
