# P01 paper completion — what was run, what was written, what is still open

Repo: `/Users/jimschwoebel/Desktop/parallax`, branch `main`.
Base `9417cd3` → head `6810bfc`. Three commits.

| SHA | What |
| --- | --- |
| `4cd3739` | `parallax tiers` subcommand, `parallax solve --format latex`, new `tex` module, results wiring |
| `660b45f` | `\allowbreak` in generated LaTeX identifiers; regenerated the two affected tables |
| `6810bfc` | Section 5 filled, Section 6 written, register fixes, `main.pdf` rebuilt |

Tests: 165 passing (123 lib + 36 acceptance + 6 robustness), up from 144.
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `./scripts/regen-results.sh` (no diff after commit) and
`tectonic -Z shell-escape main.tex` all clean.
`grep -c '\placeholder{' paper/main.tex` → **0**.

---

## 1. The experiment, and whether it agreed with your hand computation

It agreed exactly. `parallax tiers` derives, independently of anything typed:

| | Assumptions | Principals | Undetectable | Composed Δ |
| --- | --- | --- | --- | --- |
| Σ₁ software-only | 3 | 3 | 3 | ∞ |
| Σ₂ TDX | 5 | 5 | 4 | ∞ |
| Σ₃ quorum | 11 | 11 | 7 | ∞ |
| Σ₄ ZK | 5 | 5 | 3 | ∞ |

Every figure matches the numbers in your brief. No disagreement to report.

**Cardinality.** Ranks `sigma1-software` (3) < `sigma2-tdx` (5) =
`sigma4-zk` (5) < `sigma3-quorum` (11). The software-only host is the most
verifiable deployment and the 5-of-7 witness quorum the least. It also ties
Σ₂ with Σ₄, so it is not a total order even where it ranks — a second,
independent failure I had not expected to find and which the paper now
states.

**Set inclusion.** Six unordered pairs. Four refused (different claims),
two compared, both `Incomparable`, zero ranked. No order at all.

**Composed Δ.** `never` for all four. The key is constant, so it has no
discriminating power whatever.

**Collusion cost.** Reported as not computable, with a one-line reason. No
metric was invented.

The tool reports these as four *structurally distinct* verdict variants
(`Ties`, `Partial`, `NoDiscrimination`, `NotComputable`), and a test —
`all_four_candidates_fail_and_each_fails_differently` — pins that they stay
distinct. A change that collapsed two of them into the same shape would
weaken §6's argument without failing anything else in the suite.

The cardinality inversion has its own test, named for what it is:
`cardinality_ranks_the_software_only_host_first_and_the_quorum_last` in
`src/tiers.rs`. Its doc comment says that if it fires, §6 is wrong and must
be rewritten rather than patched.

**Scope choice worth flagging.** The ordering experiment runs over Σ₁–Σ₄,
per your instruction and matching the comparison matrix's scope. Σ₅ is a
hybrid built to carry a shared dependency, not a fifth design competing for
a rung. It *does* appear in the per-deployment summary table (which is facts,
not a ranking), so §5's composed-Δ result covers all five. The §6 placeholder
had said "Σ₁–Σ₅"; the new text says Σ₁–Σ₄ and the caption says why.

## 2. Placeholders

All five are gone; none remains.

| Was | Now |
| --- | --- |
| §5 opener, "partly written" | A statement that every figure is tool output and none was typed |
| §5.1 Σ₂ trust set | Table 3, `\input` from `results/sigma2-trust-set.tex` |
| §5.3 shared-dependency listing | Figure 1, `\lstinputlisting` of the verbatim run |
| §5.4 composed Δ + policy | Tables 5 and 6, plus prose reading them |
| §6 entire section | Written from `parallax tiers` output, plus Table 7 |

None of the five covered the independent-encoding experiment, so no
admission was deleted in removing them. §7.1 still says that experiment is
a plan and not a result, verbatim and untouched. `paper/README.md`'s claims
audit now lists it explicitly as statement (e) that must not stop being made.

## 3. New generated files

`results/sigma2-trust-set.tex`, `results/deployment-summary.tex`,
`results/tier-orderings.{txt,tex}`, `results/policy-checks.{txt,tex}`.
All produced by `scripts/regen-results.sh`, all covered by the existing CI
staleness gate (`git add -A results/` then `git diff --cached`), all
documented in `results/README.md` and in a new file→table map in
`paper/README.md`.

The policy loop in the script captures `check`'s exit code and branches on
it rather than using `|| true`, so "this deployment violates the policy" —
the expected, interesting outcome, exit 1 — stays distinguishable from "the
tool broke", exit 2, which aborts the script with the output attached.

## 4. Prose I changed for register, and prose I left

**Changed, §3 (both small):**

- "Note that $\mathcal{L}$ has *infinite* height" → "$\mathcal{L}$ has
  *infinite* height". Throat-clearing; the sentence is stronger without it.
- "Two further constructions in this area are refused rather than
  interpreted." → "Two more things the tool refuses to answer, rather than
  answering wrongly." Passive, and "constructions in this area" is the kind
  of phrase the register exists to avoid. The replacement also says what is
  actually at stake, which the original only implied.

**Changed elsewhere, for accuracy rather than register:**

- Abstract: one sentence added for the ordering result.
- §1's roadmap list: an item for §6, which was missing because §6 had no
  content.
- §8 Conclusion: one sentence naming the four failures.
- Artifact note: now covers §§5 *and* 6, since §6 also reads generated files.
- Preamble comment and `paper/README.md` status: no longer say the results
  sections are placeholdered.
- §6 title: "Re-Deriving the Tiers" → "Can the Ladder Be Repaired?". See
  the caveat below.

**Deliberately left alone:** §7 in its entirety. I read it looking for the
drift you expected and did not find it — "This is the thing to worry about,
and it is worse than an ordinary limitation, because the failure mode is not
silence but confidence" is exactly the register, and §§7.2–7.6 are the same.
Rewriting any of it would have been a regression. §§1, 2, 4 likewise
untouched.

## 5. Things I was unsure about

1. **The §6 rename** is the one judgement call I would most expect you to
   reverse. My reasoning: the section's result is that the tiers *cannot* be
   re-derived, and a table-of-contents line reading "Re-Deriving the Tiers"
   promises an outcome the section does not reach. The new title matches the
   paper's question-form titles ("Does It Actually Work?"). But the paper's
   own subtitle still says "Re-Deriving Verifiability", so there is now a
   mild tension between title and §6 heading. I did not touch the subtitle —
   that is your call. Reverting is a one-line change; `paper/README.md`
   records the decision and the tension.

2. **Σ₅'s exclusion from the ordering experiment** is defensible but not
   forced. Including it would give four comparable pairs instead of two under
   set inclusion; I checked and all four would still come out incomparable,
   so the verdict would not change. I followed your instruction and the
   matrix's scope. One line in `regen-results.sh` changes it.

3. **§5.4's caption claims** "Principals is lower than |T| only for Σ₅".
   True today and visible in the table right beside it, but it is a
   hand-written sentence about generated content and nothing pins it. Same
   class of risk as Table 2's caption, which does have a tripwire. I did not
   add one; it may be worth it.

4. **`Verdict` carries preformatted `detail` strings** rather than fully
   structured counts. Tests match on the variant and on the structured
   `Rung`s, which is the load-bearing part, but two of the set-inclusion
   assertions match on substrings of the detail sentence. If somebody
   rewords that sentence the tests fail noisily rather than silently, which
   is the right direction, but it is a slightly brittle seam.

5. **`main.pdf` is committed and current**, built from `6810bfc`'s source.
   It is not byte-reproducible, so rebuilding it produces a diff even with
   no source change — nothing enforces its currency and the root README
   already says so. If you rebuild, expect a dirty tree and discard it
   unless the source actually moved.

6. **Two underfull hboxes remain** in the build (`main.bbl:25` twice,
   `main.tex:558` once). All three predate this work — I confirmed by
   building the stashed tree. All overfull boxes introduced by the new
   generated tables are fixed.

## 6. What still has not been run, and is not written up as though it had

- The **independent-encoding experiment**: a second author encoding the same
  deployment without seeing the first, and diffing. `parallax diff` exists to
  support it, and the comparison was made order-independent so it could mean
  something, but nobody has run it with a genuinely independent author. §7.1
  says so.
- **Validation against any real-world system.** The evidence base is five
  deployments plus one negative control, all self-authored. §1, §5, §6 and
  §7.5 each say so; §6 adds a "What this rests on" paragraph that separates
  the two failures I would expect to reproduce anywhere (cardinality's
  inversion, collusion cost's absence from the input) from the two that are
  contingent on these four encodings (set inclusion's emptiness, composed Δ's
  constancy).
- **A soundness proof** for the composition rules. §7.2, unchanged.
- **A complexity bound.** §7.5, unchanged.

---

# Wave 2 — review response

Not approved on the first pass. `08a843f` and `93002a2` address every item.

| SHA | What |
| --- | --- |
| `93002a2` | C2, M15 — full LaTeX escaping; the shell guard; the CI comment |
| `08a843f` | C1, I3–I7, M9–M14 — the headline count and the paper corrections |

Tests 170 → **170** (127 lib + 37 acceptance + 6 robustness), up from 165.
`cargo fmt --check`, `clippy -D warnings`, `cargo test`, `regen-results.sh`
(no diff), `tectonic` (zero overfull boxes) all clean.
`grep -c '\placeholder{'` → 0. `main.pdf` rebuilt and committed.

## C1 — the headline number

The paper said three of the five TDX parties are undetectable. It is four:
endorser, quoting enclave, host and reference-value provider. Only the
collateral authority is bounded, at the 12-hour refresh. Fixed in the
abstract (~:150), §1 (~:212), §1's enumeration — which listed three parties
and dropped the cloud operator, now names all four — and the conclusion
(~:1198). Both the abstract and §1 now also say what the one bounded party
buys you, so a reader is not left to infer that "four" means "four *of the
interesting ones*".

I re-grepped every spelled-out count in `main.tex` against the generated
files. Nothing else contradicts. `docs/parallax-outcomes.{md,tex}` do not
carry the claim at all, so they needed no change.

Worth recording: this is the failure mode the paper is *about*, found in the
paper. Three tool-generated tables saying four, on facing pages, is what made
it visible — which is an argument for generating tables that I did not have
before and now do.

## C2 — escaping

`escape` now maps all ten of `\ { } $ & # ^ _ ~ %`, in a single pass (a chain
of `replace` calls corrupts the backslashes an earlier step introduced). The
doc comment's safety argument was not merely incomplete, it was false, and it
now states the real failure mode: `~` builds clean and silently renames the
party; `%` opens a comment and eats the row's separators and terminator.

**Escape vs. reject, and why both appear.** `tex::escape` renders principal
ids and capability names out of somebody else's deployment file. `%` is
legitimate there — `did:web` percent-encodes ports — so refusing conformant
input to keep a table generator simple would be the wrong way round. It
escapes. `scripts/regen-results.sh` interpolates *our* deployment and claim
names, from the file list in the script itself; a special character in one of
those is a mistake, not input, so it now aborts with the value named and a
pointer to `tex::escape`. Each side's comment states the other's choice.

Four tests: exact mapping per character; all ten at once; a scan asserting no
special reaches a cell unescaped; and an end-to-end one putting a nasty id
through `trust_set_tabular` and asserting the row still has four columns and
its `\\`.

**Repro re-run, as asked.** A deployment with principals
`urn:qe:tdx~v2`, `did:web:localhost%3A8080` and `did:web:a#b$c&d^e{f}g`
through `solve --format latex` → tectonic → `pdftotext` renders all three
literally, with the rows intact. Verified separately that
`\textbackslash{}`, `\textasciitilde{}` and `\%` render as `\`, `~`, `%`.

## I3, I4 — captions and the "nothing was typed" claim

Table 3's caption said the detection column comes from the rule and then said
the bound comes from the file. Rewritten to split them: the rule supplies
which row is bounded and every capability and impact; the file supplies five
identifiers and one number.

"None of it was typed" was false. The tables are generated; the sentences
restating figures from them are not. §5's opener, the artifact note and both
READMEs now narrow the claim to tables and figures, and say in as many words
that the surrounding prose carries a weaker guarantee. I did both things the
review offered rather than choosing: narrowed the sentence **and** added the
missing tripwires.

| Typed claim | Now pinned by |
| --- | --- |
| Σ₂: five rows, four ∞, one bounded | `the_tdx_trust_set_renders_five_rows_with_one_bound` |
| Eight of twelve ordered pairs N/A; two comparisons, both incomparable | `the_comparison_matrix_rests_on_exactly_two_unordered_comparisons` (new) |
| Principals < \|T\| only for Σ₅ | `only_the_hybrid_names_fewer_principals_than_it_has_assumptions` (new) |
| Per-deployment counts | `the_per_deployment_figures_are_what_the_paper_reports` |

`paper/README.md` tabulates these and says: add a sentence restating a
generated figure, add a tripwire in the same commit, or do not add the
sentence.

## I5, I6, I7

- **I5.** "Four ways have been proposed" now reads as what it is: our own
  enumeration from the design study this paper implements, not a survey, and
  §6 says it does not claim the list is exhaustive.
- **I6.** §6 now owns the convention its generalisation rests on. Cardinality
  puts Σ₃ last only because `witness_quorum` attributes
  `non_collusion_k_of_n` to each of the *n*; under one-assumption-per-
  mechanism, Σ₃'s seven witness assumptions collapse to one and it stops
  sitting last. Σ₁ on top survives — it has the fewest mechanisms as well as
  the fewest assumptions — but "backwards" does not. The paragraph points at
  §3's defence of the convention, says we still think it is the honest
  encoding, and spells out the weaker claim a reader who rejects it is left
  with. You were right that this is the first thing a referee attacks; I
  should have written it without being told.
- **I7.** Subtitle changed to "Testing Whether Deployments Can Be Ranked".
  Heading kept.

## I8 and the minors

Root `README.md` committed with the wave, with its `\input` sentence narrowed
the same way as I4. M9 repaired to your suggested wording (my previous edit
left a fragment). M10's contradiction removed. M11 `ranks`→`covers` in
`main.tex`, `regen-results.sh` and `results/README.md`. M12, M13, M14, M15
done.

## Concerns after this wave

1. **C1 predates this work but I restated it.** §6's abstract-level summary
   and §1's roadmap item were written by me in wave 1 against a paper that
   already said "three", and I did not check the claim against the artifact I
   had just generated three tables from. The tables and the prose disagreed on
   the same page and I did not look. The tripwires added for I4 would not have
   caught this one either — nothing pins §1's or the abstract's prose. A
   tripwire for the headline count specifically is probably worth adding; I
   have not, because it would have to assert against a sentence rather than a
   number, and I would rather you decide the shape.
2. **The `escape`/reject split is a judgement call.** If you would rather have
   one rule everywhere, the change is to route the script's values through the
   binary; I did not, because the script has no natural place to call it and
   because aborting is genuinely the better answer for values we control.
3. **`\textasciicircum{}` and friends assume the default font encoding.**
   True for this paper; a fragment reused under a different setup could differ.
   The generated files are only ever `\input` into `main.tex`.
4. **The Table 3 caption is now long.** It earns it — the rule/file split is
   the subsection's actual claim — but it is four sentences under a five-row
   table.

---

# Wave 3 — the prose guardrail

`3fc8349`. Tests 170 → **175** (131 lib + 38 acceptance + 6 robustness).
`fmt --check`, `clippy -D warnings`, `cargo test`, `regen-results.sh` (no
diff), `tectonic` (zero overfull) clean. `main.pdf` rebuilt and committed.
`grep -c '\placeholder{'` → 0.

## Which mechanism, and why

You offered a test or a generated macro and said the macro was probably
stronger. It is, and I took it: a test detects the fifth occurrence, a macro
removes the possibility of one. `parallax solve --format latex-counts
--macro-prefix SigmaTwo` writes `results/sigma2-counts.tex` — four
`\newcommand`s — and `paper/main.tex` `\input`s it in the preamble. The
abstract, §1 (twice), Table 3's caption and the Conclusion now call
`\SigmaTwoUndetectable{}` and `\SigmaTwoParties{}`.

Counts are spelled as words, generated: `\newcommand{\SigmaTwoUndetectable}
{four}`. A macro expanding to `4` where the prose wants `four` would have
traded a correctness bug for a register one. `number_word` covers 0–20 and
falls back to digits above that, on the grounds that a sentence needing a
number that large should be pointing at a table.

I did **not** try to macro-ify every count in the paper. §5's other figures
are already tripwired, and a paper where every number is a macro call is a
paper nobody can edit.

## What the macro cannot do, and what covers each gap

The macro guarantees the *number* matches the artifact. Two holes remain,
and I think naming them is more useful than the fix itself:

1. **It updates the number and leaves adjacent prose stale.** §1 enumerates
   the four undetectable parties *by name*. If the count moved, the macro
   would print the new number under a list of the old parties — a worse
   failure than the one being fixed, because it now looks generated.
   `the_tdx_headline_count_is_four` (`src/tex.rs`) asserts the exact four
   principal ids, so any change fails with a message telling you to go read
   §1's enumeration rather than bump a constant.
2. **It does not stop the number being typed into a *new* sentence**, or a
   macro call being "simplified" to the word it currently expands to.
   `the_headline_count_is_never_typed_into_the_paper`
   (`tests/acceptance.rs`) reads `main.tex`, asserts each of the four sites
   is immediately preceded by the macro, and asserts no stale spelling
   survives in typeset text.

That second test strips `%`-comment lines before scanning, and the reason is
worth recording: the preamble note explaining why these macros exist has to
quote the wrong old number ("said three of the five"), and my first run of
the test failed on it. Scanning comments makes the note about the bug
indistinguishable from the bug.

## Mutation-checked

All three guards were verified to discriminate, not just pass:

| Mutation | Caught by | Message |
| --- | --- | --- |
| `\SigmaTwoUndetectable{}` → `four` at one site | acceptance guard | "the count before … is typed, not generated" |
| `three of them` reintroduced in a new sentence | acceptance guard | "`three of them` is still in paper/main.tex; the count is four" |
| `collateral_refresh = "never"` in the deployment | `the_tdx_headline_count_is_four` | prints both principal lists, names §1's by-hand enumeration |

Each names which side to change. The deliberate-reword case fails too, with
a message saying to confirm the macro is still there and then update the
anchor — brittle by design at exactly the moment a human should look.

## Also in this commit

- `tex::header` hardcoded "A bare tabular: the caption and float live in
  paper/main.tex". The macro file is not a tabular, so the generated header
  contradicted its own contents two lines below. `header` now takes the note.
  Caught by reading the generated file, not by a test.
- `--macro-prefix` is required with `latex-counts` (no sensible default for a
  name another document has to know) and rejected alongside any other
  format rather than silently ignored.
- **Concern 3 resolved.** Table 3's caption had four sentences; the second
  ("The rule and the file each supply part of this, and it is worth keeping
  them apart") only announced what the next two did. Cut. Three sentences,
  same content, and the remaining "five identifiers" also became a macro.

## Concerns

1. **The acceptance guard reads `paper/main.tex` from a Rust test.** It
   couples the crate's test suite to a sibling directory, and it will fail if
   the paper is ever moved or vendored separately. That coupling is the
   point — the artifact and the paper are supposed to agree — but it is worth
   knowing it is there before someone restructures the repo.
2. **`\input` in the preamble means a missing `results/sigma2-counts.tex`
   fails the paper build**, not just a table. That is the right direction
   (loud, early) but it makes `regen-results.sh` a hard prerequisite for
   building the paper at all, where before a stale `results/` still produced
   a PDF. `paper/README.md` says to run it; nothing enforces the order.
3. **Four typed sites became four macro sites.** If the paper grows a fifth
   sentence stating this count and the author does not know about the macro,
   the guard catches it only if they use one of the three stale spellings I
   scan for. Someone writing "all but one of the five" bypasses both the
   macro and the guard. I judged a broader scan not worth the brittleness,
   but it is a real gap and I would rather flag it than imply the hole is
   closed.
4. **Still unrun, unchanged:** the independent-encoding experiment, and any
   validation against a system we did not write.
---

# Wave 4 — the mechanism-count family

`7891863`. Tests 175 → **176** (132 lib + 38 acceptance + 6 robustness).
`fmt --check`, `clippy -D warnings`, `cargo test`, `regen-results.sh` (no
diff), `tectonic` (zero overfull) clean. `main.pdf` rebuilt. Placeholders 0.
Manifest mutation re-run: all four count sites still move in the PDF.

## CRITICAL — and it was worse than the clause

`main.tex:1132` said Σ₁ "has the fewest mechanisms as well as the fewest
assumptions". Confirmed against the files: Σ₁ = 3 blocks / 2 kinds, Σ₂ = 1/1,
Σ₃ = 3/3, Σ₄ = 2/2. Σ₁ has the **most** under either reading, Σ₂ the fewest.

The consequence you drew is the one that matters. Under the convention the
paragraph invokes, the ranking is Σ₂ 1 < Σ₄ 2 < Σ₁ 3 = Σ₃ 3 — the ranking
*inverts*, it does not merely lose its shape. The paragraph now says so,
says the earlier draft had it backwards, and refuses the narrower reading
(collapse the quorum's non-collusion assumptions alone) that would have kept
Σ₁ on top, on the grounds that nothing in "one assumption per mechanism"
singles it out and we do not get to pick the flattering version.

The §6 sentence upstream that called this failure "structural" was also
narrowed: cardinality *charges a deployment for every party it names* is what
survives; *ranks these four backwards* is convention-dependent.

## The §3/§6 contradiction — my judgement

You were right that they pull opposite ways, and §3 was the one at fault.
"The assumption is about the set, not about any individual" is an argument
for counting it **once**. It cannot also be the defence of counting it *n*
times.

What is actually true splits in two, and §3 now says both halves:

- **Naming all *n* is not arguable.** Drop any witness and the threshold
  changes, so every one is load-bearing; and a trust set listing only *k*
  would have to say which *k*, which the deployment cannot know in advance.
- **The count is arguable.** A threshold asks a verifier to accept one
  proposition about a set. Our assumption tuple is keyed by a principal, so a
  set-valued assumption has nowhere to live except unrolled across its
  members. `|T|` charges a quorum *n* times for something accepted once.

That is a limitation of the representation, not a claim about the world, and
we have no fix. I judged saying so to be stronger than any defence — which is
the option you offered, and I think it is right rather than merely available.
§6 now cites §3 for the *distinction* instead of for a defence.

**No code changed.** The tool is right about principals; it was the paper's
account of the tool that was wrong. Worth stating, because the tempting move
was to "fix" `witness_quorum`.

## Closing the class

Both defects were mechanism counts — the family the deployment files expose
and no macro covered. `counts_macros` now emits `\SigmaNMechanisms`
alongside the trust-set counts, `regen-results.sh` writes a counts file per
deployment, and §6's numbers come from the files. Macros available:
`\SigmaN{Assumptions,Parties,Undetectable,Bounded,Mechanisms}` for N in
One..Five.

The acceptance guard is now data-driven over seven (anchor, macro) pairs
covering both families. `one_assumption_per_mechanism_would_invert_the_
cardinality_ranking` pins the shape of the concession — which end each
convention puts first, and that they disagree — because no macro covers a
claim about an *ordering*.

## Minors

- Abstract: "the four proposed ways" → "the four ways we can think of ---
  our own list, not a survey". I5 had been fixed in §6 only.
- "single-hyphen-mechanism deployments" → "non-hybrid", in `main.tex` and the
  three other files.
- Code size: 1,600 → about 1,800 (non-blank, non-comment, outside
  `#[cfg(test)]` — your figure, reproduced). "About as much again in tests"
  was *also* wrong: tests are 3,347 by the same measure, roughly twice. Now
  says "roughly twice that again". I did **not** generate it: "lines
  excluding tests" has no single defensible definition, and generating it
  would broaden the artifact note that `paper/README.md` says not to broaden.
- `tex_escape`: now returns through `TEX_ESCAPED` with every call site a bare
  statement, so `exit 1` runs in the shell `set -e` governs. Verified by
  putting a `~` in a claim name: the guard prints **once** and writes **zero**
  rows, against three prints and three corrupt rows before.

## Concerns

1. **"We had this wrong in an earlier draft" is now in the paper.** It is in
   register (§3.5 already says "embarrassing to find") and it is the
   strongest form of the concession, but it references a draft no reader
   saw. If you would rather state the correction without the confession, it
   is one sentence to cut and nothing else depends on it.
2. **Five counts files, 25 macros, 7 used.** Uniformity over a rule I would
   have had to explain. If the preamble clutter bothers you, generating only
   Σ₁–Σ₄ is a one-line loop change.
3. **`\SigmaNMechanisms` counts declared blocks, not distinct kinds.** The
   two readings give the same ranking here but need not in general. The tool
   commits to blocks and the prose says "declares"; a future sentence that
   means kinds would need a second macro.
4. **The acceptance guard's anchors are now seven strings.** Each reword of a
   guarded sentence costs a test edit. That is deliberate — it is the moment
   a human should look — but it is the most brittle thing I have added, and
   it will eventually annoy someone.
5. **Five prose-vs-artifact defects across four waves.** Two families are now
   generated. I have no evidence a third family does not exist; the ones I
   would look at next are the Δ values quoted in §5.4 ("the seven witnesses",
   the 24-hour bound) and Table 2's fourteen rows, both currently tripwired
   rather than generated.
6. **Unchanged and still unrun:** the independent-encoding experiment, and
   any validation against a system we did not write.

---

# Wave 5 — the three closers

`8e6c91c`. Tests **176** (132 lib + 38 acceptance + 6 robustness), unchanged
in count — two existing tests gained assertions and the guard gained two
sites. `fmt --check`, `clippy -D warnings`, `cargo test`, `regen-results.sh`
(no diff), `tectonic` (no overfull, no undefined references) clean.
`main.pdf` rebuilt. Placeholders 0.

## 1. The unstated reading

You were right, and the direction matters: this one ran *against* us. The
inversion holds under a `[[mechanism]]` *stanza* reading; under distinct
*kinds* it is Σ₂ 1 < Σ₁ = Σ₄ 2 < Σ₃ 3, so Σ₃ is still last, Σ₁ is
mid-table, and "ties the witness quorum for last" was false. The paragraph
about not picking the flattering reading had over-conceded.

The paragraph now names the stanza reading, states what the kinds reading
does instead, and says why we lead with the harsher one: we would rather a
referee find us conceding too much than too little, and neither reading
leaves "ranks the systems backwards" standing.

Both readings are generated rather than typed. `MechanismSpec::kind()` is a
total exhaustive accessor — adding a variant fails to compile rather than
returning a kind nothing recognises — and `counts_macros` emits
`\SigmaNMechanismKinds` beside `\SigmaNMechanisms`. The `tiers` test now pins
the milder outcome as well as the harsher one, so the paper cannot quietly
start leading with whichever reading suits it.

**On `src/tex.rs`'s comment**, which you flagged as aspirational: it is now
true. The tool committed to a reading and the prose did not say which; the
prose says which. I re-read the comment against the finished paragraph
rather than assuming the edit discharged it.

## 2. The draft confession

Cut. Your reasoning and my own concern agreed, and the reviewer's framing was
the one that decided it: the correction had no referent for a reader who
never saw the draft. The numbers survive in the paragraph above it, and the
story lives in `paper/README.md` and the preamble comment.

## 3. Reflow tolerance

Runs of whitespace now collapse to a single space in both the file and every
anchor before matching — which is also what TeX does to the text a reader
sees, so the guard now matches closer to the rendered form than the source
form. One consequence worth noting: squashing strips each anchor's leading
space, so the preceding text is `trim_end`ed before the macro check.

Verified both directions on the same paragraph: a pure rewrap at a different
column width **passes**, and replacing `\SigmaOneMechanismKinds{}` with the
typed word `two` *inside that rewrapped text* still **fails**. The guard is
now insensitive to the thing that does not matter and sensitive to the thing
that does.

## Housekeeping

Waves 2–4 of this report were being appended from inside the parallax
working tree, so wave 4 landed in `parallax/.superpowers/` instead of here.
Merged into this file and the stray directory removed; it was never
committed to the parallax repo.

## Concerns

1. **Nine anchor strings in the guard.** Up from seven. Reflow no longer
   breaks it, so the remaining brittleness is genuine rewording only — which
   is the case where a human should look. I think this is now at the right
   sensitivity, but it is the largest thing I have added that a future editor
   will have to understand before editing §6.
2. **`\SigmaNMechanismKinds` exists because §6 needed it.** Ten macros per
   deployment now, most unused. Same trade as before: uniformity over a rule
   I would have to explain.
3. **Unchanged and still unrun:** the independent-encoding experiment, and
   any validation against a system we did not write. Nothing in this wave
   touched the evidence base.
