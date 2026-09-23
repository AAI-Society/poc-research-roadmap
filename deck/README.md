# Research agenda decks

Two self-contained HTML presentations of the Proof-of-Control research roadmap, built on the
Advanced AI Society deck template (1920×1080, off-white ground, Jost / Atkinson Hyperlegible
Next / Inter, cinnabar section dividers cited from `assets/shapes/dividers.json`). Fonts are
embedded, so both present offline.

| File | Audience | Slides |
| --- | --- | :--: |
| `research-agenda.html` | Researchers and working-group members. Field-level detail, paper IDs, tool names. | 31 |
| `research-agenda-for-security-leaders.html` | CISOs and executives. One idea per slide, a picture on each: the receipt, the four rungs, who you are still trusting, what you could switch on today. | 28 |

**Present:** open the file in a browser. ← → or Space to move, Home / End, F for fullscreen,
click the right or left half of the slide. `#12` in the URL jumps to a slide.
**PDF:** ⌘P prints one slide per page at 1920×1080.

**Edit:** the slides live in `src/*.slides.html`; the shared stylesheet, lockup and stage
script in `src/_head.html` and `src/_tail.html`. Run `python3 src/build.py` to rebuild both
(needs `fonttools`, and the brand fonts at `~/Desktop/ClaudeDesign/fonts`).
