# 04: Merged Incidents move to the survivor's page

**What to build:** When an Incident is absorbed into another (a merge by CVE, a release group, a rejoined story), the
absorbed Incident's page address answers 301 to the survivor's page in the same language, so a shared link keeps
working. A move older than 90 days answers 410 like any expired page.

**Blocked by:** 02

**Status:** done (deploy pending)

- [x] The survivor records the IDs it absorbed (including IDs its absorbed Incidents had absorbed).
- [x] Each cycle writes a "moved to" document for each newly absorbed slug.
- [x] The function answers 301 to the survivor in the same language; 410 when the move or the survivor is past 90 days.
- [x] Tests: a cycle that merges two Incidents leaves the moved document (cycle seam); the 301 and 410 answers (function seam).

## Comments

**2026-11-10 (built, not deployed):** the three merge paths (`link` by CVE, `group_releases`, `rejoin`) now go through
one `fold()` in `collector/incidents.py`, which records `absorbed` on the survivor (its own absorbed IDs carried over,
so a chain A→B→C ends with C listing B and A). `write_moves` in `collector/cycle.py` writes the moved document **at
the absorbed slug's own `pages/<slug>.json`** (`{id, moved_to, moved}`), so the stale page document is overwritten and
no longer renders as its own page; the function needs no second key per slug. `moves.json` (`{slug: [survivor slug,
moved]}`) is the change index, one read per cycle like `page_hashes.json`: a document is written only when a slug
first moves or its survivor is absorbed in turn; `moved` keeps the time the address first moved. It is not pruned
(a few thousand entries a year at most). An absorbed ID that is a live Incident again keeps its own page.
`moves.json` is separate from `page_hashes.json` on purpose, so ticket 05's sitemap never sees moved slugs.
The function reads the survivor's document too: 301 (`public, max-age=300`; the edge cache keeps only 200s) when it
has a page on the Board within 90 days; 410 when the move or the survivor is past 90 days, the survivor has no page
(no Summary yet, or not on the Board), or the target slug is malformed (never read). Only merges after deploy are
recorded; older absorbed pages stay as ticket 02 left them until they expire. Left: deploy (site first, then the
collector).
