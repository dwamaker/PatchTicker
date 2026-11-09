# 02: Incident pages in Korean and English

**What to build:** Every Incident with a Summary that is on the Board has an Incident page at `/i/<slug>` (Korean) and
`/en/i/<slug>` (English): a single document without script showing the title, risk banner, CVSS and exploited
reason, plain explanation, conditions, what to do, Products and platforms, CVE IDs, Mentions (the KISA notice among
them), published and first-seen times, links to the Board (`/#i=<id>`), the other language and "Report a mistake",
and the NVD and MITRE notices. Search-worthy pages are indexable; all others carry `noindex`. Each page is canonical
to itself with `hreflang` to the other language (Korean as `x-default`), and its link preview names the Incident.
Pages older than 90 days from first seen answer 410 with a short note and links to the Board and the CVE record.
Slugs never change: a CVE ID as is, `hn-<item number>` for an HN story, `u-` plus a short hash for any other URL ID.

**Blocked by:** 01

**Status:** done (deploy pending)

- [x] Each cycle writes an Incident page document per slug (the page-facing fields), only when it changed.
- [x] Both language pages render with canonical, hreflang, og:title/description/image/locale, and `noindex` only when not search-worthy.
- [x] The page reuses the Board's rule module (risk level, exploited reason, easy action, Product names); no second copy of those rules.
- [x] Every text is escaped and non-http(s) links are dropped (hostile title and `javascript:` link in tests).
- [x] 410 for a page older than 90 days, 404 for an unknown slug, 503 on an R2 read error.
- [x] Light and dark by system setting; no sideways scroll at 375 px; one heading and labelled sections for screen readers.
- [ ] Tests at both seams (done); after deploy, a real page checked in the owner's Chrome (light, dark, 375 px) and a link preview in a messenger.

## Comments

**2026-11-10 (built, not deployed):** the collector writes `pages/<slug>.json` (the Board's fields, `board_view`) for
every Incident with a Summary first seen in the last 90 days; the function decides 404 (not on the Board), 410 (past
90 days) and `noindex` from it with the Board's own rules, so a Summary that later says "not an Incident" turns its
page into a 404 without a delete. Change detection: one `page_hashes.json` per cycle (`{slug: [hash, changed]}`, a
hash of the page's fields), so a cycle reads one document instead of one per page and writes only changed pages; the
`changed` stamp is the sitemap's last change time for ticket 05. The slug rule has a Python port (`page_slug`) checked
against `slug()` by `tests/fixtures/board/slug-case.json`. Function routes `functions/i/[slug].js` and
`functions/en/i/[slug].js`, renderer `edge/page.mjs` (no script; a CSP header allows inline styles only); sections are
labelled regions under one `h1`; Korean pages show Korean time, English pages UTC. `wrangler pages functions build`
compiles it (the Board module's JSON import included). A sample page was checked in headless Chrome in a 375 px frame,
light and dark: no sideways scroll, long URLs and commands wrap. Left: deploy (site first, then the collector, whose
first cycle writes every summarized Incident of the last 90 days once), the owner's Chrome check and a messenger link
preview. An absorbed Incident's old page document stays (and renders) until ticket 04 writes its "moved to" document.
