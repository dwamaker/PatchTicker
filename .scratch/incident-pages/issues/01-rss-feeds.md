# 01: Korean and English RSS feeds on patchticker.com

**What to build:** A reader can subscribe to `https://patchticker.com/feed.xml` (Korean) and `/en/feed.xml` (English)
and gets the newest 50 search-worthy Incidents (위험 or above, exploited, or without a CVE; on the Board and with a
Summary), newest first. Each item carries the title, the plain explanation, the Summary and what to do, and links to
the Incident on the Board (`/#i=<id>`) until Incident pages exist. The Board page announces both feeds so browsers and
RSS readers find them, and the footer and READMEs link them. This ticket also stands up the Pages Function that
later tickets extend: it reads the collector's feed document from R2 through a binding and renders RSS 2.0 per
request, with a short edge cache. See the spec (`../spec.md`) and ADR 0002's 2026-11-10 revision.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The collector has a Python port of the Board's risk rule, checked against the JavaScript rule by one shared fixture of cases.
- [ ] Each cycle writes one feed document: the newest 50 search-worthy Incidents with Summaries, newest first, only when it changed.
- [ ] `/feed.xml` and `/en/feed.xml` answer valid RSS 2.0 in their language; item GUIDs stay the same when a Summary is rewritten.
- [ ] Every text in the feed is escaped and only http/https links are emitted (a hostile title in a test proves it).
- [ ] An R2 read error answers 503, never a broken feed.
- [ ] The Board page has `rel="alternate"` links to both feeds; the footer and both READMEs link them.
- [ ] Tests at the cycle seam (store holds the right feed document) and the function seam (request plus fake R2 in, response out, `node --test`).
- [ ] Deployed: the site with the function and its R2 binding first, then the collector; the live feeds validate in an RSS validator.

## Comments

**2026-11-10 (built, not deployed):** collector writes `board/feed.json` each cycle when it changed; the Pages Function (`functions/feed.xml.js`, `functions/en/feed.xml.js`, renderer in `edge/feed.mjs`) renders RSS 2.0 with an edge cache. GUIDs are already the future Incident page addresses (`/i/<slug>`, `/en/i/<slug>`, isPermaLink false), so ticket 03 changes only the item links. Checked with `wrangler pages dev` and a feed built from the live week: 50 items, well-formed XML, both languages. Left: the Pages project's R2 binding `DATA` and the deploy (site first, then the collector, which also ships the news and KISA sources).
