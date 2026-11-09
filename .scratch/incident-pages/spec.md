Status: ready-for-agent

# Incident pages and the RSS feed

Vocabulary follows `CONTEXT.md` (Incident, Mention, Summary, Board, Incident page, RSS feed). Architecture follows
ADR 0001 (one row per Incident) and ADR 0002 with its 2026-11-10 revision (one Pages Function renders Incident pages,
the RSS feeds and the Incident sitemap from the collector's JSON in R2). Decided with the owner on 2026-11-10 in a
grilling session; the answers are summarized under Implementation Decisions.

## Problem Statement

Patch Ticker is one page whose script draws every Incident in the browser. Search engines (Google, Naver, Bing)
see almost nothing of the Incidents, so someone searching for "QNAP Plex2Shell" or "SonicWall SSL-VPN 취약점" never
lands on the Board, even when the Board has the best Korean answer. A link to one Incident (`#i=`) opens the Board
with that row open, but a messenger or SNS preview shows only the site's generic title, so a shared link says
nothing about the Incident. And there is no way to subscribe: a reader who wants to hear about the serious
Incidents has to keep the page open or come back.

## Solution

Every Incident that has a Summary gets an Incident page: a plain document at its own address on patchticker.com, one
in Korean (`/i/<slug>`) and one in English (`/en/i/<slug>`), readable without the page's script, with a link
preview that names the Incident. Pages of Incidents worth a search (위험 or above, exploited, or without a CVE) are
offered to search engines through a sitemap; the rest carry `noindex` and exist for sharing. A Korean and an English
RSS feed carry the newest 50 of those search-worthy Incidents. Pages are kept for 90 days; after that the address
answers 410 with a short note and links onward. When two Incidents merge, the address of the one that disappeared
moves permanently to the survivor. The Board's "copy this Incident's link" button and the feed items point to the
Incident page whenever one exists.

## User Stories

1. As a home-server owner searching Google for a product name and "vulnerability", I want an Incident page to appear in the results, so that I find the Korean explanation and the fix without knowing Patch Ticker exists.
2. As a Korean reader searching on Naver, I want the Korean Incident page to be the one Naver shows, so that I read it in my language.
3. As an English reader searching on Google or Bing, I want the English Incident page to be the one shown, so that I am not sent to Korean text.
4. As a reader who lands on an Incident page, I want to see the title, the risk level, the CVSS score and whether it is exploited at the top, so that I know at once how serious it is.
5. As a reader on an Incident page, I want the plain-language explanation, the conditions under which I am affected and what to do, so that I can act without opening the Board.
6. As a reader on an Incident page, I want the affected Products and platforms, so that I can tell whether it touches something I run.
7. As a reader on an Incident page, I want links to the official advisory, write-ups, the CVE record, discussions and the KISA notice, so that I can check the source before acting.
8. As a reader on an Incident page, I want to see when the news was published and when Patch Ticker first saw it, so that I know how fresh it is.
9. As a reader on an Incident page, I want a "게시판에서 보기 / Open on the Board" link that opens the Board with this Incident open, so that I can see related Incidents and use the filters.
10. As a reader on an Incident page, I want a language switch to the other language's page, so that I can read the version I prefer.
11. As a reader on an Incident page, I want the "Report a mistake" link that the Board has, so that I can correct an AI-written Summary from there too.
12. As a reader on a phone, I want the Incident page to fit a 375 px screen without sideways scrolling, so that a link opened from a messenger reads well.
13. As a reader who prefers dark screens, I want the Incident page to follow my system's light or dark setting, so that it matches the Board.
14. As a screen-reader user, I want the Incident page to be a well-structured document (one heading, labelled sections, real links), so that I can navigate it.
15. As someone sharing an Incident in KakaoTalk, Slack or X, I want the preview to show the Incident's title and a one-line explanation, so that the people I send it to know what it is about before they tap.
16. As someone sharing from the Board, I want "copy this Incident's link" to copy the Incident page address when one exists, so that the shared link has a real preview.
17. As someone sharing an Incident that has no Summary yet, I want the copy button to keep copying the Board link, so that I can still share it right away.
18. As someone who shared an Incident link that later merged into another Incident, I want the old address to lead to the surviving Incident's page, so that my link does not break.
19. As someone opening an Incident link older than 90 days, I want a short note that the page has expired with links to the Board and, for a CVE, to its CVE record, so that I am not left at a dead end.
20. As a search engine, I want expired pages to answer 410, so that I drop them from the index quickly.
21. As a search engine, I want a sitemap of every search-worthy Incident page of the last 90 days with its last change time and both language versions, so that I find new pages without crawling the Board.
22. As the owner, I want 참고-level Incidents with a CVE kept out of search indexes (`noindex`, not in the sitemap), so that hundreds of thin pages a day do not get the whole site judged as mass-produced content.
23. As the owner, I want an Incident that rises to 위험 or above (a CVSS score arrives, CISA lists it, a Summary reports attacks) to become search-worthy automatically, so that no one has to promote pages by hand.
24. As the owner, I want an Incident whose Summary says it is not an Incident to have no page, so that general news never gets a page.
25. As a reader who subscribes in an RSS reader, I want a Korean feed and an English feed of the newest 50 search-worthy Incidents, so that I hear about serious ones without visiting.
26. As an RSS subscriber, I want each item to carry the title, the plain explanation, the Summary and what to do, with a link to the Incident page, so that I can decide from the reader whether to open it.
27. As an RSS subscriber, I want an item to keep the same identity when its Summary is rewritten, so that my reader does not show it twice.
28. As a visitor of the Board, I want the browser and RSS readers to find the feed from the Board page itself, so that subscribing is one click.
29. As the owner, I want the Incident pages, feeds and sitemap to update within one collector cycle of a change, without deploying the site, so that the data path stays as it is today.
30. As the owner, I want a change to the Incident page's look to apply to every page on the next site deploy, so that I never have to re-render old pages.
31. As the owner, I want the function to cost nothing at today's traffic (Cloudflare's free allowance) and to cache its answers at the edge, so that a burst of visits does not read R2 for every request.
32. As the owner, I want every text on an Incident page escaped and every link limited to http and https, so that a hostile title or URL from a source cannot run script on patchticker.com.
33. As the owner, I want the NVD notice and the MITRE CVE notice on every Incident page, as on the Board, so that the terms of use are met wherever CVE data is shown.
34. As a developer, I want the Incident page to reuse the Board's own rules (risk level, exploited reason, easy action, Product names) rather than a second copy, so that a page and its Board row never disagree.
35. As a developer, I want the collector to record which Incident absorbed which, so that merged addresses can move without guessing.

## Implementation Decisions

- **Rendering at the edge.** A Pages Function in the site's project answers `/i/<slug>`, `/en/i/<slug>`, `/feed.xml`,
  `/en/feed.xml` and the Incident sitemap. It reads JSON from the R2 bucket through a binding and renders HTML or XML
  per request; the collector never writes HTML. Everything else stays static as today.
- **Shared rules.** The function imports the Board's rule module (risk level, exploited reason, easy action, Product
  names, on-Board check) instead of copying it. New rendering lives in its own module so it can be tested without
  the Workers runtime.
- **Who gets a page.** An Incident gets an Incident page once it has a Summary and is on the Board (a CVE-less HN or
  news story only when its Summary calls it an Incident). Pages exist for 90 days from first seen; after that the
  function answers 410.
- **Search-worthy.** An Incident at the 위험 level or above (CVSS 7.0+), exploited (KEV, or a Summary with its source),
  or without a CVE. Search-worthy pages are indexable and listed in the sitemap; all others carry `noindex`. The
  collector needs a Python port of the Board's risk rule for the feed and sitemap lists, kept in step with the
  JavaScript by a shared fixture (prior art: the Products case fixture).
- **Addresses.** The slug comes from the Incident ID and never changes: a CVE ID as is (`CVE-2026-123158`), an HN
  story as `hn-<item number>`, any other URL ID as `u-` plus a short hash of the ID. Korean at `/i/<slug>`, English at
  `/en/i/<slug>`; each page names itself canonical and links the other with `hreflang` (Korean as `x-default`).
- **Merged Incidents.** When an Incident is absorbed (a merge by CVE, a release group, a rejoined story), the
  survivor records the absorbed IDs. The collector writes a small "moved to" document for each absorbed slug; the
  function answers 301 to the survivor's page in the same language. A move older than 90 days answers 410 like any
  expired page.
- **What the collector writes** (JSON, through the existing store, so the SQLite backup keeps a copy):
  - one Incident page document per slug, holding the page-facing fields the Board file already carries, rewritten
    when any of them changes;
  - one "moved to" document per absorbed slug;
  - one feed document: the newest 50 search-worthy Incidents with Summaries, newest first;
  - one sitemap document: every search-worthy slug of the last 90 days with its last change time.
- **The page.** A single document, no script: title; risk banner, CVSS ring and exploited reason; plain explanation;
  conditions; what to do (update command, stopgap, fixed version, devices, as the Easy view shows them); Products and
  platforms; CVE IDs; Mentions grouped by kind with the KISA notice among them; published and first-seen times;
  links to the Board (`/#i=<id>`), the other language and "Report a mistake"; the NVD and MITRE notices. Same colour
  tokens and fonts as the Board, light and dark by system setting, works at 375 px.
- **Link preview.** `og:title` is the Incident's title, `og:description` the plain explanation (or the Summary's
  first sentence), `og:image` the site's shared image; `og:locale` per language.
- **Expired page.** 410 with a short note ("보관 기간 90일이 지났어요"), a link to the Board and, for a CVE, to its CVE
  record.
- **RSS feeds.** RSS 2.0 at `/feed.xml` (Korean) and `/en/feed.xml` (English), newest 50 search-worthy Incidents; each
  item has the title, the plain explanation, the Summary and what to do, links to the Incident page, and a GUID that
  is the page address (stable across Summary rewrites). The Board page announces both feeds with `rel="alternate"`
  links, and the footer and READMEs link them.
- **Sitemap.** The static `/sitemap.xml` becomes a sitemap index listing the home page's sitemap and the Incident
  sitemap the function renders; `robots.txt` keeps pointing at `/sitemap.xml`.
- **Board changes.** "Copy this Incident's link" copies the Incident page address when the Incident has one (Summary,
  on the Board, within 90 days) and the `#i=` link otherwise. The Board's `#i=` handling stays as is (the page's
  "Open on the Board" link uses it).
- **Caching.** Function answers carry a short public cache time (minutes) and use the edge cache, so repeated
  requests do not read R2; the collector's cycle (10 minutes) bounds how stale a page can be.
- **Trust boundary.** Titles, Summaries and URLs come from the web and a model: the renderer escapes every text and
  drops any link that is not http or https. The existing rate limiting rule on patchticker.com covers the function.
- **Order of work.** First the function skeleton and the RSS feeds (items link to `#i=` until pages exist), then
  Incident pages, merged moves and the sitemap, then IndexNow as a separate step.

## Testing Decisions

- Tests check behaviour at the two seams the owner agreed, never internals:
  1. **The collection cycle** (existing seam 1, `run_cycle` against recorded sources into a memory store): after a
     cycle, the store holds the right Incident page documents, "moved to" documents for absorbed Incidents, the feed
     document (only search-worthy, newest 50, newest first) and the sitemap document (search-worthy, 90 days).
     Prior art: the cycle, mention and summary tests that replay fixtures and read the store.
  2. **The function** (new seam): a request plus a fake R2 binding in, a response out, with `node --test`. Covers
     200 HTML in both languages with canonical, hreflang, `noindex` only when not search-worthy, escaped hostile text
     and dropped `javascript:` links; 301 for a moved slug; 410 for a page older than 90 days and for an unknown
     moved target; the two RSS feeds; the sitemap index and the Incident sitemap. Prior art: `tests/board.test.mjs`.
- The Python port of the risk rule is checked against the JavaScript rule through one shared fixture of cases.
- A manual check after deploy: a real page in the owner's Chrome (light, dark, 375 px), a link preview in a messenger,
  the feed in an RSS validator, and the sitemap in Google Search Console.

## Out of Scope

- IndexNow notifications (next step, after pages are live; Naver's support to be checked then).
- Per-Incident preview images (the shared image is used).
- Pages older than 90 days, and search beyond what the Board loads.
- Structured data (JSON-LD) on Incident pages.
- A feed per Product or per filter; feeds of all Incidents.
- Any change to how Incidents are collected, linked or summarized, other than recording absorbed IDs.

## Further Notes

- About 650 Incidents a day; the search-worthy share is estimated at a few dozen a day, so the 90-day sitemap stays
  well under one sitemap file's 50,000-URL limit (to be confirmed on real data before relying on it).
- The function should fail closed: an R2 read error answers 503 with a link to the Board, never a half-rendered page.
- Deploy order matters: the site (function) first, then the collector that writes the new documents; until the
  collector writes them, the function answers 404 for unknown slugs, which is harmless.
- Pending deploys to coordinate with: the news-site and KISA sources (committed 52a422a, not deployed) and the
  end of the 7-day backfill.
