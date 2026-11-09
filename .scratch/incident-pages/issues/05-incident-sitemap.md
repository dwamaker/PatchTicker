# 05: Incident sitemap for search engines

**What to build:** Search engines find every search-worthy Incident page of the last 90 days through the sitemap,
without crawling the Board. `/sitemap.xml` becomes a sitemap index listing the home page's sitemap and the Incident
sitemap that the function renders from the collector's sitemap document, with each page's last change time and both
language versions linked by `hreflang`. `robots.txt` keeps pointing at `/sitemap.xml`.

**Blocked by:** 02

**Status:** done (deploy pending)

- [x] Each cycle writes one sitemap document: every search-worthy slug of the last 90 days with its last change time.
- [x] The function renders a valid sitemap with both language URLs and hreflang alternates; non-search-worthy pages never appear.
- [x] The static sitemap becomes a sitemap index; the home page keeps its own entry.
- [x] The URL count on real data is checked against the 50,000 limit and noted in Comments.
- [ ] After deploy: resubmitted in Google Search Console and Naver Search Advisor, and accepted.

## Comments

**2026-11-10 (finding while building 01):** on the live week (backfill included) 314 of 746 Incidents were search-worthy, about 42%, not a few dozen a day. At ~650 a day that is ~270 a day, ~24,000 in 90 days and ~48,000 URLs with both languages: at the 50,000 limit of one sitemap. Split the Incident sitemap by month (a sitemap index entry each) from the start, and recheck the share once the backfill is over.

**2026-11-10 (built):** the collector writes `sitemap.json` (`{pages: {slug: [first_seen, last change]}}`, the last
change from `page_hashes.json`) when it changed. The static `/sitemap.xml` is a sitemap index of `sitemap-home.xml`
(the home page, as before) and four fixed Incident sitemaps `/sitemaps/incidents-0.xml` to `-3.xml`: slot n lists the
search-worthy pages first seen n calendar months ago (UTC) and within 90 days, in both languages, each URL with
`hreflang` ko, en and x-default (Korean) and `lastmod`. Fixed slots rather than `YYYY-MM` names because the index is
static: calendar names would need a site deploy every month (or a function in place of the static index). The cost:
a slot's content turns over when the month does, and slot 3 (and early on, slots 1-3) can be an empty `urlset`, which
Search Console reports as empty, not as an error. 503 when R2 cannot be read, 404 for any other name under
`/sitemaps/`.

**URL count (offline):** no live data in the repo. The only local snapshot (`web/data`, a local-test run of
2026-11-08..09) has 88 search-worthy of 265 Incidents (33%), 176 URLs. On the live week's 42% share (~270 a day), a
calendar month is ~8,400 Incidents, ~16,800 URLs per monthly sitemap, ~48,000 over the four: each well under 50,000.
`sitemap.json` would be ~1.7 MB at that size. Recheck the share and the slot sizes on live data after the backfill.

**2026-11-10 (review fixes):** `sitemap.json` is now `{pages: {slug: {first_seen, changed}}}` (named fields). A sitemap
file lists at most 25,000 pages (50,000 URLs), newest first; past that the oldest are left out (a `shortcut:` comment
in `edge/sitemap.mjs`). A `sitemap.json` without its `pages` object answers 503, never an empty list a crawler would
read as "all gone". The 90-day check is `withinPageDays` from `web/board.mjs`, shared with the page and `shareLink`.
