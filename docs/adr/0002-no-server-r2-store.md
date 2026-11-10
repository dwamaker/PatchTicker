# No public server: static page, R2 monthly files as the store

The site is public and free, so nothing that answers visitors runs on our machines. The page is static on Cloudflare Pages, filtering and search run in the browser, and the data is monthly JSON files in Cloudflare R2, which is also the primary store (each collector keeps an SQLite copy only as a backup). The collector runs on the Oracle free-tier VM; the `.104` homelab box runs the same image as a standby that takes over only when R2 has not been updated for 45 minutes. This keeps the homelab and the proxy VM's address off the public path and lets either collector resume from R2 alone.

## Consequences

- Search covers what the page downloads: the last 90 days (three monthly files) in v1. A longer range means loading more files, or later a search service.
- The Pages site is deployed only when the code changes; data updates never trigger a deploy.

## Revision (2026-11-08): the page opens on the last week

The "last 90 days" consequence above does not hold at real volume: about 650 Incidents a day is roughly
60,000 rows and over 100 MB for three months. The collector now also writes page-facing files without
its linking keys (`board/recent.json` for the last 7 days of first-seen Incidents, and `board/YYYY-MM.json`
per month); the page loads only the week, draws 100 rows at a time, and loads the last three months'
board files when the visitor asks ("이전 사건 불러오기"). Search and the Product filter cover what is
loaded. The collector's own `months/` files are unchanged.

## Revision (2026-11-08, late): the picker's Product list covers 90 days

With only the week loaded, the Product picker could not offer a Product whose Incidents are older, so the
"no Incident" all-clear sign was out of reach. Each cycle also writes `board/products.json`: every Product of
Board Incidents first seen in the last 90 days, with its Korean and English names. The page adds it to the
picker; the Board rows themselves still come only from what is loaded.

## Revision (2026-11-10): one edge function for Incident pages and the RSS feed

Search engines cannot read Incidents drawn by the page's script, and a shared `#i=` link has no preview of its
own. A Cloudflare Pages Function on patchticker.com now answers `/i/*`, `/en/i/*`, the RSS feeds and the Incident
sitemaps: it reads the collector's JSON from R2 and renders HTML or XML per request. It runs on Cloudflare's edge,
not on our machines, and needs no deploy when data changes, so the two points above still hold. Rejected: writing
finished HTML from the collector (the store and its SQLite backup carry JSON only, and a template change would mean
re-rendering every page), serving pages from the data domain (worse for search and sharing), and redeploying the
site every cycle.

## Revision (2026-11-10, late): the Board draws from row views first

The 2026-11-08 Revision's "the page loads only the week" is no longer the whole story: the week is 9.2 MB decoded
(1.2 MB on the wire) and held a phone's first row back about a second. Each cycle also writes `board/rows.json`: the
same Incidents as Row views (CONTEXT.md), without details or search text, except the newest 100 and the week's
Highlights, which stay whole. The page draws from it and fetches `board/recent.json` only to open a Row view or to
search, never in the background. "Search and the Product filter cover what is loaded" still holds, but a search now
waits for the full week first.
