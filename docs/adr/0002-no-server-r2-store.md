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
