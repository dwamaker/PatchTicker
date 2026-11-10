# Development

How the collector and the page work, and how to run them. The project is Patch Ticker in public;
the repository and the code are named vuln-radar. Vocabulary: `CONTEXT.md`; decisions: `docs/adr/`.

Needs Python 3.13 and Node 24. Dependencies: the Anthropic SDK and boto3 for R2 (`pip install -r requirements.txt`);
no build step.

## Run one cycle locally

```sh
cp .env.example .env        # then set VR_STORE_DIR=web/data, VR_COLLECTOR_ID, VR_CONTACT
python -m collector         # one cycle: cvelistV5, oss-security, HN, GitHub, news sites, NVD, CISA KEV, curators, KISA -> web/data/
python -m http.server 8000 -d web
```

Open http://localhost:8000/ to see the Board. The first cycle with an empty store reads only the
newest delta log entry; later cycles pick up everything since the last checkpoint.
`VR_GITHUB_TOKEN` (optional, no scopes) lets GitHub search run at 30 instead of 10 requests a minute.

## Run live (R2, every 10 minutes)

Leave `VR_STORE_DIR` empty and set the four `VR_R2_*` settings in `.env`, then `docker compose up -d --build`
(`compose.yaml`; one cycle now: `docker compose run --rm collector python -m collector`). Every document is written as JSON with a
30-second cache. The loop stops a cycle after 50 minutes (`timeout` in `compose.yaml`; logged "cycle timed out") so a
hung source cannot block later cycles.
Every write also lands in an SQLite copy (`VR_BACKUP_DB`, `./backup` in Compose); `--seed-backup` fills it once from
the store and `--restore` rebuilds the store from it (commands in `compose.yaml`).

The store keeps an Incident 90 days from its first seen (`PAGE_DAYS` in `collector/cycle.py`, the Incident page's span;
owner, 11-10). Each cycle, before any source is read, older Incidents leave their month (`months/<m>.json` and
`board/<m>.json`, rewritten for that alone); a month left with none is dropped from `index.json` and then deleted, from
the SQLite copy too, and the week, row, feed, page, sitemap and Product documents follow as they are rebuilt from what is
held. Deletion cannot be undone, so a cycle that would prune more than half of the Incidents it holds prunes none and
logs one `retention:` line (a wrong clock or bad data; ageing takes about 1/90 a day, so only a 45-day outage comes
near it). The R2 token needs object delete as well as read and write; a refused delete is one `store: could not delete`
line and the object stays, listed by no index. An aged-out CVE comes back only as a new Incident and only through a new
story (an HN story, a news site, a fresh oss-security post): cvelistV5 reads updated records only of CVEs still held,
and NVD, CISA KEV, curators, KISA, GitHub repos and oss-security replies only join Incidents.

Vendor spellings put in front of bare Product names ("IBM Storage Scale") live in `web/vendors.json`; each cycle
lists the missing ones in `unknown_vendors.json` in the store. How to add one: `docs/agents/vendors.md`.
Summaries given up after three tries (last 30 days, on the Board) are listed in `summary_failures.json` each cycle; how
to act on one: `docs/agents/summary-failures.md`.
With `VR_DISCORD_WEBHOOK` set (a `https://discord.com/api/webhooks/...` address only; anything else is refused at
start-up, and the value is never logged), a cycle that newly gives up a Summary (an id not in the last cycle's
`summary_failures.json`) or merges by `same_as` posts one short Korean message there (`collector/discord.py`; no pings,
at most about 1,800 characters). A failed post is one stderr line and is not retried.

Mentions join an Incident when they cite one of its CVE IDs or, while either side has no CVE, one
of its URLs (`collector/incidents.py`, ADR 0001).
CVE-less stories of one event share neither (owner, 11-10), so a CVE-less Incident's Summary request also lists, beside
the input, up to 20 Board Incidents with a Summary and no CVE published in the last seven days (id, English title,
Products), and the reply names the same event in `same_as` or "". The model only proposes; the code decides
(`apply_same_as` in `collector/same_event.py`, run by the cycle right after Summaries, instant and batch alike): the id
must have been listed, that Incident must still exist with no CVE and on the Board, and the two must share a Product
key (`products_of`). Then they fold as `link()` folds (the earlier first seen survives, the other's page moves) and the
survivor is due a new Summary (`merged` in its Summary basis). Every answer that named an id or had a list goes into
`merge_log.json` in the store (newest first, last 300: `at`, `incident`, `candidates`, `same_as`, `accepted`, `why`),
and each merge into one stderr line. An answer naming an Incident already folded away counts for the one that
absorbed it, so rows naming each other end as one.

The Board opens on `board/rows.json` (owner, 11-10): the week of `board/recent.json` as row views (marked `rows`), with
only what a row, the filters, folds and Highlights read, and the collector's `wp_plugin` answer; the newest 100 and the
week's Highlights stay whole (ports kept in step by `tests/fixtures/board/rows-case.json`). The page fetches
`board/recent.json` only to open a row view or to search.

Highlights (of the last seven days: every exploited one, then the best-scored well-known one of each product, then the
rest by score, at least ten and at most twenty; `pickHighlights`, owner 11-10 and 11-11) are scored in the page
(`highlightScore` in `web/board.mjs`) from the exploited flag (KEV, or a Summary reporting attacks), HN points, curator newsletter Mentions, CVSS (an exploited Incident with no score counts as 9.0, the floor of its 최고 band) and Mention count (up to ten, so a many-CVE release does not outrank exploited Incidents); among equal scores the newer is first. Curator issues add 25 each, two at most however many issues cite the Incident; one issue cites an Incident once (by its link).
Well known (`wellKnown`): a row at 최고, not exploited, that the collector stamped `known` on both its row and board
views, worked out at each write and never stored (`known_label` in `collector/incidents.py`): the label of its first
Product on `collector/well_known.json`, else, when its Summary says `widely_used` (none since 11-11: the schema cannot carry it), that Product's English name; and
`known_rank`, the label's place in that file, which orders the well-known Highlights (none for a label on no list,
which comes last). The
collector picks the same Highlights (`highlights` in `collector/cycle.py`, kept in step by
`tests/fixtures/board/highlights-case.json`) so each is whole in `board/rows.json`. How to add a product:
`docs/agents/vendors.md`.
Curator feeds default to tl;dr sec and the Risky Business News newsletter (`news.risky.biz/rss/`; the `risky.biz` feed is the podcast, with no text to cite from); `VR_CURATOR_FEEDS` overrides them.
Security news sites (BleepingComputer and SecurityWeek, `collector/news.py`) start Incidents like HN stories: a story,
or an HN story linking to one of `incidents.NEWS_HOSTS`, is summarized at once whatever its points, and a CVE-less one
shows only once its Summary calls it an Incident (company breaches, arrests and scams stay off). KISA 보호나라 notices
(`collector/kisa.py`) join the Incidents of the CVE IDs on their pages as "notice" Mentions: never the Lead, never read
for a Summary.

With `ANTHROPIC_API_KEY` set, Highlight candidates (KEV, HN or curator Mention, CVSS 9.0+, or an
Unassigned incident seen in discussion, first seen in the last seven days) get a Summary from Claude
Haiku 5.5 in the same cycle (`collector/summaries.py`). The input is the Incident, its CVE records and
the text of up to two advisory or write-up pages; a reply whose numbers, versions or Lead link are not
in that input, or whose Korean and English numbers differ, is rejected and retried (three tries).
A digit inside a fixed Korean word (`KO_DIGIT_WORDS`, only "제3자" so far) is not counted in Korean text.
Each retry says why the last reply was rejected, beside the input and never inside it (so a number named there is
still not allowed); a reply cut off at the token cap gets more room. After the third rejected try the Summary is given
up and never asked for again; an older Summary stays on the page.
A fixed version below the CVE records' first fixed version of the same major (the Incident's `product<version`
fix keys, one product only) is rejected on every try, the last included (`fixed_conflict`; FreeRDP's advisory said
3.22.2 for 3.32.2), and a stored Summary that names one is made again within the usual limits.
The collector refuses to fetch non-public addresses, since Mentions name the pages it reads.

Every other Incident (first seen in the last 30 days) goes into one Message Batch per cycle with the
same request and a one-hour prompt cache; a later cycle collects the results (`batches.json` in the
store holds the pending batches and their inputs). Expired or errored requests are sent again. A new
official advisory, a new KEV listing or a newly attached CVE brings a new Summary, at most three per
Incident. A credit-exhausted or spend-limit error stops Summaries for the cycle and sets
`"summaries": "paused"` in `status.json`, which the page shows as a short notice; Briefs keep flowing.

The same request fills the Easy view (a tab on each Incident, normal by default, remembered per
Incident): one or two plain sentences per language, the fixed version, a device list, and an update
command and stopgap that are kept only when they appear verbatim in the input. The Risk banner comes
from rules in `riskLevel` (`web/board.mjs`), not from the model.

`python -m collector other.env` reads a different environment file. Real environment variables
override the file.

## Deploy the page

The page is static: deploy everything in `web/` except `web/data/` (local test data, git-ignored) to the Pages
project `patchradar`, for example from a copy without that folder:

```sh
npx wrangler@4 pages deploy <copy of web without data/> --project-name patchradar --branch main
```

Run it from the repository root: `functions/` (the Pages Function) is taken from the working directory, and it imports
`edge/` (`edge/shared.mjs`: the site address, escaping, the R2 read, the edge cache and the what-to-do text every
function shares). The function answers `/feed.xml` and `/en/feed.xml` from `board/feed.json` in R2 through the binding
`DATA` (bucket `patchradar`), which the Pages project must have. Locally: `npx wrangler@4 pages dev <copy> --r2 DATA=patchradar`
with a `board/feed.json` put into local R2 (`npx wrangler@4 r2 object put patchradar/board/feed.json --local --file ...`).
It also answers the Incident pages `/i/<slug>` and `/en/i/<slug>` (`functions/i/[slug].js`, renderer in
`edge/page.mjs`, rules imported from `web/board.mjs`) from `pages/<slug>.json`: one document per Incident with a
Summary first seen in the last 90 days, written by the collector only when its fields changed (`page_hashes.json` in
the store, `{slug: {hash, changed}}` for the current page set only, so a cycle reads one document instead of one per
page). 404 for an unknown slug or an Incident not on the Board, 410 past 90 days, 503 when R2 cannot be read or a
document cannot be rendered. When an Incident that had a page is absorbed into another, the survivor lists its ID in
`absorbed` and the collector replaces its page document with `{id, moved_to, moved_to_id, moved}` (`moves.json` in the
store, `{slug: {moved_to, moved_to_id, moved}}`, drops moves past 90 days): 301 to the survivor's page in the same
language, 302 to the survivor's row on the Board (`/#i=<id>`) while the survivor has no page yet, 410 once the move or
the survivor is past 90 days. The edge cache keeps 200, 301, 302 and 410 answers for 5 minutes and 404s for 1 minute,
never a 503. Every function answers HEAD as it answers GET, without the body (`cached()` reads and keeps it under GET's
cache entry); without a HEAD handler Pages would serve `index.html` for it, a 200 `text/html` even for a feed or an
unknown slug.
The static `web/sitemap.xml` is a sitemap index: the home page's `sitemap-home.xml` and four Incident sitemaps
`/sitemaps/incidents-<n>.xml` (`functions/sitemaps/[name].js`, renderer in `edge/sitemap.mjs`), each listing the
search-worthy pages first seen n calendar months ago (UTC) and within 90 days, in both languages with `hreflang`
alternates and the page's last change as `lastmod`, at most 25,000 pages (50,000 URLs) per file, newest first. They
come from `sitemap.json`, which each cycle rewrites when it changed: `{pages: {slug: {first_seen, changed}}}`, the last
change taken from `page_hashes.json`.
Old page documents are not deleted by code: an R2 object lifecycle rule on the bucket deletes objects under the
`pages/` prefix 100 days after their last write (set once by the owner at deploy, in the Cloudflare dashboard or with
`wrangler r2 bucket lifecycle`). A page document is written on or after its Incident's first seen and a moved document
when the move happens, so 100 days after the last write is always past the 90 days in which it answers anything but
410; after the rule deletes it, the address answers 404. The rule does not reach the SQLite copy, which keeps every
page document it was sent.
`pages dev` also loads `.env` into the function's local environment (hidden, never uploaded). Stopping it leaves
`workerd` processes holding `.wrangler/`: end them before deleting that folder.

`robots.txt` allows every crawler (AI crawlers too) and points to `sitemap.xml`; `llms.txt` lists the public data
files for AI systems. A Cloudflare rate limiting rule on patchticker.com and data.patchticker.com blocks one IP for
10 s after 40 requests in 10 s.

## Redeploy the collector (Oracle VM)

Pack `Dockerfile .dockerignore compose.yaml requirements.txt collector web/vendors.json`, copy it to
`~/vuln-radar` on the box, `sudo docker build -t vuln-radar-collector .`, then recreate the container only while no
cycle runs (`sudo docker compose up -d --force-recreate`). The idle check: inside the container, list
`/proc/[0-9]*/cmdline` and count lines that start with `python -m collector`; a plain grep for "collector" matches the
checking shell itself. Cycles start on the 10-minute marks, so a recreate keeps the schedule.

## Tests

```sh
python -m unittest discover tests   # collector: cycle (seam 1), fake Claude client, store contract
node --test                         # page: the Board's filter function (seam 2); the Pages Function (seam 3)
```

The Python tests run whole collection cycles on a memory store and check the documents it holds; among them
`test_feed.py` (`board/feed.json`), `test_pages.py` (`pages/<slug>.json`, `page_hashes.json`, moved documents and
`moves.json`) and `test_sitemap.py` (`sitemap.json`). The node tests check the Board's rules (`board.test.mjs`) and the
Pages Function: a request's inputs and a fake R2 binding in, a `Response` out (`feed.test.mjs`, `page.test.mjs` with
the edge cache, `sitemap.test.mjs`). The slug and risk rules live in both languages; `tests/fixtures/board/slug-case.json`
and `risk-case.json` are checked by both suites so the two never drift. So are `highlightScore` and the WordPress-plugin
rule (`highlight_score`, `is_wordpress_plugin`) with `rows-case.json`, which also holds the Row view's fields
(`rows_view` in `collector/incidents.py`).
Tests replay recorded responses from `tests/fixtures/`; they make no network calls.
