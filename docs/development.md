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
30-second cache.
Every write also lands in an SQLite copy (`VR_BACKUP_DB`, `./backup` in Compose); `--seed-backup` fills it once from
the store and `--restore` rebuilds the store from it (commands in `compose.yaml`).

Vendor spellings put in front of bare Product names ("IBM Storage Scale") live in `web/vendors.json`; each cycle
lists the missing ones in `unknown_vendors.json` in the store. How to add one: `docs/agents/vendors.md`.

Mentions join an Incident when they cite one of its CVE IDs or, while either side has no CVE, one
of its URLs (`collector/incidents.py`, ADR 0001).

Highlights (top ten of the last seven days) are scored in the page (`highlightScore` in
`web/board.mjs`) from the exploited flag (KEV, or a Summary reporting attacks), HN points, curator newsletter Mentions, CVSS and Mention count.
Curator feeds default to tl;dr sec and Risky Business News; `VR_CURATOR_FEEDS` overrides them.
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
`edge/`. The function answers `/feed.xml` and `/en/feed.xml` from `board/feed.json` in R2 through the binding `DATA`
(bucket `patchradar`), which the Pages project must have. Locally: `npx wrangler@4 pages dev <copy> --r2 DATA=patchradar`
with a `board/feed.json` put into local R2 (`npx wrangler@4 r2 object put patchradar/board/feed.json --local --file ...`).
It also answers the Incident pages `/i/<slug>` and `/en/i/<slug>` (`functions/i/[slug].js`, renderer in
`edge/page.mjs`, rules imported from `web/board.mjs`) from `pages/<slug>.json`: one document per Incident with a
Summary first seen in the last 90 days, written by the collector only when its fields changed (`page_hashes.json` in
the store holds each page's hash, so a cycle reads one document instead of one per page). 404 for an unknown slug or an
Incident not on the Board, 410 past 90 days, 503 when R2 cannot be read.
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
node --test                         # page: the Board's filter function (seam 2)
```

Tests replay recorded responses from `tests/fixtures/`; they make no network calls.
