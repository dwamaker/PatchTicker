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
lists the missing ones in `unknown_vendors.json` in the store (not public; see Reading the store). How to add one:
`docs/agents/vendors.md`.
Summaries given up after three tries (last 30 days, on the Board) are listed in `summary_failures.json` each cycle; how
to act on one: `docs/agents/summary-failures.md`.
With `VR_DISCORD_WEBHOOK` set (a `https://discord.com/api/webhooks/...` address only; anything else is refused at
start-up, and the value is never logged), a cycle that newly gives up a Summary (an id not in the last cycle's
`summary_failures.json`) or merges by `same_as` posts one short Korean message there (`collector/discord.py`; no pings,
at most about 1,800 characters). A failed post is one stderr line and is not retried.
The same message says when the Summary step stops on an API error (the error's type and its message, cut to 200
characters; new rows show their source text as the title until it is fixed) and when it works again, once each:
`status.json` keeps `"summaries": "paused"` (a budget error) or `"stopped"` (any other), and a cycle compares with the
state the last cycle left, so a stop that lasts says nothing more.
A cycle that fails posts too (`collector/alert.py`): compose.yaml's loop runs `python -m collector --cycle-end <exit
code>` after every cycle, so an uncaught exception (its type and first line, which `main()` leaves in the state file),
the 3000 s timeout (exit 124: the process is killed and no Python handler runs) and any other non-zero exit all reach
it. The first failed cycle posts at once, then at most one line an hour while they keep failing (how many, since when),
and the first success after them posts "복구". The count lives in `cycle_alert.json` beside `VR_BACKUP_DB` (`/backup`),
so it survives a failing R2. The posted text never carries an environment value or a query string. The step always
exits 0 and never changes a cycle's outcome. After a deploy, send one marked test line by hand, without touching the
count: `docker compose exec collector python -m collector --alert-test` (exit 1 when nothing was sent).

### Reading the store

Since 2026-11-22 a Cloudflare rule on data.patchticker.com answers 403 for every path but `/index.json`,
`/status.json`, `/sitemap.json`, `/board/*`, `/pages/*` and `/check/*`. The bucket still holds the collector's own
documents (`months/<m>.json`, `checkpoints.json`, `batches.json`, `merge_log.json`, `summary_failures.json`,
`unknown_vendors.json`, `sheets/`, `distros/`, `page_hashes.json`, `check_hashes.json`, `moves.json`), but the public
address refuses them: read them from the store on the collector box, never over the public address.

```sh
docker compose exec -T collector python - <<'EOF'
import json
from collector.__main__ import load_settings, make_store
print(json.dumps(make_store(load_settings("/nonexistent")).read("summary_failures.json"), ensure_ascii=False, indent=1))
EOF
```

The settings come from the container's environment (the file name is a dummy). The SQLite copy holds the same
documents (`SqliteStore("/backup/store.sqlite").read(name)` from `collector.store`, in the container); locally they are
files under `web/data/`.

### The lasting log

The container's output goes when the container is recreated (owner, 11-18), so with `VR_LOG_DIR` set every line the
collector prints also goes into `collector-YYYY-MM-DD.log` there (one file a UTC day, each line led by its UTC time;
`collector/logfile.py`). Compose sets `VR_LOG_DIR=/backup/logs`: `./backup/logs` on the host, made by the collector
in the backup folder it can already write. Files older than 30 days are deleted and a day's file stops at 20 MB; a
setting holding a secret (the API keys, the R2 keys and endpoint, the Discord webhook) is written as `…`.
`docker compose logs` shows the same lines as before. Unset (a laptop), no file is written.

```sh
less backup/logs/collector-2026-11-18.log                          # a day
grep -E ' cycle(_end)? \w+=' backup/logs/collector-2026-11-18.log  # its cycles, one line each
grep -c 'result=ok' backup/logs/collector-2026-11-18.log           # cycles that ended well
```

Each cycle ends with one line, also when it fails (a cycle killed by the 3000 s timeout writes none; the `--cycle-end`
step after it then writes `cycle_end exit=124 result=timed_out`, or `result=failed` for another non-zero exit):

```
cycle start=2026-11-18T06:40:01Z took=212 read=58 link=6 distros=off sheets=31 summaries=96 board=21 new=96 summaries_asked=9 summaries_kept_back=84 summaries_failed=1 summaries_batched=0 sheets_asked=10 sheets_kept_back=4 sheets_failed=0 summaries_deadline=0 titles_kept_back=0 distros_asked=0 distros_kept_back=0 refused=3 refused_hosts=openjdk.org,www.reuters.com skipped=- fixes_lines=0 fixes_flagged=0 fixes_carried=0 records_missing=0 result=ok
```

Fields, in this order (times in whole seconds; a stage shows `off` when not set up, `skipped` when its source failed,
`stopped` or `paused` when an API error ended the Summary step, `-` when a failed cycle never got to it):
`start` (UTC), `took`; the stages `read` (every source read), `link` (joining Mentions into Incidents, NVD and KEV
facts), `distros` (the Distribution table), `sheets`, `summaries` (batches, instant Summaries, titles, batch requests),
`board` (every document written); `new` (Incidents first seen this cycle); `summaries_asked` (instant requests, the
in-cycle edits of number-refused replies included, a collected batch reply's too),
`summaries_kept_back` (instant candidates left for the next cycle by `INSTANT_SECONDS` or the cycle deadline,
`CYCLE_SECONDS` into the cycle, past which the Summary step starts nothing but the first of each kind),
`summaries_failed` (instant asks that stored no Summary), `summaries_batched` (requests sent in a Message Batch);
`sheets_asked`, `sheets_kept_back` (pages past `SHEETS_PER_CYCLE` or the cycle deadline), `sheets_failed`;
`summaries_deadline` (due Summaries left for a later cycle because the cycle deadline had passed: instant candidates
not asked and Incidents left out of the batch), `titles_kept_back` (rows left untitled by the deadline);
`distros_asked` (CVEs looked up for the Distribution table) and `distros_kept_back` (due CVEs left for a later cycle by
`DISTRO_PER_CYCLE` or `DISTRO_SECONDS`); `refused` (requests answered 401, 403 or 429) and
`refused_hosts` (the five most refused); `skipped` (sources that failed and were skipped: `hn`, `github`, `hn_points`,
`nvd`, `kev`, `distros`); `fixes_lines` (lines code added to `fixes` from the page sheets, marked `from_sheet`, in the Summaries stored
this cycle); `fixes_flagged` (Summaries stored this cycle on their last try with a fixed version every CVE record of its
release line calls affected, the versions kept in the Summary's `fixes_flagged`, which the Board does not read);
`fixes_carried` (lines code carried from the stored Summary into a re-summary that dropped them twice, or on its last
try, while the input still gives them as fixes, marked `from_stored`, which the Board does not read, in the Summaries
stored this cycle); `records_missing` (CVE records the delta log named that answered an error, 404 included, or no
JSON, or were left unasked after `MISSING_STOP` such failures: left out of this cycle and asked again next cycle, kept
in `checkpoints.json` as `cvelist_missing`, given up with one `cvelist: gave up record` line after `MISSING_TRIES`
cycles); `result` (`ok`, or
`failed:<stage>:<exception type>`).

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

Highlights (of the last seven days, at 위험 or above; `pickHighlights`, owner 11-19) are ranked by one score in the page
(`highlightScore` in `web/board.mjs`, ported as `highlight_score`): 5 x CVSS (an exploited Incident with no score counts
as 9.0, a provisional level as 9.0 or 7.0), wide use by the label's tier (14, 10, 5; none unless `corroborated`:
exploited, or with an advisory, notice, curator or discussion Mention), urgency (exploited 12, any other 긴급 3), recency
(15 x 0.5^(age / 2 days), rounded to a millionth so the ports agree), and `attention` up to 8 (a notice 3, a curator 2,
HN points / 100 up to 3, five or more repos 1; 11-22, `.scratch/checks/highlights-score-2026-11-22/report.md`, Option
3). The best is taken each time after 10 off per chosen row that shares a key with it (`sameKeys`: the vendor and
well_known category, the label, the Summary's first product name; 11-22);
twenty in all (owner, 11-20); ties go to the newer, then the lower id. No kind has a reserved place (until 11-19 every exploited one came
first, then the best-scored well-known one of each product). The four shown first are ranks 1 to 4 (`pinOrder`; owner,
11-22; from 11-16 to then four different vendors).
Well known: a row the collector stamped `known` on both its row and board
views, worked out at each write and never stored (`known_label` in `collector/incidents.py`): the label of its first
Product on `collector/well_known.json`, else, when its Summary says `widely_used` (none since 11-11: the schema cannot carry it), that Product's English name; and
`known_tier`, the label's tier of reach in that file (1 on most computers or phones, 2 the standard of its field,
3 known inside it), the wide-use part of the Highlight score (none for a label on no list, which the site counts as 3). The
collector picks the same Highlights (`highlights` in `collector/cycle.py`, kept in step by
`tests/fixtures/board/highlights-case.json`) so each is whole in `board/rows.json`. How to add a product:
`docs/agents/vendors.md`.
Curator feeds default to tl;dr sec and the Risky Business News newsletter (`news.risky.biz/rss/`; the `risky.biz` feed is the podcast, with no text to cite from); `VR_CURATOR_FEEDS` overrides them.
Security news sites (BleepingComputer and SecurityWeek, `collector/news.py`) start Incidents like HN stories: a story,
or an HN story linking to one of `incidents.NEWS_HOSTS`, is summarized at once whatever its points, and a CVE-less one
shows only once its Summary calls it an Incident (company breaches, arrests and scams stay off). KISA 보호나라 notices
(`collector/kisa.py`) join the Incidents of the CVE IDs on their pages as "notice" Mentions: never the Lead; since
11-18 a Summary's input reads them beside the advisories (`page_mentions` in `collector/summary_input.py`).

With `ANTHROPIC_API_KEY` set, instant candidates (`is_candidate`) get a Summary from Claude Haiku 5.5 in the same
cycle (`collector/summaries.py`): a KEV listing no Summary has covered yet, whatever the Incident's age; else, published
in the last seven days (by Published time, else first seen), a KEV listing, CVSS 7.0 or higher, an HN story at
`hn.BUZZ_POINTS` or more, a curator Mention, a security news site's story, a CVE-less Incident seen in a discussion
off HN, or a vendor advisory rated Critical or High while no CVSS exists (`stated_level`). The input is the Incident
(at most `MENTIONS_MAX` Mention lines, the rest counted by kind), the text of up to four pages (`MAX_PAGES`: the Lead,
then advisories and notices, write-ups, news, curator issues, discussions, one per host before a second; never HN, a
repo or cve.org), the CVE records of its first
`CVE_LINES_MAX` CVEs and each later CVE's own description, cut from the end past `INPUT_CHARS_MAX`
(`collector/summary_input.py`); a reply whose numbers, versions or Lead link are not
in that input, or whose Korean and English numbers differ, is rejected and retried (three tries). A digit whose
number word the input spells ("zero", "eight"; never "one") counts as in it (`number_words`), and a Korean digit
matches its word in the English text.
A digit inside a fixed Korean word (`KO_DIGIT_WORDS`, only "제3자" so far) is not counted in Korean text.
Each retry says why the last reply was rejected, beside the input and never inside it (so a number named there is
still not allowed); a reply cut off at the token cap gets more room. A reply refused for a number (not in the input,
or Korean and English differ) is sent back at once in the same cycle, with the same input, to be edited in the
sentences that hold the refused number only (`edit_now`; a refused edit is edited again, up to the three tries); each
edit is a request within `INSTANT_SECONDS` and the cycle deadline (a collected batch reply's within `BULK_SECONDS`,
as a direct full-price call), else the row waits for a fresh draw in a later cycle. The refused reply is never stored
(decided while the month file was public; since 2026-11-22 the public address refuses it, but the bucket still holds
it). After the third rejected try the Summary is given
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
`"summaries": "paused"` in `status.json`, which the page shows as a short notice; Briefs keep flowing. The next cycle
then sends a one-request batch to test the budget. Any other API error sets `"stopped"`, which the page does not show,
and the next cycle asks again in full.

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

The copy must keep the hidden folder `web/.well-known/` (the API catalog). `web/404.html` makes an unknown path answer
404 with that page (owner, 11-17); without it Pages treats the site as a single-page app and answers every unknown
path with the home page and a 200. Every address the site uses is a file or a Function route (the Board routes by
`#`), so nothing relied on that fallback. `/.well-known/api-catalog` is an RFC 9727 API catalog, a Linkset listing
`/api/check` with `llms.txt` as its `service-doc`; `_headers` gives it its type
(`application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"`, the file has no extension) and a
`Link: rel="api-catalog"` header, which the RFC requires on a HEAD. The home page's Function adds a Link header to the
catalog (`api-catalog`), `llms.txt` (`describedby`) and the two feeds (`alternate`, RSS), after any Link the asset
carries. `404.html`'s one style block has its own hash in `_headers`' `style-src`.

Run it from the repository root: `functions/` (the Pages Function) is taken from the working directory, and it imports
`edge/` (`edge/shared.mjs`: the site address, escaping, the R2 read, the edge cache and the what-to-do text every
function shares). The function answers `/feed.xml` and `/en/feed.xml` from `board/feed.json` in R2 through the binding
`DATA` (bucket `patchradar`), which the Pages project must have. The feed holds the newest 200 search-worthy Incidents
(`FEED_SIZE`; owner, 11-17: 50 were 14 hours; on 11-17 200 were about 3.5 days, a 0.9 MB document rendered in about
3 ms on a desktop into a 215 KB feed), each item with its products as the row shows them and its level as
`<category>`. With `?products=<names>` (and `days`, `min`) the same address answers the products feed instead
(`productFeedResponse` in `edge/feed.mjs`): `/api/check`'s query and matching without the model, from the check documents
alone, at most 40 documents and 100 items, 400 for bad input as the API, 503 while there is no index, never kept in the
edge cache (`cache-control` five minutes), so asked names are kept nowhere.
`/feed/all.xml` and `/en/feed/all.xml` (`functions/feed/all.xml.js`, `allFeedResponse`; owner, 11-17) carry the whole
Board, notice level included: the newest 600 Board Incidents (`FEED_ALL_SIZE`) from `board/feed-all.json`, which each
cycle rewrites only when it changed. Each entry is the check documents' (`feed_entry` in `collector/checks.py`) plus the
row's tags in both languages (`row_tags`, a port of `rowTags` kept in step by
`tests/fixtures/board/row-tags-case.json`); an item has no Summary text. Its link is where `/api/check` sends (the page,
else the Board row) and its GUID the Incident page's address, as in `/feed.xml`, so an Incident in both is one item and
keeps its GUID when it gains a page. Until the collector has written the document the feed answers 503. Locally: `npx wrangler@4 pages dev <copy> --r2 DATA=patchradar`
with a `board/feed.json` put into local R2 (`npx wrangler@4 r2 object put patchradar/board/feed.json --local --file ...`).
The home page `/` goes through `functions/index.js` (`edge/home.mjs`) too: the current static `index.html` with links to
the feed's 20 newest Incident pages in place of its `<!--home-links-->` marker, for readers that run no script (search
crawlers). `index.html`'s `#about` block holds that text and is hidden once the inline script has set `.js` on `<html>`. It stands last in `<main>` so that the Board's own children
keep their positions (a content blocker rule hid the 12th-child section when it stood first).
Only the link list is cached (300 s); when it cannot be read the page answers without it. Any other path that falls
back to `index.html` keeps the marker as a comment.
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
`/api/check?products=<names>&days=&min=` (`functions/api/check.js`, logic in `edge/check.mjs`; owner, 11-11) answers an
agent's question "which Incidents touch the products I run?" as JSON (`web/llms.txt` says how to ask). A Function has
about 10 ms of CPU, too little to read a month file, so the collector writes `check/index.json` (each name a Product is
asked by, normalized by `product_key`, which `productKey` ports, kept in step by
`tests/fixtures/board/product-key-case.json`, -> its Products' slugs) and one `check/p/<slug>.json` per Product of the
last 90 days' Board Incidents, operating-system tags aside (`collector/checks.py`; the slug is a hash of the Product id).
Only changed documents are written (`check_hashes.json` in the store, `{slug: hash}`); a Product with no Incident left
loses its document after the index stops naming it. The function reads the index and at most 40 product documents,
answers 400 for a bad query, 503 (never kept) while there is no index, and does not use the edge cache, so no asked
names are kept; the answer's `cache-control` is five minutes. On 2026-11-11 the live month (2,765 Incidents) made
2,167 documents (1.9 MB in all, the largest Android's at 70 KB) and a 137 KB index.
A name is matched by its exact key, then by its Korean alias (`SEARCH_ALIASES` in `web/board.mjs`, the table the
Board's search uses; the entry then carries `alias`), then broadly. Names that still match nothing, at most 10 a
request and none over 60 characters, are read once by `@cf/meta/llama-3.3-70b-instruct-fp8-fast` through the Pages
project's Workers AI binding `AI` (owner, 11-11): the model is asked only for the product's official English name,
and that name counts only when it is a key of the index (exactly, broadly, or exactly without its last word), so the
model never decides a match. Those go to the answer's `maybe` list, apart from `products`. Without the binding, on a
HEAD, after 5 seconds, or when the model fails (the free 10,000 neurons a day are used up), the answer is as it is
without the model. Measured on 30 typed names against the live index: 22 `maybe` entries, none wrong, about 15
neurons and 1.6 to 3.4 s for 10 names. Nothing is cached or stored; the names do go to Cloudflare's model.
To try it without the network, pass a fake binding as `checkResponse`'s fourth argument (`tests/check.test.mjs`).
Each Incident of a check document carries `detail` (owner, 11-17), the address of its page document on the data host
(`https://data.patchticker.com/pages/<slug>.json`, its whole record), when it has a Summary; `cves` stays the first five.
An older document without it answers as before.
The product pages `/p/<slug>` and `/en/p/<slug>` (`functions/p/[slug].js`, `edge/product.mjs`; owner, 11-17) are drawn
from the same `check/p/<slug>.json`: the product's Incidents of the last 90 days with level, title, date and fixed
version, each linking its Incident page (or its Board row), in the Incident page's shell and CSP, with a link to the
product's feed. A product with fewer than 3 Incidents (`PRODUCT_PAGE_MIN`, in `edge/product.mjs` and
`collector/checks.py`) is `noindex`. 404 for a slug that is not 16 hex characters or has no document, 503 when R2 cannot
be read. An Incident page links its products' pages (at most five, operating systems aside), and states its headline,
description, dates, language and address as JSON-LD in a `<script type="application/ld+json">` block, which runs
nothing (the CSP's `script-src` does not apply to it) and holds no `<`, `>` or `&` unescaped.
The static `web/sitemap.xml` is a sitemap index: the home page's `sitemap-home.xml` and four Incident sitemaps
`/sitemaps/incidents-<n>.xml` (`functions/sitemaps/[name].js`, renderer in `edge/sitemap.mjs`), each listing the
pages worth a listing first seen n calendar months ago (UTC) and within 90 days, in Korean and English with `hreflang`
alternates and the page's last change as `lastmod`, at most 25,000 pages (50,000 URLs) per file, newest first.
Since 2026-11-27 (owner, after Google crawled 1,831 pages without indexing them) the list is narrower than
search-worthy: `sitemap_worthy` in `collector/incidents.py` keeps a page about a Product on
`collector/well_known.json`, an attacked one, a story without a CVE, or one told by three sites besides its CVE
records (1,271 of 3,414 search-worthy pages on that day); the other pages answer as before, without `noindex`.
Japanese is no search language (`SEARCH_LANGS` in `edge/shared.mjs`): a `/ja/` page is the English text under
Japanese labels, so it is in no sitemap and no `hreflang`, and names its `/en/` twin as canonical. They
come from `sitemap.json`, which each cycle rewrites when it changed: `{pages: {slug: {first_seen, changed}}, products:
[slug]}`, the last change taken from `page_hashes.json`. A fifth, `/sitemaps/products.xml`, lists the product pages in
`products`, those with at least 3 Incidents (`product_pages` in `collector/checks.py`); a `sitemap.json` from before the
list gives an empty one.
The list pages (`edge/lists.mjs`; owner, 2026-11-27, when Google visited one to eight times a day and the home page's
HTML linked 20 Incident pages) lead a crawler from the home page to every page the sitemaps list: `/d/` lists the
days, `/d/<YYYY-MM-DD>` the Incident pages first seen that day in Korea (UTC+9; `LIST_DAY_HOURS` in
`collector/cycle.py`), newest first, with the previous and next day, and `/p/` the product pages by name with their
counts; `/en/` the same, `/ja/` with its `/en/` twin as canonical (`functions/{,en/,ja/}{d,p}/`). The home page's list
links the newest seven days, `/d/` and `/p/` (`homeLinks` in `edge/home.mjs`, failing open without the index), and
`sitemap-home.xml` lists `/d/` and `/p/` in both search languages. Each cycle's `write_lists` writes them from the very
Incidents and Products of `sitemap.json`: `lists/d/<day>.json` (`{day, incidents}`, the check documents' entries
without `detail`) only when it changed (`list_hashes.json` keeps `{day: {hash, count}}`, as `check_hashes.json` does),
then `lists/index.json` (`{days: {day: count}, products: [{slug, name, count}]}`, naming only the days whose document is
stored), then deletes the days past 90. Neither is public on data.patchticker.com. 404 for a day that is not
`YYYY-MM-DD` (no read) or has no document; 503 when the index is missing or unusable or R2 cannot be read.
A product page also says what its list holds as a whole (its Incidents by Risk, how many are attacked, the newest) and
names each Incident's CVE IDs; no "newest fixed version" and no CVE total: `fixed` and `cve_count` are the Incident's
own, on an Incident of several Products partly another Product's (136 of 651 product pages on 11-27).
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

With `VR_INDEXNOW_KEY` set (32 lowercase hex characters; anything else is refused at start-up with one stderr line),
each cycle sends one IndexNow request (`collector/indexnow.py`, to `api.indexnow.org`, which passes it to Bing, Naver,
Yandex and the others) listing the search-worthy Incident pages it wrote, in both languages, at most 10,000 URLs; none
written, no request. A cycle writes only pages whose fields changed (`page_hashes.json`), so the first cycle with the key
sends only that cycle's pages, never the whole set. The key is public by design: `web/<key>.txt` holds it for the
engines to check, and `.env.example` names the value the live box uses. A failed request is one stderr line (the
status or the error's kind) and is not retried.

## Redeploy the collector (Oracle VM)

Pack `Dockerfile .dockerignore compose.yaml requirements.txt collector web/vendors.json`, copy it to
`~/vuln-radar` on the box, `sudo docker build -t vuln-radar-collector .`, then recreate the container only while no
cycle runs (`sudo docker compose up -d --force-recreate`). The idle check: inside the container, list
`/proc/[0-9]*/cmdline` and count lines that start with `python -m collector`; a plain grep for "collector" matches the
checking shell itself. Cycles start on the 10-minute marks, so a recreate keeps the schedule.
Unit tests cannot see what Anthropic accepts (2026-11-11: one more required field in the Summary schema made every
request fail with "The compiled grammar is too large"), so a change to a schema or a prompt is checked with
`python -m collector --smoke`: with the collector's own settings and key, one small real request of each shape (the
Summary, quick titles, per-CVE lines; batches send the same parameters), one line each, exit 1 on a rejection, nothing
read from or written to the store. Before those it builds what a cycle builds (`cycle_parts`: the HTTP getter, the
clients, the notifier and the pinger; nothing sent) and prints `smoke: cycle wiring ok`, or `smoke: cycle wiring
FAILED: <error>` and exits 1 (2026-11-21: a NameError there stopped every cycle while `--smoke` passed). Run it from the new image
(`docker compose run --rm -T --no-deps collector python -m collector --smoke`) before recreating, and do not
recreate when it fails; the live box's redeploy script does both (it is kept with the owner's ops notes, not in this
repository).

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
