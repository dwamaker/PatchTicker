# vuln-radar

A public, no-login page that lists security Incidents newest first (see `CONTEXT.md`).

Needs Python 3.13 and Node 24. No dependencies, no build step.

## Run one cycle locally

```sh
cp .env.example .env        # then set VR_STORE_DIR=web/data, VR_COLLECTOR_ID, VR_CONTACT
python -m collector         # one cycle: cvelistV5, oss-security, HN, GitHub, NVD, CISA KEV, curators -> web/data/
python -m http.server 8000 -d web
```

Open http://localhost:8000/ to see the Board. The first cycle with an empty store reads only the
newest delta log entry; later cycles pick up everything since the last checkpoint.
`VR_GITHUB_TOKEN` (optional, no scopes) lets GitHub search run at 30 instead of 10 requests a minute.

Mentions join an Incident when they cite one of its CVE IDs or, while either side has no CVE, one
of its URLs (`collector/incidents.py`, ADR 0001).

Highlights (top ten of the last seven days) are scored in the page (`highlightScore` in
`web/board.mjs`) from the KEV flag, HN points, curator newsletter Mentions, CVSS and Mention count.
Curator feeds default to tl;dr sec and Risky Business News; `VR_CURATOR_FEEDS` overrides them.

`python -m collector other.env` reads a different environment file. Real environment variables
override the file.

## Tests

```sh
python -m unittest discover tests   # collector: cycle (seam 1) and store contract
node --test                         # page: the Board's filter function (seam 2)
```

Tests replay recorded responses from `tests/fixtures/`; they make no network calls.
