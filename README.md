<p align="center">
  <a href="https://patchticker.com"><img src="docs/assets/logo.svg" width="88" alt="Patch Ticker logo"></a>
</p>

<h1 align="center">Patch Ticker</h1>

<p align="center"><b>English</b> | <a href="README.ko.md"><b>한국어</b></a></p>

<p align="center">
  <b>New security vulnerabilities, sorted by the products you run.</b><br>
  A free, no-login live tracker, Korean first with English alongside.
</p>

<p align="center">
  <a href="https://patchticker.com"><img src="https://img.shields.io/badge/live-patchticker.com-1a5fb4?style=for-the-badge" alt="Live: patchticker.com"></a>
  <img src="https://img.shields.io/badge/updates-every%2010%20min-2e7d32?style=for-the-badge" alt="Updates every 10 minutes">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-555?style=for-the-badge" alt="License: MIT"></a>
</p>

<p align="center">
  <b>Follow by RSS</b> (Korean · English)<br>
  Main feed, Elevated and up, attacked or no CVE yet: <a href="https://patchticker.com/feed.xml">/feed.xml</a> · <a href="https://patchticker.com/en/feed.xml">/en/feed.xml</a><br>
  The whole Board: <a href="https://patchticker.com/feed/all.xml">/feed/all.xml</a> · <a href="https://patchticker.com/en/feed/all.xml">/en/feed/all.xml</a><br>
  Only your products: <code>/feed.xml?products=openssh,nginx</code> (up to 30 names; the site's RSS button builds it from the products you pick)
</p>

<p align="center">
  <em>Find it useful? A coffee keeps it running.</em><br>
  <a href="https://buymeacoffee.com/dwamaker"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>

<p align="center">
  <a href="https://patchticker.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screenshot-en-dark.png">
      <img src="docs/assets/screenshot-en-light.png" width="860" alt="Patch Ticker: Highlights on top, each Incident with its risk level, CVSS score and products">
    </picture>
  </a>
</p>

## Why

When a vulnerability hits the news, you want two answers: **does it touch anything I run**, and **what do I do now**.
Patch Ticker answers both in seconds, with no security background needed.

## Features

- **Live**: collected every 10 minutes; an open page updates by itself.
- **Your products only**: pick what you run and the list narrows to it. Picks stay in your browser.
- **Plain summaries** in Korean and English: what it is, who is affected, how to fix it.
- **Easy view**: no jargon, just the risk and one thing to do now.
- **Highlights**: Incidents under attack, or in widely used products, stand on top.
- **Before a CVE exists**: write-ups and mailing-list posts show up at once and merge when the CVE is assigned.
- **Folds**: one vendor's same-day notices, and fixes shipped in one update, fold into one line.
- **Linked to sources**: every claim links to its source; a command is shown only as a source wrote it.
- **Share and subscribe**: every Incident has an address, and filters live in the address. RSS in
  [Korean](https://patchticker.com/feed.xml) and [English](https://patchticker.com/en/feed.xml), the newest 200 with
  products and level as categories, or only your products with `?products=openssh,chrome`. The whole Board, notice
  level included, as light items: [Korean](https://patchticker.com/feed/all.xml) and
  [English](https://patchticker.com/en/feed/all.xml). Each product has a page of
  its Incidents, linked from every Incident page.
- **For AI agents**: `GET https://patchticker.com/api/check?products=openssh,chrome` answers which Incidents touch
  those products, as JSON, each with `detail`, the address of its whole record. Send a User-Agent that names your
  client (`my-agent/1.0`): Cloudflare answers 403 to Python urllib's default one. How to ask:
  [llms.txt](https://patchticker.com/llms.txt).

## Risk levels

Rules set the level, never the AI.

| Sign | Rule |
| --- | --- |
| **Urgent** | Attacked (CISA KEV, or a source reporting attacks) or CVSS 9.0+ |
| **Elevated** | CVSS 7.0+ |
| **Notice** | Everything else |

"Attacked" always shows its evidence. Published exploit code alone is flagged as "Exploit code is public".

## Data sources

| Source | Used for |
| --- | --- |
| [CVE List (cvelistV5)](https://github.com/CVEProject/cvelistV5) | New CVEs, affected products and versions, advisories |
| [NVD](https://nvd.nist.gov/) | CVSS scores, product data |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited in the wild |
| [oss-security](https://www.openwall.com/lists/oss-security/), Hacker News, GitHub | News and write-ups before a CVE |
| tl;dr sec, Risky Business News | Incidents getting attention |
| [BleepingComputer](https://www.bleepingcomputer.com/), [SecurityWeek](https://www.securityweek.com/) | Attacks and compromises reported as news, often with no CVE |
| [KISA 보호나라](https://www.boho.or.kr/) | Korean security notices for an Incident's CVEs |
| Debian, Ubuntu, Red Hat, SUSE, Alpine and Arch security trackers | Whether each Linux distribution has the fix |

Summaries are written by AI from these sources only and reviewed once more; one with a number or version not in its
sources is thrown away and written again. When `/api/check` does not know a product name, AI guesses its English name
for a second lookup, and a result found that way is marked `maybe`.

## Privacy

No login, no cookies, no ad trackers. Visits are only counted anonymously. Picks and filters never leave your
browser. `/api/check` stores nothing about a request; only a product name it does not know is sent to AI.

## Found a mistake?

Open the Incident and press **Report a mistake**: a new issue opens here with the Incident filled in. Or
[open an issue](https://github.com/dwamaker/PatchTicker/issues) yourself. Fixes are listed under [Releases](https://github.com/dwamaker/PatchTicker/releases).

## How it works

```
Collector (Docker, every 10 min)  ──writes──▶  Cloudflare R2 (public JSON)  ◀──reads──  Web page (Cloudflare Pages)
  CVE List, NVD, KEV,                          monthly Incident files,                  filters and search run
  mailing lists, HN, GitHub                    status.json                              in the browser
```

No server of ours answers visitors. The page, the feeds and `/api/check` are all made from the same public files.
Running it yourself: [docs/development.md](docs/development.md).

## Notices and license

- For reference only: check each Incident's source advisory before you act. Incidents are kept for at most 90 days.
- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- CVE® records: Copyright © 1999–2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation.
  Used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
- Code: [MIT License](LICENSE). CVE and NVD data keep their own terms; the collected data and summaries are not
  covered by this license.
