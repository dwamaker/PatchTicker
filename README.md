<p align="center">
  <img src="docs/assets/logo.svg" width="72" alt="">
</p>

<h1 align="center">Patch Ticker</h1>

<p align="center">
  New security vulnerabilities, fast, sorted by the products you run.<br>
  A free, no-login vulnerability board, Korean first with English alongside.
</p>

<p align="center">
  <a href="https://patchticker.dwamaker.com"><b>patchticker.dwamaker.com</b></a>
  &nbsp;·&nbsp;
  <a href="https://github.com/dwamaker/vuln-radar/issues/new">Report a mistake</a>
  &nbsp;·&nbsp;
  <a href="README.ko.md">한국어</a>
</p>

---

## Who it is for

When news of a new vulnerability breaks, you want two answers. **Does it touch anything I run?** If it does, **what do
I do now?**

Patch Ticker is built to answer both in seconds: for security staff, and just as much for people running a server at
home, admins at small companies, and readers with no security background.

## What you can do

- **Newest first**: new Incidents land at the top. Data is collected every 10 minutes, and an open page updates
  without a reload.
- **Highlights**: Incidents with attacks confirmed or a high risk level are pinned above the list.
- **Your products only**: pick what you run and only its Incidents stay. Your picks are saved in your browser only.
- **Plain summaries** in Korean and English: what the problem is, who is affected, when it is dangerous, and how to
  fix or contain it.
- **Easy view**: no security jargon, just the risk level and one thing to do now.
- **Source links**: every statement leads to the official advisory or the original write-up. Check it before you act.
- **Folds**: notices one vendor published on the same day, and vulnerabilities one update fixed together, fold into
  one line.
- **News before a CVE exists**: write-ups and mailing-list posts appear right away and merge with the CVE once it is
  assigned.
- **Shareable links**: copy a link that opens one Incident directly. Filters live in the address too.
- Korean and English, light and dark themes, and phone screens.

## How the risk level is set

Rules set the risk level, not the AI.

| Sign | Rule |
| --- | --- |
| **High risk** | Attacks confirmed (the CISA KEV catalog, or a source that reports attacks), or CVSS 9.0 and up |
| **Elevated** | CVSS 7.0 and up |
| **Notice** | Everything else |

"Exploited" is shown only with evidence, and the panel shows that evidence (the KEV listing date, or the source that
reports attacks). When only exploit code has been published, it is flagged separately as "Exploit code is public".

## Where the data comes from

| Source | Used for |
| --- | --- |
| [CVE List (cvelistV5)](https://github.com/CVEProject/cvelistV5) | New CVEs, affected products and versions, official advisory links |
| [NVD](https://nvd.nist.gov/) | CVSS scores, product data |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities exploited in the wild |
| [oss-security](https://www.openwall.com/lists/oss-security/), Hacker News, GitHub | News and write-ups before a CVE number exists |
| Security newsletters (tl;dr sec, Risky Business News) | Incidents getting attention |

Summaries are written by Anthropic's Claude from those sources only. A summary with a number or version that is not in
its sources is thrown away and written again. An update command is shown only when a source states it word for word.

## Privacy

No login, no cookies, no analytics, no third-party trackers. Your picks and filters stay in your browser and are
never sent to a server. The page is static files, and the data is public JSON.

## Found a mistake?

Summaries and judgments come from the AI first; readers' reports correct them. Open an Incident and press **Report a
mistake**: a new issue opens in this repository with the Incident filled in (a GitHub account is needed). You can also
[open an issue](https://github.com/dwamaker/vuln-radar/issues) yourself.

## How it runs

```
Collector (Docker, every 10 min)  ──writes──▶  Cloudflare R2 (public JSON)  ◀──reads──  Web page (Cloudflare Pages)
  CVE List, NVD, KEV,                          monthly Incident files,                  filters and search run
  mailing lists, HN, GitHub                    status.json                              in the browser
```

No server answers visitors' requests. How to develop and run it: [docs/development.md](docs/development.md).

## Notices

- This board is for reference only. Check each Incident's source advisory before you act.
- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- CVE® records: Copyright © 1999–2026, The MITRE Corporation. CVE is a registered trademark of The MITRE Corporation.
  Used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse).
