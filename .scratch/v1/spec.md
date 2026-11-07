Status: ready-for-agent

# vuln-radar v1 spec

Vocabulary follows `CONTEXT.md` (Incident, Mention, Lead mention, Unassigned incident, Brief,
Summary, Mitigation, Highlight, Board, Product). Architecture follows ADR 0001 (one row per
Incident) and ADR 0002 (no public server; R2 monthly files are the store). The working plan with
measurements and source facts is `plan.md` beside this file.

## Problem Statement

Security incidents now surface almost daily, and the useful facts are scattered: a write-up site,
a GitHub repo, a Hacker News thread, and a CVE record that may appear hours later. Someone who runs
a home server, a router or a small fleet has to read all of it to learn one thing: does this hit
something I run, and what do I do about it? On 2026-11-05 "sshole" (CVE-2026-123158) showed the
gap: the site and repo were up hours before the CVE, the CVE text itself had the length boundary
slightly wrong, and judging whether a musl router was exposed (it was not: Dropbear) took manual
digging. English aggregators exist; nothing gives a Korean reader a fast, filtered answer.

## Solution

A public, free, no-login web page, the Board. It lists security Incidents newest first, with up to
ten Highlights pinned on top like notices. A visitor picks the Products they run and types in a
search box; the Board narrows at once, in the browser, and remembers the choice. Each Incident
appears within one collection cycle as a Brief built from source data (original one-line text,
severity, Products, exploited-in-the-wild flag, Lead mention link). A Summary in Korean and English
(what it is, who is affected, preconditions, Mitigation) follows, usually within an hour; urgent
Incidents get theirs at once. Every Incident links out to its best Mention so readers can verify.

## User Stories

1. As a home-server owner, I want to see new security Incidents newest first, so that I notice what changed since my last visit.
2. As a visitor, I want the most important recent Incidents pinned at the top, so that I see what matters to many people right now without scrolling.
3. As a visitor, I want at most ten Highlights from the last seven days, so that the pinned area stays short and current.
4. As a visitor, I want an Incident to drop out of the Highlights after seven days while staying in the list, so that the top area does not go stale.
5. As a visitor, I want to pick the Products I run from a list, so that the Board shows only Incidents that affect them.
6. As a visitor, I want to find a Product in that list by typing part of its name, so that I do not scroll through thousands of names.
7. As a visitor, I want the Product list to contain only Products seen in the last 90 days, so that it is not cluttered with names that have no Incidents.
8. As a visitor, I want a search box that filters live as I type, so that I can find an Incident by keyword, CVE ID, version text or Product.
9. As a visitor, I want search to match both the Korean and the English text, so that either language finds the same Incident.
10. As a returning visitor, I want my Product picks remembered in my browser, so that I do not pick them again every visit.
11. As a visitor, I want my filter encoded in the page address, so that I can bookmark it or share it with a colleague.
12. As a privacy-minded visitor, I want my filter never sent to any server, so that nobody learns what software I run.
13. As a Korean reader, I want the page in Korean when my browser is Korean, so that I read it without switching.
14. As an English reader, I want the page in English when my browser is not Korean, so that the Board is usable abroad.
15. As any reader, I want a language toggle that is remembered, so that I can override the browser default.
16. As a visitor, I want a new Incident on the Board within one collection cycle of its first Mention, so that I learn about it quickly.
17. As a visitor, I want an Incident shown even before it has a CVE, so that I hear about it during the hours before assignment.
18. As a visitor, I want an Unassigned incident to merge into the same row when its CVE arrives, so that I do not see the same event twice.
19. As a visitor, I want one row per real-world event even when it has several CVEs, so that related CVEs are read together.
20. As a visitor, I want each row to list its Mentions (advisory, write-up, repo, CVE record, discussion), so that I can go deeper.
21. As a visitor, I want the Lead mention shown prominently, picked as official advisory or release note first, then the discoverer's write-up, then the CVE record, then discussion, so that I land on the most reliable detail.
22. As a visitor, I want proof-of-concept repositories linked as Mentions too, so that I can judge exploitability myself.
23. As a visitor, I want a Brief (original one-line description, severity, Products, Lead mention) the moment an Incident appears, so that I am not waiting on a Summary.
24. As a Korean reader, I want a clear "summary in preparation" marker on a Brief, so that I know Korean text is coming.
25. As a visitor, I want a short Summary in Korean and English, so that I understand the Incident in two or three sentences.
26. As a visitor, I want the preconditions for exposure listed (for example musl, no PAM, password login on), so that I can tell whether my setup is hit.
27. As a visitor, I want the Mitigation (fixed version, or a stopgap until then) when one is known, so that I know what to do now.
28. As a visitor, I want numbers and boundaries kept exactly as the best source states them, so that I do not act on a rounded-off fact.
29. As a visitor, I want a severity score and an "exploited in the wild" flag on each row, so that I can prioritize.
30. As a visitor, I want urgent Incidents (newly exploited in the wild, widely discussed, severity 9.0 or higher, or Unassigned incidents seen in discussion) summarized immediately, so that the most important ones are never waiting.
31. As a visitor, I want a Summary refreshed when an official advisory or fixed version appears, the Incident becomes exploited in the wild, or a CVE is attached, so that the Mitigation stays current.
32. As a visitor, I want a "this is wrong" link on each Incident that opens a prefilled GitHub issue, so that I can report a mistake without hunting for a contact.
33. As a visitor, I want a visible note that the Board is for reference and the Lead mention is authoritative, so that I verify before acting.
34. As a visitor, I want the required NVD and CVE attribution shown, so that the data sources are credited correctly.
35. As a visitor, I want the Board to load quickly on a phone, so that I can check it anywhere.
36. As a visitor, I want the page to keep working when updates pause, so that a collector outage does not take the site down.
37. As a visitor, I want to see when the data was last updated, so that I know whether I am looking at fresh information.
38. As the operator, I want the collector to run every 15 minutes on the Oracle VM, so that the Board stays current without my home network.
39. As the operator, I want the `.104` standby to take over when R2 has not been updated for 45 minutes and step back when the main collector resumes, so that an outage on one box does not stop updates.
40. As the operator, I want both collectors to read and write the same R2 store, so that either can resume from where the other stopped.
41. As the operator, I want each collector to keep an SQLite backup copy, so that I can recover if R2 data is lost or damaged.
42. As the operator, I want data split into monthly files with the page reading the last three months, so that the download stays small and the range can grow later.
43. As the operator, I want most Summaries sent through the Batch API, so that AI cost is halved.
44. As the operator, I want prompt caching on the fixed instructions, so that repeated input is billed at the cache rate.
45. As the operator, I want AI usage to stop cleanly when the credit or workspace limit is hit, so that Briefs keep flowing and nothing is charged beyond the credit.
46. As the operator, I want each collector to use its own API key, so that one leaked key can be revoked without stopping the other.
47. As the operator, I want API keys only in each server's environment file and never in the public repository, so that the code can be public safely.
48. As the operator, I want the collector to respect each source's rate limits and send polite, identifiable requests, so that no source blocks us.
49. As the operator, I want only official sources and APIs collected, never other aggregators' pages, so that we stay within their terms.
50. As the operator, I want the page deployed only when the code changes and data updates to never trigger a deploy, so that free-plan deploy limits are not used up.
51. As the operator, I want the homelab and the proxy VM never on the public request path, so that the site's traffic and attacks cannot reach them.
52. As a contributor, I want the source code in a public repository, so that anyone can check how Incidents are matched and summarized.
53. As a contributor, I want tests that replay recorded source responses, so that I can change the collector without calling live sources.
54. As a non-expert visitor, I want an Easy view tab next to the normal view, so that I can understand an Incident without security jargon.
55. As a non-expert visitor, I want a big Risk banner (for example "고위험!") instead of a CVE number at the top of the Easy view, so that I grasp the urgency at a glance.
56. As a non-expert visitor, I want one or two plain sentences on what the problem means for me, so that I am not lost in technical detail.
57. As a non-expert visitor, I want the single action to take now, such as "run this command to update", with a copy button, so that I can fix it right away.
58. As a device owner, I want a device Incident to say "update these devices now!" with the device list, so that I know whether my router or camera is on it.
59. As a visitor, I want the Easy view's command shown only when a source states it, and otherwise a plain "update to version X", so that I never run a made-up command.
60. As a returning visitor, I want my choice of normal or Easy view remembered, so that the Board opens the way I like it.

## Implementation Decisions

- **Collector, one process per box, one cycle per run.** A cycle: load current state from the R2
  store; fetch each source since its last checkpoint; turn new or changed source items into
  Mentions; attach Mentions to Incidents; enrich CVEs; build Briefs; submit Summary work; collect
  finished batch results; recompute Highlights; write the changed monthly files and a status file
  back to R2; update the SQLite backup.
- **Source adapters, one per source**, each with the same narrow contract: given a checkpoint,
  return new items and the next checkpoint. Sources: HN Algolia search, cvelistV5 delta log,
  NVD API (by last-modified range, with a free API key, sleeping between calls), oss-security RSS
  from seclists, CISA KEV JSON feed, curator RSS feeds, GitHub search (with a no-scope token).
- **Incident linking.** An Incident is keyed by its CVE IDs when it has any, and otherwise by the
  URLs its Mentions point at. A Mention that cites a CVE or a URL already on an Incident joins it;
  an Unassigned incident whose Mentions later cite a new CVE merges into that CVE's Incident.
- **Products** come from CVE CPE data (vendor and product, version dropped) plus Product names the
  Summary extracts from text, normalized to a display name. The Product list on the page is the set
  seen in the last 90 days.
- **Brief** is built without AI from source data: original one-line description, CVSS, KEV flag,
  Products, Lead mention.
- **Summary** is one Haiku 5.5 request per Incident producing both languages and structured fields
  (titles, summaries, conditions, Mitigation, Products, Lead mention). Input is the CVE record's
  relevant fields plus text from the best Mentions, so stopgaps and exact boundaries from write-ups
  reach the model. Effort low; generous max tokens because thinking counts toward it.
- **Easy view.** The same Summary request also returns, per language, a plain one-to-two
  sentence explanation and one action: a command (only if it appears verbatim in a source), or the
  list of affected devices with "update now", or "update to version X". The Risk banner is set by
  rules, not the model: exploited in the wild or CVSS 9.0+ → highest ("고위험!"), CVSS 7.0+ → high,
  otherwise notice. The page has a normal/Easy tab per Incident and a remembered default (normal).
  The code check that guards numbers also rejects an Easy command not found in the input text.
  Expected cost: more output per Incident (estimate, not measured), still well within the credit.
- **Summary routing.** Highlight candidates (new KEV entry, HN or curator buzz, CVSS 9.0+, or an
  Unassigned incident seen in discussion) go to the regular API at once; everything else goes into
  one Batch per cycle, collected on later cycles. Re-summarize only on: new official advisory or
  fixed version, newly KEV-listed, CVE newly attached; at most three Summaries per Incident.
- **Prompt caching.** The fixed instructions, with a worked example, exceed the 512-token minimum
  and carry a cache breakpoint (one-hour TTL for batches).
- **Highlight score** combines KEV, discussion signal (HN points, curator mention), CVSS and the
  number of linked Mentions; top ten from the last seven days.
- **Store layout in R2.** One JSON file per calendar month of Incidents (by first-seen time), a
  small index naming the available months, a status file with last-update time and collector
  identity, and per-source checkpoints. Served through a custom domain on the user's existing
  domain (r2.dev is development only), with a CORS rule for the page's origin.
- **Failover.** The standby reads the status file every cycle; it runs a full cycle only when the
  last update is older than 45 minutes, and writes its identity so the main collector can tell it
  has resumed. Writes are whole-file replacements of the months that changed.
- **AI budget.** The project's Console workspace has a monthly spend
  limit and no card on file, so reaching it stops AI calls. The collector treats a credit or limit
  error as "Summaries paused" and keeps publishing Briefs.
- **Page.** Static HTML, CSS and JS on Cloudflare Pages. It downloads the index and the last three
  monthly files, then renders the Board. The filter and search logic is one pure function: given
  Incidents, the visitor's Product picks, a query string and the current time, it returns the
  Highlights and the ordered list. Filter state lives in localStorage and the URL query. Language
  comes from the browser with a remembered toggle. Footer carries the NVD notice, the MITRE CVE
  notice and the reference-only note.
- **Packaging.** One container image for the collector, run with Docker Compose on both boxes
  (Docker to be installed on the Oracle VM), environment file per box holding its own API key,
  GitHub token, NVD key and R2 credentials.

## Testing Decisions

- Good tests check external behavior only: what lands in the store, and what the Board would show.
  No assertions on internal helpers, call order or private structure.
- **Seam 1: one collection cycle.** Inputs: recorded source responses, a fake R2 store, a fake
  Claude client and a controllable clock. Assertions on the monthly files and status file written.
  Core cases:
  - sshole replay: the HN story, sshhole.com, the `oz9un/sshole` repo and CVE-2026-123158 end up as
    one Incident; it is first an Unassigned incident and merges when the CVE arrives; it is a
    Highlight candidate and is summarized at once; its Lead mention is the OpenSSH release note;
    its Summary input includes the write-up text so the 257-character boundary and the
    `PasswordAuthentication no` stopgap can appear.
  - An ordinary CVE gets a Brief immediately and its Summary only after the batch result arrives
    on a later cycle.
  - Re-summary triggers fire on KEV listing and on a new advisory, and stop after three.
  - A credit-exhausted error from the fake client leaves Briefs flowing and marks Summaries paused.
  - Failover: with the status file 46 minutes old the standby runs and writes; at 30 minutes it
    does nothing; once the main writes again the standby stands down.
  - Month rollover writes into the new month's file and the index lists it.
- **Seam 2: the Board's filter and search function.** Inputs: Incident data shaped like the monthly
  files, Product picks, a query and a clock. Assertions: Products narrow the list; search matches
  Korean and English text, CVE IDs and version text; Highlights are at most ten and only from the
  last seven days; newest-first order; an Incident with no Product match is hidden when a Product
  filter is set.
- Live calls to sources and the Claude API are not part of the test suite; each adapter is
  checked once by hand against the real source when first written (no bulk calls).
- Prior art: none in this repository yet. The token probe from 2026-11-07 (outside the repo) shows
  the Summary request shape and the measured cost.

## Out of Scope

- Logins, accounts, comments, or any server-side visitor data.
- Alerts of any kind; per-Product RSS is the next step after v1.
- Version-aware matching of a visitor's installed versions.
- Scraping aggregators (Sploitus, Talkback, CVE Crowd and the like) or X/Twitter.
- Search beyond the last 90 days; a search service.
- Weekly digest pages.
- Choosing the public name and domain (done before launch, outside this spec).
- Scanning anyone's devices.

## Further Notes

- Measured on 2026-11-07: new CVEs average 574 per day (peak about 800); Summary cost $0.00039 to
  $0.00041 per Incident in both languages, about $4 a month with Batch; English only would be
  $0.00028. No discounted "flex" tier exists in the Claude API.
- Source limits and attribution text are recorded in `plan.md` (step 0 results).
- The repository will be public: commit with the GitHub noreply identity and never commit the
  environment file.
