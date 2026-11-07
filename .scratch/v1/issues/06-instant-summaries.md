# 06: Instant Summaries for Highlight candidates

**What to build:** Highlight candidates (newly KEV-listed, HN or curator buzz, CVSS 9.0 or higher, or an Unassigned incident seen in discussion) get a Summary at once from Claude Haiku 5.5: one request yields Korean and English titles and summaries, preconditions, Mitigation, Products and a Lead mention. Input is the CVE record's relevant fields plus text from the best Mentions. Fixed instructions with a worked example exceed 512 tokens and carry a prompt-cache breakpoint. The page shows the Summary in the browser's language with a remembered toggle; a Brief shows a 'summary in preparation' marker.

**Blocked by:** 04, 05

**Status:** resolved (2fef475)

- [ ] With a fake Claude client, a Highlight candidate gets its Summary in the same cycle; other Incidents do not (seam 1).
- [ ] The sshole replay Summary input includes the write-up text, so the fake can assert the 257-character boundary and the PasswordAuthentication stopgap are present in what was sent.
- [ ] Summary fields are stored for both languages; search matches Korean and English (seam 2).
- [ ] A malformed model reply leaves the Brief in place and is retried on a later cycle.
- [ ] One manual live run on a handful of real Incidents confirms output shape and cost close to the 2026-11-07 measurement ($0.0004 per Incident).
- [ ] The API key comes from the environment file only.
- [ ] The Summary is requested with a JSON schema (structured output), so missing fields or broken JSON cannot occur.
- [ ] The instructions say: when sources disagree on a number, follow the official advisory or the discoverer's write-up; when unsure, leave the field empty.
- [ ] A code check rejects a Summary whose versions or numbers do not appear in the input text, whose Lead mention is not one of the input URLs, or whose Korean and English numbers differ; the Brief stays and the Summary is retried or flagged.
- [ ] A small comparison on real Incidents (sshole among them) of effort `low` vs `medium` for Highlight candidates decides the effort for that path; the result and cost are recorded in the plan.

## Comments

- 2026-11-07: done in 2fef475 on `ticket-06-instant-summaries`. Effort `low` kept (live run: 6 requests, $0.0072; low ~$0.0012 per Incident, medium no better, up to 33% more output; see plan.md). Cost is ~3x the 11-07 probe because page text is in the input and output is ~1,500 tokens; fine for candidates, ticket 07 should trim before batching everything. Limits: candidates are read from the last seven days, at most ten per cycle; "HN buzz" is any HN Mention (points are frozen at first sight); input reads the CVE record from cvelistV5 and at most two advisory/write-up/discussion pages (HN threads skipped), each cut at 8,000 characters; the number check compares digit tokens only (a number written as a word passes, a date written differently in Korean and English is rejected), so false rejections fall back to the Brief after three tries with `summary_error` left on the Incident; Summary Products are stored and searchable but not yet in the Product filter; an API error stops Summaries for the cycle without a status flag (ticket 07). The collector's `http_get` refuses non-public addresses and redirects to them; DNS rebinding is not covered. The page toggles only the Summary's language; the rest of the UI stays English.
