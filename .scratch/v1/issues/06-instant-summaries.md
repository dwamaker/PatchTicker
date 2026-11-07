# 06: Instant Summaries for Highlight candidates

**What to build:** Highlight candidates (newly KEV-listed, HN or curator buzz, CVSS 9.0 or higher, or an Unassigned incident seen in discussion) get a Summary at once from Claude Haiku 5.5: one request yields Korean and English titles and summaries, preconditions, Mitigation, Products and a Lead mention. Input is the CVE record's relevant fields plus text from the best Mentions. Fixed instructions with a worked example exceed 512 tokens and carry a prompt-cache breakpoint. The page shows the Summary in the browser's language with a remembered toggle; a Brief shows a 'summary in preparation' marker.

**Blocked by:** 04, 05

**Status:** ready-for-agent

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
