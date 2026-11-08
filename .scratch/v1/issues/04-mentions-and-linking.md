# 04: Mention sources and Incident linking (sshole replay)

**What to build:** HN Algolia, oss-security RSS and GitHub search become Mention sources. Mentions that cite a CVE ID or a URL already on an Incident join it; Mentions with no CVE form an Unassigned incident; when a CVE later appears in any Mention, the Unassigned incident merges into that CVE's Incident. Each Incident has a Lead mention picked as official advisory or release note, then discoverer write-up, then CVE record, then discussion. PoC repositories are listed as Mentions.

**Blocked by:** 01

**Status:** resolved (8cb0ec5)

- [ ] sshole replay (seam 1): the HN story, sshhole.com, the oz9un/sshole repo and CVE-2026-123158, fed over several cycles in their real order, end as exactly one Incident.
- [ ] Before the CVE arrives that Incident is an Unassigned incident and is on the Board; after, it carries the CVE with no duplicate row.
- [ ] Its Lead mention becomes the OpenSSH release note once that Mention is known.
- [ ] An Incident with two CVEs named in one advisory stays one row.
- [ ] Each adapter respects its source's documented limit (HN 10,000/h per IP, GitHub search 30/min with a token).
- [ ] The Board shows the Mentions list and the Lead mention link for each Incident.

## Comments

- 2026-11-07: done in 8cb0ec5 on `v1`. Limits: HN security filter is a word regex (includes "hole", will misfire); GitHub search only finds repos mentioning "CVE"; a failing Mention source still aborts the cycle (only NVD failures are skipped).
- 2026-11-08: real-run fixes on `fix/real-run-2`. HN points are no longer frozen at first sight: each cycle `hn.refresh_points` asks Algolia once for stories of the last seven days at 100 points or more (`hitsPerPage=1000`; 277 such stories in the week to 2026-11-08) and updates the matching Mentions of Incidents first seen in that week; no request when no recent Incident has an HN story. HN is now at most 11 requests a cycle (44/h, limit 10,000/h). Limits: a story below 100 points keeps its first-seen count; more than 1,000 qualifying stories in a week would drop the rest.
