# 04: Mention sources and Incident linking (sshole replay)

**What to build:** HN Algolia, oss-security RSS and GitHub search become Mention sources. Mentions that cite a CVE ID or a URL already on an Incident join it; Mentions with no CVE form an Unassigned incident; when a CVE later appears in any Mention, the Unassigned incident merges into that CVE's Incident. Each Incident has a Lead mention picked as official advisory or release note, then discoverer write-up, then CVE record, then discussion. PoC repositories are listed as Mentions.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] sshole replay (seam 1): the HN story, sshhole.com, the oz9un/sshole repo and CVE-2026-123158, fed over several cycles in their real order, end as exactly one Incident.
- [ ] Before the CVE arrives that Incident is an Unassigned incident and is on the Board; after, it carries the CVE with no duplicate row.
- [ ] Its Lead mention becomes the OpenSSH release note once that Mention is known.
- [ ] An Incident with two CVEs named in one advisory stays one row.
- [ ] Each adapter respects its source's documented limit (HN 10,000/h per IP, GitHub search 30/min with a token).
- [ ] The Board shows the Mentions list and the Lead mention link for each Incident.
