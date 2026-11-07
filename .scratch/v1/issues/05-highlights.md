# 05: Highlights

**What to build:** CISA KEV (JSON feed) marks Incidents exploited in the wild; curator RSS feeds add a curator signal. A Highlight score combines KEV, discussion signal (HN points, curator mention), CVSS and the number of Mentions. The page pins the top ten Highlights from the last seven days above the newest-first list, and shows the severity and exploited flag on every row.

**Blocked by:** 03, 04

**Status:** ready-for-agent

- [ ] A cycle with a recorded KEV feed flags the listed Incidents (seam 1).
- [ ] The filter function returns at most ten Highlights, all first seen in the last seven days, ordered by score (seam 2).
- [ ] An Incident older than seven days leaves the Highlights and stays in the list (seam 2, fake clock).
- [ ] Product filter and search apply to Highlights too.
- [ ] The sshole replay Incident becomes a Highlight.
