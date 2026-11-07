# 05: Highlights

**What to build:** CISA KEV (JSON feed) marks Incidents exploited in the wild; curator RSS feeds add a curator signal. A Highlight score combines KEV, discussion signal (HN points, curator mention), CVSS and the number of Mentions. The page pins the top ten Highlights from the last seven days above the newest-first list, and shows the severity and exploited flag on every row.

**Blocked by:** 03, 04

**Status:** resolved (d8977dc)

- [ ] A cycle with a recorded KEV feed flags the listed Incidents (seam 1).
- [ ] The filter function returns at most ten Highlights, all first seen in the last seven days, ordered by score (seam 2).
- [ ] An Incident older than seven days leaves the Highlights and stays in the list (seam 2, fake clock).
- [ ] Product filter and search apply to Highlights too.
- [ ] The sshole replay Incident becomes a Highlight.

## Comments

- 2026-11-07: done in d8977dc on `ticket-05-highlights`. Score lives in the page (`highlightScore`): KEV +100, HN points/10 up to 50, curator Mention 25 each (max 2), 2 x CVSS, +1 per Mention; no minimum, so a quiet week pins low scorers. Curators: tl;dr sec and Risky Business News (ThinkstScapes has no feed); Risky Business items were not read, RSS 2.0 assumed. Limits: HN points are frozen at first sight (a 15-minute-old story has few), so live HN buzz barely counts until points are re-read; KEV only flags CVEs already on the Board, so an old CVE newly added to KEV does not appear; the whole KEV catalog (~1.8 MB) is read every cycle and a KEV failure aborts the cycle (a dead curator feed is skipped); a newsletter is read once, so an issue that arrives before its Incident is missed, and it can match an Incident through a shared project URL in the CVE references. `url_key` now drops `utm_` parameters everywhere.
