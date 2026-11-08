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
- 2026-11-08: review fixes on `fix/review-findings`. A KEV listing that no Summary has covered yet now sends the Incident down the instant path however old it is (still at most ten a cycle and three Summaries per Incident); before, an Incident past seven days got no Summary for it at all. The Board's Highlights still take only the last seven days, and a CVE not already on the Board is still not added by KEV. The seven-day window and the 9.0 cutoff now carry a comment where Python (`is_candidate`) and JS (`filterBoard`, `riskLevel`) repeat them. `Mention group` and `Citation` are now CONTEXT.md terms; the spec records KEV as a snapshot adapter (no checkpoint).
- 2026-11-08: real-run fixes on `fix/real-run-2`. The real run's Highlights were general security news seen only on HN (a bank heist, a soldier's SIM card). A story seen only on HN (no CVE, no other discussion or curator pick) now becomes a Highlight only from 100 points (`HN_BUZZ` in `web/board.mjs`, `hn.BUZZ_POINTS` in Python): about where a story reaches the front page; the run's general news peaked at 93, sshole was at 2,910 when first seen. It stays in the list either way. Points are re-read for a week (ticket 04 note), so a story that climbs later can still qualify.
