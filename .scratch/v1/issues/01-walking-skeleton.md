# 01: Walking skeleton: a CVE reaches the Board

**What to build:** One collection cycle pulls new CVEs from the cvelistV5 delta log, turns each into an Incident with a Brief (original one-line description, CVE ID, first-seen time, CVE record as Lead mention), and writes them into the current month's file plus an index and a status file in a store. A static page loads the index and the last three monthly files and shows the Board newest first. The store has two implementations behind one interface: an in-memory fake for tests and a local-folder store for running on a laptop. Both test seams exist from here on.

**Blocked by:** None (can start immediately)

**Status:** resolved (5a2343e)

- [ ] A cycle run against recorded cvelistV5 responses writes the expected Incidents into the right monthly file (seam 1).
- [ ] A second cycle with no new records changes nothing; a record seen again does not create a second Incident.
- [ ] Incidents first seen in a new month go into that month's file and the index lists the month.
- [ ] The status file holds the last update time and the collector identity.
- [ ] The Board's filter function returns Incidents newest first (seam 2).
- [ ] Opening the page against a local-folder store shows the Incidents newest first.
- [ ] The collector reads its settings from an environment file that git ignores; no secret is committed.

## Comments

- 2026-11-07: done in 5a2343e on `v1`. Open: first run reads only the newest delta entry (shortcut in code); deltaLog.json is 36 MB and is downloaded in full every cycle, fix before going live; REJECTED-record skip has no test.
