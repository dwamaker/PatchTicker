# 09: Launch polish: notices, corrections, freshness, phone layout

**What to build:** The page shows the NVD notice and the MITRE CVE notice, a reference-only note pointing readers to the Lead mention, the last-updated time from the status file, and a 'this is wrong' link per Incident that opens a prefilled GitHub issue in the public repository. The layout works at phone width.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Footer carries the NVD notice text and the MITRE CVE copyright and license notice.
- [ ] Each Incident's 'this is wrong' link opens a new-issue form with the Incident's ID and title filled in.
- [ ] The last-updated time matches the status file and warns when it is older than one hour.
- [ ] At 375 px width there is no horizontal scroll and the filter is usable.
- [ ] No analytics, cookies or third-party trackers are loaded.
