# 09: Launch polish: notices, corrections, freshness, phone layout

**What to build:** The page shows the NVD notice and the MITRE CVE notice, a reference-only note pointing readers to the Lead mention, the last-updated time from the status file, and a 'this is wrong' link per Incident that opens a prefilled GitHub issue in the public repository. The layout works at phone width.

**Blocked by:** 02

**Status:** done (2026-11-09 night)

- [x] Footer carries the NVD notice text and the MITRE CVE copyright and license notice.
- [x] Each Incident's 'this is wrong' link opens a new-issue form with the Incident's ID and title filled in.
- [x] The last-updated time matches the status file and warns when it is older than one hour.
- [x] At 375 px width there is no horizontal scroll and the filter is usable.
- [x] No cookies or ad trackers are loaded (see Comments for the one analytics script).

## Comments

**2026-11-09 night (done):** footer has the NVD sentence, the MITRE CVE copyright and license text, and a GitHub link;
each Incident has "틀린 내용 알리기 / Report a mistake" opening a new issue in github.com/dwamaker/PatchTicker with
the Incident filled in, in Korean and English; the stale notice after one hour already existed; at 375 px nothing
scrolls sideways (checked with an Incident open and the footer). Cloudflare injects its Web Analytics beacon
(cookieless, aggregate) into the Pages site: the owner keeps it (11-10) and README and PRODUCT.md say so.
