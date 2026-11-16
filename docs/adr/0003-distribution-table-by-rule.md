# The Distribution table is built by rule from the distributions' own data, not written by the Summary

Readers on Debian, Ubuntu, Alpine, RHEL, SUSE or Arch need their own package's fixed version, which is often a backport
below the product's fixed version: Alpine 3.24 fixed the OpenSSH flaw CVE-2026-123158 in 10.3_p1-r2, not 10.6p2, and
RHEL 8 fixed the GStreamer flaw CVE-2026-125712 in 1.16.1-8.el8_10 against an upstream 1.28.4. The Summary saw such
versions only when a Mention linked a distribution's advisory, and its own version checks rejected backports as "below
the fixed version" (owner, 2026-11-12). So the collector builds the Distribution table itself
(`collector/distros.py`, step 10 of the 2026-11-12 review): for each of an Incident's CVEs, what each distribution's
own security data says about each supported release's package (fixed in a version, not affected, not fixed yet, and
for Ubuntu also will not be fixed), by rule, nothing inferred. A release the data does not name gets no line. The
Summary names only the product's fixed version.

Each distribution's own machine-readable data is the source where it can be used (owner, 2026-11-16): Debian's
security tracker JSON and Alpine's secdb, fetched once a day; Canonical's OpenVEX and OSV files
(`ubuntu-security-notices`), Red Hat's Security Data API, SUSE's CSAF VEX files and Arch's security tracker, per CVE.
These say "not affected" where OSV does not (Debian, Ubuntu, Alpine), tell Ubuntu's "under investigation" apart, and
were fresher than OSV in the checks. Ubuntu's CVE API (`ubuntu.com/security/cves/{CVE}.json`) is an auxiliary source
only, because Canonical calls it a work in progress, subject to change: it stands in when Canonical's files fail or
are missing, and it tells "decided not to fix" (its `ignored`) apart from "not fixed yet", which the VEX files merge
(owner, 2026-11-16). It is asked at most once a lookup, and any failure or unexpected answer leaves the main lines as
they are. Ubuntu Pro builds, and Ubuntu's cloud, OEM and board kernel flavours, are left out (owner, 2026-11-16). Each
line links the distribution's own page for the CVE, and a credit line names the sources and their licences.

A CVE that Debian's or Alpine's daily file knows is asked once a day for 7 days from its first ask; one that got a
line is followed 30 days more, until every line is fixed or not affected (owner, 2026-11-15). A CVE neither file knows
is not asked at all; it becomes due, by the same rule, from the day the index comes to know it (owner, 2026-11-16: on
the first live cycles about 88% of new CVEs were unknown to both files, mostly web apps, and the newest of them took
every slot; 40 of them asked in Ubuntu, Red Hat, SUSE and Arch found no line). A cycle looks up at most 15 CVEs, which
bounds its time (about a minute) and the pages it rewrites. Order: known CVEs new, their follow-ups, then known CVEs of
Incidents posted before step 10 (under 30 days old).

## Consequences

- About 4 to 7 requests per CVE asked and two daily files: roughly 40 MB a day, most of it SUSE's CSAF files (no
  compression) and Debian's 15 MB file, whose parse peaks at about 333 MB of memory.
- The supported releases and their end dates are a table kept by hand in `collector/distros.py`: a new release shows
  no line until it is added, and a release taken out of the table drops from every page.
- Debian's and Alpine's answers come from an index built at the day's first cycle (`distros/index.json`), so a CVE
  that arrives later gets their lines on the next day's ask; the other four answer at once.
- `distros/state.json` keeps, for every CVE held, the day it was first seen and the days it was asked: about 2 to 4 MB
  at 90 days, rewritten each cycle that asks.
- The budget is 2,160 lookups a day. At about 480 new CVEs a day, the known ones (about 56) cost about 390 lookups
  a day for their first week and at most about 1,700 more if every one keeps a line waiting for 30 days (Debian's
  open, Red Hat's "Will not fix", Ubuntu's won't-fix never settle): the owner's rule fits.
- Given up: a package that only Red Hat, SUSE, Ubuntu or Arch carries, and neither Debian nor Alpine, gets no table
  (measured 0 of 40 such CVEs with any line, 2026-11-16).
- Canonical's data is CC BY-SA 4.0, Red Hat's and SUSE's CC BY 4.0: the page states each source's licence.
- Source formats can change; a source that answers something unexpected fails alone and keeps the lines it gave before.
