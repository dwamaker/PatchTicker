# vuln-radar

A public, no-login page that lists security incidents newest first and lets each visitor narrow them to the products they run.

## Language

**Incident** (사건):
One real-world vulnerability event, the unit of one row on the board. It may carry zero, one or several CVEs.
_Avoid_: item, entry, vuln, CVE (as a row)

**Mention** (언급):
One published piece that points at an Incident: an advisory, a CVE record, a write-up site, a repository, a forum or HN post.
_Avoid_: source, article, post, link

**Lead mention** (대표 언급):
The one Mention a Summary points to first, picked in this order: the product's official advisory or release note, the discoverer's write-up, the CVE record, then discussion.
_Avoid_: main link, primary source

**Unassigned incident** (CVE 미배정 사건):
An Incident that has no CVE yet. It joins the same Incident when a CVE appears later.
_Avoid_: 0-day, pre-CVE

**Highlight** (주목 사건):
An Incident shown pinned above the newest-first list, like a notice, because it matters to many visitors right now. At most ten, chosen from the last seven days.
_Avoid_: featured, top, hot, pinned item

**Board** (보드):
The page's list of Incidents: Highlights on top, then every Incident newest first.
_Avoid_: leaderboard, feed, timeline

**Brief** (속보):
What the Board shows for an Incident the moment it arrives, built from source data alone: the original one-line description, severity, Product and Lead mention. It stands until the Summary is ready.
_Avoid_: preview, stub, placeholder

**Summary** (요약):
The short text the site writes for an Incident: what it is, who is affected and, when known, the Mitigation. It always sends the reader to the best Mention for detail.
_Avoid_: description, analysis, verdict

**Mitigation** (대처법):
What a visitor can do about an Incident: the fixed version to update to, or a stopgap until then.
_Avoid_: fix, workaround, remediation

**Product** (제품):
A piece of software or firmware a visitor can pick in the filter, named without a version (OpenSSH, Dropbear, OpenWrt).
_Avoid_: package, component, CPE (as a user-facing word)
