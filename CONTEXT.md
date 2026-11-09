# vuln-radar

A public, no-login page that lists security incidents newest first and lets each visitor narrow them to the products they run.

## Language

**Incident** (사건):
One real-world vulnerability event, the unit of one row on the board. It may carry zero, one or several CVEs. A vendor release that fixes more than two CVEs of one product in the same version, published within
48 hours, is one Incident (a release group, 2026-11-09).
_Avoid_: item, entry, vuln, CVE (as a row)

**Mention** (언급):
One published piece that points at an Incident: an advisory, a CVE record, a write-up site, a repository, a forum or HN post.
_Avoid_: source, article, post, link

**Mention group** (언급 묶음):
What one source item becomes before linking: its Mentions plus the CVE IDs and URLs it cites. Linking attaches it to an Incident or starts a new one.
_Avoid_: item, record, hit

**Citations** (인용):
For an HN story with no CVE, the CVE IDs and outside links found in the page it links to. Kept on its
Incident for a week; when they point at exactly one other Incident (a CVE ID, or its advisory, write-up
or repo page), the story is folded into it, whichever arrived first.

**Citation** (인용):
A curator newsletter's Mention plus the CVE IDs and URLs it cites, or a KISA 보호나라 notice (kind "notice") plus the CVE IDs
on its page. It joins only the Incidents it cites and never starts one.
_Avoid_: reference, curated link

**Lead mention** (대표 언급):
The one Mention a Summary points to first, picked in this order: the product's official advisory or release note, the discoverer's write-up, the CVE record, then discussion.
_Avoid_: main link, primary source

**Unassigned incident** (CVE 미배정 사건):
An Incident that has no CVE yet. It joins the same Incident when a CVE appears later.
_Avoid_: 0-day, pre-CVE

**Highlight** (주요 사건):
(Called 주목 on the page until 2026-11-09.) An Incident shown pinned above the newest-first list, like a notice, because it matters to many visitors right now. At most four (ten until 2026-11-08, when the pinned frames ran past 1,900px on a phone), chosen by importance from Incidents at 위험 or above published in the last seven days (by Published time, not first sighting: an old CVE seen again is not new; user, 2026-11-09) and shown in the visitor's sort order (newest first by default, 2026-11-08); 더 보기 appends the rest below the first four,
which keep their place (2026-11-09); the rest stay in the list below.
_Avoid_: featured, top, hot, pinned item

**Published time** (게시 시각):
When the news of an Incident first broke: the earliest post time among the Mentions that could start it
(CVE record datePublished, HN story, oss-security post), else NVD's publish date. Shown on the row and used for
"newest first" and the Highlight window. Not the cycle that first saw it (first_seen, which only picks the monthly
file): when no source gives a time it stays unknown, and the row says "처음 확인 12:38" (first seen) instead.

**Board** (보드):
The page's list of Incidents: Highlights on top, then every other Incident, in one visitor-chosen order for both (newest first by default, or by risk level, or by CVSS).
_Avoid_: leaderboard, feed, timeline

**Brief** (속보):
What the Board shows for an Incident the moment it arrives, built from source data alone: the original one-line description, severity, Product and Lead mention. It stands until the Summary is ready.
_Avoid_: preview, stub, placeholder

**Summary** (요약):
The short text the site writes for an Incident: what it is, who is affected and, when known, the Mitigation. It always sends the reader to the best Mention for detail.
_Avoid_: description, analysis, verdict

**Easy view** (쉬운 설명):
The second way to read the Board, chosen with one Normal|Easy switch at the top: a loud risk banner, one or two plain sentences, and the one action to take now (a command to run, or the devices to update). The normal view is the default.
_Avoid_: simple mode, ELI5, beginner view

**Risk banner** (위험 배너):
The big label at the top of the Easy view, set by rules from exploitation and severity, not by the model. Exploited
(악용 발생) means a CISA KEV listing or a Summary whose sources report attacks (2026-11-08), naming the source that says
so (2026-11-09; public exploit code alone is not exploited): the model reports what the sources say; the rule sets the level.
_Avoid_: alert, badge, warning level

**Mitigation** (대처법):
What a visitor can do about an Incident: the fixed version to update to, or a stopgap until then.
_Avoid_: fix, workaround, remediation

**Product** (제품):
A piece of software or firmware a visitor can pick in the filter, named without a version (OpenSSH, Dropbear, OpenWrt).
One Product however a source writes its name (critique 14, 2026-11-09): letter case, a generic suffix ("WordPress
plugin", "플러그인", "theme"), company words and a known vendor in front do not make another one ("GemBooking" and
"GemBooking WordPress plugin" are one). Product names are never translated.
_Avoid_: package, component, CPE (as a user-facing word)
