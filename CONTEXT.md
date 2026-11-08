# vuln-radar

A public, no-login page that lists security incidents newest first and lets each visitor narrow them to the products they run.

## Language

**Incident** (사건):
One real-world vulnerability event, the unit of one row on the board. It may carry zero, one or several CVEs.
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
A curator newsletter's Mention plus the CVE IDs and URLs it cites. It joins only the Incidents it cites and never starts one.
_Avoid_: reference, curated link

**Lead mention** (대표 언급):
The one Mention a Summary points to first, picked in this order: the product's official advisory or release note, the discoverer's write-up, the CVE record, then discussion.
_Avoid_: main link, primary source

**Unassigned incident** (CVE 미배정 사건):
An Incident that has no CVE yet. It joins the same Incident when a CVE appears later.
_Avoid_: 0-day, pre-CVE

**Highlight** (주목 사건):
An Incident shown pinned above the newest-first list, like a notice, because it matters to many visitors right now. At most four (ten until 2026-11-08, when the pinned frames ran past 1,900px on a phone), chosen by importance from the last seven days and shown in the visitor's sort order (newest first by default, 2026-11-08); the rest stay in the list below.
_Avoid_: featured, top, hot, pinned item

**Published time** (게시 시각):
When the news of an Incident first broke: the earliest post time among the Mentions that could start it
(CVE record datePublished, HN story, oss-security post). Shown on the row and used for "newest first".
Not the cycle that first saw it (first_seen, which only picks the monthly file and the time windows).

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

**To-do** (지금 할 일):
The Easy view's checklist for one Incident: whether the visitor uses it (써요, 안 써요, 몰라요), then the Mitigation and the visitor's own tick. The answer stays in the visitor's browser; an answered Incident shows 조치함 or 해당 없음, which is the visitor's word, not a check the Board ran.
_Avoid_: task, ticket, checklist item

**Risk banner** (위험 배너):
The big label at the top of the Easy view, set by rules from exploitation and severity, not by the model. Exploited
(악용 발생) means a CISA KEV listing or a Summary whose sources report attacks (2026-11-08): the model reports what the
sources say; the rule sets the level.
_Avoid_: alert, badge, warning level

**Mitigation** (대처법):
What a visitor can do about an Incident: the fixed version to update to, or a stopgap until then.
_Avoid_: fix, workaround, remediation

**Product** (제품):
A piece of software or firmware a visitor can pick in the filter, named without a version (OpenSSH, Dropbear, OpenWrt).
_Avoid_: package, component, CPE (as a user-facing word)
