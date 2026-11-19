# vuln-radar

A public, no-login page that lists security incidents newest first and lets each visitor narrow them to the products they run.

## Language

**Incident** (사건):
One real-world vulnerability event, the unit of one row on the board. It may carry zero, one or several CVEs. A vendor release that fixes more than two CVEs of one product in the same version, published within
48 hours, is one Incident (a release group, 2026-11-09). The 48 hours run from the first of each burst of that fix, not
from the first Incident that ever held it, so an old CVE of the same fixed version keeps no later release apart (2026-11-16).
An Incident whose CVE records give no fixed version (not published yet) is grouped by its Summary's one product and fixed
version instead, by the same rule (2026-11-16).
_Avoid_: item, entry, vuln, CVE (as a row)

**Mention** (언급):
One published piece that points at an Incident: an advisory, a CVE record, a write-up site, a repository, a forum or HN post.
_Avoid_: source, article, post, link

**Mention group** (언급 묶음):
What one source item becomes before linking: its Mentions plus the CVE IDs and URLs it cites. Linking attaches it to an Incident or starts a new one.
_Avoid_: item, record, hit

**Citations** (인용):
For an HN story with no CVE, the CVE IDs and outside links found in the page it links to; a page that fails to load
is tried again three times in the story's first day (`refetch_pages`, 2026-11-18). Kept on its
Incident for a week; when they point at exactly one other Incident (a CVE ID, or its advisory, write-up
or repo page), the story is folded into it, whichever arrived first. A CVE ID outranks a link: when the page's CVE
IDs are held by one Incident, the story joins it whatever its links point at; held by several, it stands alone
(owner, 2026-11-18). Links decide only when no CVE ID does. A page counts only when no other Incident
links it, and an advisory only when it names one notice: a vendor's list of notices says nothing about which
Incident a story is about (owner, 2026-11-15).

**Citation** (인용):
A curator newsletter's Mention plus the CVE IDs and URLs it cites, or a KISA 보호나라 notice (kind "notice") plus the CVE IDs
on its page. It joins only the Incidents it cites and never starts one.
_Avoid_: reference, curated link

**Advisory** (공식 공지):
A Mention written by the product's own vendor or project: its security advisory or release note. A link in a CVE
record is one when the record tags it so, or when the vendor itself wrote the record, gave the link no tag, and the
link names one notice on the vendor's own site (owner, 2026-11-15). Not a list of notices, which many Incidents
share, and not a bug tracker entry, where outsiders write too: that one is a write-up. Its text, like the CVE
record's, may be the source of a command or a stopgap; a write-up's may not.
_Avoid_: bulletin, notice (a KISA notice is a Citation), vendor link

**Lead mention** (대표 언급):
The one Mention a Summary points to first, picked in this order: the product's official advisory or release note, the discoverer's write-up, the CVE record, then discussion.
_Avoid_: main link, primary source

**Lead CVE** (대표 CVE):
The one CVE an Incident with several CVEs is written around: its title, Summary and Easy view speak of this CVE first.
Picked in this order: a CVE reported as exploited, else the one with the highest score, else the one that arrived first
(owner, 2026-11-15). The Incident keeps its address whichever CVE leads. Its score stays the highest among its CVEs,
shown with the CVE that score belongs to. A CVE's own score is the highest any source gives it: every CVSS 3.x and 4.0
score in its CVE record (the CNA's and each ADP's, such as CISA's) and at NVD (NVD's own and the CNA's); CVSS 2 only
when none of those exists (owner, 2026-11-18). A page's score counts too when the page is the vendor's advisory, a
CNA record or the finder's own disclosure, its publisher gives the score itself for one of the Incident's CVEs, and the
page says it in those words; the score then keeps who gave it (a Page sheet's rule, owner, 2026-11-18).
_Avoid_: main CVE, primary CVE, top CVE

**Page sheet** (페이지 정리표):
What one page states about one Incident, filed by the model: the flaw's names, each version with its status (fixed,
affected, first affected), scores with who gives them, the flawed component and its upstream project, attacks, public
exploit code, stopgaps. Only an Incident with four or more pages to read and at most twelve CVEs gets them, from its
first ten pages. Code merges an Incident's sheets, each fact with its sources ranked, drops a fixed version a record or
an official page calls affected, and puts the result in the Summary's input. A page is read once per Incident.
_Avoid_: fact sheet (in code: the rendered text), page summary

**Unassigned incident** (CVE 미배정 사건):
An Incident that has no CVE yet. It joins the same Incident when a CVE appears later.
_Avoid_: 0-day, pre-CVE

**Highlight** (주요 사건):
(Called 주목 on the page until 2026-11-09.) An Incident shown pinned above the newest-first list, like a notice, because it matters to many visitors right now. Chosen by importance from Incidents at 위험 or above published in the last seven days (by Published time, not first sighting: an old CVE seen again is not new; user, 2026-11-09) only: a CISA KEV listing this week does not bring an older Incident in (owner, 2026-11-17: "일주일로 잡아야지 적어도", after
an August Incident listed this week stood among them): every exploited one, then one Incident at 최고 for each well-known product not already held by an exploited one (the best-scored; owner, 2026-11-11, 2026-11-16), by
the product's tier of reach on the hand-kept list (1 on most computers or phones, 2 the standard of its field, 3 known
inside it; a product on no list counts as 3), tier 1 before 2 before 3 and by importance inside a tier (owner,
2026-11-17: "많은 사람이 사용하는걸 위로"), then the rest by importance, at least ten and at most twenty in all (owner, 2026-11-10). Importance counts, besides attacks,
discussion, curators, the score and Mentions, how new the Incident is: the newest gain as much as the whole score can
give, falling evenly to nothing at seven days old (owner, 2026-11-19: "최신소식이 위에 올라와야"); an Incident with a
provisional level counts as its level's lowest score (9 or 7). A product is well known when it is
on the collector's hand-kept list or its Summary says a large share of ordinary people or organisations run it (both,
owner, 2026-11-11). Four are pinned at first (the pinned frames ran past 1,900px on a phone at ten, 2026-11-08), each of a different vendor
while four remain (owner, 2026-11-16: "고정 네 자리는 서로 다른 회사로"); the same vendor in another category of the
hand-kept list counts apart (owner, 2026-11-17: Android and Chrome, both Google, take a pin each; Office and Outlook
share one). The pins and 더 보기 run in one order whatever the
visitor's sort (owner, 2026-11-17): tier 1, tier 2, exploited Highlights on tier 3 or no list, tier 3, the rest; inside
each, exploited first, then by importance. The pins are the first four of that order of different vendor-and-category pairs; 더 보기 appends
the others below them in the same order; the four keep their place (2026-11-09); the rest stay in the list below. The list is the whole Board in the visitor's
order: every Highlight, pinned or not, also stands at its own place there, edged in its Risk colour like its pinned frame
(owner, 2026-11-16), never inside a vendor fold: the fold holds and counts the rest, or unfolds below its minimum (owner,
2026-11-17). An old event is no Highlight, though it stays on the Board with its level and flag: a CVE Incident whose CVEs
are all two or more years older than this year, or one whose Summary dates the reported attack or incident (`event_date`)
more than 14 days back (owner, 2026-11-17: "오래된 만큼 주요 사건엔 올라오지 못하게", after an October 29 attack reported on
November 14 stood among them).
_Avoid_: featured, top, hot, pinned item

**Published time** (게시 시각):
When the news of an Incident first broke: the earliest post time among the Mentions that could start it
(CVE record datePublished, HN story, oss-security post), else NVD's publish date. Shown on the row and used for
"newest first" and the Highlight window. Not the cycle that first saw it (first_seen, which only picks the monthly
file): when no source gives a time it stays unknown, and the row says "처음 확인 12:38" (first seen) instead.

**Public date** (공개일):
The day a CVE record says its flaw became public, when that is earlier than the Published time. Shown beside the
Published time; it never orders the Board and never counts for the Highlight window (owner, 2026-11-15: an Incident
that arrives today must not land six days down the list).
_Avoid_: disclosure date, release date

**Board** (보드):
The page's list of Incidents: Highlights on top, then every other Incident, in one visitor-chosen order for both (newest first by default, or by risk level, or by CVSS).
_Avoid_: leaderboard, feed, timeline

**Row view** (행 보기):
An Incident as the Board first draws it (`board/rows.json`, owner 2026-11-10): only what its row, the filters, folds
and Highlights read, marked `rows`; no details and no text to search. Opening one or searching fetches the whole week
first. The newest 100 and the week's Highlights come whole.
_Avoid_: stub, preview, light Incident

**Incident page** (사건 페이지):
One Incident as a standalone document at its own address, one per language, made once it has a Summary and kept
90 days. Only an Incident at the 위험 level or above, exploited, or without a CVE is offered to search engines; the
rest are for sharing.
_Avoid_: detail page, permalink, post

**RSS feed** (구독 피드):
The newest search-worthy Incidents (the same ones offered to search engines), one feed per language, for readers who subscribe.
_Avoid_: feed (alone: the Board is not a feed), newsletter

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
The big label at the top of the Easy view, set by rules from exploitation and severity, not by the model. Attacked
(공격 발생; the data's `exploited`; shown as 악용 발생 / Exploited until 2026-11-17, renamed by the owner as a supply-chain
attack that delivered malware carries it too, with no flaw exploited) means a CISA KEV listing or a Summary whose sources
report attacks (2026-11-08), naming the source that says
so (2026-11-09; public exploit code alone is not exploited): the model reports what the sources say; the rule sets the level.
The Summary must itself say that attacks were seen; a source of any kind counts then, the product's own advisory or CVE
record included, and never when it only describes the flaw (owner, 2026-11-16: bird-lg-go's own advisory reported none).
While an Incident has no CVSS score, the severity word its product's own Advisory states under its label ("Severity
Critical", Drupal's "Security risk: Critical") sets a provisional level: Critical the top one, High the next; Medium, Low
or none change nothing, and a score, once there, always wins. Code reads the word from the Advisory's page in the
Summary's input, never from a write-up, news, a discussion or a Mention title, and the row names it (owner, 2026-11-19:
Ruby2Shell, Synology-SA-26:21 and SA-CORE-2026-017, all Critical, sat at 참고 for hours).
_Avoid_: alert, badge, warning level

**Score pending** (점수 대기):
An Incident with no CVSS score yet and no report of attacks. Its own choice in the risk filter beside the three risk
levels, not part of the lowest one; ordered above the lowest level when the Board is sorted by risk (owner,
2026-11-15). An exploited Incident without a score is at the top level, never here. One whose Advisory gives a
provisional level (Risk banner) is still drawn as pending, with the word ("점수 대기 · 공지 등급 Critical"), but filed
under that level in the filter (2026-11-19).
_Avoid_: unrated, unscored, unknown risk

**Mitigation** (대처법):
What a visitor can do about an Incident: the fixed version to update to, or a stopgap until then.
_Avoid_: fix, workaround, remediation

**Distribution table** (배포판 표):
For an Incident's CVEs, what each Linux distribution's own security data says about its packages, one line per
release: the fixed package version, not affected, or not fixed yet (for Ubuntu also: will not be fixed, 2026-11-16).
Built by rule from that data, never written by
the Summary, and checked again while distributions catch up; a release the data does not name gets no line. A
distribution's package version appears only here: the Mitigation's fixed version is the product's own (owner,
2026-11-15).
_Avoid_: backport list, package matrix

**Product** (제품):
A piece of software or firmware a visitor can pick in the filter, named without a version (OpenSSH, Dropbear, OpenWrt).
One Product however a source writes its name (critique 14, 2026-11-09): letter case, a generic suffix ("WordPress
plugin", "플러그인", "theme"), company words and a known vendor in front do not make another one ("GemBooking" and
"GemBooking WordPress plugin" are one). Product names are never translated. Picked Products show Incidents of any of
them, picked operating systems likewise; with both picked, an Incident must have one of each (owner, 2026-11-10).
_Avoid_: package, component, CPE (as a user-facing word)
