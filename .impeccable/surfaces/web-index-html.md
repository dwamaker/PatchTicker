---
version: 1
slug: "web-index-html"
primary_target: "web/index.html"
related_targets: []
---

# Board (web/index.html)

Scope: the public Board, the only surface. Mode: Operate (a visitor scans once or twice a day).
Audience and job: anyone, Korean first; find whether a new Incident touches something they run and
what to do. Constraints: PRODUCT.md; light and dark themes; WCAG 2.2 AA; no header row of column
labels (user steer); top Normal|Easy switch; Highlights pinned.

## Direction contract

THESIS: The Board reads like Seoul subway signage: every Product has its own fixed line colour, every
CVE ID is a station name in bold over the Incident's Korean title, so a row is understood without a
header row. It refuses the category-default white table with labelled columns.

OWN-WORLD: Dark graphite ground (#121417) and a light twin; near-white text; Product tags are rounded
line badges, each Product a stable hue from a fixed line palette; risk is a separate filled dot at the
row start (red 고위험, amber 위험, grey 참고), never sharing hues with line badges; tabular numerals for
CVE IDs and dates; one hairline between rows.

STORY: The visitor sees the pinned Highlights first, grouped like stacked emergency alerts, reads
risk, title and line badges in one glance, opens a row to get summary, conditions, Mitigation and the
Lead mention, and leaves knowing whether to act.

FIRST VIEWPORT: Top bar: name left, segmented 기본|쉬운 설명 centred, theme and language right. One
line below: product picker and search. Status line with last update and count. Then a "주목 N" group
of framed rows (thin outline, left accent bar in the risk colour, expanded panel attached inside the
frame, taken from the 재난문자 sketch), then a "최신순" group of plain rows: risk dot + word, bold
CVE ID with the Korean title under it (the Easy view and CVE-less Incidents lead with the title),
CVSS ring (arc filled to the score, number inside, coloured by rating), line badges with the vendor
in the name, published date over time, chevron. Changed 2026-11-08 at the user's request; the English
line left the row. Easy view (same day): plain headline over one plain sentence, CVSS ring kept, every
Mention listed in the details. Evening of 11-08: operating systems are outline badges, not lines (eight
distinct line hues); a "읽는 법" legend sits on
the status line. Late 11-08: 필터 joins the picker and search row (its panel opens under it); 정렬 and 모두 펼치기 sit on the 주목
line and one order serves 주목 and the list; 악용 발생 (KEV or reported attacks) is the top level; light-theme 위험 is gold. After critique 6 the Easy to-do list was removed: the panel shows the action only. 11-09: the risk dot is gone; every level is an unfilled ring sign.

FORM: user-pinned combination: 지하철 안내 (pick, rank 1 of the re-rolled list) with the grouping
and framed-Highlight UI of 재난문자 (assigned). Signature move: Product line badges with fixed
colours. seed:a2f4f22edc3ead8a

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
