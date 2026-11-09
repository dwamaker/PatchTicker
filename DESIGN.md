---
name: vuln-radar
description: Korean-first public board of security Incidents, read like Seoul subway signage.
colors:
  platform-ground: "light-dark(#f4f5f7, #121417)"
  kiosk-panel: "light-dark(#ffffff, #191c20)"
  recessed-panel: "light-dark(#eceef1, #1f2328)"
  sign-ink: "light-dark(#16191d, #ececec)"
  secondary-ink: "light-dark(#4f5862, #a8afb7)"
  hint-ink: "light-dark(#5f6872, #8c949d)"
  hairline: "light-dark(#dde1e5, #2a2f35)"
  rail: "light-dark(#c4c9cf, #3a4048)"
  control-edge: "light-dark(#858e97, #6b737c)"
  emergency-red: "light-dark(#c4231c, #ff6b62)"
  caution-amber: "light-dark(#8a6100, #f5b400)"
  caution-amber-mark: "light-dark(#a87700, #f5b400)"
  notice-slate: "light-dark(#5f6b76, #9aa3ad)"
  wayfinding-blue: "light-dark(#1a5fb4, #7cc4ff)"
  clear-green: "light-dark(#1d7a45, #4fc48c)"
  scrim: "rgb(0 0 0 / 0.45)"
  line-01: "#0052a4"
  line-02: "#00a84d"
  line-03: "#00a5de"
  line-04: "#7f4f9a"
  line-05: "#b0ce18"
  line-06: "#77c4a3"
  line-07: "#00828f"
  line-08: "#c25bb8"
  line-ink-dark: "#0d0f12"
  line-ink-light: "#ffffff"
typography:
  headline:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "-0.005em"
  body-detail:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.7
  label:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 700
  meta:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    fontFeature: "tnum"
  description:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: "-0.01em"
  marker:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 700
  badge:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "0.78125rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0em"
  code:
    fontFamily: "ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.875rem"
    lineHeight: 1.5
rounded:
  marker: "4px"
  code: "6px"
  ctl: "8px"
  frame: "10px"
  pill: "999px"
spacing:
  gutter: "1rem"
  gutter-wide: "1.5rem"
  column-gap: "1.25rem"
  risk-column: "6.5rem"
  container: "75rem"
components:
  button-outline:
    backgroundColor: "transparent"
    textColor: "{colors.sign-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.ctl}"
    padding: "0 16px"
    height: "44px"
  button-outline-hover:
    backgroundColor: "{colors.recessed-panel}"
    textColor: "{colors.sign-ink}"
  view-switch:
    backgroundColor: "{colors.recessed-panel}"
    rounded: "{rounded.pill}"
    padding: "3px"
  view-switch-option:
    backgroundColor: "transparent"
    textColor: "{colors.secondary-ink}"
    rounded: "{rounded.pill}"
    padding: "0 20px"
    height: "44px"
  view-switch-option-active:
    backgroundColor: "{colors.sign-ink}"
    textColor: "{colors.platform-ground}"
  input-field:
    backgroundColor: "{colors.kiosk-panel}"
    textColor: "{colors.sign-ink}"
    rounded: "{rounded.frame}"
    padding: "0 14px"
    height: "48px"
  line-badge:
    backgroundColor: "{colors.line-01}"
    textColor: "{colors.line-ink-light}"
    typography: "{typography.badge}"
    rounded: "{rounded.pill}"
    padding: "3px 11px"
    height: "26px"
  board-row:
    backgroundColor: "transparent"
    textColor: "{colors.sign-ink}"
    padding: "12px"
    height: "72px"
  cvss-ring:
    backgroundColor: "transparent"
    textColor: "{colors.sign-ink}"
    typography: "{typography.meta}"
    size: "44px"
  board-row-hover:
    backgroundColor: "{colors.recessed-panel}"
  highlight-frame:
    backgroundColor: "{colors.kiosk-panel}"
    rounded: "{rounded.frame}"
  command-code:
    backgroundColor: "{colors.recessed-panel}"
    typography: "{typography.code}"
    rounded: "{rounded.code}"
    padding: "6px 10px"
---

# Design System: vuln-radar

## Overview

**Creative North Star: "The Station Board"**

The Board is read the way a commuter reads a Seoul subway sign: no column labels, just a
coloured line, a bold station name and the line under it that says where it goes. Every Product rides
its own fixed line colour, every CVE ID is set like a station name with the Incident's title under it,
the CVSS score is a ring filled to its value, and the reader understands a row in one glance. Risk sits apart from the lines as a filled dot at the row start, so "which line"
and "how dangerous" never share a colour.

Density is that of a departure board: rows of 72 px minimum, one hairline between them, generous
column gaps, nothing decorative. The ground is graphite at night and pale concourse paper by day; the
visitor's system setting picks one and a remembered toggle overrides it. The only thing that lifts off
the ground is the "주요 사건" group, stacked like emergency alerts in thin framed rows with a risk-coloured
edge.

The Normal view is restrained: calm type, quiet colour, the facts. The Easy view is the same board
with a friendlier voice: the risk word gains its "!", the row leads with a plain headline ("SonicWall
VPN 인증 우회 위험 발견") over one plain sentence in Sign Ink, and each opened row ends in one plain
action line set heavier than the text around it. The sign does not change; only the announcement does.

**Key Characteristics:**
- No column header row; the row's grid position carries the meaning.
- Two separate colour alphabets: risk and severity (red, amber, slate) and Product lines
  (eleven fixed hues).
- The CVE ID as the bold name over the Incident title, like a station name over its direction.
- CVSS as a ring filled to the score out of 10, number inside.
- Flat rows on hairlines; only the Highlight frames carry a shadow.
- Light and dark twins from one set of `light-dark()` tokens.

## Colors

A graphite-and-paper ground, a strict three-colour risk alphabet, and a subway-map line palette kept
for Products only.

### Primary
- **Emergency Red** (`emergency-red`): the 고위험 risk dot and word, the KEV marker, the left edge
  and faint wash of a 고위험 Highlight frame. Used only for risk.
- **Caution Amber** (`caution-amber`, text) and **Caution Amber Mark** (`caution-amber-mark`, marks): the 위험 word is
  the dark gold (#8a6100 by day, 4.77:1+); its dot, ring arc, frame edge and wash are the brighter gold (#a87700 by day,
  non-text, 3.4:1+), so 위험 reads gold and never as the red of 고위험 (user, 11-08). By night both are #f5b400.
- **Notice Slate** (`notice-slate`): the 참고 risk dot and word, the default Highlight edge, and the
  CVSS ring below 7.0.
- The CVSS ring uses the same three: Emergency Red at 9.0+, Caution Amber at 7.0+, Notice Slate below.
  (A separate orange for 7.0+ was dropped on 11-08: in light theme it read as the amber dot, 1.03:1.)

### Secondary
- **Line palette** (`line-01` to `line-08`): Product line badges, after the Seoul subway map. Eight hues at least
  0.13 apart in OKLab, so no two lines look alike at badge size (a test checks it). Operating systems are not
  lines: they get an outline badge (Secondary Ink text, Control Edge inset ring). Light
  hues carry `line-ink-dark` text, deep hues carry `line-ink-light`. The source is `LINES` in
  `web/board.mjs`, which assigns each Product a colour by an FNV-1a hash of its Product id ("openbsd:openssh"; a device model by its
  name), mixed before the remainder so Products spread over the eight lines.

### Tertiary
- **Wayfinding Blue** (`wayfinding-blue`): links, the focus ring, the caret, and the text selection
  wash (32% mix). Never a fill.
- **Clear Green** (`clear-green`, `--ok`): "done" and "nothing found", like a board's 정상 운행: the all-clear
  check and the copy stamp.
  Text and icons only; never a risk colour, never a line-badge fill.
  4.6:1 or more on every surface in both themes.

### Neutral
- **Platform Graphite / Concourse Paper** (`platform-ground`): the page and the scrollbar track.
- **Kiosk Panel** (`kiosk-panel`): input fields, Highlight frames, an opened row and its details.
- **Recessed Panel** (`recessed-panel`): row and button hover, the view switch track, command code.
- **Sign Ink** (`sign-ink`): titles and body text; also the active view-switch fill.
- **Secondary Ink** (`secondary-ink`): the Incident title under the CVE ID, dates, status line, group headings.
- **Hint Ink** (`hint-ink`): placeholders and field icons.
- **Hairline** (`hairline`): the line between rows and around the top bar and footer.
- **Rail** (`rail`): the top rule of the list, Highlight frame borders, label dividers.
- **Control Edge** (`control-edge`): borders of buttons, fields and the view switch.

### Named Rules
**The Two Alphabets Rule.** Risk and severity speak only in red, amber and slate (Clear Green is a third,
separate alphabet for "done", never for risk), and the same severity
is always the same colour; Product lines never use a red, orange, amber or grey hue, and a line colour
never signals risk. Adding a line colour means checking it against all three first.

**The Fixed Line Rule.** A Product's line colour is a function of its Product id, never its translated name, the same on every row and
every visit. Never pick a line colour per page or per row.

## Typography

**Body Font:** Pretendard Variable when installed (with Apple SD Gothic Neo, Malgun Gothic, Noto Sans
KR, system-ui). The face is not self-hosted yet, so most Windows visitors see Malgun Gothic.
**Code Font:** ui-monospace (with Cascadia Mono, Consolas), only for commands quoted from sources.

**Character:** one Korean sans in tight negative tracking, carried by weight steps rather than size
jumps, like signage lettering.

### Hierarchy
- **Headline** (700, 1.25rem, line-height 1, -0.02em): the site name in the top bar.
- **Title** (700, 1.0625rem, 1.35, -0.02em): the row's name, the CVE ID (the Incident title in the
  Easy view or before a CVE exists).
- **Body** (400, 15px, 1.55): base text; `word-break: keep-all` keeps Korean words whole.
- **Body detail** (400, 0.9375rem, 1.7): the Summary and Easy text inside an opened row, measure
  capped at 46rem.
- **Label** (700, 0.875rem): group headings ("주요 사건 N", "최신순"), field labels, button text (500).
- **Description** (400, 0.875rem, 1.45, -0.01em): the Incident title under the CVE ID, Secondary
  Ink, at most two lines.
- **Meta** (400, 0.8125rem, tabular numerals): the published date and time ("처음 확인 12:38" when no source gave a time), status line, CVSS number (700) and
  rating word, risk word (700), footer.
- **Badge** (600, 0.78125rem, 1.2): Product line badge text.

### Named Rules
**The Station Name Rule.** In the normal view the CVE ID is the bold name and the Incident title in
the page language sits under it in Description size, cut after two lines. With more CVEs the name adds
"외 N건". The Easy view leads with the Summary's plain headline over its one plain sentence (the opened panel starts with the CVE IDs) (Sign Ink,
500, never cut); without a Summary, and for an Incident with no CVE yet, the title leads and the CVE
line goes under it. On 주의 rows a headline ending in "위험" ends in "문제" instead ("risk" → "issue"), so only
경계 and 심각! rows speak of danger; the page swaps the word by the rule-based level, the Summary is unchanged.

**The Tabular Rule.** CVE IDs, counts, dates and times use tabular numerals so columns of
numbers do not shimmer.

## Layout

A single centred column, 75rem wide, with a 1rem gutter (1.5rem from 768 px). The top bar is a
three-part grid: name left, the 기본|쉬운 설명 switch centred, theme and language buttons right;
under 600 px the switch drops to its own full-width line. The product picker and search sit on one
line (picker up to 24rem), stacking under 768 px.

A row is a six-column grid: risk (6.5rem), name and title (fluid), CVSS ring (2.75rem), line
badges (up to 15rem), published date over time (5.5rem), chevron. Column gap is 1.25rem. Opened details align with the
name column. From 768 to 1023 px (tablets, landscape phones) the badges move to a second line under the title, so the name
column is not squeezed. Under 768 px the row restacks into risk, CVSS ring and date with time on one line on top, then name
and title, then badges, and the details drop their indent. Under 600 px the header puts the name and controls on one line
while they fit and drops the controls under the name when they do not (320 px, larger text), with the 기본|쉬운 설명
switch on its own line. Nothing scrolls sideways from 320 px up, also at 150% text. Hover tints apply only where a pointer
can hover, so a tapped row does not stay tinted on a phone.

### Named Rules
**The No Header Row Rule.** The Board never shows a row of column labels. If a column needs a label
to be understood, the column is wrong.

## Elevation & Depth

Flat by default. Depth comes from tonal steps (ground, recessed panel, kiosk panel) and hairlines.
The one exception is the Highlight frame, which lifts slightly to read as a stacked alert.

### Shadow Vocabulary
- **Alert lift** (`box-shadow: 0 6px 18px -8px` in a theme shadow colour, 7% ink by day, 32% black
  by night): Highlight frames only.

### Named Rules
**The One Lift Rule.** Only the "주요 사건" frames cast a shadow. Plain rows, fields, buttons and opened
details stay flat. The phone filter sheet is set apart by the Scrim (`--scrim`, 45% black over the Board), not by a lift.

## Shapes

Three radii: gently rounded controls (8px), slightly softer frames for fields and Highlights (10px),
and full pills for line badges and the view switch (999px). Command code uses 6px, the small
"원문" marker 4px. Borders are 1px throughout; the only thicker edge is the 3px risk-coloured left
edge of a Highlight frame. The risk dot is a filled 0.875rem circle, the chevron a 1.5px stroked
corner that turns when a row opens.

## Components

### Buttons
Restrained outlined buttons for theme, language and copying a command.
- **Shape:** gently rounded (8px), 1px Control Edge border, transparent fill.
- **Size:** at least 44 px high and 44 px wide (the shared touch target), 16px side padding, Label
  size at weight 500.
- **Hover / Focus:** Recessed Panel fill and Sign Ink text on hover; a 2px Wayfinding Blue ring at
  2px offset on keyboard focus.

### View switch (기본 | 쉬운 설명)
- **Style:** a pill track in Recessed Panel with a Control Edge border and 3px inset; two pill options
  44 px high.
- **State:** the pressed option fills with Sign Ink and turns its text to the ground colour at weight
  700; the other option is Secondary Ink, gaining the Recessed hover fill.

### Filter button and panel
- **Place:** a 필터 button (funnel icon, count badge in Wayfinding Blue) at the end of the filter row, beside search
  (on phones, under the product field next to search); the panel opens right under that row.
- **Order and expand:** a 정렬 select (최신순 · 위험도순 · CVSS 높은순) and 모두 펼치기 / 모두 접기 sit on the 주요 사건 line; one order
  serves 주요 사건 and the list (주요 사건 is still chosen by importance), and the list heading names it.
- **Panel:** opens under that line in Kiosk Panel with a Rail border: 게시일 시작/끝, 최소 CVSS, CVE, then chip rows
  for 위험 단계, 조건 (악용 중만, 공식 공지, 공개 익스플로잇·PoC) and OS, then 정렬. Nothing changes until 필터 적용;
  필터 초기화 clears the panel only (Products picked at the top and the search stay). Everything lives in the hash.

### Text size
- Two buttons, 가− and 가+ (A− and A+ on the English page), in one outlined control left of the theme button (the user's pick), glyphs 12 and 18 px
  (px on purpose, so the control does not grow with the text). Steps 87.5, 100, 112.5, 125, 150%, remembered; the end
  steps disable their button. Only text grows: every font size is multiplied by `--ts`; gaps, columns and controls
  stay the same size (the first version scaled the root size, which zoomed the whole page).

### Inputs / Fields
- **Style:** Kiosk Panel fill, 1px Control Edge border, 10px radius, 48 px high. The product field
  carries an inline bold label divided by a Rail line; the search field carries a drawn magnifier in
  Hint Ink.
- **Focus:** the whole field takes the 2px Wayfinding Blue ring at 1px offset.

### Product line badge (signature)
- **Style:** a pill in the Product's line colour, with dark or white text chosen per hue, Badge type,
  at least 26 px high. Wraps rather than truncates.
- **Names:** a badge names the vendor with the model ("SonicWall Gen7", never "Gen7" alone).
- **Picked products:** shown as the same badges with a drawn × inside a 44 px tap area.

### CVSS ring (signature)
- **Style:** a 44 px ring, 3.5px stroke on a Rail track, turned so the arc starts at the top and fills
  clockwise to score/10 with round ends. The score sits inside with one decimal (Meta, 700, Sign Ink);
  nothing sits beside it (the risk word is the one severity word, the reading guide names the ring, and a
  "CVSS 7.5" tooltip and screen-reader label carry it); "exploited" is said once, as "악용 발생" in red (a CISA KEV listing, or a Summary reporting attacks)
  under the risk word, and the opened Normal panel does not repeat it.
- **Colour:** by CVSS rating: Emergency Red 9.0+, Caution Amber 7.0+, Notice Slate
  below. Unrated shows no ring, only a quiet dash in Hint Ink ("점수 아직 없음" in its tooltip). Shown in both views.

### Board row (signature)
- **Style:** a full-width button, 72 px minimum, on a single hairline. Risk dot and word, CVE ID over
  the Incident title, CVSS ring, line badges, published date and time, chevron.
- **Time:** when the news first broke (the earliest source post: CVE record, HN story, oss-security
  post), in the visitor's time zone as `YYYY-MM-DD` over `HH:MM`; how long ago sits in the tooltip.
  The list orders by it.
- **Details:** both views end with the Lead link and every Mention, so links a CVE record gains later
  appear in either view.
- **State:** Recessed Panel on hover; an opened row and its details take Kiosk Panel; `aria-expanded`
  turns the chevron.

### Reading guide (이 게시판 읽는 법)
- **Place:** a link-coloured "읽는 법" disclosure at the right of the status line (wraps under it on
  phones), 44px tall, chevron turning up when open. The guide opens below it in a Kiosk Panel with a
  1px Rail border and 10px radius, like the filter panel, with a 닫기 button.
- **First visit:** opens by itself once on screens 600px and wider (on phones it would fill about a screen
  before the first row, so there it waits for the button); closing it stores `vr-guide` and it stays shut after that.
  With storage blocked it waits for the button.
- **Content:** each mark drawn with the row's own parts beside one plain line: the three risk levels
  (words follow the current view) with their rules, the CVSS ring, line badges, the published date,
  then 주요 사건, an opened row, the Easy switch and the product picker and filters; hairlines split the
  three groups; a closing note says Summaries are written by AI and to check the source links.
- **Rule:** the guide never invents a mark; anything it shows comes from the same render functions as
  the rows, so it cannot drift.

### Highlight frame (signature)
- **Style:** Kiosk Panel, 1px Rail border, 10px radius, 3px left edge in the risk colour, the Alert
  lift shadow. A 고위험 frame adds a faint red wash (7%) and a 위험 frame a fainter amber one (5%), each fading out by 40% of its width. Details open inside
  the frame.

### Command line
- **Style:** the command in the code face on Recessed Panel with a 1px Rail border and 6px radius,
  followed by an outlined copy button. Only commands a source states verbatim appear here.

### Risk sign (bolder after critique 6; both views since 11-09)
- In both views the risk word is a sign, a 1.5px ring around the word with no dot: the top level (고위험 / 심각!) in
  Signal Red, the next (위험 / 경계) gold text in the brighter gold mark's ring, the last (참고 / 주의) in Slate; all
  15px/800. Rings are never filled (user, 11-09). 악용 발생 sits centred under the ring (beside it on phones), and a
  row with no CVSS shows its dash centred where a score ring would be.

### Easy view panel
- **Shape:** an opened Easy row shows the plain action (version, command, devices or the plain action sentence and any
  stopgap) with no question, checklist or tick; the to-do list ("지금 할 일", 써요 / 안 써요 / 몰라요, 다 했어요) was
  removed at the user's request on 2026-11-08 after critique 6.
- **Product lines and models:** when product lines have their own fixed versions, the panel lists them one per
  line ("SonicWall Gen7 7.3.4-7013 이상"); past four device models the row shows the product alone and the panel
  folds the models under "해당 모델 보기 (N개)", where the reader looks for their own. When the Summary says which
  models each line has (`fixes[].devices`), the fold groups them under the line's name in Ink, models no line names last; inside a group a model drops the vendor the line already names.
- **Caution line:** the config caution is Secondary Ink with a drawn warning mark, never the 위험 amber (Two Alphabets).
- **Stopgap follow-up:** when a source says what a stopgap needs ("바꾼 뒤 sshd를 다시 시작하세요."), it follows the stopgap line.
- **Context lines:** a command says which system it is for when a source or its package tool tells ("Alpine 리눅스라면
  이 명령으로 업데이트하세요:"); a config line names its file when a source does ("설정 파일 /etc/ssh/sshd_config에 이 줄을
  넣으세요:"). On the Korean page an English source title reads as the Summary's Korean line; the original is its tooltip.

### Small moments (delight)
- **Empty state names every narrowing:** with Products picked and a search, it says both ("고른 제품(OpenSSH) 가운데
  'zzqq'에 맞는 사건이 없습니다."), never "nothing for OpenSSH" while the search hid an OpenSSH row; its recovery
  buttons say what they bring back ("검색 지우기 · 1건 보기"). Counts appear only in the empty state.
- **Stale data notice:** an hour without an update (six missed 10-minute runs) puts a notice under the status line:
  Ink on Recessed Panel with a Rail border and the drawn warning mark, never amber or red (Two Alphabets); "마지막
  업데이트가 8시간 전입니다. 수집이 멈춰 최근 사건이 빠졌을 수 있습니다." It is a status region (heard once) and is
  rechecked every minute, as is the status line's age, so a tab left open goes stale visibly.
- **All-clear sign:** when only Products are picked and none is on the Board, the empty state is a sign, not a
  sentence: a drawn check, the picked Products as line badges, "최근 7일 동안 게시된 사건이 없습니다" (or 3개월 once
  older months are loaded) and that the picks live in the address, so a bookmark brings them back. It never says
  "safe".
- **'/' for search:** on pages with a keyboard and a hovering pointer the search box shows a small "/" key cap;
  pressing "/" anywhere outside a field jumps there. Hidden on touch screens and while typing.
- **Copy stamp:** copying a command turns the button into a check and "복사됨" and lights the command in the focus
  blue for a moment, like a stamped ticket; both settle back after 2 seconds; screen readers hear "복사됨".
- **Search older:** while a search or filter is on, the button under the list reads "이전 사건에서도 찾기 (최근
  3개월)" instead of "이전 사건 불러오기".

### Motion
- **One authored moment:** when the Board first arrives, each CVSS ring fills from the top to its score
  (700ms, `cubic-bezier(0.16, 1, 0.3, 1)`, after 120ms). Filter changes, view switches and paging redraw
  without replaying it.
- **Folding:** an opened row's details and a folded model list grow from 0 to their height (220ms, ease-out) and
  shrink back faster (160ms) when closed, so the rows below glide; a click mid-way turns them round.
- **Opening:** the reading guide and the filter panel ease in over 200ms (a 6px drop
  and a fade); the phone's filter sheet rises from the bottom over 300ms, dims the Board behind it (a tap there closes
  it), is a modal dialog with the focus inside (Tab wraps, Escape closes) and keeps its 닫기 header in view; its fields run from risk and exploited down to the dates. Closing is instant. The chevron turns
  in 180ms.
- **Vendor fold (trial, 11-09):** five or more list rows of one vendor on one publish day show as one ordinary row
  (gravest member's risk sign, highest CVSS ring, "IBM 보안 공지 25건 묶음" over the first product names, the vendor as
  its badge, the newest date) that opens its members in place; never with a search or a picked Product. A "묶음 풀기 /
  묶어 보기" button beside the list heading turns folds off or on (remembered, `vr-fold`). No look of its own (user, 11-09).
  Opened (critique 9), the fold row, its members and a closing line "IBM 묶음 접기" share one list item on the panel
  ground, members in their own labelled list with the list's columns, a stronger edge below; opening announces the
  count, closing from the bottom brings the fold row back into view.
- **Group ground and tag (11-09, owner: groups were hard to find):** a row that stands for several Incidents (a release
  group of three or more CVEs, or a vendor fold) sits on `--group` (#e6ebf1 / #1a2028, a cool step off the page,
  distinct from the opened-row white) and leads its badge cell with a "묶음" tag: square corners, ink outline, so it
  never reads as a Product (filled pill) or an OS (outlined pill). An opened fold keeps that ground for its row and
  members; its closing "IBM 묶음 접기" is an outlined house button. In 주요 사건 frames only the tag shows.
- **Live updates (11-09, owner):** the page reads `status.json` every 10 minutes and when the tab comes back into view;
  only a new update time fetches the week again. New Incidents take their place in the visitor's sort and filter.
  Near the top of the page they come in with the Board's motion; further down, the rows on screen stay put (the scroll
  is corrected by what was added above) and an inverse pill at the top centre says "↑ 새 사건 N건" until they are
  reached or it is pressed. Each new row wears a 2px blue edge and a faint blue tint (the interface colour, never a
  risk colour), held four seconds after it is half on screen, or cleared at once when the pointer or the keyboard reaches the row;
  it leaves by thinning to 1px and fading into the row's ground (520ms). Screen readers hear one sentence
  per refresh ("새 사건 N건이 추가되었습니다"); focus never moves. Changes to rows already shown (a Summary, an
  exploited flag) apply in place, opened rows stay open.
- **Applied filter chips (11-09):** conditions from the filter panel sit right under the bar that holds 필터; picked
  Products stay under the picker.
- **Bar (11-09):** 주요 사건 heading with 모두 펼치기 on the left, 필터 and 정렬 on the right; the filter panel opens under it.
- **Reload keeps the place:** scroll position, 더 보기 counts, opened rows and folds, and loaded older months come back
  on a reload (sessionStorage `vr-place`).
- **Board continuity:** a redraw the visitor asked for (필터 적용, a chip's ×, clear buttons, a picked Product, 정렬,
  주요 사건 더 보기 / 접기, 더 보기, 모두 펼치기 / 접기) keeps each row's identity through a View Transition: rows that stay
  glide to their new place (260ms ease-out), new rows fade in, gone ones leave faster (140ms). Only rows on or within
  200px of the screen are named, so a long Board stays cheap; typing in search redraws plainly. Reduced motion: rows
  do not move, the change only cross-fades.
- **Micro-feedback (100-250ms):** buttons, chips and the switch press in to 96% and tint in 120ms; the 기본|쉬운
  설명 pill slides under the pressed side (240ms); a copied command's check draws itself and "복사됨" slides in; the
  filter count pops when it changes; the all-clear check draws itself when the sign first appears; the theme icon
  turns in, and a theme or language change cross-fades the page (View Transitions, 200ms, where supported).
- **Reduced motion:** the ring fill and every movement are dropped; opened panels keep only the fade, so the
  change is still seen.
- **First visit (critique 9, 11-09):** the reading guide no longer opens by itself. A first visit gets one framed line
  under the status line: the three risk signs and a CVSS ring, each with a few words, then 읽는 법 자세히 (opens the full
  guide) and a close button. Closing either marks the guide seen (`vr-guide`); the line never returns. The first row
  stays in the first viewport.
- **Phones and larger text (critique 9, 11-09):** a phone row's first line flows: risk sign, CVSS ring, date and
  chevron share it while they fit, and the date drops to its own line at the right when they do not (320px, 가+,
  a sign with 악용 발생); nothing overlaps at any step. The CVSS ring and its number grow with 가+ (`--ts`). Under 600px
  the bar puts the 주요 사건 heading on its own short line and 모두 펼치기 | 필터 · 정렬 on one line.
- **Hardening (critique 9, 11-09):** the Product picker matches what is typed regardless of case: a whole name wins,
  one partial match is picked, several keep the text and say "맞는 제품이 N개입니다" under the fields, none searches as
  before. 이전 사건 불러오기 leaves a visible result line that takes the focus when no button is left. The load error
  keeps its plain sentence and shows the technical cause on a quieter line below. While the phone filter sheet is
  open, the rest of the page is inert.
- **Information over tidiness (owner, 11-09, after critique 10):** heuristic 8 is not chased toward minimalism; what a
  visitor needs to judge an Incident (OS badges, counts, tags) stays visible even when a row gets busier.
- **Headline first (owner, 11-09):** in both views a row leads with what happened (the Summary or quick title; a raw
  source line, clamped to three lines, when there is none) and the CVE ID is the line under it.
- **Frozen search (owner, 11-09):** like frozen panes, the search stays at the top while the Board scrolls: on 768px
  and wider the whole field row (product + search, with applied product chips), on phones only the search line. Its
  height is `--stick`; `scroll-padding-top`, the new-Incidents pill and focus moves clear it. A hairline and a soft
  shadow appear once the page has scrolled.
- **Jump buttons (owner, 11-09):** 맨 위로 and 맨 아래로 sit at the bottom right (44px circles, Panel on Edge), each shown
  only when there is more than 60% of a screen to go that way.
- **Phone header (critique 10, a.1):** one line with the name, 기본|쉬운 설명 and a settings button; 가−/가+, theme and
  language open under it (Escape or a tap elsewhere closes). At 375px the first Highlight moved from 490px to 430px.
- **쉬운 설명 beckons (owner, 11-09):** as the Board arrives in 기본, a light blue band sweeps across the 쉬운 설명 button
  twice (1.2s each), until the visitor has tried that view once (`vr-easy-tried`); never with reduced motion.
- **악용 발생 (critique 10, b.2):** the reason a row sits at the top is set at 14px/800, no longer the row's smallest text.
- **Two kinds of 묶음 kept apart (owner, 11-09):** a vendor fold is "묶음" and the list button says "회사 묶음 풀기 /
  회사별로 묶기"; a release group (CVEs fixed by one update) is one Incident tagged "함께 패치", which that button never
  splits. The "↑ 새 사건 N건" pill now scrolls to the first new row and focuses it.
- **Hardening 2 (critique 10, 11-09):** an Easy row without a Summary says "쉬운 설명 준비 중" only while one is coming;
  a Summary that failed for good says "원문만 있음", and with no quick title and no Product the source's own line is
  the title instead of a blank "새 보안 문제". 모두 펼치기 carries no pressed state beside its swapped label; 회사 묶음
  풀기 announces what it did; a closed fold has no aria-controls; 주요 사건 더 보기 moves focus to the first Highlight it
  added; with no result only the empty state offers 필터 모두 지우기; a reload that restores the older months restores
  their result line; the product and search fields have spellcheck off.
- **Clarify (critique 10, 11-09):** "위험" names a level only; the 10-point measure is "CVSS 점수" everywhere (first-visit
  line, guide, filter field "최소 CVSS 점수"). 필터 적용 reads "필터 적용 · N건" and recounts as choices change. When
  filters leave nothing, the empty state offers up to three single conditions back ("‘고위험’ 빼기 · 12건 보기"),
  the ones that bring back the most first, beside 필터 모두 지우기.
- **Layout pass (critique 10, 11-09):** the filter panel on 1024px and wider puts risk, attacks and OS side by side and
  CVSS, CVE and the dates on one line; a checked risk chip is a ring in its level's colour on a faint tint, never a
  filled block. The dark group ground is #1c2531 (a clear step from the opened-row panel). The guide shows the "묶음"
  and "함께 패치" tags as the Board draws them. From 125% text the fields use their short placeholders.
- **Loading (11-09, user: the reload screen was a bare splash):** until the data arrives the Board stands in its own
  shape, four Highlight frames and six list rows of placeholder bars in the rows' cells, and one scan band runs down
  them (1.6s, the only loop, and only while loading; reduced motion: still bars). When the rows arrive, those on
  screen rise 8px and fade in top to bottom (360ms, 28ms apart, at most twelve) while the rings fill; reduced
  motion: one fade. A reload plays it the same way, at the restored place.
- **Motion for views, folds and arrivals (11-09, owner):** switching 기본 / 쉬운 설명 runs through the Board's View
  Transition: each row on screen lets its old words sink 5px and fade (160ms) while the new ones rise into place
  (300ms, 60ms later), and rows whose height changed glide. A vendor fold opens like an Incident's details: its
  members grow out of the fold row (220ms) with the first ten fading in 24ms apart, and close faster (160ms) before
  the list redraws. A row that arrives by a refresh drops 14px into its place (420ms): through the View Transition at
  the top of the Board, by itself further down. Reduced motion: cross-fades only, folds appear at once.
- **Small motions for the new controls (owner, 11-09):** 맨 위로 / 맨 아래로 rise 8px and grow from 90% (200ms) and sink
  away faster (140ms); the "↑ 새 사건" pill drops in (240ms) and lifts out (160ms); the settings menu fades out (120ms)
  as it faded in; the first-visit line folds away when closed; hints ("맞는 제품이 N개", the older-months result) slide
  in 4px; the frozen row's shadow eases in; the settings icon turns 90°; presses dip to 94-96%.
- **쉬운 설명 beckon, louder (owner, 11-09: the first one was barely seen):** twice, 1.4s each, the word swells to 116%
  in the interface blue and settles with a small bounce, a ring rolls 10px out of the switch and a bright band
  crosses the button; reduced motion keeps the blue word and a still ring. The one place the Board performs.
- **Never:** pulsing alerts, scroll reveals, or loops outside loading; the Board is read, not watched.

## Do's and Don'ts

### Do:
- **Do** open every source link in a new tab (`target=_blank`, `noopener noreferrer`, a hidden "새 탭에서 열림"
  for screen readers), so the Board, its filters and opened rows stay put.
- **Do** keep a line badge on one line: a long name ends in "…" inside the pill, whole in its tooltip and to screen readers.
- **Do** list several 해당 조건 one per line; never join them with " · " (a condition may hold its own dot, "팩스·SMS").
- **Do** draw the focus ring inside a framed 주요 사건 row (`outline-offset: -3px`): the frame clips anything outside it.
- **Do** use the `:root` tokens (`--tap`, `--r-ctl`, `--r-frame`, `--r-pill`, `--fs-meta`,
  `--fs-small`) and the shared `.btn` for any new outlined button.
- **Do** keep every interactive target at least 44 px.
- **Do** theme browser surfaces from the palette: selection, caret, scrollbar, focus ring, link
  underline offset (3px).
- **Do** keep Normal view calm and let the Easy view carry the louder voice (levels 심각! / 경계 / 주의, "!" only at 심각, a plain
  headline, one plain sentence that may end in "!", one action line at weight 600).
- **Do** check both themes for WCAG 2.2 AA contrast after any colour change.
- **Do** write a device or Product badge with its vendor in front.

### Don't:
- **Don't** add a column header row to the Board.
- **Don't** give a Product line a red, amber or grey hue, or use a line colour for risk.
- **Don't** put shadows on plain rows, fields or buttons; the Highlight frame is the only lift.
- **Don't** widen the Highlight's risk edge past 3px or add a coloured edge to plain rows.
- **Don't** set a column of numbers without tabular numerals.
