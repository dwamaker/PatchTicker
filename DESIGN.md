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
  control-fill: "light-dark(#dedfe1, #353739)"
  control-hover: "light-dark(#d5d6d8, #424446)"
  control-on: "light-dark(#cccdd0, #4f5053)"
  segment-on: "light-dark(#ffffff, #4f5053)"
  group-ground: "light-dark(#e6ebf1, #1c2531)"
  skeleton: "light-dark(#ccd3db, #5a5e66)"
  warning-wash: "light-dark(#e2a40033, #e2a4003f)"
  patch-edge: "light-dark(#007c88, #3fc1cc)"
  patch-ink: "light-dark(#005a63, #3fc1cc)"
  fold-edge: "light-dark(#7340f2, #a98bff)"
  fold-ink: "light-dark(#5326c9, #c2adff)"
  emergency-red: "light-dark(#c0262c, #ff6b62)"
  caution-amber: "light-dark(#8a6100, #f5b400)"
  caution-amber-mark: "light-dark(#a87700, #f5b400)"
  notice-slate: "light-dark(#5a6570, #9aa3ad)"
  emergency-wash: "light-dark(#ffc4be, #5b2b28)"
  emergency-ink: "light-dark(#76000c, #ffaea7)"
  caution-wash: "light-dark(#fae19e, #453a1c)"
  caution-ink: "light-dark(#4b3900, #eec448)"
  notice-wash: "light-dark(#dae2ea, #323940)"
  notice-ink: "light-dark(#434f5a, #bdc5ce)"
  ring-red: "light-dark(#ff705d, #c9303a)"
  ring-gold: "light-dark(#ffce2f, #c29900)"
  ring-slate: "light-dark(#9aa3ad, #5a6570)"
  wayfinding-blue: "light-dark(#1a5fb4, #7cc4ff)"
  clear-green: "light-dark(#1f6f1f, #68c8a8)"
  scrim: "rgb(0 0 0 / 0.45)"
  line-01: "#0052a4"
  line-02: "#00a84d"
  line-05: "#b0ce18"
  line-08: "#c25bb8"
  line-09: "#960078"
  line-ink-dark: "#0d0f12"
  line-ink-light: "#ffffff"
  # 쉬운 설명 beckon only (owner, 11-09): never a risk, never a Product line
  beckon-red: "#ff4d4d"
  beckon-orange: "#ffa02e"
  beckon-yellow: "#ffe03a"
  beckon-yellow-light: "#d9a400" # the yellow stop on the light ground, where #ffe03a all but vanished (critique 12)
  beckon-green: "#4cd964"
  beckon-blue: "#3ab7ff"
  beckon-violet: "#7a6cff"
  beckon-pink: "#ff5ad8"
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
  section:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "-0.01em"
  panel-heading:
    fontFamily: "Pretendard Variable, Pretendard, Apple SD Gothic Neo, Malgun Gothic, Noto Sans KR, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "-0.01em"
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
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0em"
  code:
    fontFamily: "ui-monospace, Cascadia Mono, Consolas, monospace"
    fontSize: "0.875rem"
    lineHeight: 1.5
rounded:
  marker: "4px"
  code: "6px"
  ctl: "6px"
  frame: "6px"
  pill: "999px"
spacing:
  gutter: "1rem"
  gutter-wide: "1.5rem"
  column-gap: "1.25rem"
  risk-column: "6.5rem"
  container: "75rem"
components:
  button:
    backgroundColor: "{colors.control-fill}"
    textColor: "{colors.sign-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.ctl}"
    padding: "0 12px"
    height: "36px"
  button-hover:
    backgroundColor: "{colors.control-hover}"
    textColor: "{colors.sign-ink}"
  button-open:
    backgroundColor: "{colors.control-on}"
    textColor: "{colors.sign-ink}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.sign-ink}"
    rounded: "{rounded.ctl}"
    height: "36px"
  button-primary:
    backgroundColor: "{colors.wayfinding-blue}"
    textColor: "{colors.platform-ground}"
    typography: "{typography.label}"
    rounded: "{rounded.ctl}"
    padding: "0 12px"
    height: "36px"
  view-switch:
    backgroundColor: "{colors.control-fill}"
    rounded: "{rounded.ctl}"
    padding: "2px"
  view-switch-option:
    backgroundColor: "transparent"
    textColor: "{colors.secondary-ink}"
    rounded: "{rounded.code}"
    padding: "0 16px"
    height: "32px"
  view-switch-option-active:
    backgroundColor: "{colors.segment-on}"
    textColor: "{colors.sign-ink}"
  search-bar:
    backgroundColor: "{colors.kiosk-panel}"
    textColor: "{colors.sign-ink}"
    rounded: "{rounded.frame}"
    padding: "0 14px"
    height: "48px"
  search-token:
    backgroundColor: "{colors.recessed-panel}"
    textColor: "{colors.sign-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.marker}"
    padding: "0 8px 0 10px"
    height: "36px"
  risk-badge:
    backgroundColor: "{colors.emergency-wash}"
    textColor: "{colors.emergency-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.marker}"
    padding: "0 8px"
    height: "24px"
  group-tag:
    textColor: "{colors.patch-ink}"
    typography: "{typography.badge}"
    rounded: "{rounded.marker}"
    padding: "0 8px"
    height: "24px"
  line-badge:
    backgroundColor: "{colors.line-01}"
    textColor: "{colors.line-ink-light}"
    typography: "{typography.badge}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
    height: "24px"
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
    rounded: "{rounded.ctl}"
    padding: "12px 16px"
  menu:
    backgroundColor: "{colors.kiosk-panel}"
    textColor: "{colors.sign-ink}"
    typography: "{typography.description}"
    rounded: "{rounded.frame}"
    padding: "4px"
  menu-row:
    backgroundColor: "transparent"
    textColor: "{colors.sign-ink}"
    rounded: "{rounded.code}"
    padding: "6px 8px"
    height: "36px"
  banner-warning:
    backgroundColor: "{colors.warning-wash}"
    textColor: "{colors.sign-ink}"
    typography: "{typography.description}"
    rounded: "{rounded.frame}"
    padding: "12px 16px"
---

# Design System: vuln-radar

## Overview

**Creative North Star: "The Station Board"**

The Board is read the way a commuter reads a Seoul subway sign: no column labels, just a
coloured line, a bold station name and the line under it that says where it goes. Every Product rides
its own fixed line colour, every Incident's title is set like a station name with its CVE ID under it,
the CVSS score is a ring whose arc runs to its value, and the reader understands a row in one glance. Risk sits apart from the lines as a square-cornered badge (a pale wash with dark same-hue text) at the row start, and
the product lines are round pills, so "which line" and "how dangerous" never share a colour or a shape.

Density is that of a departure board: rows of 72 px minimum, one hairline between them, generous
column gaps, nothing decorative in the rows. The ground is graphite at night and pale concourse paper by day; the
visitor's system setting picks one and a remembered toggle overrides it. The "주요 사건" group stands
apart as one alert band: a thin frame, a hairline between Highlights, each opening on a header strip (risk sign, 공격
발생 and its evidence, time) the way a disaster text opens on its header (critique P2, 11-19).

The Normal view is restrained: calm type, quiet colour, the facts. The Easy view is the same board
with a friendlier voice: the risk word gains its "!", the row leads with a plain headline ("SonicWall
VPN 인증 우회 위험 발견") over one plain sentence in Sign Ink, and each opened row ends in one plain
action line set heavier than the text around it. The sign does not change; only the announcement does.

**Key Characteristics:**
- No column header row; the row's grid position carries the meaning.
- Two separate colour alphabets: risk and severity (red, amber, slate) and Product lines
  (eight fixed hues).
- The Incident title as the bold name over its CVE ID, like a station name over its direction (owner, 11-09).
- CVSS as a ring whose arc runs to the score out of 10, number inside; the ring itself is never filled.
- Flat rows on hairlines; the Highlights band is framed, never lifted, washed or edged in colour.
- Light and dark twins from one set of `light-dark()` tokens.

## Colors

A graphite-and-paper ground, a strict three-colour risk alphabet, and a subway-map line palette kept
for Products only.

### Primary
- **Emergency Red** (`emergency-red`): the 긴급 word in text, the KEV marker, 공격 발생. Used only for risk. By day
  #c0262c (Astryx red 45, 11-19: farther from the gold under deutan vision).
- **Risk badge colours** (owner, 11-19, after Astryx's Token): each level's sign is a wash with ink of the same hue,
  `emergency-wash`/`emergency-ink`, `caution-wash`/`caution-ink`, `notice-wash`/`notice-ink` (Astryx neutral: pale
  wash and dark text by day, dark wash and light text by night). Text on its wash 6.4:1+.
- **Caution Amber** (`caution-amber`, text) and **Caution Amber Mark** (`caution-amber-mark`, marks other than the
  ring): the 위험 word in text is the dark gold (#8a6100 by day, 4.77:1+), so 위험 reads gold and never as the red of
  긴급 (user, 11-08). By night both are #f5b400.
- **Notice Slate** (`notice-slate`): the 참고 word where it stands as text and the dashed edge of a sign with no score
  yet (#5a6570 by day since critique 13: 4.96:1+ on the hover and group grounds).
- **Warning Wash** (`warning-wash`, `--warn-wash`, Astryx `--color-warning-muted`): the ground of the two warning
  banners only, stale data and a failed load, with the warning icon in Caution Amber (owner, 11-19). They say something
  is wrong with the Board itself, never how dangerous an Incident is.
- The CVSS ring has its own three tones (owner, 11-19: "어둠은 고리 어둡게, 밝은건 밝게"): bright by day, deep by
  night, as Astryx's status tones run: `ring-red` 9.0+, `ring-gold` 7.0+, `ring-slate` below. No 3:1 floor for the
  arc (owner: the number inside carries the value). The ring is never filled.
  (A separate orange for 7.0+ was dropped on 11-08: in light theme it read as the amber mark, 1.03:1.)

### Secondary
- **Line palette** (`line-01`, `line-02`, `line-05`, `line-08`, `line-09`): Product line badges, after the Seoul subway
  map. Five hues at least 0.13 apart in OKLab, so no two lines look alike at badge size (a test checks it): blue
  #0052a4 (white text 7.66:1), green #00a84d (dark 6.13:1), lime #b0ce18 (dark 10.68:1), pink #c25bb8 (dark 5.01:1),
  plum #960078 (white 8.18:1); the fills are the same in both themes. No line is a group colour or within 0.13 of one,
  in either theme (owner, 11-16: Product pills were taking the release group's teal and the fold's violet; a test reads
  `--patch-edge` and `--fold-edge` from index.html): line-03 sky, line-04 purple, line-06 violet and line-07 teal left
  the palette and plum joined. Operating systems are not
  lines: they get an outline badge (Secondary Ink text, Control Edge inset ring). Light
  hues carry `line-ink-dark` text, deep hues carry `line-ink-light`. The source is `LINES` in
  `web/board.mjs`, which assigns each Product a colour by an FNV-1a hash of its Product id ("openbsd:openssh"; a device model by its
  name), mixed before the remainder so Products spread over the lines. WordPress alone is pinned, to pink (line-08) for
  every key that names it (owner, 11-16), so it is one colour everywhere. Every line also sits 0.13+ from Clear Green
  in both themes (a test reads `--ok` from index.html): critique 13 found mint #77c4a3 0.05 from the dark `--ok`, so
  line-06 became violet #7340f2 (white text), line-07 teal darkened to #007c88 (white 4.95:1, was 4.58), and `--ok`
  moved to #1f6f1f / #68c8a8.

### Tertiary
- **Wayfinding Blue** (`wayfinding-blue`): links, the focus ring, the caret, the text selection wash (32% mix), the
  ticks of the current menu choice and the new rows' edge. Its fills are few and small: the one primary button in view
  (필터 적용; the page ground on it 5.76:1 by day, 9.84:1 by night), the 필터 count badge and 맨 위로's progress ring.
- **Clear Green** (`clear-green`, `--ok`): "done" and "nothing found", like a board's 정상 운행: the all-clear
  check, and the copy stamp (the check, the block's edge and a 16% wash under the copied command).
  Never a risk colour, never a line-badge fill.
  4.6:1 or more on every surface in both themes.

### Neutral
- **Platform Graphite / Concourse Paper** (`platform-ground`): the page and the scrollbar track.
- **Kiosk Panel** (`kiosk-panel`): the search bar, the Highlights band, an opened row and its details, the filter
  panel, the reading guide, the first-visit line and the menus (frosted, see Elevation).
- **Recessed Panel** (`recessed-panel`): row hover, the band's header strips, the search bar's tokens, the command block.
- **Control Fill** (`control-fill`, `control-hover`, `control-on`; `--ctl-fill`, `--ctl-hover`, `--ctl-on`): the
  secondary button, the filter chips and the segmented tracks (Astryx `--color-neutral`), a step darker on hover and
  another while its menu or panel is open (owner, 11-19). **Segment On** (`segment-on`, `--seg-on`): the raised chosen
  segment, the panel by day and by night a step lighter than its track, so it reads raised, not sunk.
- **Sign Ink** (`sign-ink`): titles and body text; also the ground of the tooltip and of the new-Incidents pill.
- **Secondary Ink** (`secondary-ink`): the CVE line under the title, dates, status line, counts beside headings.
- **Hint Ink** (`hint-ink`): placeholders, field icons, the empty states' icon.
- **Hairline** (`hairline`): the line between rows and around the top bar and footer.
- **Rail** (`rail`): the top rule of the list, the Highlights band's border and the line between its Highlights, the
  menus' and panels' edge, label dividers.
- **Control Edge** (`control-edge`): borders of the search bar, the date fields, the OS badges and the jump buttons.
- **Skeleton** (`skeleton`, `--skel`, Astryx `--color-skeleton`): the loading Board's bars.
- **Patch Teal** (`patch-edge`, `--patch-edge`) and **Fold Violet** (`fold-edge`, `--fold-edge`): the colours of the two
  kinds of group (owner, 11-16): a release group (함께 공개) is teal (#007c88 by day, #3fc1cc by night); a
  vendor fold (묶음) violet (#7340f2 by day, #a98bff by night). Both were Product lines once (line-07, line-06); since
  11-16 no Product line is either, or within 0.13 of either. Each colours its kind's tag, a filled token on an 18% wash
  of its colour with its own ink (`patch-ink` / `fold-ink`: dark by day, light by night; 5.0:1+ on every ground, owner,
  11-19, after Astryx's Token); Fold Violet also draws the rail and stops an opened fold's members hang on (critique P2,
  11-19). As the rail on the group ground 4.13:1 / 7.15:1 and 4.68:1 / 5.76:1 (day / night), on the page higher. Apart
  in both themes under simulated protan, deutan and tritan vision (CIELAB distance 31+). Never a risk colour; the
  Highlights' blue stays theirs. The words stay, so colour is never the only signal; a tag is a square-cornered token,
  never a Product's round pill.

### Named Rules
**The Two Alphabets Rule.** Risk and severity speak only in red, amber and slate (Clear Green is a third,
separate alphabet for "done", never for risk), and the same severity
is always the same colour; Product lines never use a red, orange, amber or grey hue, and a line colour
never signals risk. Adding a line colour means checking it against all three first. Amber has two uses outside a risk
level, both owner's (11-19): the warning banners (stale data, a failed load) and a filter chip that would leave nothing
(dashed, on `caution-wash` in `caution-ink`).

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
- **Title** (700, 1.0625rem, 1.35, -0.02em): the row's name, the Incident title (the Easy view's plain headline),
  clamped to three lines.
- **Section** (700, 1.0625rem, 1.35, -0.01em, Ink): the section heads, "주요 사건" and the list's order ("최신순"), their
  count beside them in Secondary Ink at 600 (Astryx Section/Heading, 11-19); the filtered Board's answer line takes the
  same size.
- **Panel heading** (700, 1rem, 1.4): 대처법, 요약, 해당 조건 and the CVE-line heads inside an opened row (real headings).
- **Body** (400, 15px, 1.55): base text; `word-break: keep-all` keeps Korean words whole.
- **Body detail** (400, 0.9375rem, 1.7): the Summary and Easy text inside an opened row, measure
  capped at 46rem.
- **Label** (700, 0.875rem): the filter panel's title, the risk word in its badge, field labels; button text is this
  size at 500.
- **Description** (400, 0.875rem, 1.45, -0.01em): the CVE line under the title, Secondary Ink, at most two lines;
  also the menus' rows.
- **Meta** (400, 0.8125rem, tabular numerals): the published date and time ("처음 확인 12:38" when no source gave a time), status line, CVSS number (700) and
  rating word, footer.
- **Badge** (500, 0.75rem, 1.2): Product line badge, group tag (600) and 원문 text (Astryx Badge size).
- The steps between neighbours are small (1.13 to 1.18); the 11-19 audit's detector reads that as a flat hierarchy
  (F5), left open.

### Named Rules
**The Station Name Rule.** In the normal view the Incident title in the page language is the bold name and the
CVE ID sits under it in Description size (owner, 11-09: "Headline first"); with more CVEs the line adds "외 N건". The
Easy view leads with the Summary's plain headline over its one plain sentence (Sign Ink, 500, never cut); without a
Summary the quick title leads, and an Incident with no CVE yet says so on the line under it. On 주의 rows a headline ending in "위험" ends in "문제" instead ("risk" → "issue"), so only
경계 and 긴급! rows speak of danger; the page swaps the word by the rule-based level, the Summary is unchanged.

**The Tabular Rule.** CVE IDs, counts, dates and times use tabular numerals so columns of
numbers do not shimmer.

## Layout

A single centred column, 75rem wide, with a 1rem gutter (1.5rem from 768 px). The top bar is a
three-part grid: name left, the 기본|쉬운 설명 switch centred, theme and language buttons right (from 1024 px). From 600 to
1023 px it is one wrapping line instead: the name on one line, RSS as an icon, the switch centred in the room left,
the buttons right; where that does not fit (larger text) it breaks into two lines rather than run the name under the
switch, as the grid did at 600 px (owner, 11-17);
under 600 px the name, the switch and a settings button share one line (GitHub and RSS leave the line; RSS moves into
the settings panel). Under the header one search bar runs the width of the column with 필터 and 정렬 at its end, on one
line at every width (owner, 11-19, after Astryx PowerSearch; see Search bar); where they would leave the bar under 8em
(large text on a phone) they wrap under it at the end. From 768px the Board's right padding grows where the page's
side margin is narrower than the jump buttons need, so no row sits under them (owner, 11-19). The footer holds the data notices and, in its top right corner, the Support badge (see
Components) (owner, 2026-11-18: 후원 left the header, and the footer's GitHub · RSS line was dropped). It opens with
what the Board holds (the collection note) over a Hairline divider. Two
notices stay visible: the reference line and the NVD API sentence, which the API's terms require shown, so it is never
folded. The rest (the Korean NVD line, the Attacked sign's sources, the CVE terms and MITRE's licence) sit in a native
disclosure, 출처와 라이선스 / Sources and licences / 出典とライセンス, closed by default: footer-sized Secondary Ink
text with the folded model list's chevron, 44 px tall at every width (owner, 2026-11-18; 44px everywhere since 11-19).
Its text is Astryx's supporting text (leading 1.65). Up to 81em, where the jump column would stand over the footer's
last lines and 후원, the footer ends below the column (audit, 11-19). The Incident and product pages keep the full block.

A row is a six-column grid: risk (6.5rem), name and title (fluid), CVSS ring (2.75rem), line
badges (up to 15rem), published date over time (5.5rem), chevron. Column gap is 1.25rem. Opened details align with the
name column; an opened row hands its ring and tags to the panel's top, which repeats these columns from 768px (see
Board row). From 768 to 1023 px (tablets, landscape phones) the badges move to a second line under the title, so the name
column is not squeezed. Under 768 px the row restacks into risk, CVSS ring and date with time on one line on top, then name
and title, then badges, and the details drop their indent (Highlights too, critique 12); the chevron rides with the
date, so when the date wraps under the sign the chevron goes with it and never sits alone. Under 600 px the header keeps
name, 기본|쉬운 설명 and the settings button on one line, also at 360 px (tighter name and switch under 375 px; at
320 px the settings button still wraps under the name, 17 px short); larger
text may still wrap it. The 주요 사건 line holds its heading and 모두 펼치기 at its end (with no Highlights 모두 펼치기
stands at the list head instead, critique 14); 필터 and 정렬 stay beside the closed search bar. Per-CVE
공지/분석 links get finger-sized padding on touch screens. Nothing scrolls sideways from 320 px up, also at 150% text. Hover tints apply only where a pointer
can hover, so a tapped row does not stay tinted on a phone.

### Named Rules
**The No Header Row Rule.** The Board never shows a row of column labels. If a column needs a label
to be understood, the column is wrong.

## Elevation & Depth

Flat by default. Depth comes from tonal steps (ground, recessed panel, kiosk panel) and hairlines.
The Highlights band no longer lifts (critique P2, 11-19: the lift, the wash and the risk edge were a
template card's, and with four 긴급 in a row they told nothing); it is set apart by its frame and its header strips.

### Shadow Vocabulary
- `--lift-menu`: the menus and the phone settings panel. `--lift-float`: the jump buttons and the step squares. The
  new-Incidents pill wears Astryx Toast's `--shadow-med` (no blue halo, which read as keyboard focus at rest).
- `--lift-low` (Astryx `--shadow-low`): the raised chosen segment of a segmented control (기본|쉬운 설명, 최소 CVSS,
  CVE 번호), the one shadow inside a control.
- The frozen search row gains a Hairline and a soft shadow once the page has scrolled under it.
- Nothing else in the Board's flow.

### Frosted menus (owner, 11-19, an experiment)
The four menus (search suggestions, 정렬, language, RSS) are 70% Kiosk Panel over a 12px blur (owner, 11-19: 90% before) (saturate 1.2) of what
lies behind, where the browser has `backdrop-filter`. While the Board redraws through its transition they are solid: the
frozen search bar is drawn apart from the page, so a see-through menu in it showed the old rows sharp (owner, 11-19). `?menu=solid` draws them solid to compare; deleting the one CSS
rule makes them solid for good. Every menu text keeps 4.5:1+ even over a solid ink or white ground behind it, the hover
fill included.

### Named Rules
**The Flat Board Rule.** No row, band, field, button or opened detail casts a shadow (the raised segment above aside).
The phone filter sheet and the floating filter panel are set apart by the Scrim (`--scrim`, 45% black over the Board),
not by a lift.

## Shapes

Five radii, all `:root` tokens: square-ish marks (4px, `--r-marker`: risk badges, group tags, the search bar's tokens,
"원문", skeleton bars, the Support badge, menu rows, the chosen segment inside its track), inner corners (6px,
`--r-code`: the tooltip, the keyboard-focus square around a row's chevron), controls (6px, `--r-ctl`: buttons, chips,
segmented tracks, the command block, the step squares), frames (6px since 11-19, owner's slider pick; 10px before,
`--r-frame`: the search bar, the Highlights band, the filter panel, the guide,
the first-visit line, banners, menus) and full pills (999px: Product line badges, the 필터 count, the new-Incidents
pill). A corner inside a frame or track is concentric with it (a 6px track less its 2px inset holds a 4px segment).
Borders are 1px throughout, and no row wears a coloured side edge (critique P2,
11-19); the one coloured line is an opened vendor fold's 2px Fold Violet rail with a 0.875rem stop ring (2px) at each
member's sign, like stations on a subway line. The risk sign is a filled 4px-corner badge (a dashed edge while no
score; owner, 11-19), the chevron a 2px stroked corner that turns when a row opens, with no ring around it (owner, 11-19:
"테두리 없애고 화살표 살짝 두껍게"); a keyboard focus alone draws a 1.5px Wayfinding Blue 28px square (6px corners)
around it, without moving the row's columns. On a phone the date stands 0.875rem further left to clear it, and the chevron 0.5rem in from the row's edge, so the
ring stays inside the row and a group's frame at 320px too.

## Components

### Buttons (owner, 11-19, after Astryx Button)
- **Secondary** (the shared `.btn`, the default): Control Fill, no visible edge (a transparent 1px one, so sizes hold
  and forced colours still draw it), 6px corners, 0.75rem side padding, an 0.5rem gap after an icon, Label size at 500.
  Control Hover under the pointer; Control On while its menu or panel is open (not 주요 사건 접기, which only expands
  the list).
- **Ghost:** the header's controls (GitHub, RSS, settings, theme, language) and the icon-only closes (the first-visit
  line, the filter panel): no fill until hover or while open.
- **Primary:** 필터 적용 alone, the one filled-accent button in view: Wayfinding Blue with the page ground's colour at
  700. At 0 results it drops to secondary, no longer the obvious next step.
- **Size:** drawn 36 px under a mouse (`--ctl-h`, Astryx `--size-element-lg`) and 44 px under a finger, where
  `--ctl-h` becomes `--tap`; layout heights keep `--tap`.
- **Focus:** a 2px Wayfinding Blue ring at 2px offset on keyboard focus.
- **Waiting:** a button at work (이전 사건 불러오기 while it loads) shows a spinner in its label's colour, is
  `aria-disabled` and `aria-busy`, keeps the focus, dims its text to Hint Ink and takes no hover tint.
- **Names (Astryx pass, owner 11-19):** an icon-only button (theme, GitHub, RSS, settings, 필터 below 1024px, the search
  ×, the jump buttons) also shows its name in a tooltip: an Ink bubble with page-coloured Meta text, 6px corners, after
  200ms under a hovering pointer and at once on keyboard focus, never on touch or while the button's word shows; it
  fades in over 120ms. The theme button is a switch (`role="switch"`, `aria-checked`): a lasting setting, not a pressed
  button.

### Support badge (owner, 2026-11-18)
- The README's Buy Me a Coffee badge, alone, drawn by the page itself (no third-party image: `img-src 'self'`): Buy Me
  a Coffee yellow `#ffdd00`, the cup icon and "BUY ME A COFFEE" in black, 14px bold upper case, 0.1em tracking, 4px
  corners, 44 px high, about 220 px wide. It does not follow the text size: it is a mark.
- Place: inside the footer, under its line, in the top right corner beside the notices (they keep their 46rem column),
  level with the first of them, from 1024 px. Narrower it takes a row of its own above the notices, centred, which
  also keeps it clear of the jump column at 360 px. One element: first in the footer's markup, moved to the corner by
  a two-column grid.
- The yellow is the one colour outside the palette, kept so the badge reads as the service's own mark, the same in both
  themes; black on it is 15.6:1.

### RSS menu (owner, 11-17)
- **Place:** an RSS button (the RSS mark, 16px, and the word "RSS") in the brand row after GitHub, a ghost button in
  Secondary Ink (Ink on hover and while its menu is open, which also gives it Control On); name, GitHub and RSS sit at one
  even spacing (owner, 11-19). From 600 to 1023 px it shows
  its icon alone, the word kept as its name for screen readers. Under 600 px the header line
  is full, so the button sits in the settings panel after the language button, a ghost button like its neighbours, and opens
  the same menu. Where the browser has no popovers neither button is drawn; the footer's RSS link,
  once the fallback there, was dropped at the owner's word (2026-11-18): such browsers have no RSS link on the page,
  and feed readers still find the feeds through the `<link rel="alternate">` tags in the head.
- **Menu:** the shared menu (see Menus), up to 23rem and never wider than the screen less 2rem, anchored under its
  button. A section label (RSS로 받아 보기 / Follow by RSS), then three entries 2px apart, no dividers: 주요 피드 (위험 이상
  사건과 CVE 번호 전 속보), 현황판 전체 (참고까지 모든 사건), 내 제품. Each entry is its name in Ink at 600 as the link
  (the row fills while the link is hovered) with a Meta-size note in Secondary Ink under it, a secondary 복사 button at
  the right, and the full address under both in Secondary Ink mono at 0.75rem (up to three lines; Secondary, not Hint
  Ink, for contrast on the frosted ground). Every link is the feed in the page's language (/en/ on the English page,
  /ja/ on the Japanese one).

### Language menu (owner, 11-17)
- Three languages: 한국어, English, 日本語. Japanese is the interface only: the collector writes Summaries in Korean and
  English, and a Japanese page shows the English Summary (web/board.mjs `withJapanese`; the guide's note says so).
- **Board:** the language button (a 16px globe, then the page's language in itself; the short code under 600 px) opens the
  shared menu, anchored under it at its end: one row per language, each in its own language, the current one semibold
  with a Wayfinding Blue tick at the row's end. Tab reaches the rows; unlike 정렬 it does not answer arrow keys yet
  (audit, 11-19, F7). Where the browser has no popovers the button steps to the next language.
- **Incident and product pages:** the same button as a details whose list links this page in every language
  (/i/, /en/i/, /ja/i/), without script.
- **내 제품:** built from the Products picked in the search bar (not the OS chips), names comma-separated as the products
  feed reads them, at most 30 (the rest are named as left out); the note lists the first three and counts the rest. It
  follows the picks as they change. With nothing picked it is no link: the note says to pick products above, beside a
  제품 고르기 button that closes the menu and puts the caret in the search bar.
- **Behaviour:** the browser opens and closes the menu from its button (Enter, Space, click), closes it on Escape or a
  click elsewhere and returns focus to the button; Tab walks link, 복사, link, 복사…, and tabbing out closes it. On a
  phone, Escape closes the menu alone and the settings panel stays. 복사 is the copy stamp (check and 복사됨, 2 s);
  with the clipboard blocked the address is selected for a manual copy. Open during a Board redraw it stays above the
  moving rows, like the frozen row.

### Menus (owner, 11-19: "드롭다운 디자인 통일")
- **One look for the four dropdowns** (the search bar's suggestions, 정렬, the language and RSS menus), after Astryx
  DropdownMenu: a Kiosk Panel surface (frosted, see Elevation), Rail edge, 6px corners, `--lift-menu`, 4px inside, rows
  2px apart, 4px from its trigger. A row is 8px in (6px block), at least the control height, 4px corners, Description
  size; hover and press are see-through ink (8% and 14%, Astryx overlay-hover/-pressed), so they also sit on the frosted
  ground. A keyboard's row gets the fill and the focus ring inside it. The current choice is semibold with a Wayfinding
  Blue tick at the row's end. A section label is Meta size in Secondary Ink at normal weight.
- **Placing:** anchored under the trigger where anchor positioning exists, flipping sideways or upward when it would
  leave the screen; placed by script elsewhere. Popover menus fade in from 4px above in 100ms and out in 150ms; never
  with reduced motion.
- **정렬** is a button (the current order and a chevron; its icon alone under 360px; 6.5rem wide at most under 600px, so
  "Highest CVSS" ends in "…" there) that opens a `role="listbox"` menu of the three orders (최신순 · 위험도순 · CVSS
  높은순): arrows (stopping at the ends), Home/End, Enter/Space, Escape, type-ahead of Latin letters; Up or Down on the
  closed button opens it. Address (`#s=`) and storage are unchanged. Without popovers the button steps to the next order.

### View switch (기본 | 쉬운 설명)
- **Style (owner, 11-19, after Astryx SegmentedControl):** a borderless track in Control Fill, 2px inset, 6px corners;
  two options at the control height less 4px (44 px under a finger), 1rem side padding, 4px corners.
- **State:** the chosen option is a raised segment (Segment On, `--lift-low`, Ink at 600) that slides under the pressed
  side (240ms); the other is Secondary Ink at 500, gaining Control Hover under the pointer. The same segmented look
  draws 최소 CVSS and CVE 번호 in the filter panel and the guide's small switch.
- **Keys (Astryx pass, owner 11-19):** Left or Right on either option picks the other one and takes the focus.

### Filter button and panel
- **Place:** a 필터 button (funnel icon, the word from 1024 px, a count badge in Wayfinding Blue) and 정렬 at the end of
  the search line, at every width; the panel opens right under the search bar (owner, 11-19).
- **Order and expand:** 정렬 (see Menus) orders the list, and the list heading names the order; 모두 펼치기 / 모두 접기
  sits at the end of the 주요 사건 line (at the list head when there are no Highlights). 주요 사건 is chosen and shown in its own order whatever the list's: tier
  of reach first (1, 2, then exploited rows on tier 3 or no list, then 3, then the rest; owner, 2026-11-17), exploited
  then by importance inside each, its four pins of four different vendor-and-category pairs (owner, 2026-11-16, 2026-11-17; until then the pins
  followed the visitor's order). An old event (its CVEs all two or more years old, or an event date over 14 days
  back) is never a Highlight, though its row stays (owner, 2026-11-17).
- **Panel:** Kiosk Panel with a Rail border, 6px corners, 1.25rem in; its head holds the title and an icon-only ghost
  × close. Chip rows for 위험 단계, 조건 (악용 중만, 공식 공지, 공개 익스플로잇·PoC) and OS; 최소 CVSS and CVE 번호 as
  segmented controls (Astryx: a select is wrong for two or a few options); 게시일 시작/끝, the panel's only fields,
  keeping a field's Control Edge. Nothing changes until 필터 적용; 필터 초기화 clears the panel only (Products picked
  in the bar and the search stay). Everything lives in the hash.
- **Chips:** Control Fill, 6px corners (the risk chips 4px, like the signs), Secondary Ink at 500. Chosen, a chip fills
  (Ink with the page ground's colour at 700; a risk chip takes its sign's wash and ink) and carries a tick, so the state
  never rests on colour alone (Astryx ToggleButton). A chip that would leave nothing is dashed in the caution tone,
  `caution-wash` with `caution-ink` text and a dashed edge, also under the pointer (owner, 11-19; 8.7:1 by day, 6.7:1
  by night), and points to its note (`aria-describedby`).
- **Footer (owner, 11-19):** the groups' notes on the left (what 위험 단계 means, that OS shows everything running on
  that system, and the dashed-chip note with a small dashed swatch, which keeps its line while hidden so nothing jumps),
  필터 초기화 and the primary 필터 적용 · N건 on the right, over a Hairline.
- **Phone sheet:** under 600 px the panel is a bottom sheet (up to 85vh, 6px top corners) over the Scrim, a modal
  dialog with the focus inside. Its head sticks, with a 36 × 4 px handle (Astryx BottomSheet); a drag down the head
  follows the finger and closes the sheet past 80px. The notes scroll in flow; 필터 적용 stays pinned at the bottom.
- **Applied conditions** are tokens in the search bar after the picked Products (see Search bar); the old row of chips
  under the status line is gone.

### Text size
- Two buttons, 가− and 가+ (A− and A+ on the English page), left of the theme button (the user's pick), glyphs 12 and 18 px
  (px on purpose, so the control does not grow with the text): a ghost ButtonGroup with a Rail hairline between them
  (Astryx, 11-19). Steps 87.5, 100, 112.5, 125, 150%, remembered; an end step disables its button (`aria-disabled`, so
  the focus stays on it), its glyph at half strength. The pair is a toolbar and one Tab stop, resting on the first
  member that is not disabled: Left and Right move between the two, Home and End to the ends. Only text grows: every font size is multiplied by `--ts`; gaps, columns and controls
  stay the same size (the first version scaled the root size, which zoomed the whole page).

### Search bar (owner, 11-19, after Astryx PowerSearch)
- **One bar** replaced the product field and the search field side by side: Kiosk Panel, 1px Control Edge border, 6px
  radius, 48 px high, a drawn magnifier in Hint Ink. The typed text is the keyword search and suggests Products; picked
  Products and the filter panel's conditions are tokens inside it. Spellcheck is off.
- **Tokens:** Products first, then each condition read as "field value" with the value bold. A token is 36px tall,
  Recessed Panel, 4px corners (concentric with the bar: it sits 5px in), Label size at 600, a drawn × at its end; the
  whole token is its remove button (a 44px tap on touch). Backspace in the empty input takes back the last one.
  Unfocused, the tokens keep one row, the first cut with "…", and "+N" says how many are hidden; focused, they wrap into
  view. On phones the closed bar sums them up as one "선택 N개" token beside 필터 and 정렬, and a tap anywhere on it opens
  it, so a tap meant for the field never removes a token.
- **End lane:** the result count ("N건"), one clear-all × (36px; 44px on touch) for picks, search and panel conditions,
  and the "/" key cap where there is a keyboard and a hovering pointer. Rows of tokens stop short of the lane.
- **Suggestions:** a menu under the bar at its width, at most 300px (55% of the screen) tall: a section label, then one
  row per Product, its Incident count over the last 30 days under the name; at most ten, ranked whole name, start, word
  start, inside, more Incidents first. Near-duplicate names fold into one suggestion as a person names it (a CVE
  record's platform tail such as "installed on Mac OS" and servicing branches drop out; one vendor's spellings join), and
  picking it picks every id behind it; the ids stay as stored, so links, Incident pages and feeds are unchanged
  (`pickerEntries` in board.mjs). Keys: arrows, Enter on the row moved to, Escape; never while an IME is composing.
- **Placeholder:** "제품, 키워드, CVE 번호"; it is measured, the long one, else the short one, else "검색".
- **Focus:** the whole bar takes the 2px Wayfinding Blue ring at 1px offset.

### Product line badge (signature)
- **Style:** a pill in the Product's line colour, with dark or white text chosen per hue, Badge type,
  at least 24 px high (the risk sign's height), 0.5rem sides, 4px apart (owner, 11-19, after Astryx Badge). On a closed
  row each badge keeps one line and a long name ends in "…" (its tooltip and the opened row give it whole); where every
  name is listed (the opened row, the suggestions) it wraps inside its pill. Operating-system outlines lead the cell in
  one fixed order: Windows, macOS, Linux, Android, iOS. "외 N개" after them is a quiet count at the badges' size, not a
  control.
- **Names:** a badge names the vendor with the model ("SonicWall Gen7", never "Gen7" alone). A name that differs only in
  letter case shows once, first spelling kept ("Qiskit SDK" / "Qiskit Sdk"; critique 12).
- **Picked products** are tokens in the search bar, not badges.
- **Group tag** (함께 공개, 묶음): a filled square-cornered token at the badges' height, 4px corners, Badge type at 600,
  on an 18% wash of its kind's colour in that kind's ink (see Patch Teal and Fold Violet), no border.
- **원문:** a small filled token in the 참고 wash and ink (20px, 4px corners, 0.75rem at 500).

### CVSS ring (signature)
- **Style:** a 44 px ring, 3.5px stroke on a Rail track, turned so the arc starts at the top and fills
  clockwise to score/10 with round ends. The score sits inside with one decimal (Meta, 700, Sign Ink);
  nothing sits beside it (the risk word is the one severity word, the reading guide names the ring, and a
  "CVSS 7.5" tooltip and screen-reader label carry it); "exploited" is said once, as "공격 발생" / "Attacked" in red (a CISA KEV listing, or a Summary reporting attacks)
  under the risk word, and the opened Normal panel does not repeat it.
- **Colour:** by CVSS rating: `ring-red` 9.0+, `ring-gold` 7.0+, `ring-slate` below (bright by day, deep by night,
  owner 11-19); never filled (owner, 11-19: "누가 내부 채우래?"). Unrated shows an empty dashed ring with a dash in Hint Ink ("CVSS 점수 대기" as its tooltip and label). Shown in both views.
  The Incident page has not caught up: its ring is still filled with its level's wash and drawn in the risk red and gold
  (`edge/page.mjs`), a follow-up.

### Board row (signature)
- **Style:** a full-width button, 72 px minimum, on a single hairline. Risk sign, the Incident title over
  its CVE ID (owner, 11-09), CVSS ring, line badges, published date and time, chevron.
- **Time:** when the news first broke (the earliest source post: CVE record, HN story, oss-security
  post), in the visitor's time zone as `YYYY-MM-DD` over `HH:MM`; how long ago sits in the tooltip.
  The list orders by it.
- **Opened row as an inspector (owner, 11-19, after Astryx's incident console):** the facts come first as one
  label-value list (CVE, 점수 for every scored row, one CVE or many, the public date, the attack evidence), labels in
  Secondary Ink at 500, values in Ink at 600; then 대처법, 요약 and 해당 조건 (Easy: its conditions) under real headings
  (Panel heading type); a Hairline before the sources. The Easy view keeps CVE and 점수 in a quiet group at its foot.
- **The ring and tags move (owner, 11-19: a move, not a repeat):** an opened row's header hides its CVSS ring and tags,
  keeping their places so the title never moves; the panel's top shows them as one group beside the facts, the ring
  then 제품 with the tags as working filter buttons (the first five, then 나머지 N개 보기, since one row has 50). From
  768 px the panel's top repeats the header's columns from the title on, so they stand straight under their header
  places; from 768 to 1023 px the tags take their own line, as in the header; on phones the group stacks under the facts
  and the ring is moved sideways to the header ring's x. Opening and closing carry them down and up with the fold (see
  Motion). Vendor-fold headers and rows still loading keep theirs.
- **Sources:** both views end with the Lead link and every Mention, so links a CVE record gains later
  appear in either view. Mentions are grouped by kind; a kind with three or more links folds into one line, "분석 글
  15건: aikido.dev, hadrian.io 외", opening to the list (owner, 11-19; `mentionGroups`, also on the Incident page, where
  a Lead whose kind folds keeps a line of its own). A folded line is 24px tall under a mouse and 44px under a finger.
  Every panel starts flush, whichever line leads. An 공격 발생 panel gives its reason as one of the facts (CISA KEV 등재
  with its day, or the reporting source linked; in a group, which CVEs are attacked); in the 주요 사건 band only a
  reporting source's line or a group's attacked CVEs, as the strip already says "CISA KEV 등재 <day>" (polish 11-19).
  Easy: under the ring and tags, the red "지금 실제 공격에 쓰이고 있어요!" and its reason, one group, and "이럴 때만
  해당돼요" starts the next, 0.5rem below (critique 14 polish). The KEV day is kept whole on one line.
- **State:** Recessed Panel on hover; an opened row and its details take Kiosk Panel; `aria-expanded`
  turns the chevron.

### Reading guide (이 현황판 읽는 법)
- **Place:** a link-coloured "읽는 법" disclosure at the right of the status line (wraps under it on
  phones), 44px tall, chevron turning up when open. The guide opens below it in a Kiosk Panel with a
  1px Rail border and 6px radius, like the filter panel, with a 닫기 button.
- **First visit:** the guide never opens by itself (critique 9); a first visit gets the first-visit line instead (see
  Motion), and drawing that line stores `vr-guide`.
- **Content:** each mark drawn with the row's own parts beside one plain line: the three risk levels
  (words follow the current view) with their rules, the CVSS ring, line badges, the published date,
  then 주요 사건, an opened row, the Easy switch and the search bar's picks and filters; hairlines split the
  three groups; a closing note says Summaries are written by AI and to check the source links.
- **Rule:** the guide never invents a mark; anything it shows comes from the same render functions as
  the rows, so it cannot drift.

### Highlights band (signature; critique P2, 11-19)
- **Style:** one frame for all the Highlights: Kiosk Panel, 1px Rail border, 10px radius, a Rail hairline between
  Highlights; no lift, no wash, no risk edge. Each Highlight opens on a header strip edge to edge (Recessed Panel, a
  Hairline under it, at least 2.5rem): the risk sign with 공격 발생 and its evidence in Secondary Ink ("CISA KEV 등재
  2026-11-13", or "<site> 보도" for a reporting source; text only, the link stays in the panel), or the pin reason
  (뉴스레터, HN), then the date and time on one line and the chevron at the right. Under it the title, the ring and
  the badges (26rem); under 1024px the badges take a line of their own. Details open inside the band, under the title.
  The loading Board draws the same strip, and on phones the strip's two-line title and badge rows' height.
- **In the list too (owner, 11-16):** the list under the frames is the whole Board, so every Highlight also stands at its
  own place there (never inside a vendor fold, which holds and counts the rest or unfolds below its minimum; owner,
  11-17), as an ordinary row that says "주요 사건" / "Highlight" in
  Secondary Ink under its sign (critique P2, 11-19: the 3px edge it wore made two stripes on a grouped row); screen
  readers hear it after its level. A pinned one is then drawn twice: each copy opens on its own, `#i=`
  links land on the pinned copy, and counts (results, new rows above) count Incidents, not rows.

### Command line
- **Style (11-19, after Astryx CodeBlock):** one framed block on Recessed Panel with a 1px Rail border and 8px radius:
  the command in the code face, padded 0.75rem 1rem, and 복사 a ghost button in the block's own end column. On phones
  the code takes the block's full width and 복사 sits under it at the end, on a hairline. Only commands a source states
  verbatim appear here.

### Risk sign (bolder after critique 6; both views since 11-09)
- **Not rated yet (critique 12):** an Incident with no CVSS that is not exploited keeps the last level (참고 / 주의) but
  draws its sign with a dashed edge and says "점수 대기" (both views; ring label "CVSS 점수 대기"; English "Score pending") at
  14px/700 under the sign, where 공격 발생 would sit, and an empty dashed ring stands in the ring's place (also on
  phones). The first-visit line and the guide show the dashed sign and ring with "점수 대기"; 위험도순 and CVSS 높은순 put
  these rows above scored 참고 rows (critique 13). The rule that sets the level is unchanged.
- In both views the risk word is a badge after Astryx's Token (owner, 11-19, replacing the 11-09 unfilled ring: pills
  and curves read as generated): square corners (`--r-marker`, 4px), no border, 1.5rem tall, 0.5rem side padding, Label
  size (0.875rem) at 700; the top level (긴급 / 긴급!) on `emergency-wash` in `emergency-ink`, the next (위험 / 경계) on
  `caution-wash` in `caution-ink`, the last (참고 / 주의) on `notice-wash` in `notice-ink`. Not rated yet keeps a dashed
  edge. The same badge in the band's strip, the guide's sample, the checked filter chips and the Incident page.
- Every sign starts at the risk column's start, and the reason under it (공격 발생, 점수 대기, 주요 사건) is centred on
  the sign (owner, 11-19: "글자 배지 중앙기준으로 정렬시켜"; a reason wider than the sign overflows it evenly). On phones
  and in the band's strip the reason sits beside the sign. A row with no CVSS shows its dash centred where a score ring
  would be.

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

### Product page (owner, 11-17)
- **What it is:** `/p/<slug>`, one product's Incidents of the last 90 days, newest first, for search and for a reader who
  follows one product; plain HTML in the Incident page's shell (header, footer, tokens, CSP), one script (the times).
- **Shape:** the product's name as the heading ("OpenSSH 보안 사건"), one Secondary Ink line with the count, then a list
  of panels, each edged on the left in its Risk colour like the Incident page's banner: the risk word in its sign
  (with 공격 발생 in red when attacked) and the time on a small Secondary Ink line, the title in Ink and bold as the
  link to its Incident page (or its Board row when it has none), and the fixed version and CVE count under it. The
  page's links end it: the Board filtered to the product, and the product's RSS.
- **From the Incident page:** a "제품별 사건" section after the products lists each product's page (at most five,
  operating systems aside); the tags keep linking the Board's filter.
- **Thin pages:** fewer than 3 Incidents and the page is `noindex` and out of the sitemap (the number is the owner's to
  change).

### Not found page (owner, 11-17)
- `web/404.html`, which Pages serves with a 404 for any unknown path: the Incident page's header, tokens and type in
  both themes, laid out as Astryx's EmptyState (11-19): centred, an icon over the title, the description, then the
  way on (the Board, llms.txt), in Korean and in English. No script; its one style block is hashed in `_headers`. The
  Incident page's notes (404, 410, 503) take the same anatomy: a crossed page or, for 503, a warning sign, the first
  sentence as the title, the rest as the description, then the way on, with 32/24 padding and a 16 gap.

### Small moments (delight)
- **Empty state names every narrowing:** with Products picked and a search, it says both ("고른 제품(OpenSSH) 가운데
  'zzqq'에 맞는 사건이 없습니다."), never "nothing for OpenSSH" while the search hid an OpenSSH row; its recovery
  buttons say what they bring back ("검색 지우기 · 1건 보기"). Counts appear only in the empty state. Its look is
  Astryx's EmptyState (owner, 11-19): centred, a search or filter glyph in Hint Ink over the sentence as the title
  (1.0625rem, 600), the Board's reach as the description in Secondary Ink, the text group at most 30rem, the buttons in
  one centred row; an empty list leaves no top rule hanging.
- **Warning banners (owner, 11-19, after Astryx Banner, status warning):** the stale notice and a failed load are one
  banner as wide as the Board: Warning Wash, no border, 10px corners, 12/16 padding, the warning icon in Caution Amber,
  a semibold title and the rest as a description in Secondary Ink. A failed load names its cause in the description and
  carries 다시 시도 at its end; an opened row whose details failed shows the same banner.
- **Stale data notice:** an hour without an update (six missed 10-minute runs) puts the warning banner under the status
  line (its text names no age since critique 12: the status line just above says it, and fixed text is announced once):
  "업데이트가
  멈춰 있습니다. 수집이 끊겨 최근 사건이 빠졌을 수 있습니다." (critique 13: no "an hour"; the data may be a day old). On
  phones it is "· 업데이트 멈춤" at the end of the status line, the full sentence kept for screen readers. It is a status region (heard once) and is
  rechecked every minute, as is the status line's age, so a tab left open goes stale visibly.
- **All-clear sign:** when only Products are picked and none is on the Board, the empty state is a sign, not a
  sentence, in the empty state's centred layout: a drawn check in Clear Green as its icon, the picked Products as line badges, "최근 7일 동안 게시된 사건이 없습니다" (or 3개월 once
  older months are loaded) and that the picks live in the address, so a bookmark brings them back. It never says
  "safe".
- **'/' for search:** on pages with a keyboard and a hovering pointer the search box shows a small "/" key cap;
  pressing "/" anywhere outside a field jumps there. Hidden on touch screens and while typing.
- **Copy stamp:** copying a command turns the button into a check and "복사됨" and lights the command block in Clear
  Green (its edge and a 16% wash, in 120ms) for a moment, like a stamped ticket; both settle back after 2 seconds (the
  block fades back over 700ms); screen readers hear "복사됨".
- **Search older:** while a search or filter is on, the button under the list reads "이전 사건에서도 찾기 (최근
  3개월)" instead of "이전 사건 불러오기".

### Motion
- **One authored moment:** when the Board first arrives, each CVSS ring fills from the top to its score
  (700ms, `cubic-bezier(0.16, 1, 0.3, 1)`, after 120ms). Filter changes, view switches and paging redraw
  without replaying it.
- **Folding:** an opened row's details and a folded model list grow from 0 to their height in 300ms and shrink back in
  240ms, both on one gentle ease-out (`FOLD_EASE`, `cubic-bezier(0.33, 1, 0.68, 1)`; owner, 11-10, frame by frame on a
  phone: the sharper curve was three quarters open in 50ms), so the rows below glide; a click mid-way turns them round.
  `fold()` in app.mjs is the source.
- **The ring and tags travel (owner, 11-19):** opening or closing a row carries its ring and tags between the header
  and the panel's top as one motion with the fold (same 300 / 240ms and curve): a ghost copy travels straight down or
  up (never diagonally) while the real copies are held invisible; the rings hand over on landing, the tags cross-fade
  from 60% of the way. A click mid-way starts from where the ghosts are. The first open of a row still loading its full
  Incident, 모두 펼치기 and redraws stay instant. Reduced motion: a 200ms cross-fade in place.
- **Opening:** the reading guide opens and closes like a row's details (the same fold, both ways; its top margin moves
  with it so nothing below jumps; reduced motion: a 200ms fade; owner, 11-19: it had no motion). The inline filter panel
  grows open over 260ms and shrinks shut in 160ms on `--ease-exit` (X, 필터, Escape), so the Board below slides down
  and back up instead of jumping (owner, 11-19; reduced motion: a fade); floating mid-list it drops 6px and fades; the phone's filter sheet rises from the bottom over 300ms and slides down whole in 220ms while its dim
  fades. 필터 적용 shuts the inline panel inside the Board's transition, so its old picture fades while the rows glide
  once. The chevron turns in 180ms.
- **Filter motion (owner, 11-19: "the small animations are missing"):** a chip's tick grows in and out with its fill
  (160ms); the 최소 CVSS and CVE 번호 pill slides under the chosen option (200ms); 필터 초기화 cross-fades the chosen
  chips to clear; the number in 필터 적용 · N건 swaps in (160ms) when a choice changes it, never as the panel opens; the
  필터 badge fades and shrinks out keeping its number (140ms); the search bar's tokens pop in when added and shrink out
  when removed, one at a time; the dashed-chip note rises in. While the phone sheet or the floating panel is over the
  Board, the Board redraws without a transition (its named rows would show through the sheet), and a reset under a
  sheet fades the cleared choices in (160ms).
- **Vendor fold (trial, 11-09; three since late 11-09, owner):** three or more list rows of one vendor (or of WordPress plugins and themes, one
  pseudo-vendor since critique 14) on one publish day show as one ordinary row
  (gravest member's risk sign, highest CVSS ring, "IBM 보안 공지 25건 묶음" over the first product names, the vendor as
  its badge, the newest date) that opens its members in place; never with a search or a picked Product. A "묶음 풀기 /
  묶어 보기" button beside the list heading turns folds off or on (remembered, `vr-fold`). Its look is the group ground
  and tag below.
  Opened (critique 9), the fold row, its members and a closing line "IBM 묶음 접기" share one list item on the group
  ground, members in their own labelled list, indented as a nested list on the Fold Violet rail (2rem in; 1.5rem on a
  phone) so they cannot be taken for rows of the main list, their columns aligned with each other; opening announces the
  count, closing from the bottom brings the fold row back into view. Its members run gravest first, ranked as the
  위험도순 sort ranks, members of one level keeping the visitor's order, so the sign and ring the fold row promises lead
  its list (owner, 11-16); the fold keeps its place and its newest date. Its "one publish day" is the visitor's own
  calendar day, the date the rows show, not the UTC day (owner, 11-16: in Korea the UTC day broke folds at 09:00).
- **Group ground and tag (11-09, owner: groups were hard to find):** a row that stands for several Incidents (a release
  group of three or more CVEs, or a vendor fold) leads its badge cell with its group tag (see Product line badge):
  square corners, so it never reads as a Product (round filled pill) or an OS (round outlined pill). Closed, it is a plain row on its hairline (critique
  P2, 11-19: the 11-16 frames with a 3px band made four kinds of side stripe; the tag's colour still tells two touching
  groups apart). Opened, a vendor fold stands on `--group` (#e6ebf1 / #1c2531, a cool step off the page) for its row,
  members and closing line; the members sit 2rem in (1.5rem on phones) and hang on a 2px Fold Violet rail with a stop at
  each member's sign; its closing "IBM 묶음 접기" is a house button on the panel ground. In the 주요 사건 band only the tag shows.
- **Live updates (11-09, owner):** the page reads `status.json` every 30 seconds, live like a ticker, and at once when the tab or window comes back (owner, later 11-09: no conditions); the server should cache `status.json` for 30 s or less;
  only a new update time fetches the week again. New Incidents take their place in the visitor's sort and filter.
  Near the top of the page they come in with the Board's motion; further down, the rows on screen stay put (the scroll
  is corrected by what was added above) and an inverse pill at the top centre says "↑ 새 사건 N건" until they are
  reached or it is pressed. Each new row wears a 2px blue edge and a faint blue tint (the interface colour, never a
  risk colour), held four seconds after it is half on screen, or cleared at once when the pointer or the keyboard reaches the row;
  it leaves by thinning to 1px and fading into the row's ground (520ms). Screen readers hear one sentence
  per refresh ("새 사건 N건이 추가되었습니다"); focus never moves. Changes to rows already shown (a Summary, an
  exploited flag) apply in place, opened rows stay open.
- **Section heads (11-19, after Astryx Section):** the 주요 사건 heading and its count, with 모두 펼치기 at the line's
  end; the list head names the order, with 모두 펼치기 (when there are no Highlights, critique 14) and 묶음 풀기 at its end.
  Wrapped under a long heading they keep the end.
- **Reload keeps the place:** scroll position, 더 보기 counts, opened rows and folds, and loaded older months come back
  on a reload (sessionStorage `vr-place`).
- **Board continuity:** a redraw the visitor asked for (필터 적용, a chip's ×, clear buttons, a picked Product, 정렬,
  주요 사건 더 보기 / 접기, 모두 펼치기 / 접기, the view switch) keeps each row's identity through a View Transition: rows
  that stay glide to their new place (260ms ease-out), new rows fade in, gone ones leave faster (140ms). Only rows on or
  within 200px of the screen are named, so a long Board stays cheap. Typing in search runs the same redraw, quicker
  (owner, 11-19: "no animation at all when it switches"): rows glide in 200ms, gone ones leave in 120ms, the page, the
  answer line and the result count cross-fade in 160ms; a keystroke during one skips it to its end, so nothing queues.
  The result count cross-fades (160ms) on every redraw. Reduced motion:
  rows do not move, the change only cross-fades (typing: one 160ms cross-fade). What stays put on screen stays above the moving rows (owner, 11-17:
  rows lay over the frozen search bar): while a Board transition runs, the frozen bar (`#filter` from 768px, the
  search row on phones), the jump group and the new-Incidents pill are named, drawn over the rows, and neither fade
  nor move. 더 보기 runs through no transition when it only adds rows (owner, 11-17: the old picture of its button and
  the footer showed through the new rows): nothing drawn moves, and the added rows on screen fade in (180ms; reduced
  motion: none). When the Board changed since it was drawn, 더 보기 draws it whole through the transition.
- **Micro-feedback (100-250ms):** buttons and the switch press in to 98% (Astryx Button), tokens, filter chips,
  segment options and the search × to 96%, and all tint in 120ms; the 기본|쉬운
  설명 pill slides under the pressed side (240ms); a copied command's check draws itself and "복사됨" slides in; the
  filter count pops when it changes; the all-clear check draws itself when the sign first appears; the theme icon
  turns in, and a theme or language change cross-fades the page (View Transitions, 200ms, where supported).
- **Reduced motion:** the ring fill and every movement are dropped; opened panels keep only the fade, so the
  change is still seen. A row's details fade in and out (opacity only, 200ms) instead of growing; the phone sheet's
  fade is 200ms, not 300ms; the filter panel, its chips and badge change by opacity and colour only (Astryx pass, owner
  11-19: "opacity only, in 200 ms or less").
- **First visit (critique 9, 11-09):** the reading guide no longer opens by itself. A first visit gets one framed line
  under the status line (Kiosk Panel, Rail edge, 10px corners, Astryx Banner's 12/16 padding): the three risk signs and
  a CVSS ring, each with a few words, then 읽는 법 자세히 (opens the full guide) and a ghost × close. Closing either marks the guide seen (`vr-guide`); the line never returns. The first row
  stays in the first viewport.
- **Phones and larger text (critique 9, 11-09):** a phone row's first line flows: risk sign, CVSS ring, date and
  chevron share it while they fit, and the date drops to its own line at the right when they do not (320px, 가+,
  a sign with 공격 발생); nothing overlaps at any step. The CVSS ring and its number grow with 가+ (`--ts`).
- **Hardening (critique 9, 11-09):** 이전 사건 불러오기 leaves a visible result line that takes the focus when no button
  is left. The load error keeps its plain sentence and shows the technical cause apart (now the warning banner's
  description). While the phone filter sheet is open, the rest of the page is inert.
- **Information over tidiness (owner, 11-09, after critique 10):** heuristic 8 is not chased toward minimalism; what a
  visitor needs to judge an Incident (OS badges, counts, tags) stays visible even when a row gets busier.
- **Headline first (owner, 11-09):** in both views a row leads with what happened (the Summary or quick title; a raw
  source line, clamped to three lines, when there is none) and the CVE ID is the line under it.
- **필터 and 정렬 frozen too (owner, after critique 12: "like Excel frozen panes"):** they sit on the search line, so
  they freeze with it (see the distill notes below).
- **Motion of the jump buttons (owner, after critique 12):** 맨 위로 wears a 3px ring in the focus blue on a 22% track
  that fills clockwise with how far down the page is. An arrow leans 2px its way on hover; on a press it leaves the way
  the page goes and returns from the other side (440ms). Reduced motion: none of it.
- **Jump buttons rest on phones (owner, after critique 12):** under 768px 맨 위로 / 맨 아래로 show while the page moves
  and fade 2 s after it stops, so they do not sit on the text being read; keyboard focus keeps them.
- **Korean search words (owner, after critique 12):** a small alias table lets 윈도우, 맥, 리눅스, 안드로이드, 아이폰,
  공유기, 워드프레스 and a few more match the English names sources use; product names are still typed as they are.
- **OS chips say what they mean:** the filter's OS group notes that it shows everything running on that system,
  including web software such as WordPress plugins; a note on dashed chips shows while any chip is dashed.
- **Easy conditions in everyday words:** Summaries carry easy_conditions (same count and order as conditions, same
  banned-word check as the other Easy fields); the Easy panel prefers them and falls back to the conditions. New
  Summaries only; older ones keep the source wording until regenerated (an API cost, asked first).
- **Easy action louder, one guide entry:** the Easy panel's action line is 17px/800 in Ink (the loud Easy voice);
  while the first-visit line shows, the status line's 읽는 법 link hides (the line has 읽는 법 자세히).
- **Frozen search (owner, 11-09):** like frozen panes, the search stays at the top while the Board scrolls: on 768px
  and wider the search line (the bar, 필터 and 정렬) with the hints under it, on phones only the search line, one
  control high (64px) while the bar is closed. Its
  height is `--stick`; `scroll-padding-top`, the new-Incidents pill and focus moves clear it. A hairline and a soft
  shadow appear once the page has scrolled.
- **Jump buttons (owner, 11-09):** 맨 위로 and 맨 아래로 sit at the bottom right (44px circles, Panel on Edge), each shown
  only when there is more than 60% of a screen to go that way.
- **What the Board holds (owner, 11-17: "우리가 공지를 해야할거 같은데"):** the first of the footer's notes since
  critique 11-17, over a Hairline divider, with no close button, and a note of the guide. It says collection began on
  9 November 2026 and that a patch removes no Incident, kept 90 days. Its text is in the markup in every language; once
  the store is 90 days old (2027-02-07) the head script leaves it undrawn. The start date lives once, on
  `<html data-collected-since>`. A search that finds nothing says the same facts.
- **One screen up and down (owner, 11-17: "스크롤 말고 눌러서 이동"; "작은 사각형 2개로 하자, 알약형 말고"):** between them, two
  small squares (32px, the 8px control radius, Panel on Edge with the circles' shadow; on touch a 44px target around the
  same 32px square), centred on the circles' axis with the group's gap, so the two kinds read apart: 한 화면 위로 / 한 화면 아래로
  ("Up one screen" / "Down one screen") move by a press, not a scroll, 87% of the window's height below the frozen
  search row, so the line the reader was on stays in view (`stepDistance`), smooth unless motion is reduced. Top and
  bottom wear an arrow against a bar, the steps a plain chevron; every button names itself on hover and to screen
  readers. A step with nowhere to go dims and is disabled (`aria-disabled`: the focus stays on it); the two are one Tab
  stop (a toolbar, its stop resting on the first member that is not disabled), Up and Down moving between them. The pill
  shows whenever the page scrolls. On a phone the group rests 5 s after a step press instead of 2 s (owner, 11-19:
  "five seconds"), so the next press finds it under the finger; once rested, a small scroll brings it back (a tap
  cannot, as the buttons are hidden). While shown on a phone the column can still cover a row's line end and chevron
  (audit, 11-19, F10, open). Page Up/Down, Space, Home and End stay the browser's.
- **Phone header (critique 10, a.1):** one line with the name, 기본|쉬운 설명 and a settings button; 가−/가+, theme and
  language open under it (Escape or a tap elsewhere closes), and since 11-17 the RSS button (RSS menu). At 375px the first Highlight moved from 490px to 430px.
- **쉬운 설명 beckons (owner, 11-09):** as the Board arrives in 기본, until the visitor has tried that view once
  (`vr-easy-tried`); how it looks is the louder beckon below.
- **공격 발생 (critique 10, b.2):** the reason a row sits at the top is set at 14px/800, no longer the row's smallest text.
- **Two kinds of 묶음 kept apart (owner, 11-09):** a vendor fold is "묶음" and the list button says "회사 묶음 풀기 /
  회사별로 묶기"; a release group (CVEs of one product disclosed together) is one Incident tagged "함께 공개" / "Disclosed
  together", which that button never splits. The tag said "함께 패치" / "One fix" until 11-16, when the owner made it one
  label for every release group ("함께 공개로 통일"): many are grouped by the same last affected version, with nothing
  fixed yet. Since 11-16 (owner: "함께패치와 묶음이 구분이 안감 애초에 색이") each kind also has its own colour on its tag
  (and a fold on its open members' rail): 함께 공개 Patch Teal, 묶음 Fold Violet. The "↑ 새 사건 N건" pill now scrolls to the first new row and focuses it.
- **Hardening 2 (critique 10, 11-09):** an Easy row without a Summary says "쉬운 설명 준비 중" only while one is coming;
  a Summary that failed for good says "원문만 있음", and with no quick title and no Product the source's own line is
  the title instead of a blank "새 보안 문제". 모두 펼치기 carries no pressed state beside its swapped label; 회사 묶음
  풀기 announces what it did; a closed fold has no aria-controls; 주요 사건 더 보기 moves focus to the first Highlight it
  added; the search bar's × clears picks, search and conditions at any time, and with no result the empty state also
  offers 필터 모두 지우기; a reload that restores the older months restores their result line.
- **Clarify (critique 10, 11-09):** "위험" names a level only; the 10-point measure is "CVSS 점수" everywhere (first-visit
  line, guide, filter field "최소 CVSS 점수"). 필터 적용 reads "필터 적용 · N건" and recounts as choices change. When
  filters leave nothing, the empty state offers up to three single conditions back ("‘긴급’ 빼기 · 12건 보기"),
  the ones that bring back the most first, beside 필터 모두 지우기.
- **Layout pass (critique 10, 11-09):** the filter panel on 1024px and wider puts risk, attacks and OS side by side and
  CVSS, CVE and the dates on one line; a checked risk chip wears its sign's wash and ink (11-19). The dark group ground
  is #1c2531 (a clear step from the opened-row panel). The guide shows the "묶음" and "함께 공개" tags as the Board draws
  them.
- **Back undoes a filter; one Incident has an address (owner, 11-09):** every filter change the visitor makes (panel,
  chips, picks, sort, clear buttons) is a step in the browser's history, so Back and Forward walk through them with
  the Board's motion; typing in search rewrites the current step. Each opened Incident ends with "이 사건 링크 복사",
  which copies its Incident page (`/i/<slug>`, `/en/i/<slug>` in the visitor's language) when it has one, else
  `…#i=<id>` (incident-pages 03); opening an `#i=` link shows the Board with that row open, in view, focused and wearing the
  blue arrival edge (a vendor fold is ungrouped, older months load if needed); a link to an Incident no longer on
  the Board says so under the search bar.
- **Version help and CVE list in the Easy panel (owner, 11-09):** the help line no longer sends readers to a "maker's
  site" (plugins and libraries have none) or to an "AI 도우미" (reads as a product name): "내 버전은 보통 그 프로그램의
  설정이나 ‘정보’ 화면에 나와요. 모르겠으면 AI 챗봇에 CVE-… 번호로 물어보세요." A group's "CVE N건" opens to every ID,
  each linked to its CVE record.
- **Clarify 2 (critique 11, 11-09):** the Easy panel gives the Summary's conditions under "이럴 때만 해당돼요" (one on
  the line, several as a list, body weight); since critique P2 (11-19) they follow the action, "what to do" first, and
  the panel opens on the ring and tags; quick Easy titles take the same level
  wording as Summary titles (주의 rows never say 위험); the Easy "CVE N건" fold keeps its new-tab note for screen
  readers only; closing a vendor fold announces "IBM 묶음을 접었습니다."; English Easy rows say "Under attack".
- **Hardening 3 (critique 11, 11-09):** recovery buttons focus the field only when that field changed, else the first
  returned row; in the filter panel a chip that would leave nothing is dashed (in the caution tone since 11-19) with a
  tooltip, and 필터 적용 at 0 drops its primary fill; a link into a closed vendor fold opens that fold only; a blocked clipboard shows the
  address in a selected field under the button instead of a browser prompt.
- **First-visit line at 320px / 150% (critique 11):** on phones a key's words wrap instead of running under the close ×, and the line's CVSS ring grows with the text like the Board's rings.
- **Loading (11-09, user: the reload screen was a bare splash):** until the data arrives the Board stands in its own
  shape, four Highlight frames and six list rows of placeholder bars in the rows' cells, drawn as Astryx's Skeleton
  (owner, 11-19, replacing the scan band): Skeleton bars resting at 45% (Astryx's 25% was fainter on white than the bars
  they replaced) that, after one second (no flash on a fast load), pulse to 92.5% and back over 550ms, each row 100ms
  after the one above, a wave down the Board; the only loop, and only while loading; reduced motion: still bars at 60%.
  When the rows arrive, those on
  screen rise 8px and fade in top to bottom (360ms, 28ms apart, at most twelve) while the rings fill; reduced
  motion: one fade. A reload plays it the same way, at the restored place.
  That loading Board is in `index.html` itself, painted before `app.mjs` runs (owner, 11-17: CLS 0.18 on a phone): the
  frames and rows, the heads' bars on the lines their words will take, 불러오는 중, the step buttons, and the first-visit
  line unless the head script finds it seen; first-screen words are in the markup in both languages, the head script's
  `lang` showing one. The Highlights head keeps the 44px of 모두 펼치기, which comes with the rows. Whatever `app.mjs`
  draws on the first screen before the data must be in the markup the same, or it moves the page when the script runs.
- **The whole list stays light (owner, 11-17: 789 rows, each 더 보기 slower, a theme flip 106 ms):** a list row from the
  eleventh on is skipped by the browser while it is off the screen (`content-visibility: auto`), holding its last
  measured height and until then a closed row's usual one (84px, phones 170px); the first ten never are, so the first
  paint waits for nothing, and a focused row never is, so its ring outside the row is not cut. 더 보기 adds the next
  rows under the drawn ones (Board continuity); the whole list is drawn again only when the Board changed since. Plain scrolling shows
  every row; the long 맨 위로 / 맨 아래로 flight can pass rows not yet drawn (their frames, empty) for a frame or two.
- **Motion for views, folds and arrivals (11-09, owner):** switching 기본 / 쉬운 설명 runs through the Board's View
  Transition: each row on screen fades its old words out (120ms), then the new ones in (180ms, starting at 110ms),
  never both at once (owner, 11-10: overlapping, they read as two titles), and rows whose height changed glide; the
  page itself does not fade. A vendor fold opens like an Incident's details: its members grow out of the fold row
  (300ms) with the first ten dropping 6px in, 24ms apart (240ms each, after 40ms), and close in 240ms before the list
  redraws. A row that arrives by a refresh drops 14px into its place (420ms): through the View Transition at
  the top of the Board, by itself further down. Reduced motion: cross-fades only, folds appear at once.
- **Small motions for the new controls (owner, 11-09):** 맨 위로 / 맨 아래로 rise 8px and grow from 90% (200ms) and sink
  away faster (140ms); the "↑ 새 사건" pill drops in (240ms) and lifts out (160ms); the settings menu fades out (120ms)
  as it faded in; the first-visit line folds away when closed; hints (the older-months result, a link to a gone
  Incident) slide in 4px; the frozen row's shadow eases in; the settings icon turns 90°; the jump buttons and the pill
  dip to 94-96% on a press.
- **쉬운 설명 beckon, louder (owner, 11-09: it sits at the very top, so it must be loud):** twice, 1.4s each, the whole
  기본|쉬운 설명 switch swells to 112% and settles with a bounce, a rainbow ring spins once around it per beat, the
  word 쉬운 설명 runs through a rainbow and swells to 116%, and a rainbow band crosses the button. The rainbow belongs
  to this one moment only (it never marks risk). Reduced motion: the rainbow word and a still rainbow ring.
- **Critique 13 (11-09):**
  - 필터 keeps the place: the panel remembers its opener and the scroll; closed without 필터 적용 both come back.
    Mid-list it opens where the reader is: the phone sheet in place, wider a panel floating under the frozen row over
    the Scrim (modal like the sheet; a tap on the Board closes it).
  - Under 360px 정렬 is its icon; the stuck phone search says "검색" when the longer hints do not fit.
  - Korean search words match their English names only in Product names, ids, devices and OS tags, as whole words; the
    typed word still matches any text. A line under the search bar says it: "‘맥’으로 검색해 macOS도 함께 찾았습니다."
  - Easy update lines name the product: "OpenEMR 8.3.0 이상으로 업데이트하세요." The collector sends back a Summary whose
    Easy action names a version the mitigation lacks, or sends the reader to update while the mitigation says no fix
    exists; on the last try it keeps the Summary without that Easy action, so Easy shows the mitigation.
  - NVD names keep brand casing and small words (webMethods, watsonx, "Cloud Pak for Data"); a name from NVD or the CVE
    record gets a known vendor in front ("IBM Storage Scale") and keeps its Product id's line.
  - Dashed filter chips point to their note (aria-describedby), which sits in the panel's footer (since 11-19). On
    1024px+ the columns are 0.8 : 1 : 1.25 so the OS chips fit one line. Panel notes are 합니다체.
  - Phones: the first-visit line is one line whose keys run sideways inside it, its cut end fading (11-19) so a key
    never stops mid-word with no sign of more; the stale notice joins the status line.
  - 기본 is 44px wide at 320px; the name is 19px there (a 1.25 step over the 15px body).
  - #empty is no live region; its sentence is said through the polite announcer. 이전 사건 불러오기 says the sentence the
    screen shows. "↑ 새 사건 N건" is named "새 사건 N건, 첫 새 사건으로 이동". Folds: "IBM 묶음을 펼쳤습니다 (공지 25건)." /
    "IBM 묶음을 접었습니다."
  - CVE IDs never break at their hyphens in Easy text and version help. "쉬운 설명 준비 중" is plain hint words in the
    line under the title, not a tag. The Lead link says what it is: "공식 공지 읽기 · github.com".
  - Per-CVE 공지/분석 links on touch screens are 44px tall, with no negative margins.
- **Critique 14 (clarify, owner 11-09):**
  - 공격 발생 needs evidence: a KEV listing, or a Summary's `exploited` with the input URL that reports the attacks
    (`exploited_source`). The opened panel says the reason: "CISA KEV 등재 · 2026-11-06" (the day when the collector has
    it) or "공격 보고: <host>" linked, as one of the facts in 기본 (since 11-19) and under Easy's "지금 실제 공격에 쓰이고
    있어요!" in Secondary Ink 14px/600.
  - Public exploit code alone (`poc_public`) gets no sign or tag: one red line (`--high`, 700) in the summary text,
    "공격 코드 공개됨" in 기본 (after the summary), "공격 코드가 공개됐어요!" first in Easy; English "Exploit code is public".
  - A row without a Summary reads the same in both views: its quick title (Easy: the quick Easy title) on the row, and
    in the panel "요약 준비 중", then the source's line under a "원문(영어)" tag ("Source text"), then the links.
  - Easy headlines name the product: a headline with no word of the row's first Product (in either language;
    "WordPress", "plugin" do not count) is shown as "<Product>: <headline>". The collector prompt now says must.
  - Libraries, SDKs, frameworks and packages (the Summary's `library`, else the name) get other version help: "앱에 들어
    있는 부품이라 직접 확인이 어려워요. 쓰는 프로그램을 업데이트하거나, 서버 관리자·호스팅 업체에 물어보세요."
  - The date cell's two spans have a space between them for screen readers; the polite announcer is emptied when the
    language changes.
- **Critique 14 (harden, owner 11-09):**
  - One Product however its name is written (owner chose b.1): the collector and the page key Summary names by
    `productKey` (letter case, brackets, company words, a "WordPress plugin" / "플러그인" / "theme" suffix and a
    vendors.json vendor in front drop out), so "GemBooking" and "GemBooking WordPress plugin" are `name:gembooking`.
    Old ids in a saved link or products.json read back as the new id. A pick also shows Incidents filed under a CPE id
    of the same name ("gemcode:gembooking"; two vendors' "Firmware" never match), and says so under the search bar in the
    pick-note style: "비슷한 이름 N건도 함께 보여 줍니다." / "Also showing N under a similar name." The Summary prompt
    never translates a product name (only names the vendor ships in Korean, such as "Windows 그림판").
  - The count is said again for a new filter or search with the same number (0 → 0); a new sort still says only 정렬.
  - Search aliases: 아파치, 깃허브, 깃랩, 도커, 쿠버네티스, 엔진엑스, 톰캣, 노드, 리액트, 스프링, 시스코, 포티넷, 마이크로소프트, 구글,
    애플. 자바 and java never match inside 자바스크립트 / JavaScript.
  - A vendor fold's member title is led by the fold's vendor when it lacks it ("IBM Langflow OSS 파일 접근 …"); only
    vendors.json spellings lead (apache_software_foundation added as "Apache"), never a guessed name.
  - With no Highlights, 모두 펼치기 moves beside 최신순 at the list head; it never stands alone on the 주요 사건 line.
- **Critique 14 (layout, owner c.1, 11-09):**
  - WordPress plugins and themes (about a quarter of the list: 67 of 265 rows on 11-09 data, 40 + 27 in two day folds)
    fold like a vendor: the same row, ground, "묶음" tag, motion and announcements, five or more on one publish day, list
    only. `foldByVendor` keys them as the pseudo-vendor `wordpress` (board.mjs `isWordPressPlugin`: "WordPress plugin",
    "plugin for WordPress", "워드프레스 … 플러그인" in the brief, the Summary's title, summary or Easy lines, or a Product
    id; WordPress itself never), so an IBM plugin sits in the WordPress fold only. Title "워드프레스 플러그인 40건 묶음" /
    "WordPress plugins: 40, grouped" (as "IBM: 55 security notices, grouped"), badge "WordPress", the line under it names plugins without the repeated "plugin" words;
    closing line "워드프레스 플러그인 묶음 접기". Risky and exploited plugins fold too, as in vendor folds.
  - The list button is now "묶음 풀기 / 묶어 보기" ("Ungroup / Group again"; done: "묶음을 풀었습니다." / "다시 묶었습니다."):
    a WordPress fold is no company.
  - List head on phones: gap 0.75rem keeps 최신순 · 모두 펼치기 · 묶음 풀기 on one line at 320px in Korean (all three
    sorts); a longer English heading wraps 묶음 풀기 under it at the right edge, never on top of 모두 펼치기.
- **Critique 11-17 (distill, 11-19; supersedes the frozen copy of 필터 and 정렬 above):**
  - A product or search filter is a question: the 주요 사건 block is not drawn (the list still edges its Highlights), and
    one sentence over the list answers it, as heavy as a row title: "Gitea: 최근 7일 2건 · 위험 2 · 공격 보고 없음" (`answerLine`,
    counts from `answerCounts`; the period is the one searched, none under a date condition; the risk words of the view).
    More than three picks name two, then "외 N개 제품". A search counts from the moment it is typed or restored (no block
    while it waits for the full week). Not a live region; with no result the empty state answers. The loading Board
    under such a filter (head script `pf-on`) draws no Highlight frames and keeps the answer's line, so nothing moves
    when the rows arrive (a two-line answer on a phone still moves the list by one line).
  - 필터 and 정렬 live at the end of the search line at every width (one control each, no copy, no rise motion); mid-list
    (the Board's head under the frozen row) 필터 opens the floating panel and a new order scrolls back to the head. Up to
    1023px 필터 is its icon; the search hint is measured: the long one, else the short one, else "검색".
  - The collection notice left the top: it is the first of the footer's notes (no close button) and a note of the guide.
  - The first-visit line shows once: drawing it with the Board marks the guide as seen.
- **Astryx pass 2 (owner, 11-19: "the whole thing"):** the polite announcer also says a failed first load, a row whose
  full data failed, and a blocked copy (복사하지 못했습니다 …). Per-CVE links keep their words as their name, with the CVE
  said before them for screen readers (no aria-label). The filter panel's risk and OS notes describe their chip groups;
  필터 초기화 keeps the focus. The inline filter panel does not take the focus yet, so the next Tab reaches 정렬 first
  (audit, 11-19, F8, open). Under reduced motion the "↑ 새 사건" pill only fades (200ms) and a new Highlight's strip
  lets go in 200ms.
- **Never:** pulsing alerts, scroll reveals, or loops outside loading; the Board is read, not watched.

## Do's and Don'ts

### Do:
- **Do** open every source link in a new tab (`target=_blank`, `noopener noreferrer`, a hidden "새 탭에서 열림"
  for screen readers), so the Board, its filters and opened rows stay put.
- **Do** let a long line badge name wrap inside its pill wherever every name is listed (the opened row, the
  suggestions); only a closed row's badge keeps one line and ends in "…", its tooltip giving the whole name (11-19).
- **Do** list several 해당 조건 one per line; never join them with " · " (a condition may hold its own dot, "팩스·SMS").
- **Do** draw the focus ring inside a 주요 사건 row (`outline-offset: -3px`): the band clips anything outside it.
- **Do** use the `:root` tokens (`--tap`, `--ctl-h`, `--ctl-fill`, `--ctl-hover`, `--ctl-on`, `--seg-on`, `--r-marker`,
  `--r-code`, `--r-ctl`, `--r-frame`, `--r-pill`, `--fs-meta`, `--fs-small`, `--skel`, `--warn-wash`, the lifts
  `--lift-low`, `--lift-menu` and `--lift-float`, the curves `--ease-out` and `--ease-exit`), the shared `.btn` for any
  new button (`.primary` only for the one main action in view) and the shared `.menu` / `.mi` for any new dropdown.
  A few colours stay literal on purpose: the CVSS ring's day and night tones and the new-Incidents pill's inverted
  blue (`web/index.html`), and the Support badge's yellow.
- **Do** say "새 탭에서 열림" to screen readers on every link that opens a new tab, the Board's own buttons included
  (GitHub, 틀린 내용 알리기, Buy Me a Coffee).
- **Do** keep every interactive target at least 44 px under a finger. Under a mouse controls are drawn 36 px
  (`--ctl-h`, Astryx, 11-19) and a folded source line 24px; layout heights keep `--tap`.
- **Do** theme browser surfaces from the palette: selection, caret, scrollbar, focus ring, link
  underline offset (3px).
- **Do** keep Normal view calm and let the Easy view carry the louder voice (levels 긴급! / 경계 / 주의, "!" only at 긴급, a plain
  headline, one plain sentence that may end in "!", one action line at 17px/800).
- **Do** check both themes for WCAG 2.2 AA contrast after any colour change.
- **Do** write a device or Product badge with its vendor in front.

### Don't:
- **Don't** add a column header row to the Board.
- **Don't** give a Product line a red, amber or grey hue, or use a line colour for risk.
- **Don't** put shadows on rows, the Highlights band, fields or buttons (a segmented control's raised segment aside).
- **Don't** give any row a coloured side edge; risk is said by the sign, a group by its tag (and an open fold's rail).
- **Don't** set a column of numbers without tabular numerals.
