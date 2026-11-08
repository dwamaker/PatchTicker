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
  caution-amber: "light-dark(#8f5c00, #f5b400)"
  notice-slate: "light-dark(#5f6b76, #9aa3ad)"
  wayfinding-blue: "light-dark(#1a5fb4, #7cc4ff)"
  line-01: "#0052a4"
  line-02: "#00a84d"
  line-03: "#00a5de"
  line-04: "#7f4f9a"
  line-05: "#93a10c"
  line-06: "#77c4a3"
  line-07: "#0c8e72"
  line-08: "#b0ce18"
  line-09: "#6789ca"
  line-10: "#2e3a8c"
  line-11: "#4a7c2a"
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

The Board is read the way a commuter reads a Seoul subway sign: no column labels, no legend, just a
coloured line, a bold station name and the line under it that says where it goes. Every Product rides
its own fixed line colour, every CVE ID is set like a station name with the Incident's title under it,
the CVSS score is a ring filled to its value, and the reader understands a row in one glance. Risk sits apart from the lines as a filled dot at the row start, so "which line"
and "how dangerous" never share a colour.

Density is that of a departure board: rows of 72 px minimum, one hairline between them, generous
column gaps, nothing decorative. The ground is graphite at night and pale concourse paper by day; the
visitor's system setting picks one and a remembered toggle overrides it. The only thing that lifts off
the ground is the "주목" group, stacked like emergency alerts in thin framed rows with a risk-coloured
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
- **Caution Amber** (`caution-amber`): the 위험 risk dot and word and the left edge of a 위험
  Highlight frame.
- **Notice Slate** (`notice-slate`): the 참고 risk dot and word, the default Highlight edge, and the
  CVSS ring below 7.0.
- The CVSS ring uses the same three: Emergency Red at 9.0+, Caution Amber at 7.0+, Notice Slate below.
  (A separate orange for 7.0+ was dropped on 11-08: in light theme it read as the amber dot, 1.03:1.)

### Secondary
- **Line palette** (`line-01` to `line-11`): Product line badges, after the Seoul subway map. Light
  hues carry `line-ink-dark` text, deep hues carry `line-ink-light`. The source is `LINES` in
  `web/board.mjs`, which assigns each Product a colour by an FNV-1a hash of its name.

### Tertiary
- **Wayfinding Blue** (`wayfinding-blue`): links, the focus ring, the caret, and the text selection
  wash (32% mix). Never a fill.

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
**The Two Alphabets Rule.** Risk and severity speak only in red, amber and slate, and the same severity
is always the same colour; Product lines never use a red, orange, amber or grey hue, and a line colour
never signals risk. Adding a line colour means checking it against all three first.

**The Fixed Line Rule.** A Product's line colour is a function of its name, the same on every row and
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
- **Label** (700, 0.875rem): group headings ("주목 N", "최신순"), field labels, button text (500).
- **Description** (400, 0.875rem, 1.45, -0.01em): the Incident title under the CVE ID, Secondary
  Ink, at most two lines.
- **Meta** (400, 0.8125rem, tabular numerals): the published date and time, status line, CVSS number (700) and
  rating word, risk word (700), footer.
- **Badge** (600, 0.78125rem, 1.2): Product line badge text.

### Named Rules
**The Station Name Rule.** In the normal view the CVE ID is the bold name and the Incident title in
the page language sits under it in Description size, cut after two lines. With more CVEs the name adds
"외 N건". The Easy view leads with the Summary's plain headline over its one plain sentence (the opened panel starts with the CVE IDs) (Sign Ink,
500, never cut); without a Summary, and for an Incident with no CVE yet, the title leads and the CVE
line goes under it.

**The Tabular Rule.** CVE IDs, counts, dates and times use tabular numerals so columns of
numbers do not shimmer.

## Layout

A single centred column, 75rem wide, with a 1rem gutter (1.5rem from 768 px). The top bar is a
three-part grid: name left, the 기본|쉬운 설명 switch centred, theme and language buttons right;
under 600 px the switch drops to its own full-width line. The product picker and search sit on one
line (picker up to 24rem), stacking under 768 px.

A row is a six-column grid: risk (6.5rem), name and title (fluid), CVSS ring and words (7.5rem), line
badges (up to 15rem), published date over time (5.5rem), chevron. Column gap is 1.25rem. Opened details align with the
name column. Under 768 px the row restacks into risk and date with time on one line on top, then name and title, then the
CVSS ring, then badges, and the details drop their indent. Nothing scrolls sideways at 375 px.

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
**The One Lift Rule.** Only the "주목" frames cast a shadow. Plain rows, fields, buttons and opened
details stay flat.

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
- **Place:** a 필터 button (funnel icon, count badge in Wayfinding Blue) at the right end of the 주목 line.
- **Panel:** opens under that line in Kiosk Panel with a Rail border: 게시일 시작/끝, 최소 CVSS, CVE, then chip rows
  for 위험 단계, 조건 (악용 중만, 공식 공지, 공개 익스플로잇·PoC) and OS, then 정렬. Nothing changes until 필터 적용;
  필터 초기화 clears the panel only (Products picked at the top and the search stay). Everything lives in the hash.

### Text size
- Two buttons, 가− and 가+, in one outlined control left of the theme button (the user's pick), glyphs 12 and 18 px
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
  only the word "CVSS" sits beside it (the risk word is the one severity word); an exploited row shows "실제
  악용 중" in red under its risk word instead.
- **Colour:** by CVSS rating: Emergency Red 9.0+, Caution Amber 7.0+, Notice Slate
  below. Unrated shows no ring, only "점수 아직 없음" in Hint Ink. Shown in both views.

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

### Highlight frame (signature)
- **Style:** Kiosk Panel, 1px Rail border, 10px radius, 3px left edge in the risk colour, the Alert
  lift shadow. A 고위험 frame adds a faint red wash fading out by 40% of its width. Details open inside
  the frame.

### Command line
- **Style:** the command in the code face on Recessed Panel with a 1px Rail border and 6px radius,
  followed by an outlined copy button. Only commands a source states verbatim appear here.

## Do's and Don'ts

### Do:
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
