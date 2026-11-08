# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Anyone. Korean speakers first (English second): individuals, home-lab owners, small admins and
people with no security background alike. The job: when news of a new vulnerability breaks, find
out fast whether it touches something they run and what to do about it. Non-experts read the Easy
view; others read the normal view.

## Product Purpose

A public, free, no-login board of security Incidents, newest first, with up to four Highlights
pinned on top like notices. Each Incident appears within one 15-minute cycle as a Brief from source
data, then gets a Korean and English Summary (what it is, who is affected, preconditions,
Mitigation) and an Easy view (Risk banner, plain sentences, one action). Success: a visitor learns
in seconds whether an Incident applies to them and leaves with the right next step, verified at the
Lead mention.

## Positioning

Korean-first and filtered to the visitor's own Products; English aggregators exist, nothing gives a
Korean reader a fast, filtered answer. Incidents are shown before a CVE exists (the sshole case:
write-up and repo hours before CVE-2026-123158). The Easy view turns an Incident into one concrete
action, and a command is shown only when a source states it verbatim.

## Operating Context

Visitors arrive from news, chat links or a bookmarked filtered address, on desktop and phone. The
filter lives in the browser and the address hash, never on a server. Data refreshes every 15
minutes from official sources (cvelistV5, NVD, CISA KEV, oss-security, HN, curator feeds, GitHub).

## Capabilities and Constraints

- Static page (vanilla HTML/CSS/JS, no build step) on Cloudflare Pages; data as monthly JSON in R2;
  no public server (ADR 0002).
- One row per Incident, not per CVE (ADR 0001). Vocabulary in `CONTEXT.md`.
- Board is a bulletin-board list (risk, CVE, title, target tags, date); rows expand in place; one
  Normal|Easy switch at the top; language toggle.
- Risk banner set by rules: exploited (a CISA KEV listing, or a Summary whose sources report attacks; user, 2026-11-08)
  or CVSS 9.0+ is the top level, 7.0+ the next, else notice. The model only reports what sources say, never the level.
- Easy view to-do per Incident: does the visitor use it (써요 / 안 써요 / 몰라요), then the action and their own
  tick. Answers stay in the visitor's browser (shared between open tabs, never sent); answered rows step back.
  "조치함" is the visitor's word, never a check the Board ran.
- Judgments are the AI's first (Summary text, Incident or not, reported attacks); corrections come from readers through
  public GitHub issues, not a hand-kept override list (user, 2026-11-08).
- Required notices: the NVD sentence verbatim in English; reference-only note.
- No login, no analytics, no cookies, no third-party trackers.
- Light and dark themes: follows the system setting with a remembered toggle; both meet WCAG 2.2 AA
  (user asked for dark mode, 2026-11-08).
- Undecided: public name and domain (chosen before launch).

## Brand Commitments

- Name: vuln-radar is a working name only.
- Voice: the normal view is calm, precise, polite Korean (존댓말). The Easy view is loud and lively
  ("심각!" for the top level only, then 경계 and 주의; "어서 업데이트하세요!") but stays polite, and never overstates beyond the sources.

## Evidence on Hand

Real Incident data from local test cycles (`web/data/`, git-ignored). No users, testimonials,
traffic figures or press yet; do not invent any.

## Product Principles

1. Speed over polish of wording: a Brief now beats a perfect Summary later.
2. Never hide by mistake: when unsure whether an Incident applies, show it.
3. Every claim points to its source; the Lead mention is the authority.
4. Commands only when a source states them verbatim.
5. Nothing about the visitor leaves the browser.

## Accessibility & Inclusion

WCAG 2.2 AA: contrast, full keyboard use (rows are buttons with aria-expanded), screen-reader labels,
no horizontal scroll at 375 px, 44 px touch targets.
