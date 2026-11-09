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
pinned on top like notices. Each Incident appears within one 10-minute cycle as a Brief from source
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
filter lives in the browser and the address hash, never on a server. Data refreshes every 10
minutes from official sources (cvelistV5, NVD, CISA KEV, oss-security, HN, curator feeds, GitHub, security news sites, KISA 보호나라).

## Capabilities and Constraints

- Static page (vanilla HTML/CSS/JS, no build step) on Cloudflare Pages; data as monthly JSON in R2;
  no public server (ADR 0002).
- One row per Incident, not per CVE (ADR 0001). Vocabulary in `CONTEXT.md`.
- Board is a bulletin-board list (risk, CVE, title, target tags, date); rows expand in place; one
  Normal|Easy switch at the top; language toggle.
- Risk banner set by rules: exploited (a CISA KEV listing, or a Summary whose sources report attacks; user, 2026-11-08)
  or CVSS 9.0+ is the top level, 7.0+ the next, else notice. The model only reports what sources say, never the level.
  Evidence required (owner, 2026-11-09): a Summary counts as exploited only with the input source that states attacks in
  the wild (`exploited_source`, checked in code), and the panel shows that reason (KEV and its date, or the reporting
  source). Public exploit or PoC code alone is not exploited: it shows as "공격 코드 공개됨" in red text, with no sign.
- The Easy view shows the action only: no question to answer and no tick to keep (the to-do list was removed,
  user, 2026-11-08, after critique 6). The Board stores nothing about which Incidents a visitor uses or handled.
- Judgments are the AI's first (Summary text, Incident or not, reported attacks); corrections come from readers through
  public GitHub issues, not a hand-kept override list (user, 2026-11-08).
- Required notices: the NVD sentence verbatim in English; reference-only note.
- No login, no cookies, no ad or cross-site trackers. The one analytics is Cloudflare Web Analytics, cookieless and
  aggregate, injected by Cloudflare for the Pages site (owner kept it, 2026-11-10; Google Analytics declined).
- Light and dark themes: follows the system setting with a remembered toggle; both meet WCAG 2.2 AA
  (user asked for dark mode, 2026-11-08).
- Public name: Patch Ticker, one English name in both languages (owner, late 2026-11-09; it replaced 패치레이더 / PatchRadar, because patchradar.com is a game patch-notes site and "SyncNet Patch Radar" is a security-alert WordPress plugin). Live at `patchticker.com` (the owner bought it on 11-09, on Cloudflare), data at `data.patchticker.com`; `www.patchticker.com` and the first address `patchticker.dwamaker.com` redirect there.

## Brand Commitments

- Name: Patch Ticker in public (owner, 2026-11-09); vuln-radar stays the repository and code name. The R2 bucket and Pages project keep the internal name patchradar.
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
