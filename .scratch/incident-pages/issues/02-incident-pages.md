# 02: Incident pages in Korean and English

**What to build:** Every Incident with a Summary that is on the Board has an Incident page at `/i/<slug>` (Korean) and
`/en/i/<slug>` (English): a single document without script showing the title, risk banner, CVSS and exploited
reason, plain explanation, conditions, what to do, Products and platforms, CVE IDs, Mentions (the KISA notice among
them), published and first-seen times, links to the Board (`/#i=<id>`), the other language and "Report a mistake",
and the NVD and MITRE notices. Search-worthy pages are indexable; all others carry `noindex`. Each page is canonical
to itself with `hreflang` to the other language (Korean as `x-default`), and its link preview names the Incident.
Pages older than 90 days from first seen answer 410 with a short note and links to the Board and the CVE record.
Slugs never change: a CVE ID as is, `hn-<item number>` for an HN story, `u-` plus a short hash for any other URL ID.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Each cycle writes an Incident page document per slug (the page-facing fields), only when it changed.
- [ ] Both language pages render with canonical, hreflang, og:title/description/image/locale, and `noindex` only when not search-worthy.
- [ ] The page reuses the Board's rule module (risk level, exploited reason, easy action, Product names); no second copy of those rules.
- [ ] Every text is escaped and non-http(s) links are dropped (hostile title and `javascript:` link in tests).
- [ ] 410 for a page older than 90 days, 404 for an unknown slug, 503 on an R2 read error.
- [ ] Light and dark by system setting; no sideways scroll at 375 px; one heading and labelled sections for screen readers.
- [ ] Tests at both seams; after deploy, a real page checked in the owner's Chrome (light, dark, 375 px) and a link preview in a messenger.
