# 03: Shared links and feed items point to Incident pages

**What to build:** "Copy this Incident's link" on the Board copies the Incident page address in the visitor's
language when the Incident has one (a Summary, on the Board, within 90 days), and the `#i=` link otherwise. RSS items
link to the Incident page instead of the Board, with the same GUID rule as before so readers do not see items twice.

**Blocked by:** 02

**Status:** done (deploy pending)

- [x] The copy button gives `/i/<slug>` or `/en/i/<slug>` for an Incident with a page, `#i=` for one without.
- [x] Feed items link to the Incident page; GUIDs unchanged from ticket 01 (or changed once, with the reason in Comments).
- [x] Board unit tests cover both copy cases; the function test covers the new item links.
- [ ] Checked in the owner's Chrome after deploy (force-reload modules; save and restore every `vr-*` localStorage key).

## Comments

**2026-11-10 (built, not deployed):** the slug rule moved from `edge/feed.mjs` to `web/board.mjs` (`slug`), because the
browser loads only `web/`; the function (feed and page) imports it from there, so there is still one JavaScript copy
plus the Python port (`page_slug`, same fixture). `PAGE_DAYS` moved there too and `edge/page.mjs` imports it.
`shareLink(i, pageSlug, lang, board, now)` decides the copied address with the page's own test (a Summary, `onBoard`,
first seen within 90 days); the button works out the slug when the row opens, so the click writes to the clipboard
without an await (Safari drops the click's permission across one); until it is ready, or without `crypto.subtle`
(a non-secure origin), the button copies the `#i=` link. Feed items link to the page; the GUIDs are unchanged (they
were already the page address), so readers see no duplicates. The "Report a mistake" form still names the `#i=` link
(out of scope). Left: deploy and the owner's Chrome check.
