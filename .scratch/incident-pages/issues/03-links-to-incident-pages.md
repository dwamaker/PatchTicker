# 03: Shared links and feed items point to Incident pages

**What to build:** "Copy this Incident's link" on the Board copies the Incident page address in the visitor's
language when the Incident has one (a Summary, on the Board, within 90 days), and the `#i=` link otherwise. RSS items
link to the Incident page instead of the Board, with the same GUID rule as before so readers do not see items twice.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] The copy button gives `/i/<slug>` or `/en/i/<slug>` for an Incident with a page, `#i=` for one without.
- [ ] Feed items link to the Incident page; GUIDs unchanged from ticket 01 (or changed once, with the reason in Comments).
- [ ] Board unit tests cover both copy cases; the function test covers the new item links.
- [ ] Checked in the owner's Chrome after deploy (force-reload modules; save and restore every `vr-*` localStorage key).
