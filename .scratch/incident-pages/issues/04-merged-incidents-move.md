# 04: Merged Incidents move to the survivor's page

**What to build:** When an Incident is absorbed into another (a merge by CVE, a release group, a rejoined story), the
absorbed Incident's page address answers 301 to the survivor's page in the same language, so a shared link keeps
working. A move older than 90 days answers 410 like any expired page.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] The survivor records the IDs it absorbed (including IDs its absorbed Incidents had absorbed).
- [ ] Each cycle writes a "moved to" document for each newly absorbed slug.
- [ ] The function answers 301 to the survivor in the same language; 410 when the move or the survivor is past 90 days.
- [ ] Tests: a cycle that merges two Incidents leaves the moved document (cycle seam); the 301 and 410 answers (function seam).
