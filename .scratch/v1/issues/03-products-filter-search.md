# 03: Product filter and search

**What to build:** CVE Incidents are enriched from the NVD API (CVSS, CPE) by last-modified range, with an API key and pauses between calls. Products are derived from CPE (vendor and product, version dropped) with a display name. The page gets a Product picker (type to find, only Products seen in the last 90 days) and a live search box; picks and query are stored in localStorage and in the page address, and never sent anywhere.

**Blocked by:** 01

**Status:** resolved (98db998, ac60069)

- [ ] A cycle against recorded NVD responses adds CVSS and Products to the matching Incidents (seam 1).
- [ ] The NVD adapter never exceeds the documented rate limit in a cycle (asserted with the fake clock).
- [ ] The filter function hides Incidents with no matching Product when Products are picked, and shows all when none are (seam 2).
- [ ] Search matches title text, CVE ID, Product and version text, case-insensitively (seam 2).
- [ ] Reloading the page or opening a copied address restores the same filter.
- [ ] The NVD notice text is shown on the page.

## Comments

- 2026-11-07: done in 98db998 and ac60069 on `ticket-03-products-filter`. Found: every record in a live 2-hour NVD window was `Deferred` with no NVD `configurations`, so Products also come from the CNA `affected` CPEs (only some CNAs, e.g. VulDB, Red Hat, give CPEs; Patchstack/Wordfence give names only, so their Incidents get no Product until the Summary adds one). Filter lives in the address hash, not the query string, so a shared link never sends it to a server. Open: display names are title-cased CPE names ("Openssh"); downward CVSS revisions are not applied (highest score kept); first NVD run reads only the last day.
