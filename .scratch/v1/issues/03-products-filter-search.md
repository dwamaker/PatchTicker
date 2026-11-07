# 03: Product filter and search

**What to build:** CVE Incidents are enriched from the NVD API (CVSS, CPE) by last-modified range, with an API key and pauses between calls. Products are derived from CPE (vendor and product, version dropped) with a display name. The page gets a Product picker (type to find, only Products seen in the last 90 days) and a live search box; picks and query are stored in localStorage and in the page address, and never sent anywhere.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A cycle against recorded NVD responses adds CVSS and Products to the matching Incidents (seam 1).
- [ ] The NVD adapter never exceeds the documented rate limit in a cycle (asserted with the fake clock).
- [ ] The filter function hides Incidents with no matching Product when Products are picked, and shows all when none are (seam 2).
- [ ] Search matches title text, CVE ID, Product and version text, case-insensitively (seam 2).
- [ ] Reloading the page or opening a copied address restores the same filter.
- [ ] The NVD notice text is shown on the page.
