# 05: Incident sitemap for search engines

**What to build:** Search engines find every search-worthy Incident page of the last 90 days through the sitemap,
without crawling the Board. `/sitemap.xml` becomes a sitemap index listing the home page's sitemap and the Incident
sitemap that the function renders from the collector's sitemap document, with each page's last change time and both
language versions linked by `hreflang`. `robots.txt` keeps pointing at `/sitemap.xml`.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Each cycle writes one sitemap document: every search-worthy slug of the last 90 days with its last change time.
- [ ] The function renders a valid sitemap with both language URLs and hreflang alternates; non-search-worthy pages never appear.
- [ ] The static sitemap becomes a sitemap index; the home page keeps its own entry.
- [ ] The URL count on real data is checked against the 50,000 limit and noted in Comments.
- [ ] After deploy: resubmitted in Google Search Console and Naver Search Advisor, and accepted.
