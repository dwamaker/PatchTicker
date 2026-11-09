"""Source adapter: CVEs exploited in the wild, from the CISA KEV catalog (CC0; no CISA logo)."""

import json

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(http_get):
    """Return the catalog's CVE IDs, each with the day CISA added it ("2026-11-06", "" if absent). One request per cycle.

    shortcut: reads the whole catalog (~1.8 MB) every cycle so Incidents that arrive after their
    KEV listing are flagged too; send If-Modified-Since if the bandwidth starts to matter.
    """
    return {v["cveID"].upper(): v.get("dateAdded") or "" for v in json.loads(http_get(FEED_URL))["vulnerabilities"]}
