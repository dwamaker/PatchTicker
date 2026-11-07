"""Source adapter: new CVE records from the cvelistV5 delta log."""

import json

from collector.incidents import is_http

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
# CVE JSON 5 reference tags that mark the product's own advisory or release note.
ADVISORY_TAGS = {"vendor-advisory", "release-notes"}


def fetch(checkpoint, http_get):
    """Return (new published CVE records, next checkpoint). The checkpoint is a delta fetchTime."""
    log = json.loads(http_get(DELTA_LOG_URL))  # newest entry first
    if not log:
        return [], checkpoint
    # shortcut: with no checkpoint, start from the newest entry instead of backfilling 30 days.
    entries = [e for e in log if e["fetchTime"] > checkpoint] if checkpoint else log[:1]
    links = {}
    for entry in entries:
        for item in entry["new"]:
            links.setdefault(item["cveId"], item["githubLink"])
    records = [json.loads(http_get(url)) for url in links.values()]
    return [r for r in records if r["cveMetadata"]["state"] == "PUBLISHED"], log[0]["fetchTime"]


def mention_group(record):
    """The CVE record as a Mention; references it tags as an advisory or release note join it."""
    cve = record["cveMetadata"]["cveId"]
    refs = [r for r in record["containers"]["cna"].get("references", []) if is_http(r.get("url"))]
    advisories = [r["url"] for r in refs if ADVISORY_TAGS & set(r.get("tags", []))]
    return {
        "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}]
        + [{"kind": "advisory", "url": u} for u in dict.fromkeys(advisories)],
        "cves": [cve],
        "urls": [r["url"] for r in refs],
        "text": one_line_description(record),
    }


def one_line_description(record):
    for d in record["containers"]["cna"].get("descriptions", []):
        if d["lang"].startswith("en"):
            return " ".join(d["value"].split())
    return record["containers"]["cna"].get("title") or ""
