"""Source adapter: new CVE records from the cvelistV5 delta log."""

import json

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"


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


def one_line_description(record):
    for d in record["containers"]["cna"].get("descriptions", []):
        if d["lang"].startswith("en"):
            return " ".join(d["value"].split())
    return record["containers"]["cna"].get("title") or ""
