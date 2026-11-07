"""One collection cycle: read the store, fetch new CVEs, write changed monthly files and status."""

import json
import sys
import time

from collector import cvelist, nvd


def run_cycle(store, http_get, now, collector_id, sleep=time.sleep, nvd_api_key=""):
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    checkpoints = store.read("checkpoints.json") or {}
    index = store.read("index.json") or {"months": []}
    # shortcut: loads every month to find known CVEs; fine for v1 volumes, revisit past a year.
    months = {m: store.read(f"months/{m}.json") for m in index["months"]}
    known = {cve for doc in months.values() for i in doc["incidents"] for cve in i["cves"]}

    records, checkpoints["cvelist"] = cvelist.fetch(checkpoints.get("cvelist"), http_get)

    changed = set()
    month = now.strftime("%Y-%m")
    for record in records:
        cve = record["cveMetadata"]["cveId"]
        if cve in known:
            continue
        known.add(cve)
        url = f"https://www.cve.org/CVERecord?id={cve}"
        months.setdefault(month, {"month": month, "incidents": []})["incidents"].append({
            "id": cve,
            "cves": [cve],
            "first_seen": stamp,
            "mentions": [{"kind": "cve_record", "url": url}],
            "brief": {"text": cvelist.one_line_description(record), "lead": url},
        })
        changed.add(month)

    try:
        enriched, checkpoints["nvd"] = nvd.fetch(checkpoints.get("nvd"), now, http_get, sleep, nvd_api_key)
    except (OSError, ValueError, KeyError) as err:
        # NVD is often down; Briefs still go out and the next cycle retries the same range.
        print(f"nvd: skipped this cycle: {err!r}", file=sys.stderr)
        enriched = {}
    for m, doc in months.items():
        before = json.dumps(doc)
        for incident in doc["incidents"]:
            for cve in incident["cves"]:
                if cve in enriched:
                    enrich(incident, enriched[cve])
        if json.dumps(doc) != before:
            changed.add(m)

    for m in changed:
        store.write(f"months/{m}.json", months[m])
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(months)})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", {"updated": stamp, "collector": collector_id})


def enrich(incident, data):
    """Fold one CVE's NVD data into its Incident; an Incident with several CVEs keeps the union."""
    if data["cvss"] is not None:
        # shortcut: keeps the highest score, so a downward NVD revision is not applied; store per-CVE scores if that matters.
        incident["cvss"] = max(incident.get("cvss", 0), data["cvss"])
    merged = {p["id"]: p for p in incident.get("products", []) + data["products"]}
    if merged:
        incident["products"] = sorted(merged.values(), key=lambda p: p["id"])
