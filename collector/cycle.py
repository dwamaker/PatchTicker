"""One collection cycle: read the store, fetch new CVEs, write changed monthly files and status."""

from collector import cvelist


def run_cycle(store, http_get, now, collector_id):
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

    for m in changed:
        store.write(f"months/{m}.json", months[m])
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(months)})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", {"updated": stamp, "collector": collector_id})
