"""Source adapter: new CVE records from the cvelistV5 delta log, and updates to CVEs already on the Board."""

import re
import json

from collector.hn import is_repo
from collector.incidents import is_http, to_stamp

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
# CVE JSON 5 reference tags that mark the product's own advisory or release note.
ADVISORY_TAGS = {"vendor-advisory", "release-notes"}
# Tags that mark someone else's analysis or a working exploit: listed as write-ups (a repo when on GitHub).
WRITEUP_TAGS = {"third-party-advisory", "technical-description", "exploit"}


def fetch(checkpoint, http_get, known=frozenset()):
    """Return (new published CVE records, next checkpoint). The checkpoint is a delta fetchTime.

    An updated record is read only when its CVE is in `known` (already on the Board), so a CNA adding
    an advisory or exploit link reaches the row without pulling the hundreds of old CVEs touched daily."""
    log = json.loads(http_get(DELTA_LOG_URL))  # newest entry first
    if not log:
        return [], checkpoint
    # shortcut: with no checkpoint, start from the newest entry instead of backfilling 30 days.
    entries = [e for e in log if e["fetchTime"] > checkpoint] if checkpoint else log[:1]
    links = {}
    for entry in entries:
        for item in entry["new"] + [u for u in entry.get("updated", []) if u["cveId"] in known]:
            links.setdefault(item["cveId"], item["githubLink"])
    records = [json.loads(http_get(url)) for url in links.values()]
    return [r for r in records if r["cveMetadata"]["state"] == "PUBLISHED"], log[0]["fetchTime"]


def mention_group(record):
    """The CVE record as a Mention; references it tags as an advisory, release note, analysis or
    exploit join it (untagged references only key the Incident)."""
    cve = record["cveMetadata"]["cveId"]
    # ADP containers (CISA's, mostly) add references too: sshole's sshhole.com exploit tag lives only there.
    containers = [record["containers"]["cna"], *record["containers"].get("adp", [])]
    refs = [r for c in containers for r in c.get("references", []) if is_http(r.get("url"))]
    advisories = [r["url"] for r in refs if ADVISORY_TAGS & set(r.get("tags", []))]
    writeups = [r["url"] for r in refs if WRITEUP_TAGS & set(r.get("tags", [])) and r["url"] not in advisories]
    return {
        "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}]
        + [{"kind": "advisory", "url": u} for u in dict.fromkeys(advisories)]
        + [{"kind": "repo" if is_repo(u) else "writeup", "url": u} for u in dict.fromkeys(writeups)],
        "cves": [cve],
        "urls": [r["url"] for r in refs],
        "text": one_line_description(record),
        "published": to_stamp(record["cveMetadata"].get("datePublished")),
        "cvss": record_cvss(containers),
        "products": record_products(record),
        "fix_keys": record_fix_keys(record),
    }


# CVSS versions in the order the Board reads them: its bands (9.0 / 7.0 / 4.0) are v3's; v4 uses the same.
CVSS_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")


def record_fix_keys(record):
    """Product and first fixed version pairs ("openemr:openemr<8.3.0") from the CNA's affected ranges, so CVEs one
    release fixed together can be grouped into one Incident (incidents.group_releases)."""
    keys = set()
    for a in record["containers"]["cna"].get("affected", []):
        vendor, product = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
        if not vendor or not product or vendor.lower() in ("n/a", "unknown") or product.lower() in ("n/a", "unknown"):
            continue
        key = f"{vendor}:{product}".lower().replace(" ", "_")
        keys |= {f"{key}<{v['lessThan']}" for v in a.get("versions", []) if v.get("status") == "affected" and v.get("lessThan")}
        # No range given (VulDB lists every affected version): the last affected one stands for the fix that follows it.
        # "0 up to 1.2.11" (lessThanOrEqual, Wordfence and IBM records) counts as 1.2.11.
        listed = [v.get("lessThanOrEqual") or v["version"] for v in a.get("versions", [])
                  if v.get("status") == "affected" and v.get("version") and not v.get("lessThan")]
        if listed and not any(k.startswith(f"{key}<") for k in keys):
            top = max(listed, key=lambda v: [int(p) if p.isdigit() else -1 for p in re.split(r"[.\-]", v)])
            keys.add(f"{key}<={top}")
    return sorted(keys)


def record_products(record):
    """The CNA's affected vendor/product pairs as Products, keyed like NVD's CPE ids ("sonicwall:sonicos")
    so the two sources merge; the name is the product as the CNA writes it ("SonicOS")."""
    found = {}
    for a in record["containers"]["cna"].get("affected", []):
        vendor, product = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
        if vendor and product and vendor.lower() not in ("n/a", "unknown") and product.lower() not in ("n/a", "unknown"):
            key = f"{vendor}:{product}".lower().replace(" ", "_")
            found[key] = {"id": key, "name": product}
    return sorted(found.values(), key=lambda p: p["id"])


def record_cvss(containers):
    """The record's own base score (the CNA's, else an ADP's such as CISA's), or None. NVD often defers its
    analysis, so this is the only score most new CVEs have; enrich() keeps the higher when NVD adds one."""
    for key in CVSS_KEYS:
        for c in containers:
            for metric in c.get("metrics", []):
                score = metric.get(key, {}).get("baseScore")
                if isinstance(score, (int, float)):
                    return score
    return None


def one_line_description(record):
    for d in record["containers"]["cna"].get("descriptions", []):
        if d["lang"].startswith("en"):
            return " ".join(d["value"].split())
    return record["containers"]["cna"].get("title") or ""
