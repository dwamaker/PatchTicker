"""Source adapter: new CVE records from the cvelistV5 delta log, and updates to CVEs already on the Board."""

import html
import re
import json
import sys

from collector.hn import is_repo
from collector.incidents import VENDORS, is_http, to_stamp

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
# CVE JSON 5 reference tags that mark the product's own advisory or release note.
ADVISORY_TAGS = {"vendor-advisory", "release-notes"}
# Tags that mark someone else's analysis or a working exploit: listed as write-ups (a repo when on GitHub).
WRITEUP_TAGS = {"third-party-advisory", "technical-description", "exploit"}


MAX_RECORDS = 250


def fetch(checkpoint, http_get, known=frozenset(), limit=MAX_RECORDS):
    """Return (new published CVE records, next checkpoint). The checkpoint is a delta fetchTime.

    An updated record is read only when its CVE is in `known` (already on the Board), so a CNA adding
    an advisory or exploit link reaches the row without pulling the hundreds of old CVEs touched daily.
    A long gap (a backfill, a box that was down) is read oldest first, whole entries at a time, until `limit`
    records; the checkpoint stops after the last entry read, so the next cycle goes on from there (owner, 11-09: a
    7-day backfill in one cycle would have run for hours)."""
    log = json.loads(http_get(DELTA_LOG_URL))  # newest entry first
    if not log:
        return [], checkpoint
    # shortcut: with no checkpoint, start from the newest entry instead of backfilling 30 days.
    entries = [e for e in log if e["fetchTime"] > checkpoint] if checkpoint else log[:1]
    links = {}
    reached = log[0]["fetchTime"]
    for entry in reversed(entries):
        for item in entry["new"] + [u for u in entry.get("updated", []) if u["cveId"] in known]:
            links.setdefault(item["cveId"], item["githubLink"])
        if len(links) >= limit and entry is not entries[0]:
            reached = entry["fetchTime"]
            break
    records = [json.loads(http_get(url)) for url in links.values()]
    return [r for r in records if r["cveMetadata"]["state"] == "PUBLISHED"], reached


RECORD_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group}xxx/{cve}.json"


def record_url(cve):
    _, year, number = cve.split("-")
    return RECORD_URL.format(year=year, group=number[:-3], cve=cve)


MISSING_PER_CYCLE = 20
# Real CVE numbers have 4 to 7 digits; a longer token from a post must never reach int() (over 4300 digits it raises).
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.ASCII)


def fetch_missing(cves, http_get, limit=MISSING_PER_CYCLE):
    """Records of CVEs the Board cites but never read: a Mention named the CVE before the record reached the delta
    log this store started from, or an older CVE came up in discussion (11-09: nine Apache Airflow rows had no
    Product). At most `limit` a cycle, newest IDs first; one not published yet (404) is asked again next cycle."""
    records = []
    for cve in sorted(filter(CVE_ID.fullmatch, cves), key=lambda c: [int(p) for p in c.split("-")[1:]], reverse=True)[:limit]:
        try:
            record = json.loads(http_get(record_url(cve)))
        except (OSError, ValueError):
            continue
        if record.get("cveMetadata", {}).get("state") == "PUBLISHED":
            records.append(record)
    return records


def mention_groups(records):
    """One Mention group per record; a malformed record is skipped and logged, never the rest of the cycle's records."""
    groups = []
    for record in records:
        try:
            groups.append(mention_group(record))
        except (AttributeError, KeyError, TypeError, ValueError) as err:
            meta = record.get("cveMetadata") if isinstance(record, dict) else None
            cve = meta.get("cveId") if isinstance(meta, dict) else "?"
            print(f"cvelist: skipped record {cve}: {err!r}"[:300], file=sys.stderr)
    return groups


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


def cna_products(record):
    """(key, product, affected entry) for each of the CNA's named vendor/product pairs. The product's HTML entities
    are unescaped ("Contact Form 7 &#8211; Post Fields" showed as written, 11-11); the key stays the raw one's."""
    assigner = (record.get("cveMetadata", {}).get("assignerShortName") or "").lower()
    for a in record["containers"]["cna"].get("affected", []):
        vendor, product = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
        # A CNA writing "n/a" for its own product is the vendor: a known vendor ("intel", "AI Playground software") or
        # one that leads the name ("Acme(R) Widget"), 11-11. A third party's "n/a" (WPScan, a WordPress plugin) is skipped.
        if vendor.lower() in ("", "n/a", "unknown") and assigner and product and (
                assigner in VENDORS or re.sub(r"(\(r\)|®|™)$", "", product.split()[0].lower()) == assigner):
            vendor = assigner
        if not vendor or not product or vendor.lower() in ("n/a", "unknown") or product.lower() in ("n/a", "unknown"):
            continue
        yield f"{vendor}:{product}".lower().replace(" ", "_"), html.unescape(product), a


def record_fix_keys(record):
    """Product and first fixed version pairs ("openemr:openemr<8.3.0") from the CNA's affected ranges, so CVEs one
    release fixed together can be grouped into one Incident (incidents.group_releases)."""
    keys = set()
    for key, _, a in cna_products(record):
        keys |= {f"{key}<{v['lessThan']}" for v in a.get("versions", []) if v.get("status") == "affected" and v.get("lessThan")}
        # No range given (VulDB lists every affected version): the last affected one stands for the fix that follows it.
        # "0 up to 1.2.11" (lessThanOrEqual, Wordfence and IBM records) counts as 1.2.11.
        listed = [v.get("lessThanOrEqual") or v["version"] for v in a.get("versions", [])
                  if v.get("status") == "affected" and v.get("version") and not v.get("lessThan")]
        if listed and not any(k.startswith(f"{key}<") for k in keys):
            # ASCII digits only and short: isdigit() passes "²", which int() rejects, as it does over 4300 digits.
            top = max(listed, key=lambda v: [int(p) if p.isascii() and p.isdigit() and len(p) < 20 else -1
                                             for p in re.split(r"[.\-]", v)])
            keys.add(f"{key}<={top}")
    return sorted(keys)


def record_products(record):
    """The CNA's affected vendor/product pairs as Products, keyed like NVD's CPE ids ("sonicwall:sonicos")
    so the two sources merge; the name is the product as the CNA writes it ("SonicOS")."""
    found = {key: {"id": key, "name": product} for key, product, _ in cna_products(record)}
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
