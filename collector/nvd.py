"""Source adapter: CVSS and Products from the NVD API, by last-modified range."""

import json
import re
from datetime import datetime, timedelta
from urllib.parse import unquote, urlencode

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # the API maximum
MAX_RANGE = timedelta(days=120)  # the API rejects longer last-modified ranges
# CVSS 3.x first: most sources, and our 9.0 / 7.0 thresholds, speak CVSS 3.
METRICS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


def fetch(checkpoint, now, http_get, sleep, api_key=""):
    """Return ({CVE ID: {"cvss": score or None, "products": [...]}}, next checkpoint).

    The checkpoint is the end of the last range read, as NVD wants it ("...T13:15:00.000Z")."""
    end = stamp(now)
    # shortcut: with no checkpoint, read the last day instead of backfilling.
    start = datetime.fromisoformat(checkpoint) if checkpoint else now - timedelta(days=1)
    start = stamp(max(start, now - MAX_RANGE))
    headers = {"apiKey": api_key} if api_key else {}
    # NVD allows 5 requests per rolling 30 s without a key and 50 with one; the margin keeps us under.
    pause = 30 / (50 if api_key else 5) + 0.5
    found, index, total = {}, 0, 1
    while index < total:
        if index:
            sleep(pause)
        query = urlencode({"lastModStartDate": start, "lastModEndDate": end,
                           "resultsPerPage": PAGE_SIZE, "startIndex": index})
        page = json.loads(http_get(f"{API_URL}?{query}", headers))
        if not page["vulnerabilities"]:
            break
        total = page["totalResults"]
        index += len(page["vulnerabilities"])
        for item in page["vulnerabilities"]:
            found[item["cve"]["id"]] = {"cvss": cvss(item["cve"]), "products": products(item["cve"]), "published": item["cve"].get("published")}
    return found, end


def stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def cvss(cve):
    for key in METRICS:
        scores = cve.get("metrics", {}).get(key)
        if scores:
            primary = [s for s in scores if s["type"] == "Primary"]  # NVD's own score beats the CNA's
            return (primary or scores)[0]["cvssData"]["baseScore"]
    return None


def products(cve):
    """Products (vendor and product, version dropped) from the vulnerable CPEs, sorted by id."""
    cpes = [m["criteria"] for c in cve.get("configurations", []) for n in c["nodes"]
            for m in n["cpeMatch"] if m["vulnerable"]]
    # NVD defers analysis of most new CVEs, so the CNA's affected list is often the only CPE source.
    cpes += [cpe for a in cve.get("affected", []) for d in a["affectedData"] if affected(d)
             for cpe in d.get("cpes", [])]
    found = {}
    for cpe in cpes:
        if cpe.startswith("cpe:2.3:"):
            vendor, product = (re.sub(r"\\(.)", r"\1", f) for f in re.split(r"(?<!\\):", cpe)[3:5])
        else:  # CPE 2.2 URI, "cpe:/o:redhat:enterprise_linux:9::baseos"
            vendor, product = (unquote(f) for f in (cpe.split(":")[2:4] + ["", ""])[:2])
        vendor, product = vendor.lower(), product.lower()
        if vendor not in ("", "*", "-") and product not in ("", "*", "-"):
            found[f"{vendor}:{product}"] = {"id": f"{vendor}:{product}", "name": display_name(product)}
    return sorted(found.values(), key=lambda p: p["id"])


def affected(data):
    """CVE 5 affected entry: the default status, or any listed version, says affected."""
    return data.get("defaultStatus") == "affected" or any(v.get("status") == "affected" for v in data.get("versions", []))


def display_name(product):
    # shortcut: title-cased CPE product ("http_server" -> "Http Server"); add a name table if visitors trip on it.
    return " ".join(w[:1].upper() + w[1:] for w in product.split("_"))
