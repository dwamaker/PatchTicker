"""The documents behind GET /api/check (owner, 11-11: an agent asks "does anything touch what I run?"). A Pages Function
has about 10 ms of CPU, too little to read a month file, so each cycle writes check/index.json (a normalized name ->
the slugs of the Products it stands for) and one small check/p/<slug>.json per Product of the last PAGE_DAYS's Board
Incidents. edge/check.mjs reads them; it normalizes asked names with productKey, the port of product_key."""

import hashlib
from urllib.parse import quote

from collector.incidents import (WELL_KNOWN, is_exploited, known_product, on_board, page_slug, product_key, products_of,
                                 published_at, risk_level, search_worthy, vendor_words)

SITE = "https://patchticker.com"
CVES_SHOWN = 5


def check_slug(product_id):
    """The Product's document name: never the raw id, which CNA text fills with any character (audit 12)."""
    return hashlib.sha256(product_id.encode("utf-8")).hexdigest()[:16]


def names_of(product, ko_name):
    """The names an agent may ask a Product by, normalized: its English and Korean names, its id's tail ("openbsd:openssh"
    is "openssh"), its name without a leading vendor word, and its well-known label and that label's aliases."""
    pid, name = product["id"], product["name"]
    names = {name, ko_name, pid.partition(":")[2].replace("_", " ")}
    names |= {name[len(v):] for v in vendor_words(pid.lower()) if name.lower().startswith(v)}
    label = known_product(product)
    if label:
        names |= {label, *WELL_KNOWN[label].get("names", [])}
    return {key for key in map(product_key, filter(None, names)) if key}


def entry(incident):
    """An Incident as an agent reads it: small, with its Incident page when it is offered to search engines, else its
    row on the Board."""
    summary, quick = incident.get("summary") or {}, incident.get("quick_title") or {}
    title = lambda lang: ((summary.get(lang) or {}).get("title") or (quick.get(lang) or {}).get("title")
                          or (incident.get("brief") or {}).get("text") or incident["id"])
    url = f"{SITE}/i/{page_slug(incident['id'])}" if search_worthy(incident) else f"{SITE}/#i={quote(incident['id'], safe='')}"
    return {"id": incident["id"], "url": url, "first_seen": incident["first_seen"], "published": published_at(incident),
            "level": risk_level(incident), "exploited": is_exploited(incident), "cvss": incident.get("cvss"),
            "cve_count": len(incident["cves"]), "cves": incident["cves"][:CVES_SHOWN], "fixed": summary.get("fixed") or "",
            "title_en": title("en"), "title_ko": title("ko")}


def check_docs(incidents, since):
    """({slug: document}, index) for every Product, operating systems aside, of the Board Incidents first seen since
    `since`: a document is {product: its English name, id, incidents: newest first}; the index maps each normalized name
    to its Products' slugs, keys sorted."""
    docs, index = {}, {}
    shown = sorted((i for i in incidents if i["first_seen"] >= since and on_board(i)), key=lambda i: (published_at(i), i["id"]),
                   reverse=True)
    for incident in shown:
        ko = {p["id"]: p["name"] for p in products_of(incident, "ko")}
        for product in products_of(incident, "en"):
            if product["id"].startswith("os:"):
                continue
            slug = check_slug(product["id"])
            docs.setdefault(slug, {"product": product["name"], "id": product["id"], "incidents": []})["incidents"].append(entry(incident))
            for key in names_of(product, ko.get(product["id"], "")):
                index.setdefault(key, set()).add(slug)
    return docs, {key: sorted(index[key]) for key in sorted(index)}
