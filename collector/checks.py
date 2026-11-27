"""The documents behind GET /api/check (owner, 11-11: an agent asks "does anything touch what I run?"). A Pages Function
has about 10 ms of CPU, too little to read a month file, so each cycle writes check/index.json (a normalized name ->
the slugs of the Products it stands for) and one small check/p/<slug>.json per Product of the last PAGE_DAYS's Board
Incidents. edge/check.mjs reads them; it normalizes asked names with productKey, the port of product_key."""

import hashlib
from urllib.parse import quote

from collector.incidents import (SPELLING, WELL_KNOWN, cve_order, is_exploited, known_product, on_board, page_slug, product_key, products_of,
                                 published_at, risk_level, row_tags, search_worthy, vendor_words, with_vendor)

SITE = "https://patchticker.com"
DATA = "https://data.patchticker.com"
CVES_SHOWN = 5
# A product page (/p/<slug>, edge/product.mjs) with fewer Incidents in PAGE_DAYS is thin: the page says noindex and the
# sitemap leaves it out (edge/product.mjs PRODUCT_PAGE_MIN is the same number; owner's choice to change, 11-17).
PRODUCT_PAGE_MIN = 3


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
    row on the Board, and `detail`, its whole record (pages/<slug>.json: every CVE, the Summary, the sources), when it has
    one: a page document is written for each Incident with a Summary (cycle.write_pages). Owner, 11-17: an agent read
    the 11 MB week file for a group's other CVEs."""
    summary, quick = incident.get("summary") or {}, incident.get("quick_title") or {}
    title = lambda lang: ((summary.get(lang) or {}).get("title") or (quick.get(lang) or {}).get("title")
                          or (incident.get("brief") or {}).get("text") or incident["id"])
    url = f"{SITE}/i/{page_slug(incident['id'])}" if search_worthy(incident) else f"{SITE}/#i={quote(incident['id'], safe='')}"
    return {"id": incident["id"], "url": url, "first_seen": incident["first_seen"], "published": published_at(incident),
            "level": risk_level(incident), "exploited": is_exploited(incident), "cvss": incident.get("cvss"),
            "cve_count": len(incident["cves"]), "cves": cve_order(incident)[:CVES_SHOWN], "fixed": summary.get("fixed") or "",
            "title_en": title("en"), "title_ko": title("ko"),
            **({"detail": f"{DATA}/pages/{page_slug(incident['id'])}.json"} if incident.get("summary") else {})}


def feed_entry(incident):
    """One item of the whole-Board feed (board/feed-all.json, owner 11-17): the check documents' entry, plus the row's tags
    in both languages for its categories. No Summary text: 270 to 560 Incidents a day."""
    return entry(incident) | {"tags": {lang: row_tags(incident, lang) for lang in ("ko", "en")}}


def product_pages(docs):
    """The product pages worth a sitemap entry, sorted: the check documents' slugs with PRODUCT_PAGE_MIN Incidents or
    more, not all of them 참고 Incidents without a page of their own (owner, 11-27: a 참고 Incident with a CVE has no page in
    search already, so a list of only those is not offered either; edge/product.mjs says noindex on it). A 참고 story
    without a CVE has its page (Vim, the GNU C Library on 11-27): its list stays."""
    # A redirect has no Incidents; a page another stands for (same_lists) is left to that one.
    return sorted(slug for slug, doc in docs.items() if len(doc.get("incidents", ())) >= PRODUCT_PAGE_MIN and "canonical" not in doc
                  and any(e["level"] != "notice" or e["url"].startswith(f"{SITE}/i/") for e in doc["incidents"]))


def name_aliases(incidents):
    """{"name:..." id: the record Product id it names}: a Product a Summary named where the Incident's record has no
    Product of that name ("name:chrome", "Google Chrome") is the record Product another Incident lists under that very
    name, with or without its web/vendors.json vendor ("google:chrome"), when exactly one record Product has it. Only the
    pages and the check documents fold it: the Board's filter joins the two already (sameProduct in web/board.mjs)."""
    form = lambda name: SPELLING.sub("", name.lower())  # noqa: E731
    named, record = {}, {}
    for incident in incidents:
        for p in products_of(incident, "en"):
            if p["id"].startswith("name:"):
                named.setdefault(p["id"], set()).add(form(p["name"]))
            elif not p["id"].startswith("os:"):
                for name in (p["name"], with_vendor(p)):
                    record.setdefault(form(name), set()).add(p["id"])
    found = {pid: {r for f in forms for r in record.get(f, ())} for pid, forms in named.items()}
    return {pid: hit.pop() for pid, hit in found.items() if len(hit) == 1}


def moved_docs(aliases, docs):
    """{slug: {"moved": the slug of the Product it is}} for each id that became another's (product_aliases, name_aliases)
    whose Product has a document: its old product page answers with a redirect (edge/product.mjs) instead of a 404."""
    return {check_slug(old): {"moved": check_slug(new)} for old, new in sorted(aliases.items())
            if check_slug(new) in docs and check_slug(old) not in docs}


def check_docs(incidents, since, aliases=None):
    """({slug: document}, index) for every Product, operating systems aside, of the Board Incidents first seen since
    `since`: a document is {product: its English name, id, incidents: newest first}; the index maps each normalized name
    to its Products' slugs, keys sorted. A "name:" Product another Incident's record names is that Product
    (name_aliases); `aliases` ({old id: kept id}, incidents.product_aliases) adds a redirect document per old id
    (moved_docs)."""
    docs, index = {}, {}
    shown = sorted((i for i in incidents if i["first_seen"] >= since and on_board(i)), key=lambda i: (published_at(i), i["id"]),
                   reverse=True)
    folded = name_aliases(shown)
    for incident in shown:
        ko = {folded.get(p["id"], p["id"]): p["name"] for p in products_of(incident, "ko")}
        mine = set()
        for product in products_of(incident, "en"):
            if product["id"].startswith("os:"):
                continue
            pid = folded.get(product["id"], product["id"])
            slug = check_slug(pid)
            doc = docs.setdefault(slug, {"product": product["name"], "id": pid, "incidents": []})
            if slug not in mine:  # "Google Chrome" and its "name:chrome" in one Incident: one entry
                doc["incidents"].append(entry(incident))
                mine.add(slug)
            for key in names_of(product | {"id": pid}, ko.get(pid, "")):
                index.setdefault(key, set()).add(slug)
    for slug, kept in same_lists(docs).items():
        docs[slug]["canonical"] = kept
    docs |= moved_docs({**(aliases or {}), **folded}, docs)
    return docs, {key: sorted(index[key]) for key in sorted(index)}


def same_lists(docs):
    """{slug: the slug of the page that stands for it} among product pages with the very same Incidents (owner, 11-27:
    one advisory naming 30 GL.iNet models made 30 equal pages): one page per list is offered to search engines, the
    others name it canonical and stay for visitors. A well-known Product no other page of the list shares a label with
    (collector/well_known.json: "macOS" beside "iOS") keeps its own page; the page standing for the rest is a labelled
    one first, then the shortest name, then the slug."""
    lists = {}
    for slug in product_pages(docs):
        lists.setdefault(tuple(e["id"] for e in docs[slug]["incidents"]), []).append(slug)
    found = {}
    for slugs in lists.values():
        label = {s: known_product({"id": docs[s]["id"], "name": docs[s]["product"]}) for s in slugs}
        alone = {s for s in slugs if label[s] and sum(label[o] == label[s] for o in slugs) == 1}
        rest = [s for s in slugs if s not in alone]
        if len(rest) < 2 and not (rest and alone):
            continue
        kept = min(slugs, key=lambda s: (label[s] is None, len(docs[s]["product"]), docs[s]["product"], s))
        found |= {s: kept for s in rest if s != kept}
    return found
