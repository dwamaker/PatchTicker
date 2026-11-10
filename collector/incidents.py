"""Incident linking (ADR 0001): attach Mentions to Incidents by CVE ID or URL, merge, pick the Lead.

Each source adapter turns its items into Mention groups: {"mentions": [{"kind", "url", "title"?}],
"cves": [...], "urls": [cited URLs], "text": one line, "join_only": bool, "published"?: the
source's own post time}. A join-only group (a PoC repo, a reply, an off-topic story) is dropped
unless it matches an existing Incident.

An Incident's "published" is the earliest post time among the groups that could start it, so a
visitor sees when the news first broke, not when a cycle noticed it ("first_seen").
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

STAMP = "%Y-%m-%dT%H:%M:%SZ"  # ISO-8601 UTC, so string order is time order

# Lead mention order (CONTEXT.md): official advisory or release note, discoverer write-up,
# CVE record, discussion (a curator's newsletter is discussion too). A KISA notice (Korean, restating the vendor's)
# and repositories are listed but come last.
LEAD_ORDER = ["advisory", "writeup", "cve_record", "discussion", "curator", "notice", "repo"]

# At most 7 digits, never the first 7 of a longer run: such a token is junk, not a CVE (audit 7: page names, int()).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE | re.ASCII)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


# What the Board page reads. Linking keys (urls, cites) and Summary bookkeeping stay in the collector's files:
# at about 650 Incidents a day they were over half of each Incident's bytes.
PAGE_FIELDS = ("id", "cves", "first_seen", "published", "mentions", "brief", "cvss", "kev", "kev_date", "products", "summary", "cve_texts",
               "cve_links", "quick_title")


def board_view(incident):
    """The page's copy of an Incident; a failed Summary keeps only its final flag (the page's 'unavailable' note)."""
    view = {k: incident[k] for k in PAGE_FIELDS if k in incident}
    if incident.get("summary_error", {}).get("final"):
        view["summary_error"] = {"final": True}
    return view


ROW_FIELDS = ("id", "cves", "first_seen", "published", "cvss", "kev", "kev_date", "products")
ROW_SUMMARY = ("exploited", "exploited_source", "platforms", "products", "library", "devices", "incident", "poc_public", "at")


def rows_view(incident):
    """board/rows.json's copy of an Incident (owner, 11-10: the Board draws first from a light file): what a row, the
    filters, folds and Highlights read, marked rows; the opened details and the text search wait for board/recent.json."""
    view = {k: incident[k] for k in ROW_FIELDS if k in incident}
    if incident.get("summary_error", {}).get("final"):
        view["summary_error"] = {"final": True}
    view |= {"rows": True, "wp_plugin": is_wordpress_plugin(incident)}  # its regex reads text a row view no longer has
    summary, quick = incident.get("summary") or {}, incident.get("quick_title") or {}
    untitled = [lang for lang in ("ko", "en") if not (summary.get(lang) or {}).get("title")]
    if untitled and quick:
        view["quick_title"] = quick  # a row titles itself from it while the Summary has no title in that language
    # The row falls back to the Brief only where neither the Summary nor the quick title names it (describe, titleCell).
    bare = any(not ((quick.get(lang) or {}).get("title") and (quick.get(lang) or {}).get("easy_title")) for lang in untitled)
    view["brief"] = {"text": incident["brief"]["text"] if bare else ""}
    view["mentions"] = [{k: m[k] for k in ("kind", "points") if k in m} for m in incident["mentions"]]
    if summary:
        view["summary"] = {k: summary[k] for k in ROW_SUMMARY if k in summary}
        for lang in ("ko", "en"):
            text = summary.get(lang) or {}
            view["summary"][lang] = {k: text[k] for k in ("title", "easy_title", "easy", "names") if k in text} | {
                "summary": "" if text.get("easy") else text.get("summary", ""), "conditions": [], "mitigation": ""}
    return view


PICKER_DAYS = 90  # the picker lists Products of these days (board/products.json), as productList in board.mjs does


# Security news sites (collector/news.py reads the first two). The Record has no feed there, but HN links to it often.
# Repeated in web/board.mjs (NEWS_HOSTS).
NEWS_HOSTS = {"bleepingcomputer.com", "securityweek.com", "therecord.media"}


def is_news(url):
    try:
        host = urlsplit(url).netloc.lower()
    except ValueError:
        return False
    return host.removeprefix("www.") in NEWS_HOSTS


def on_board(incident):
    """A port of onBoard in web/board.mjs: a CVE-less HN or news story shows only once its Summary calls it an Incident."""
    if incident["cves"] or not (incident["id"].startswith("https://news.ycombinator.com/") or is_news(incident["id"])):
        return True
    if incident.get("summary"):
        return incident["summary"].get("incident") is not False
    return bool(incident.get("summary_error", {}).get("final"))


def is_exploited(incident):
    """A port of isExploited in web/board.mjs: KEV, or a Summary reporting attacks with the source that reports them."""
    summary = incident.get("summary") or {}
    source = summary.get("exploited_source")
    return bool(incident.get("kev") or (summary.get("exploited") is True and isinstance(source, str) and source))


def risk_level(incident):
    """A port of riskLevel in web/board.mjs (tests/fixtures/board/risk-case.json keeps the two in step)."""
    cvss = incident.get("cvss")
    if is_exploited(incident) or (cvss is not None and cvss >= 9):
        return "highest"
    return "high" if cvss is not None and cvss >= 7 else "notice"


def published_at(incident):
    """A port of publishedAt in web/board.mjs: when the news first broke, else first seen (stored before 11-08)."""
    return incident.get("published") or incident["first_seen"]


def highlight_score(incident):
    """A port of highlightScore in web/board.mjs (tests/fixtures/board/rows-case.json keeps the two in step): rows.json
    keeps the week's likely Highlights whole, so a drift costs one wait when one is opened, nothing more."""
    mentions = incident["mentions"]
    points = max([0] + [m.get("points") or 0 for m in mentions])
    curated = sum(1 for m in mentions if m["kind"] == "curator")
    return (100 if is_exploited(incident) else 0) + min(points / 10, 50) + 25 * min(curated, 2) + 2 * (incident.get("cvss") or 0) + len(mentions)


# A port of WP_PLUGIN and isWordPressPlugin in web/board.mjs (tests/fixtures/board/rows-case.json keeps the two in step):
# WordPress plugins and themes fold as one, and a row view carries this answer as wp_plugin.
WP_PLUGIN = re.compile(r"(?:wordpress|워드프레스)[^.;:!?\n]{0,40}?(?:plugin|theme|플러그인|테마)|(?:plugin|theme)s?\s+for\s+wordpress", re.IGNORECASE)


def is_wordpress_plugin(incident):
    summary = incident.get("summary") or {}
    words = [(incident.get("brief") or {}).get("text"), *((summary.get(lang) or {}).get(k) for lang in ("en", "ko")
                                                          for k in ("title", "summary", "easy_title", "easy")),
             *(p["id"] for p in incident.get("products") or [])]
    first = (summary.get("products") or [""])[0]
    return str(first if first is not None else "").lower() != "wordpress" and bool(WP_PLUGIN.search("\n".join(str(w) for w in words if w)))


def search_worthy(incident):
    """Offered to search engines and the RSS feed (Incident page, CONTEXT.md): on the Board with a Summary, and at the
    위험 level or above, exploited, or without a CVE. A port of searchWorthy in web/board.mjs."""
    return bool(incident.get("summary")) and on_board(incident) and (risk_level(incident) != "notice" or not incident["cves"])


HN_ITEM = re.compile(r"https://news\.ycombinator\.com/item\?id=(\d+)", re.ASCII)  # \d as in JavaScript


def page_slug(incident_id):
    """A port of slug in web/board.mjs (tests/fixtures/board/slug-case.json keeps the two in step): a CVE ID as is, an
    HN story as hn-<item>, any other URL ID as u-<12 hex of SHA-256>. It never changes, as the Incident's ID never does."""
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", incident_id, re.IGNORECASE | re.ASCII):
        return incident_id.upper()
    hn_item = HN_ITEM.fullmatch(incident_id)
    if hn_item:
        return f"hn-{hn_item[1]}"
    return "u-" + hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:12]


def products_of(incident, lang):
    """A port of productsOf in web/board.mjs (tests/fixtures/board/products-case.json keeps the two in step)."""
    found = {p["id"]: p for p in incident.get("products") or []}
    summary = incident.get("summary") or {}
    local = (summary.get(lang) or {}).get("names") or []
    for k, name in enumerate(summary.get("products") or []):
        shown = (local[k] if k < len(local) else "") or name
        same = next((p for p in found.values() if p["name"].lower() in name.lower()), None)
        key = same["id"] if same else f"name:{product_key(name)}"
        found[key] = {**(same or {"id": key}), "name": shown}
    for os_name in summary.get("platforms") or []:
        found.pop(f"name:{os_name.lower()}", None)  # "Android" as a product and as a platform is one entry
        found[f"os:{os_name.lower()}"] = {"id": f"os:{os_name.lower()}", "name": os_name}
    return list(found.values())


def product_list(incidents, since):
    """Every Product of Board Incidents first seen since `since`, with its Korean and English names, by id."""
    found = {}
    for incident in incidents:
        if incident["first_seen"] >= since and on_board(incident):
            for lang in ("ko", "en"):
                for p in products_of(incident, lang):
                    found.setdefault(p["id"], {"id": p["id"]})[lang] = p["name"]
    return sorted(found.values(), key=lambda p: p["id"])


# Vendor spellings, shared with the page (web/board.mjs prefixes names that lack their vendor). How to add one:
# docs/agents/vendors.md.
VENDORS = json.loads((Path(__file__).parent.parent / "web" / "vendors.json").read_text(encoding="utf-8"))


SUFFIX = re.compile(r"\s+(?:(?:for\s+)?wordpress\s+)?(?:plugin|theme|플러그인|테마)(?:\s+for\s+wordpress)?$")
COMPANY = re.compile(r"(^|\s)(?:technology|technologies|inc|corp|corporation|co|ltd|limited|gmbh|llc)\.?(?=\s|$)")
LED_BY = [f"{v.lower()} " for v in VENDORS.values()]


def product_key(name):
    """A port of productKey in web/board.mjs: one id however a Summary writes a Product's name (critique 14), without
    letter case, brackets, company words, a generic suffix ("WordPress plugin", "플러그인") or a known vendor in front."""
    plain = " ".join(COMPANY.sub(r"\1", re.sub(r"[(),]", " ", name.lower())).split())
    key = SUFFIX.sub("", plain).strip() or plain
    vendor = next((v for v in LED_BY if key.startswith(v) and len(key) > len(v)), None)
    return key[len(vendor):] if vendor else key


def unknown_vendors(incidents, since):
    """Vendor keys of Board Products since `since` that are not in VENDORS and whose name does not say the vendor
    ("getgrav:grav"), each with one Product name as an example: the page shows those names bare until one is added."""
    letters = lambda text: re.sub(r"[^a-z0-9]", "", text.lower())
    found = {}
    for incident in incidents:
        if incident["first_seen"] >= since and on_board(incident):
            for p in incident.get("products", []):
                vendor = p["id"].split(":")[0]
                if vendor not in VENDORS and letters(vendor) not in letters(p["name"]) and plain_vendor(vendor, p["name"]):
                    found.setdefault(vendor, p["name"])
    return dict(sorted(found.items()))


VENDOR_KEY = re.compile(r"[a-z0-9][a-z0-9_.\-]{0,63}", re.ASCII)


def plain_vendor(key, name):
    """CNA-written text goes to an operator's agent through unknown_vendors.json (docs/agents/vendors.md), so only a
    short plain key and a short printable example name are listed."""
    return bool(VENDOR_KEY.fullmatch(key)) and len(name) < 200 and name.isprintable()


def to_stamp(value):
    """A source's ISO-8601 time ("2026-11-07T12:43:21.399Z", no zone = UTC) as a STAMP; None if unreadable."""
    try:
        at = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime(STAMP)


def month_of(stamp):
    """The monthly file a stamp belongs to ("2026-11"); an Incident stays in its first-seen month."""
    return stamp[:7]


def cves_in(text):
    return list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text or "")))


def urls_in(text):
    return [u.rstrip(".,;:") for u in URL_RE.findall(text or "")]


def is_http(url):
    return isinstance(url, str) and url.lower().startswith(("http://", "https://"))


def url_key(url):
    """The same page however it is written: no scheme, www., fragment, trailing slash or utm_ tracking."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:  # "http://[..." in scraped text: kept as written, so it never matches a real page
        return url.strip()
    host = parts.netloc.lower().removeprefix("www.")
    query = "&".join(p for p in parts.query.split("&") if p and not p.lower().startswith("utm_"))
    return host + parts.path.rstrip("/") + (f"?{query}" if query else "")


def link(incidents, group, stamp):
    """Attach one Mention group to the Incidents list in place; return the months it changed."""
    mentions = group["mentions"]
    proto = {
        "id": group["cves"][0] if group["cves"] else mentions[0]["url"],
        "cves": group["cves"],
        "first_seen": stamp,
        # A source without its own time leaves it unknown: the cycle's time is not when the news broke.
        **({"published": min(group["published"], stamp)} if group.get("published") else {}),
        **({"cvss": group["cvss"]} if group.get("cvss") is not None else {}),
        **({"products": group["products"]} if group.get("products") else {}),
        **({"fix_keys": group["fix_keys"]} if group.get("fix_keys") else {}),
        "mentions": mentions,
        "urls": sorted({url_key(u) for u in group["urls"] + [m["url"] for m in mentions]}),
        "brief": {"text": group["text"], "lead": lead(mentions)},
    }
    if group.get("page"):
        proto["cites"] = group["page"]  # rejoin() reads it; dropped once joined or a week old
    hits = [i for i in incidents if matches(i, proto)]
    if not hits:
        if group.get("join_only"):
            return set()
        incidents.append(proto)
        return {month_of(stamp)}
    target = min(hits, key=lambda i: i["first_seen"])  # min keeps the first of equal times
    before = json.dumps(target)
    changed = set()
    # Only a CVE record, an oss-security advisory or a Mention naming one CVE ties CVEs together; any other joins the
    # earliest Incident and adds no CVE to it (a PoC repo, an HN story or a headline naming several CVEs must not merge
    # their rows or lend a row another CVE's record: anyone can submit one, and a fold is permanent).
    trusted = ties(mentions[0]) or len(proto["cves"]) == 1
    merge = proto["cves"] and not group.get("join_only") and trusted
    for other in [i for i in hits if i is not target] if merge else []:
        fold(incidents, target, other)
        changed.add(month_of(other["first_seen"]))
    if not trusted:
        proto["cves"] = [c for c in proto["cves"] if c in target["cves"]]
    if group.get("join_only"):
        proto.pop("published", None)  # an old PoC repo or a reply joining later says nothing about when the news broke
    absorb(target, proto)
    if json.dumps(target) != before:
        changed.add(month_of(target["first_seen"]))
    return changed


def ties(mention):
    """A group led by a CVE record or an oss-security post (seclists.org) may fold the Incidents it names (ADR 0001)."""
    return mention["kind"] == "cve_record" or mention["url"].startswith("https://seclists.org/oss-sec/")


MAX_CITED_LINKS = 50  # the public monthly file carries these for a week; most pages cite a handful


def page_keys(page, page_url):
    """CVE IDs and outside link keys in a story's linked page (raw HTML or text). Links back to the page's
    own site are its navigation, not citations."""
    own = url_key(page_url).split("/", 1)[0]
    urls = {url_key(u) for u in urls_in(page)}
    return {"cves": cves_in(page), "urls": sorted(u for u in urls if u.split("/", 1)[0] != own)[:MAX_CITED_LINKS]}


def cited_by(incidents, keys):
    """The one Incident a CVE-less story's page is about (a blog on sshole links sshhole.com): matched by a
    CVE ID or by a link to one of its advisory, write-up or repo pages. Several or none: [] (stands alone)."""
    urls = set(keys["urls"])
    hits = [i for i in incidents if set(i["cves"]) & set(keys["cves"])
            or {url_key(m["url"]) for m in i["mentions"] if m["kind"] in ("advisory", "writeup", "repo")} & urls]
    return hits if len(hits) == 1 else []


def rejoin(incidents, since):
    """Fold each CVE-less Incident whose page cites exactly one other Incident into it, whichever came
    first; return the months changed. Citations older than `since` (a stamp) are dropped."""
    changed = set()
    for story in [i for i in incidents if i.get("cites")]:
        if story["first_seen"] < since or story["cves"]:
            del story["cites"]
            changed.add(month_of(story["first_seen"]))
            continue
        hits = cited_by([i for i in incidents if i is not story], story["cites"])
        if hits:
            fold(incidents, hits[0], story)
            changed |= {month_of(story["first_seen"]), month_of(hits[0]["first_seen"])}
    return changed


def matches(incident, proto):
    if set(incident["cves"]) & set(proto["cves"]):
        return True
    # URLs key an Incident only while it or the Mention has no CVE (spec: "keyed by its CVE IDs
    # when it has any"), so two CVE rows citing one project page stay apart.
    return not (incident["cves"] and proto["cves"]) and bool(set(incident["urls"]) & set(proto["urls"]))


def fold(incidents, target, other):
    """Merge Incident `other` into `target` and drop it. The survivor keeps its ID (ADR 0001) and records every ID it
    absorbed, those `other` had absorbed too, so the absorbed pages can move to it (ticket incident-pages/04)."""
    absorb(target, other)
    target["absorbed"] = target.get("absorbed", []) + [other["id"]] + other.get("absorbed", [])
    incidents.remove(other)


def absorb(target, other):
    if has_record(other) and not has_record(target):
        target["brief"]["text"] = other["brief"]["text"]
    target["cves"] += [c for c in other["cves"] if c not in target["cves"]]
    if other.get("fix_keys"):
        target["fix_keys"] = sorted(set(target.get("fix_keys", [])) | set(other["fix_keys"]))
    seen = {url_key(m["url"]) for m in target["mentions"]}
    for m in other["mentions"]:
        if m["kind"] == "advisory" and url_key(m["url"]) in seen:
            # Only a CVE record's tag says "advisory"; it beats the write-up an HN link guessed for the same page.
            for t in target["mentions"]:
                if url_key(t["url"]) == url_key(m["url"]):
                    t["kind"] = "advisory"
        elif url_key(m["url"]) not in seen:
            seen.add(url_key(m["url"]))
            target["mentions"].append(m)
    target["urls"] = sorted(set(target["urls"]) | set(other["urls"]) | seen)
    target["brief"]["lead"] = lead(target["mentions"])
    if other.get("published"):
        set_published(target, other["published"])
    enrich(target, {"cvss": other.get("cvss"), "products": other.get("products", [])})


# User, 2026-11-09: more than two CVEs for one product, fixed in the same version and published within two days, are one
# Incident (a release note's worth), so one vendor's batch of fixes takes one row and one Highlight slot.
GROUP_MIN_CVES = 3
GROUP_HOURS = 48


def group_releases(incidents):
    """Merge the Incidents of one release (same fix key, published within GROUP_HOURS of the earliest) once they hold
    GROUP_MIN_CVES CVEs or more; the earliest seen keeps its id. Each CVE's own description stays in "cve_texts" for the
    page. Returns the months changed."""
    changed = set()
    when = lambda i: i.get("published") or i["first_seen"]
    for key in sorted({k for i in incidents for k in i.get("fix_keys", [])}):
        members = sorted((i for i in incidents if key in i.get("fix_keys", [])), key=when)
        if not members:
            continue
        start = datetime.strptime(when(members[0]), STAMP)
        members = [i for i in members if (datetime.strptime(when(i), STAMP) - start).total_seconds() <= GROUP_HOURS * 3600]
        if len(members) < 2 or len({c for i in members for c in i["cves"]}) < GROUP_MIN_CVES:
            continue
        target = min(members, key=lambda i: i["first_seen"])
        texts = target.setdefault("cve_texts", {c: target["brief"]["text"] for c in target["cves"]})
        links = target.setdefault("cve_links", own_links(target))
        for other in members:
            if other is target:
                continue
            texts.update(other.get("cve_texts") or {c: other["brief"]["text"] for c in other["cves"]})
            links.update(other.get("cve_links") or own_links(other))
            fold(incidents, target, other)
            changed.add(month_of(other["first_seen"]))
        changed.add(month_of(target["first_seen"]))
    return changed


def own_links(incident):
    """A not-yet-grouped Incident's advisories and write-ups, filed under each of its CVEs, so the page can put each
    link on its CVE's line once the group holds dozens of them."""
    found = [{"kind": m["kind"], "url": m["url"]} for m in incident["mentions"] if m["kind"] in ("advisory", "writeup")]
    return {c: found for c in incident["cves"]}


def set_published(incident, when):
    """Keep the earliest known publish time. With none known yet, a time after the Board first saw the Incident is
    not taken: the news broke before that, so it stays unknown rather than wrong."""
    if incident.get("published"):
        incident["published"] = min(incident["published"], when)
    elif when <= incident["first_seen"]:
        incident["published"] = when


def cite(incident, citation):
    """Add a curator's Mention to an Incident it cites by CVE or URL. Its own address is not made a
    key: one newsletter issue cites many Incidents and must not tie them together."""
    if set(incident["cves"]) & set(citation["cves"]) or set(incident["urls"]) & {url_key(u) for u in citation["urls"]}:
        if all(m["url"] != citation["mention"]["url"] for m in incident["mentions"]):
            incident["mentions"].append(citation["mention"])


def enrich(incident, data):
    """Fold one CVE's NVD data into its Incident; an Incident with several CVEs keeps the union."""
    if data["cvss"] is not None:
        # shortcut: keeps the highest score, so a downward NVD revision is not applied; store per-CVE scores if that matters.
        incident["cvss"] = max(incident.get("cvss", 0), data["cvss"])
    merged = {p["id"]: p for p in incident.get("products", []) + data["products"]}
    if merged:
        incident["products"] = sorted(merged.values(), key=lambda p: p["id"])
    if data.get("published") and to_stamp(data["published"]):
        set_published(incident, to_stamp(data["published"]))  # NVD's publish date, for Incidents whose sources gave none


def lead(mentions):
    return min(mentions, key=lambda m: LEAD_ORDER.index(m["kind"]))["url"]  # first wins a tie


def has_record(incident):
    return any(m["kind"] == "cve_record" for m in incident["mentions"])
