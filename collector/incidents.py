"""Incident linking (ADR 0001): attach Mentions to Incidents by CVE ID or URL, merge, pick the Lead.

Each source adapter turns its items into Mention groups: {"mentions": [{"kind", "url", "title"?}],
"cves": [...], "urls": [cited URLs], "text": one line, "join_only": bool, "published"?: the
source's own post time}. A join-only group (a PoC repo, a reply, an off-topic story) is dropped
unless it matches an existing Incident.

An Incident's "published" is the earliest post time among the groups that could start it, so a
visitor sees when the news first broke, not when a cycle noticed it ("first_seen").
"""

import fnmatch
import hashlib
import html.parser
import json
import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from collector import distros, nvd

STAMP = "%Y-%m-%dT%H:%M:%SZ"  # ISO-8601 UTC, so string order is time order


def stamp_ago(now, days=0, hours=0):
    return (now - timedelta(days=days, hours=hours)).strftime(STAMP)

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
    view = {k: incident[k] for k in PAGE_FIELDS if k in incident} | order_fields(incident, maps=True)
    if incident.get("summary_error", {}).get("final"):
        view["summary_error"] = {"final": True}
    return (view | known_field(incident) | public_field(incident, view["cves"]) | distro_fields(incident, view["cves"])
            | score_by_field(incident))


def score_by_field(incident):
    """When the shown score is a page's raise (sheets.page_scores), it and the CVE record's, each with its CVSS version,
    for the page's "CVSS 4.0 9.2 / CVSS 3.1 8.1" (owner 11-18: two standards): {"score_by": {"cvss", "version",
    "record", "record_version"}}, a version "" when not known. Only the top CVE's."""
    top = top_cve(incident)
    entry = (incident.get("cve_scores") or {}).get(top) if top else None
    if not entry or not entry.get("by") or "record" not in entry:
        return {}
    return {"score_by": {"cvss": entry["cvss"], "version": entry.get("version", ""), "record": entry["record"]["cvss"],
                         "record_version": cvss_version(entry["record"]["vector"])}}


def cvss_version(vector):
    """"3.1" of "CVSS:3.1/AV:N/...", or "" (a CVSS 2 vector has no prefix, and none means not known)."""
    found = re.match(r"CVSS:(\d\.\d)/", vector or "")
    return found[1] if found else ""


def distro_fields(incident, order):
    """Step 10: the Distribution table, merged over the Incident's CVEs in cve_order, and the credit line of the
    distributions it shows; worked out at each write from the stored per-CVE lines (distro_lines)."""
    lines = incident.get("distro_lines") or {}
    rows = distros.merge({cve: lines[cve] for cve in order if lines.get(cve)})
    return {"distro_rows": rows, "distro_credits": distros.credits(rows)} if rows else {}


def public_field(incident, order):
    """M4 (owner, 11-15): the Lead CVE's Public date (its record's datePublic, a UTC day), shown only when it is not the
    day of the Published time; the Board's order and the Highlight window keep the Published time."""
    day = (incident.get("public_dates") or {}).get(order[0]) if order else None
    return {"public_date": day} if day and day != published_at(incident)[:10] else {}


OTHERS_DAYS = 30  # M1: "N other Incidents of this product in the last 30 days"


def product_counts(incidents, since):
    """M1 (owner, 11-15; 11-16: kept out of the per-Incident documents, whose rewrites it would multiply): {Product id: N},
    N the Board Incidents of that Product published since `since`, operating systems aside, only where N is 2 or more
    (board/others.json). The site takes the Incident itself out of N when its own Published time is in the window, and
    links the row's first Product to the Board filtered to it. Ids are productsOf's, so they are the Board's filter picks."""
    count = Counter(pid for i in incidents if on_board(i) and published_at(i) >= since
                    for pid in {p["id"] for p in products_of(i, "en") if not p["id"].startswith("os:")})
    return {pid: n for pid, n in sorted(count.items()) if n >= 2}


def exploited_cves(incident):
    """The CVEs named as attacked: KEV-listed (kev_cves) or named by the Summary's source (summary.exploited_cves)."""
    return set(incident.get("kev_cves") or {}) | set((incident.get("summary") or {}).get("exploited_cves") or [])


def cve_order(incident):
    """The CVEs as the page lists them (step 4), worked out at each write and never stored (`cves` keeps arrival order,
    ADR 0001): exploited first, then by score high to low, unscored last, ties in arrival order. The first is the Lead CVE."""
    attacked, scores = exploited_cves(incident), incident.get("cve_scores") or {}
    return sorted(incident["cves"], key=lambda c: (c not in attacked, c not in scores, -scores[c]["cvss"] if c in scores else 0))


def top_cve(incident):
    """The first CVE in cve_order whose own score is the Incident's cvss, or None: a half-filled cve_scores (or a cvss
    lowered per CVE before step 4) names no CVE rather than a wrong one."""
    scores = incident.get("cve_scores") or {}
    return next((c for c in cve_order(incident) if c in scores and scores[c]["cvss"] == incident.get("cvss")), None)


def order_fields(incident, maps):
    """`cves` in cve_order, so every cves[0] reader on the site shows the Lead CVE; with more than one CVE also top_cve
    and, for a whole Incident (maps), the per-CVE cve_scores and kev_cves."""
    fields = {"cves": cve_order(incident)}
    if len(incident["cves"]) > 1:
        top = top_cve(incident)
        fields |= ({"top_cve": top} if top else {}) | (
            {k: incident[k] for k in ("cve_scores", "kev_cves") if incident.get(k)} if maps else {})
    return fields


def known_field(incident):
    """`known` for the page (tierOf and highlightScore in web/board.mjs), worked out at each write and never stored, so an edit of
    collector/well_known.json reaches the week's rows at the next cycle. known_tier: the label's tier of reach in that
    file (1 on most computers or phones, 2 the standard of its field, 3 known inside it), which orders the Highlights
    (owner, 11-17; it replaced the label's place, known_rank); none for a label on no list (a Summary's widely_used),
    which the site counts as tier 3."""
    label = known_label(incident)
    if not label:
        return {}
    # known_kind: the label's category in that file, which with the vendor is one of a row's same keys (sameKeys).
    return {"known": label} | ({"known_tier": WELL_KNOWN[label]["tier"], "known_kind": LABEL_KIND[label]} if label in WELL_KNOWN else {})


ROW_FIELDS = ("id", "cves", "first_seen", "published", "cvss", "kev", "kev_date", "products")
ROW_SUMMARY = ("exploited", "exploited_source", "severity", "severity_source", "platforms", "products", "library", "devices", "incident", "poc_public", "at",
               "event_date")


def rows_view(incident):
    """board/rows.json's copy of an Incident (owner, 11-10: the Board draws first from a light file): what a row, the
    filters, folds and Highlights read, marked rows; the opened details and the text search wait for board/recent.json."""
    view = {k: incident[k] for k in ROW_FIELDS if k in incident} | order_fields(incident, maps=False)
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
    return view | known_field(incident)


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


HIGHEST_CVSS = 9  # HIGHEST_CVSS in web/board.mjs: the 최고 band's CVSS floor


PROVISIONAL = {"critical": "highest", "high": "high"}  # PROVISIONAL in web/board.mjs; medium and low change nothing


def provisional_level(incident):
    """A port of provisionalLevel in web/board.mjs: while an Incident has no CVSS score, the level its official advisory's
    own severity word gives (the Summary's severity and severity_source, summary_input.advisory_severity; owner, 11-19),
    "highest" or "high"; else None. A score, once there, always wins."""
    summary = incident.get("summary") or {}
    source = summary.get("severity_source")
    if incident.get("cvss") is not None or not (isinstance(source, str) and source):
        return None
    return PROVISIONAL.get(summary.get("severity"))


def risk_level(incident):
    """A port of riskLevel in web/board.mjs (tests/fixtures/board/risk-case.json keeps the two in step)."""
    cvss, provisional = incident.get("cvss"), provisional_level(incident)
    if is_exploited(incident) or (cvss is not None and cvss >= HIGHEST_CVSS) or provisional == "highest":
        return "highest"
    return "high" if (cvss is not None and cvss >= 7) or provisional == "high" else "notice"


def published_at(incident):
    """A port of publishedAt in web/board.mjs: when the news first broke, else first seen (stored before 11-08)."""
    return incident.get("published") or incident["first_seen"]


# The Highlight score: a port of highlightScore in web/board.mjs, where its parts are explained (owner, 11-19: score,
# wide use, urgency, date, in that order; reworked 11-22: exponential recency, attention, corroboration;
# tests/fixtures/board/rows-case.json keeps the two in step). rows.json keeps the week's likely Highlights whole, so a
# drift costs one wait when one is opened, nothing more.
RECENCY = 15  # when published at now, halving every HALF_LIFE_DAYS
HALF_LIFE_DAYS = 2
SEVERITY_FLOOR = {"highest": HIGHEST_CVSS, "high": 7}  # a provisional level counts as its band's floor
WIDE_USE = {1: 14, 2: 10, 3: 5}  # by tier_of; no label 0; none for an uncorroborated row
ATTENTION_MAX = 8
CORROBORATING = ("advisory", "notice", "curator", "discussion")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def epoch_ms(stamp):
    """Whole milliseconds since 1970 of an ISO stamp (Date.parse in web/board.mjs); a stamp without a zone is UTC."""
    at = datetime.fromisoformat(stamp)
    return ((at if at.tzinfo else at.replace(tzinfo=timezone.utc)) - EPOCH) // timedelta(milliseconds=1)


def recency(incident, now):
    """Rounded to a millionth as recency in web/board.mjs: the two ports' powers may differ in the last bit."""
    age = max(0, epoch_ms(now) - epoch_ms(published_at(incident)))
    return math.floor(1e6 * RECENCY * 0.5 ** (age / (HALF_LIFE_DAYS * 86_400_000)) + 0.5) / 1e6  # Math.round


def attention(view):
    """A port of attention in web/board.mjs: a notice 3, a curator issue 2, HN points / 100 up to 3, five or more repos 1;
    ATTENTION_MAX at most."""
    kinds = {m["kind"] for m in view["mentions"]}
    points = max([0] + [m.get("points") or 0 for m in view["mentions"]])
    repos = sum(1 for m in view["mentions"] if m["kind"] == "repo")
    return min(ATTENTION_MAX, (3 if "notice" in kinds else 0) + (2 if "curator" in kinds else 0) + min(points / 100, 3)
               + (1 if repos >= 5 else 0))


def corroborated(view):
    """A port of corroborated in web/board.mjs: exploited, or with an advisory, notice, curator or discussion Mention."""
    return is_exploited(view) or any(m["kind"] in CORROBORATING for m in view["mentions"])


def tier_of(view):
    """A port of tierOf in web/board.mjs: the label's tier of reach (1, 2, 3), 3 for a label without one, None unlabelled."""
    return (view.get("known_tier") if view.get("known_tier") in (1, 2, 3) else 3) if view.get("known") else None


def highlight_score(incident, now):
    """now: an ISO stamp, for the recency part."""
    exploited = is_exploited(incident)
    cvss = incident.get("cvss")
    cvss = cvss if cvss is not None else HIGHEST_CVSS if exploited else SEVERITY_FLOOR.get(provisional_level(incident), 0)
    urgency = 12 if exploited else 3 if risk_level(incident) == "highest" else 0
    wide = WIDE_USE.get(tier_of(incident), 0) if corroborated(incident) else 0
    return 5 * cvss + wide + urgency + recency(incident, now) + attention(incident)


# A port of WP_PLUGIN and isWordPressPlugin in web/board.mjs (tests/fixtures/board/rows-case.json keeps the two in step):
# WordPress plugins and themes fold as one, and a row view carries this answer as wp_plugin.
# Owner, 11-16: WooCommerce and what is made for it count, and so does an extension or add-on "for … WordPress" (AcyMailing,
# "extension for Joomla and WordPress"); a name that gives no sign (Ninja Forms) may stay out.
WP_PLUGIN = re.compile(r"(?:wordpress|워드프레스)[^.;:!?\n]{0,40}?(?:plugin|theme|플러그인|테마)"
                       r"|(?:plugin|theme|extension|add-?on)s?\s+for\s+[^.;:!?\n]{0,40}?wordpress|\bwoocommerce\b|우커머스", re.IGNORECASE)


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


SITEMAP_SITES = 3


def sitemap_worthy(incident):
    """Listed in the sitemaps (owner, 2026-11-27): a search-worthy Incident that is also about a Product on
    collector/well_known.json, attacked, a story without a CVE, or told by SITEMAP_SITES sites or more besides its CVE
    records. On 11-26 Google held 293 of our pages in its index and had crawled 1,831 without indexing them; of the 3,561
    pages listed then, 70% were about a Product on no list and 896 had a CVE record as their only source. Only the list
    gets shorter (about 1,100 of those pages): every other page answers as before and stays search-worthy (no noindex;
    the feeds and the check documents do not change)."""
    if not search_worthy(incident):
        return False
    sites = {url_key(m["url"]).split("/", 1)[0] for m in incident["mentions"] if m["kind"] != "cve_record"}
    return bool(known_label(incident) or is_exploited(incident) or not incident["cves"] or len(sites) >= SITEMAP_SITES)


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


HANGUL = re.compile(r"[가-힣]")


def shown_name(summary, lang, k):
    """shownName in web/board.mjs: the k-th Summary product's name in this language, a Latin one that differs from the
    product name being the model shortening it. The localized name is read by position only when names is as long as
    products (11-17: a misaligned list showed the RHEL 10 id as "GStreamer"); named() aligns every view's lists."""
    products = summary.get("products") or []
    names = (summary.get(lang) or {}).get("names") or []
    local = names[k] if len(names) == len(products) and isinstance(names[k], str) else ""
    product = products[k]
    return product if local and product and not HANGUL.search(local) and local != product else local or product


def product_slots(incident, lang):
    """products_of's work: ({id: Product}, the id of each Summary product by position)."""
    found = {p["id"]: p for p in incident.get("products") or []}
    own = {pid: p["name"].lower() for pid, p in found.items()}  # matched by their own names, not the ones shown
    summary = incident.get("summary") or {}
    ids = []
    for k, name in enumerate(summary.get("products") or []):
        # The longest name it contains (11-17: "TELLUS Lite" is tellus_lite, not tellus); a view lists its record
        # Products longest first (named), so the first match in web/board.mjs is the same one.
        key = max((pid for pid, n in own.items() if n in name.lower()), key=lambda pid: len(own[pid]), default=None)
        key = key or f"name:{product_key(name)}"
        own.setdefault(key, name.lower())
        found[key] = {**found.get(key, {"id": key}), "name": shown_name(summary, lang, k)}
        ids.append(key)
    for os_name in summary.get("platforms") or []:
        found.pop(f"name:{os_name.lower()}", None)  # "Android" as a product and as a platform is one entry
        found[f"os:{os_name.lower()}"] = {"id": f"os:{os_name.lower()}", "name": os_name}
    return found, ids


def products_of(incident, lang):
    """A port of productsOf in web/board.mjs (tests/fixtures/board/products-case.json keeps the two in step)."""
    return list(product_slots(incident, lang)[0].values())


def name_form(pid, name):
    """Names of one Product that differ only by case or a leading vendor word ("JetBrains YouTrack", "youtrack")."""
    low = " ".join(name.lower().split())
    vendor = next((v for v in vendor_words(pid) if low.startswith(v) and len(low) > len(v)), "")
    return low[len(vendor):]


def chosen_names(incidents):
    """{(Product id, lang): the one name every view shows for it} (owner's rule, 11-17), over the Board's Incidents: the
    name_form group most rows use (a tie: the group of the earliest first seen, then the longer name), and in it a
    spelling a Summary wrote before one taken from the record, then not all lower case, then the most used, then the
    longer. The record Product's own name beats that name plus further words, whatever the counts ("Grav" over "Grav
    Lightbox Gallery"; the parent session's decision, 11-17), and stands even when no row writes it alone. Operating
    systems are left out."""
    seen, record = {}, {}
    for i in incidents:
        if on_board(i):
            for lang in ("ko", "en"):
                found, written = product_slots(i, lang)
                for pid, p in found.items():
                    if not pid.startswith("os:"):
                        seen.setdefault((pid, lang), []).append((p["name"], i["first_seen"], pid in written))
            for p in i.get("products") or []:
                record.setdefault(p["id"], Counter())[p["name"]] += 1
    chosen = {}
    for (pid, lang), rows in seen.items():
        groups = {}
        for row in rows:
            groups.setdefault(name_form(pid, row[0]), []).append(row)
        own = record[pid].most_common(1)[0][0] if pid in record else None
        base, mine = own and name_form(pid, own), own and " ".join(own.lower().split())
        # Whole names, not forms: name_form strips the id's vendor word, which can be the product ("nocobase:nocobase").
        plain = lambda g: " ".join(g[0][0].lower().split())  # noqa: E731
        longer = [f for f, g in groups.items() if own and f != base and plain(g) != mine
                  and re.search(rf"(?:^|\s){re.escape(mine)}(?:\s|$)", plain(g))]
        if longer:
            groups.setdefault(base, [(own, "~", False)])  # "~" sorts after every stamp: no row is this early
            for f in longer:
                # Words only in front are a vendor the vendor lists lack ("Thales SafeNet ..."): its spelling, same group.
                # Words after (or both) are a sub-product: dropped.
                rows_of = groups.pop(f)
                if plain(rows_of).endswith(f" {mine}"):
                    groups[base] += rows_of
        group = min(groups.values(), key=lambda g: (-len(g), min(r[1] for r in g), -max(len(r[0]) for r in g)))
        # The record's machine name (nvd.display_name of the id) counts as derived even where a Summary copied it from the
        # input's Products line (8 of the live month's "Openshift" rows did).
        machine = nvd.display_name(pid.split(":", 1)[1]) if ":" in pid and not pid.startswith("name:") else None
        count, wrote = Counter(r[0] for r in group), {r[0] for r in group if r[2] and r[0] != machine}
        chosen[(pid, lang)] = min(count, key=lambda n: (n not in wrote, n == n.lower(), -count[n], -len(n), n))
    return chosen


def named(incidents):
    """The Incidents as the views show them: each Product with its chosen name (chosen_names), the stored ones untouched.
    The Summary's products and both languages' names are rewritten by position (so web/board.mjs productsOf, the pages,
    feeds and /api/check read the chosen names without a change of their own), a record Product no Summary name stands
    for takes its chosen English name. The record Products keep the record's order (the page's vendor fold and pin key
    read the first, a Brief-only row shows them in it) unless productsOf's first match would then give a Summary name
    to another Product than product_slots picks: then the rest, or failing that all, go longest name first (11-17)."""
    aliases = product_aliases(incidents)
    incidents = [one_id(i, aliases) for i in incidents]
    chosen = chosen_names(incidents)
    return [with_names(i, chosen) for i in incidents]


# What two spellings of one record Product id may differ by: letter case, spaces, punctuation, a doubled space ("AMD
# Ryzen™ Embedded 5000 Series  Processors"). "#", "+" and "*" are kept: they tell products apart ("MongoDB C# Driver" and
# "MongoDB C Driver").
SPELLING = re.compile(r"[^\w#+*]|_")


def id_form(pid):
    vendor, _, product = pid.partition(":")
    return f"{SPELLING.sub('', vendor.lower())}:{SPELLING.sub('', product.lower())}"


def product_aliases(incidents):
    """{record Product id: the id of the Product it is}, for ids that are one Product (owner, 11-27: "뼈대 잡혔으니 추천안대로
    진행해"; one product had two pages and split counts): ids spelled alike (id_form: "redhat:exploit_intelligence" and
    "red_hat:exploit_intelligence"), and ids of the same product under two vendors that one Incident's record lists
    together (the CNA's "aio-libs:aiohttp" beside NVD's "aiohttp:aiohttp"). The same product name under two vendors
    without that is left apart: "automattic:mongoose" and "cesanta:mongoose" are two products. Of one group the id kept is
    the one on collector/well_known.json, then with a web/vendors.json vendor, then without a doubled space, then the
    first in order: never by counts, so a product page's address does not move from day to day."""
    parent = {}

    def root(pid):
        while parent.setdefault(pid, pid) != pid:
            pid = parent[pid]
        return pid

    def join(a, b):
        parent[root(a)] = root(b)

    by_form = {}
    for incident in incidents:
        ids = [p["id"] for p in incident.get("products") or []]
        for pid in ids:
            join(pid, by_form.setdefault(id_form(pid), pid))
        tails = {}
        for pid in ids:
            join(pid, tails.setdefault(id_form(pid).split(":", 1)[1], pid))
    groups = {}
    for pid in parent:
        groups.setdefault(root(pid), []).append(pid)
    kept = lambda pid: (not KNOWN_IDS.match(pid.lower()), pid.split(":")[0] not in VENDORS, "__" in pid, pid)  # noqa: E731
    return {pid: best for group in groups.values() if len(group) > 1 for best in [min(group, key=kept)] for pid in group
            if pid != best}


def one_id(incident, aliases):
    """The Incident with each record Product under its kept id (product_aliases), one entry per id, the record's order."""
    records = incident.get("products") or []
    if not any(p["id"] in aliases for p in records):
        return incident
    seen = {}
    for p in records:
        seen.setdefault(aliases.get(p["id"], p["id"]), {**p, "id": aliases.get(p["id"], p["id"])})
    return incident | {"products": list(seen.values())}


def first_match_ids(records, products):
    """web/board.mjs productsOf's id for each Summary product: the first listed Product whose name, as shown so far, the
    Summary's name contains."""
    found, ids = {p["id"]: p["name"] for p in records}, []
    for name in products:
        key = next((pid for pid, n in found.items() if n.lower() in name.lower()), None) or f"name:{product_key(name)}"
        found[key] = name
        ids.append(key)
    return ids


def with_names(incident, chosen):
    summary = incident.get("summary") or {}
    products, records = summary.get("products") or [], incident.get("products") or []
    if not products and not records:
        return incident
    # record_order: known_label's order, the record's own (11-17: the Office group was labelled Windows by a longer name);
    # no view writes it (PAGE_FIELDS, ROW_FIELDS).
    view = dict(incident) | {"record_order": [p["id"] for p in records]}
    ids = product_slots(incident, "en")[1]
    order = [{**p, "name": chosen.get((p["id"], "en"), p["name"])} if p["id"] not in ids else p for p in records]
    if products:
        en = [chosen.get((ids[k], "en"), name) for k, name in enumerate(products)]
        # A Korean name shows as such; a Latin one would show the product name anyway (shown_name).
        ko = [n if HANGUL.search(n := chosen.get((ids[k], "ko")) or "") else en[k] for k in range(len(products))]
        view["summary"] = summary | {"products": en} | {lang: (summary.get(lang) or {}) | {"names": names}
                                                          for lang, names in (("ko", ko), ("en", en))}
        # A record Product a Summary name stands for keeps its own name, unless the chosen name no longer contains it
        # (one id of two spellings, product_aliases: "pardus-boot-repair" for "Pardus Boot Repair"): then it takes that
        # name, so productsOf matches the Summary name to it again instead of making a second Product of it.
        shown = {pid: en[k] for k, pid in reversed(list(enumerate(ids)))}
        order = [{**p, "name": shown[p["id"]]} if p["id"] in shown and p["name"].lower() not in shown[p["id"]].lower() else p
                 for p in order]
        longest = lambda ps: sorted(ps, key=lambda p: -len(p["name"]))  # noqa: E731
        for candidate in (order, order[:1] + longest(order[1:]), longest(order)):
            if first_match_ids(candidate, en) == ids:
                order = candidate
                break
        else:
            order = longest(order)
    view["products"] = order
    return view


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


# Well-known Products (Highlight, CONTEXT.md; owner, 11-11): kind -> label -> {"ids": fnmatch patterns, "names": aliases}.
# How to add one: docs/agents/vendors.md.
_KINDS = json.loads((Path(__file__).parent / "well_known.json").read_text(encoding="utf-8"))
WELL_KNOWN = {label: entry for kind in _KINDS.values() for label, entry in kind.items()}
# Label -> its kind ("Browsers"): with the vendor, one of a row's same keys (sameKeys in web/board.mjs).
LABEL_KIND = {label: kind for kind, labels in _KINDS.items() for label in labels}
LABELS = list(WELL_KNOWN)
# One pattern, one group per label in file order, so a Product id is matched once, not once per pattern.
KNOWN_IDS = re.compile("|".join(f"({'|'.join(fnmatch.translate(p.lower()) for p in e['ids']) or '(?!)'})" for e in WELL_KNOWN.values()))
# Lowercase name -> label; reversed, so a name listed twice belongs to the earlier label, as an id does.
KNOWN_NAMES = {n.lower(): label for label, e in reversed(WELL_KNOWN.items()) for n in (label, *e.get("names", []))}


def known_label(incident):
    """The label of the first Product on collector/well_known.json: its id matches a pattern, or its English name equals
    the label or an alias, as it is or without a leading vendor word (the id's vendor, or a web/vendors.json spelling:
    "Google Chrome" is "Chrome"); equal only, so "PHP" is not "phpMyAdmin". Operating-system tags never count. On no
    list, a Summary that calls the product widely used names its first Product. None otherwise."""
    products = [p for p in products_of(incident, "en") if not p["id"].startswith("os:")]
    order = {pid: n for n, pid in enumerate(incident.get("record_order") or [])}  # a view's: the record's own order
    products.sort(key=lambda p: order.get(p["id"], len(order)))
    for p in products:
        label = known_product(p)
        if label:
            return label
    if products and (incident.get("summary") or {}).get("widely_used") is True:
        return products[0]["name"]
    return None


def known_product(product):
    """One Product's label on collector/well_known.json (see known_label), or None."""
    pid, name = product["id"].lower(), product["name"].lower()
    found = KNOWN_IDS.match(pid)
    if found:
        return LABELS[found.lastindex - 1]
    for form in (name, *(name[len(v):] for v in vendor_words(pid) if name.startswith(v))):
        if form in KNOWN_NAMES:
            return KNOWN_NAMES[form]
    return None


OSES = ["Windows", "macOS", "Linux", "Android", "iOS"]  # OSES in web/board.mjs: known systems in this order on every row
MANY_DEVICES = 4


def with_vendor(product):
    """withVendor in web/board.mjs: a record Product named with its web/vendors.json vendor when the name lacks it."""
    vendor = VENDORS.get(product["id"].split(":")[0])
    return f"{vendor} {product['name']}" if vendor and vendor.lower() not in product["name"].lower() else product["name"]


def exact_os(product):
    """exactOs in web/board.mjs: the OSES name a record Product is exactly (its id's product part or English name)."""
    tail = str((product or {}).get("id")).split(":", 1)[-1]
    return next((o for o in OSES if (product or {}).get("name") == o or tail == o.lower()), None)


def row_platforms(incident):
    """rowPlatforms in web/board.mjs: the Summary's platforms; before any Summary, the record Products that are an OS."""
    s = incident.get("summary") or {}
    if s.get("platforms") or s.get("products"):
        return s.get("platforms") or []
    found = [o for o in map(exact_os, incident.get("products") or []) if o]
    return [o for k, o in enumerate(found) if o.lower() not in {x.lower() for x in found[:k]}]


def row_tags(incident, lang):
    """A port of rowTags in web/board.mjs (tests/fixtures/board/row-tags-case.json keeps the two in step): a row's tags,
    operating systems first in OSES order, then its Products (one that is also an OS only as the OS), then up to
    MANY_DEVICES device models, each name once whatever its letter case."""
    s = incident.get("summary") or {}
    products = s.get("products") or []
    names = [shown_name(s, lang, k) for k in range(len(products))] if products else [with_vendor(p) for p in incident.get("products") or []]
    platforms = row_platforms(incident)
    systems = {p.lower() for p in platforms}
    record = incident.get("products") or []
    of = lambda k: (products[k] if k < len(products) else None) if products else (exact_os(record[k]) if k < len(record) else None)
    own = [n for k, n in enumerate(names) if str(of(k) if of(k) is not None else "").lower() not in systems]
    devices = s.get("devices") or []
    rank = lambda p: OSES.index(p) if p in OSES else len(OSES)
    seen, tags = set(), []
    for name in [*sorted(platforms, key=rank), *own, *([] if len(devices) > MANY_DEVICES else devices)]:
        if name.lower() not in seen:
            seen.add(name.lower())
            tags.append(name)
    return tags


def vendor_words(pid):
    """Vendor words that may lead a Product's name, each with its space: web/vendors.json's, and its id's vendor."""
    return LED_BY + ([] if pid.startswith("name:") else [pid.split(":")[0].replace("_", " ") + " "])


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


def summary_failures(incidents, since):
    """Board Incidents first seen since `since` whose Summary was given up for good, newest first, for a person or an
    agent to fix by hand (owner, 11-10; docs/agents/summary-failures.md). shows: "summary" when an older Summary is
    still on the page (what the check rejected may be what it says), "brief" when the row has only its Brief."""
    given_up = [i for i in incidents if i["first_seen"] >= since and i.get("summary_error", {}).get("final") and on_board(i)]
    return [{"id": i["id"], "first_seen": i["first_seen"], "reason": plain_reason(i["summary_error"].get("reason", "")),
             "tries": i["summary_error"]["tries"], "shows": "summary" if i.get("summary") else "brief"}
            for i in sorted(given_up, key=lambda i: i["first_seen"], reverse=True)]


# Reasons that end in a string the model wrote as it liked (summaries.parse, summaries.stray_script), which may copy a
# source page.
FREE_TEXT_REASONS = ("lead is not an input URL", "cve_lines names a CVE not in the input", "text in another script")
REVIEW_REASON = "the review found"  # review.REASON (review.py imports nothing of incidents; a test keeps the two equal)


def plain_reason(reason):
    """A reason goes to an operator's agent through summary_failures.json. The collector writes it and cuts it to 200
    characters (summaries.failed); the rest quote model output: number tokens (NUMBER_RE), a version (VERSION_RE), API
    error text. A reason quoting free model text, or holding a character that is not printable, keeps only its own words
    before ": "; the whole reason stays on the Incident in its month file."""
    # The review's reason quotes the Summary and may follow other soft problems ("…; the review found: …"), 11-16.
    if reason.startswith(FREE_TEXT_REASONS) or REVIEW_REASON in reason or not reason.isprintable():
        head = reason.split(": ", 1)[0]
        return head if head.isprintable() else ""
    return reason


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
        **({"cve_scores": dict(group["cve_scores"])} if group.get("cve_scores") else {}),
        **({"public_dates": dict(group["public_dates"])} if group.get("public_dates") else {}),
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


MAX_CITED_LINKS = 50  # the monthly file carries these for a week; most pages cite a handful


def page_keys(page, page_url):
    """CVE IDs and outside link keys in a story's linked page (raw HTML or text). Links back to the page's
    own site are its navigation, not citations. Also the page's title and the cited CVEs named more than once in its
    text and its links to other sites (many: SecurityWeek's N-central story names the Axis CVE once and links its NVD
    page; fortirix's Optimjack post names Java4Shell once), for cited_by, and the cited GHSA ids it names outside a link,
    for cited_advisory."""
    own = url_key(page_url).split("/", 1)[0]
    urls = {url_key(u) for u in urls_in(page)}
    cves = page_cves(page, page_url)
    parser = _Links()
    if "<" in page[:2000]:
        parser.feed(page)
    outside = [h for h, _ in parser.links if h.lower().startswith(("http://", "https://")) and url_key(h).split("/", 1)[0] != own]
    text = " ".join(parser.text + outside) if "<" in page[:2000] else page
    # The page's own links first, then the addresses in its markup (images, styles, scripts): 11-19, BleepingComputer's
    # Drupal story held 97 such keys, and the 50 first in sort order were its images and ads, never its link to
    # drupal.org/sa-core-2026-017. Kept sorted.
    anchors = {url_key(h) for h in outside}
    cited = sorted(sorted((u for u in urls if u.split("/", 1)[0] != own), key=lambda u: (u not in anchors, u))[:MAX_CITED_LINKS])
    # A cited GHSA id the page names outside its links (a link's own text or address is no more than the link).
    prose = " ".join(parser.prose) if "<" in page[:2000] else URL_RE.sub(" ", page)
    named = [m[1] for m in map(CITED_ADVISORY.fullmatch, cited) if m and re.search(re.escape(m[1]), prose, re.I)]
    return {"cves": cves, "urls": cited, "title": " ".join(parser.title.split())[:300],
            "many": [c for c in cves if len(re.findall(re.escape(c), text, re.I)) > 1] + named}


class _Links(html.parser.HTMLParser):
    """A page's text (no script or style), its links as [href, text] and its <title>."""
    def __init__(self):
        super().__init__()
        self.text, self.links, self.skip, self.open, self.title, self.in_title = [], [], 0, False, "", False
        self.prose = []  # text outside links

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "template"):
            self.skip += 1
        elif tag == "a":
            self.links.append([dict(attrs).get("href") or "", ""])
            self.open = True
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "template") and self.skip:
            self.skip -= 1
        elif tag == "a":
            self.open = False
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if not self.skip:
            self.text.append(data)
            if self.open:
                self.links[-1][1] += data
            else:
                self.prose.append(data)
            if self.in_title and not self.title:
                self.title = data


def page_cves(page, page_url):
    """The CVE IDs a page cites: in a link to another site, in its own address, or in its text unless a link to another
    page of the same site names the ID in its address or text and the ID is no link's whole text. A "related posts"
    card or a sidebar names other posts' CVEs (aikido.dev, 11-12: a story folded into an unrelated Incident); a
    notice's reference list links each CVE to the site's own page with the ID as its text."""
    if "<" not in page[:2000]:
        return cves_in(page)  # plain text, e.g. an OpenSSH release note
    parser = _Links()
    parser.feed(page)
    own, here = url_key(page_url).split("/", 1)[0], url_key(page_url)
    links = []
    for href, text in parser.links:
        try:
            links.append((url_key(urljoin(page_url, href)), text.strip()))
        except ValueError:  # "http://[..." in scraped markup
            continue
    elsewhere = cves_in(" ".join(u for u, _ in links if u.split("/", 1)[0] != own)) + cves_in(page_url)
    siblings = {c for u, t in links if u.split("/", 1)[0] == own and u != here for c in cves_in(f"{u} {t}")}
    whole = {t.upper() for _, t in links if CVE_RE.fullmatch(t)}
    return list(dict.fromkeys(elsewhere + [c for c in cves_in(" ".join(parser.text)) if c not in siblings or c in whole]))


# A title about many flaws: a round-up names one CVE of many (SecurityWeek "Fortinet Patches Nearly 100
# Vulnerabilities", "Chipmaker Patch Tuesday: Over 200 Vulnerabilities ...", "Git 2.56.1 fixes six vulnerabilities").
ROUNDUP = re.compile(r"\b(?:nearly|over|more than|almost|about|around|dozens? of|several|multiple|\d+|two|three|four|five|six"
                     r"|seven|eight|nine|ten|eleven|twelve|dozen)\s+(?:[\w.-]+\s+){0,2}?(?:vulnerabilities|flaws|bugs|cves"
                     r"|security (?:holes|issues|defects)|zero-days)\b", re.I)


def roundup(keys, titles):
    """A title (the story's or its page's) that speaks of many flaws."""
    return any(ROUNDUP.search(t) for t in (*titles, keys.get("title")) if t)


def about(incident, keys, titles):
    """Whether a story's page, which names one of the Incident's CVEs, is about it and not about something wider (11-18:
    4 of the month's 21 folds were a round-up or a passing mention, fortirix's Optimjack post naming Java4Shell once): no
    title speaks of many flaws, and a title (the page's or the story's) names the CVE or a word of the Incident's
    product, or the page names the CVE more than once (keys["many"]), or it names several of the Incident's CVEs (the
    OpenJDK advisory of 11-17, all ten of the Java group's). Unsure stands alone: a fold cannot be undone."""
    from collector.summary_input import GENERIC_PRODUCT_WORDS  # summary_input imports this module
    heads = [t.lower() for t in (*titles, keys.get("title")) if t]
    if roundup(keys, titles):
        return False
    terms = {c.lower() for c in incident["cves"]} | {w.lower() for p in incident.get("products", []) for w in re.split(r"[\s/,()]+", p["name"])
                                                     if len(w) >= 4 and w.lower() not in GENERIC_PRODUCT_WORDS}
    return (any(t in h for h in heads for t in terms) or bool(set(keys.get("many", [])) & set(incident["cves"]))
            or len(set(keys["cves"]) & set(incident["cves"])) > 1)


def cited_by(incidents, keys, titles=()):
    """The one Incident a CVE-less story's page is about (a blog on sshole links sshhole.com): matched by a
    CVE ID or by a link to one of its advisory, write-up or repo pages. Several or none: [] (stands alone).
    A CVE ID outranks a link: when the page's CVE IDs are held by one Incident, that is the one whatever its links hit
    (11-18, the Java4Shell story also linked two other stories' write-ups), if the page is about it (about(); titles: the
    story's own); held by several, the one of them whose official advisory it links decides (11-20), or it stands alone.
    Only with no CVE hit do links decide alone, and the one must be named by a page no other Incident links; an advisory with no identifier (a vendor's list of notices, a changelog, a product
    page) names none."""
    from collector.cvelist import has_id  # cvelist imports this module
    urls = set(keys["urls"])
    pages = lambda i: {url_key(m["url"]): m for m in i["mentions"] if m["kind"] in ("advisory", "writeup", "repo")}
    linked = Counter(u for i in incidents for u in i["urls"])  # a Mention's page is one of its Incident's urls
    named = lambda i, kinds=("advisory", "writeup", "repo"): any(
        linked[u] == 1 and m["kind"] in kinds and (m["kind"] != "advisory" or has_id(m["url"])) for u, m in pages(i).items() if u in urls)
    by_cve = [i for i in incidents if set(i["cves"]) & set(keys["cves"])]
    if len(by_cve) > 1:
        # Several hold its CVEs: the one of them whose official advisory (one notice) it links, if exactly one, unless its
        # title speaks of many flaws (11-20: BleepingComputer's story on SA-CORE-2026-017 also named 018's CVE and two
        # old ones, and linked only drupal.org/sa-core-2026-017). A write-up or repo link never decides (owner, 11-18).
        picked = [i for i in by_cve if named(i, ("advisory",))]
        return picked if len(picked) == 1 and not roundup(keys, titles) else []
    if by_cve:
        return by_cve if about(by_cve[0], keys, titles) else []
    hits = [i for i in incidents if pages(i).keys() & urls]
    return hits if len(hits) == 1 and named(hits[0]) else []


def rejoin(incidents, since):
    """Fold each CVE-less Incident whose page cites exactly one other Incident into it, whichever came
    first; return the months changed. Citations older than `since` (a stamp) are dropped."""
    changed = set()
    for story in [i for i in incidents if i.get("cites")]:
        old = story["first_seen"] < since or story["cves"]
        hits = [] if old else cited_by([i for i in incidents if i is not story], story["cites"], [m.get("title") for m in story["mentions"]])
        # After the fold check: the advisory's address on the story first would make cited_by count its page twice.
        key = None if hits else cited_advisory(story["cites"])
        if key and key not in story["urls"]:
            story["mentions"].append({"kind": "advisory", "url": f"https://{key}"})
            story["urls"] = sorted(set(story["urls"]) | {key})
            story["brief"]["lead"] = lead(story["mentions"])
            changed.add(month_of(story["first_seen"]))
        if key and not old:
            # The one other Incident that holds the advisory among its own links is the story's (11-19: CVE-2026-132825's
            # record linked Ruby2Shell's GHSA, which cited_by never sees: it reads Mention pages only). The story's
            # advisory Mention travels with the fold, so that row's Summary reads it too.
            holders = [i for i in incidents if i is not story and key in i["urls"]]
            hits = holders if len(holders) == 1 else []
        if hits:
            fold(incidents, hits[0], story)
            changed |= {month_of(story["first_seen"]), month_of(hits[0]["first_seen"])}
        if old:
            del story["cites"]
            changed.add(month_of(story["first_seen"]))
    return changed


# A GitHub security advisory, by its url_key: a repository's own (github.com/ruby/ruby/security/advisories/GHSA-...) or
# GitHub's database entry (github.com/advisories/GHSA-...).
CITED_ADVISORY = re.compile(r"github\.com/(?:[\w.-]+/[\w.-]+/security/)?advisories/(GHSA(?:-[0-9a-z]{4}){3})", re.I)


def cited_advisory(cites):
    """The url_key of the one official advisory a story's page cites, which rejoin makes a Mention of the story (11-19,
    Ruby2Shell: the write-up's narrower wording reached the Summary while the GHSA it linked was never read), so the
    Summary reads it, the Board lists it and it may become the Lead; or None. Only when the page cites exactly one (a
    round-up linking several says nothing about which is this one's) and is about it: its title names the GHSA id, or
    its text outside links does (cites["many"]; 11-19: a blog on AI security linked an old OpenClaw GHSA once,
    Ruby2Shell's page named its own ten times)."""
    # shortcut: anyone may publish a security advisory on a repository they own, so a submitted page can bring text the
    # Summary trusts (summary_input.trusted); check the repository against the Incident's product if that is abused.
    hits = [m for m in map(CITED_ADVISORY.fullmatch, cites.get("urls", [])) if m]
    if len(hits) != 1:
        return None
    ghsa = hits[0][1].lower()
    named = ghsa in (cites.get("title") or "").lower() or ghsa in {i.lower() for i in cites.get("many", [])}
    return hits[0][0] if named else None


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
            # Only a CVE record says "advisory"; it beats the write-up an HN link guessed for the same page.
            for t in target["mentions"]:
                if url_key(t["url"]) == url_key(m["url"]):
                    t["kind"] = "advisory"
                    if m.get("severity"):  # a vendor feed's read (vendors.read_severity) on the page a record cited first
                        t["severity"] = m["severity"]
        elif url_key(m["url"]) not in seen:
            seen.add(url_key(m["url"]))
            target["mentions"].append(m)
    target["urls"] = sorted(set(target["urls"]) | set(other["urls"]) | seen)
    target["brief"]["lead"] = lead(target["mentions"])
    if other.get("published"):
        set_published(target, other["published"])
    enrich(target, {"cvss": other.get("cvss"), "products": other.get("products", [])})
    # Per CVE, only for CVEs the target holds: a narrowed join (link, not trusted) lends no other CVE's score.
    for cve, entry in (other.get("cve_scores") or {}).items():
        if cve in target["cves"]:
            scores = target.setdefault("cve_scores", {})
            if "record" in entry:  # a page's raise: the record's own pair first, so it stays under the raise
                merge_score(scores, cve, entry["record"]["cvss"], entry["record"]["vector"])
            merge_score(scores, cve, entry["cvss"], entry["vector"], entry.get("by", ""), entry.get("version", ""))
    for cve, day in (other.get("kev_cves") or {}).items():
        if cve in target["cves"]:
            listed = target.setdefault("kev_cves", {})
            listed[cve] = listed.get(cve) or day
    merge_public_dates(target, other.get("public_dates"))
    for cve, lines in (other.get("distro_lines") or {}).items():
        if cve in target["cves"]:
            target.setdefault("distro_lines", {}).setdefault(cve, lines)
    # link and group_releases fold before the cycle's KEV loop, which skips a cycle whose catalogue failed: the flag and
    # its earliest day travel with the CVEs, or basis() and needs_summary would read the fold as unlisted.
    if other.get("kev"):
        target["kev"] = True
    days = sorted(d for d in (target.get("kev_date"), other.get("kev_date")) if d)
    if days:
        target["kev_date"] = days[0]


# User, 2026-11-09: more than two CVEs for one product, fixed in the same version and published within two days, are one
# Incident (a release note's worth), so one vendor's batch of fixes takes one row and one Highlight slot.
GROUP_MIN_CVES = 3
GROUP_HOURS = 48
# A Red Hat (also its Hardened Images), Fedora, Amazon, openEuler, Debian, Ubuntu or Alpine package version
# ("1.16.1-8.el8_10", "1.16.2-7.1.hum1", "1.22.0-2+deb12u3", "10.3_p1-r2"). A digit before "-r": "KobiPBX-FOP3-SEC-r1" is a build.
DISTRO_PACKAGE = re.compile(r"-\d+(?:\.\d+)*\.(?:el|fc|amzn|oe|hum)\d|[+~-]\d*(?:deb|ubuntu)\d|\d-r\d+\b")
SUMMARY_KEY = "summary:"  # a key made from a Summary, never stored and never a bound (fixed_conflict reads only "<" keys)


def summary_key(incident):
    """Owner, 11-16: a CVE Incident no record gives a key (Apache Shiro's, before cvelistV5 has its records) is keyed by
    its Summary's one product and fixed version: "summary:apache shiro=3.0.2". Made at each group_releases from the
    Summary as it stands, so a changed fixed version changes it and a record's key replaces it. The product is lowercased
    with its punctuation folded to single spaces and nothing else: an unsure match stays apart. None without one product
    of three letters or more, or with a fixed version that has no digit or is a distribution's package."""
    s = incident.get("summary") or {}
    products, fixed = s.get("products") or [], s.get("fixed")
    # One CVE, and a Summary written for exactly it: a merge's stranger, or a group's re-written Summary naming the next
    # release, must not carry the key (review, 11-16).
    if len(incident.get("cves") or []) != 1 or (incident.get("summary_basis") or {}).get("cves") != incident["cves"] \
            or incident.get("fix_keys") or not s.get("incident", True) or len(products) != 1:
        return None
    product = " ".join(re.sub(r"[^\w]+", " ", str(products[0]).lower()).split())
    if len(product) < 3 or not isinstance(fixed, str) or not re.search(r"[0-9]", fixed) or DISTRO_PACKAGE.search(fixed):
        return None
    return f"{SUMMARY_KEY}{product}={fixed.strip()}"


def release_keys(incident):
    """The keys group_releases ties an Incident by: its records' fix keys, or else its Summary's (summary_key)."""
    return incident.get("fix_keys") or [k for k in [summary_key(incident)] if k]


def release_clusters(members):
    """The holders of one fix key (sorted by publish time) cut into bursts: a burst starts at a member and takes those
    published within GROUP_HOURS of it; the next starts at the first one past that (owner, 11-16: one Airflow holder
    from August kept 11 Incidents published within three hours on 11-09 apart)."""
    clusters = []
    for i in members:
        when = datetime.strptime(published_at(i), STAMP)
        if clusters and (when - clusters[-1][0]).total_seconds() <= GROUP_HOURS * 3600:
            clusters[-1][1].append(i)
        else:
            clusters.append((when, [i]))
    return [found for _, found in clusters]


def group_releases(incidents):
    """Merge the Incidents of one release (same fix key, one burst of release_clusters) once they hold GROUP_MIN_CVES
    CVEs or more; the earliest seen keeps its id. A group whose burst has passed takes no late joiner: that one starts a
    burst of its own. Each CVE's own description stays in "cve_texts" for the page. Returns the months changed."""
    changed = set()
    keys = {i["id"]: release_keys(i) for i in incidents}  # read once: a fold below changes the target's own
    for key in sorted({k for ks in keys.values() for k in ks}):
        if not re.search(r"[0-9]", key.split("<", 1)[-1]):
            continue  # owner, 11-16: no digit, no version; stored ones ("google:android<=Android kernel") tie nothing
        holders = (i for i in incidents if key in i.get("fix_keys", []) or key in keys.get(i["id"], ()))
        for members in release_clusters(sorted(holders, key=published_at)):
            changed |= fold_release(incidents, members)  # bursts share no member, so one's fold leaves the next whole
    return changed


def fold_release(incidents, members):
    """One burst's Incidents into the earliest seen, when they are 2 or more with GROUP_MIN_CVES CVEs; the months changed."""
    if len(members) < 2 or len({c for i in members for c in i["cves"]}) < GROUP_MIN_CVES:
        return set()
    target = min(members, key=lambda i: i["first_seen"])
    texts = target.setdefault("cve_texts", {c: target["brief"]["text"] for c in target["cves"]})
    links = target.setdefault("cve_links", own_links(target))
    changed = {month_of(target["first_seen"])}
    for other in members:
        if other is target:
            continue
        texts.update(other.get("cve_texts") or {c: other["brief"]["text"] for c in other["cves"]})
        links.update(other.get("cve_links") or own_links(other))
        fold(incidents, target, other)
        changed.add(month_of(other["first_seen"]))
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


def merge_public_dates(incident, dates):
    """M4: keep each CVE's earliest Public date (a UTC day) on the Incident, for CVEs it holds only (a narrowed join lends
    none). True when an entry changed; the Public date backfill applies its patch through this too."""
    changed = False
    for cve, day in (dates or {}).items():
        if cve in incident["cves"] and day < (incident.get("public_dates") or {}).get(cve, "9999"):
            incident.setdefault("public_dates", {})[cve] = day
            changed = True
    return changed


def merge_score(scores, cve, score, vector, by="", version=""):
    """Keep `score` and its own vector as `cve`'s entry in a cve_scores map when it has none or this one is strictly
    higher, so an equal score never flips the vector between cycles. by: who gave a score read from a page
    (sheets.page_scores), with the CVSS version the page names ("4.0", or none). Such an entry is {"cvss": the page's
    score, "vector": "", "by", "version", "record": {"cvss", "vector"}}:
    the record's (or NVD's) own pair stays under "record", and a higher record or NVD score that is still not above the
    page's updates it there. True when the entry changed."""
    old = scores.get(cve)
    if score is None:
        return False
    if old and score <= old["cvss"]:
        if by or "record" not in old or score <= old["record"]["cvss"]:
            return False
        old["record"] = {"cvss": score, "vector": vector or ""}
        return True
    if by:
        record = old and old.get("record", {"cvss": old["cvss"], "vector": old["vector"]})
        scores[cve] = ({"cvss": score, "vector": "", "by": by} | ({"version": version} if version else {})
                       | ({"record": record} if record else {}))
    else:
        scores[cve] = {"cvss": score, "vector": vector or ""}
    return True


def enrich(incident, data, cve=None):
    """Fold one CVE's NVD data into its Incident; an Incident with several CVEs keeps the union. Given the CVE, its score
    and vector also go to cve_scores (merge_score)."""
    if data["cvss"] is not None:
        # shortcut: keeps the highest score, so a downward NVD revision is not applied (per CVE too).
        incident["cvss"] = max(incident.get("cvss", 0), data["cvss"])
        if cve:
            merge_score(incident.setdefault("cve_scores", {}), cve, data["cvss"], data.get("vector"))
    merged = {p["id"]: p for p in incident.get("products", []) + data["products"]}
    if merged:
        incident["products"] = sorted(merged.values(), key=lambda p: p["id"])
    if data.get("published") and to_stamp(data["published"]):
        set_published(incident, to_stamp(data["published"]))  # NVD's publish date, for Incidents whose sources gave none


def lead(mentions):
    return min(mentions, key=lambda m: LEAD_ORDER.index(m["kind"]))["url"]  # first wins a tie


def has_record(incident):
    return any(m["kind"] == "cve_record" for m in incident["mentions"])
