"""Incident linking (ADR 0001): attach Mentions to Incidents by CVE ID or URL, merge, pick the Lead.

Each source adapter turns its items into Mention groups: {"mentions": [{"kind", "url", "title"?}],
"cves": [...], "urls": [cited URLs], "text": one line, "join_only": bool, "published"?: the
source's own post time}. A join-only group (a PoC repo, a reply, an off-topic story) is dropped
unless it matches an existing Incident.

An Incident's "published" is the earliest post time among the groups that could start it, so a
visitor sees when the news first broke, not when a cycle noticed it ("first_seen").
"""

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

STAMP = "%Y-%m-%dT%H:%M:%SZ"  # ISO-8601 UTC, so string order is time order

# Lead mention order (CONTEXT.md): official advisory or release note, discoverer write-up,
# CVE record, discussion (a curator's newsletter is discussion too). Repositories are listed but come last.
LEAD_ORDER = ["advisory", "writeup", "cve_record", "discussion", "curator", "repo"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


# What the Board page reads. Linking keys (urls, cites) and Summary bookkeeping stay in the collector's files:
# at about 650 Incidents a day they were over half of each Incident's bytes.
PAGE_FIELDS = ("id", "cves", "first_seen", "published", "mentions", "brief", "cvss", "kev", "products", "summary")


def board_view(incident):
    """The page's copy of an Incident; a failed Summary keeps only its final flag (the page's 'unavailable' note)."""
    view = {k: incident[k] for k in PAGE_FIELDS if k in incident}
    if incident.get("summary_error", {}).get("final"):
        view["summary_error"] = {"final": True}
    return view


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
    parts = urlsplit(url.strip())
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
        "published": min(group.get("published") or stamp, stamp),
        **({"cvss": group["cvss"]} if group.get("cvss") is not None else {}),
        **({"products": group["products"]} if group.get("products") else {}),
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
    # Only a Mention that may start an Incident and cites a CVE ties existing Incidents together;
    # any other joins the earliest one (a PoC repo naming several CVEs must not merge their rows).
    merge = proto["cves"] and not group.get("join_only")
    for other in [i for i in hits if i is not target] if merge else []:
        absorb(target, other)
        incidents.remove(other)
        changed.add(month_of(other["first_seen"]))
    if group.get("join_only"):
        del proto["published"]  # an old PoC repo or a reply joining later says nothing about when the news broke
    absorb(target, proto)
    if json.dumps(target) != before:
        changed.add(month_of(target["first_seen"]))
    return changed


MAX_CITED_LINKS = 50  # the public monthly file carries these for a week; most pages cite a handful


def page_keys(page, page_url):
    """CVE IDs and outside link keys in a story's linked page (raw HTML or text). Links back to the page's
    own site are its navigation, not citations."""
    own = urlsplit(page_url).netloc.lower().removeprefix("www.")
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
            absorb(hits[0], story)
            incidents.remove(story)
            changed |= {month_of(story["first_seen"]), month_of(hits[0]["first_seen"])}
    return changed


def matches(incident, proto):
    if set(incident["cves"]) & set(proto["cves"]):
        return True
    # URLs key an Incident only while it or the Mention has no CVE (spec: "keyed by its CVE IDs
    # when it has any"), so two CVE rows citing one project page stay apart.
    return not (incident["cves"] and proto["cves"]) and bool(set(incident["urls"]) & set(proto["urls"]))


def absorb(target, other):
    if has_record(other) and not has_record(target):
        target["brief"]["text"] = other["brief"]["text"]
    target["cves"] += [c for c in other["cves"] if c not in target["cves"]]
    seen = {url_key(m["url"]) for m in target["mentions"]}
    for m in other["mentions"]:
        if url_key(m["url"]) not in seen:
            seen.add(url_key(m["url"]))
            target["mentions"].append(m)
    target["urls"] = sorted(set(target["urls"]) | set(other["urls"]) | seen)
    target["brief"]["lead"] = lead(target["mentions"])
    if other.get("published"):
        target["published"] = min(target.get("published") or target["first_seen"], other["published"])
    enrich(target, {"cvss": other.get("cvss"), "products": other.get("products", [])})


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


def lead(mentions):
    return min(mentions, key=lambda m: LEAD_ORDER.index(m["kind"]))["url"]  # first wins a tie


def has_record(incident):
    return any(m["kind"] == "cve_record" for m in incident["mentions"])
