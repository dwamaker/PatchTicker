"""Incident linking (ADR 0001): attach Mentions to Incidents by CVE ID or URL, merge, pick the Lead.

Each source adapter turns its items into Mention groups: {"mentions": [{"kind", "url", "title"?}],
"cves": [...], "urls": [cited URLs], "text": one line, "join_only": bool}. A join-only group
(a PoC repo, a reply, an off-topic story) is dropped unless it matches an existing Incident.
"""

import json
import re
from urllib.parse import urlsplit

# Lead mention order (CONTEXT.md): official advisory or release note, discoverer write-up,
# CVE record, discussion (a curator's newsletter is discussion too). Repositories are listed but come last.
LEAD_ORDER = ["advisory", "writeup", "cve_record", "discussion", "curator", "repo"]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


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
        "mentions": mentions,
        "urls": sorted({url_key(u) for u in group["urls"] + [m["url"] for m in mentions]}),
        "brief": {"text": group["text"], "lead": lead(mentions)},
    }
    hits = [i for i in incidents if matches(i, proto)]
    if not hits:
        if group.get("join_only"):
            return set()
        incidents.append(proto)
        return {stamp[:7]}
    target = min(hits, key=lambda i: i["first_seen"])  # min keeps the first of equal times
    before = json.dumps(target)
    changed = set()
    # Only a Mention that may start an Incident and cites a CVE ties existing Incidents together;
    # any other joins the earliest one (a PoC repo naming several CVEs must not merge their rows).
    merge = proto["cves"] and not group.get("join_only")
    for other in [i for i in hits if i is not target] if merge else []:
        absorb(target, other)
        incidents.remove(other)
        changed.add(other["first_seen"][:7])
    absorb(target, proto)
    if json.dumps(target) != before:
        changed.add(target["first_seen"][:7])
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
