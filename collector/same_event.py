"""same_as: merging CVE-less Incidents that a Summary reply names as the same event."""

import sys

from collector.incidents import fold, month_of, on_board, products_of, published_at, stamp_ago

# Owner, 11-10: CVE-less stories of one event (Plex2Shell on BleepingComputer and SecurityWeek, 68 h apart) stayed apart,
# as only a shared CVE or URL links Incidents. Their Summary request lists these candidates; the model names one in
# same_as and apply_same_as decides. A merge cannot be undone, so the rules narrow the list and check the answer.
SAME_AS_DAYS = 7
SAME_AS_MAX = 20
SAME_AS_ID_CHARS = 200  # a longer id is left out, so the list stays under about 7,900 characters
SAME_AS_HEAD = "Recent Incidents without a CVE, newest first (id | title | products); same_as names one of these ids or \"\":"


def same_as_candidates(incident, incidents, now):
    """The Incidents a CVE-less Incident could be the same event as: Board Incidents with a Summary and no CVE, published
    (else first seen) in the last SAME_AS_DAYS, newest first, at most SAME_AS_MAX. None for an Incident with a CVE."""
    if incident["cves"]:
        return []
    since = stamp_ago(now, days=SAME_AS_DAYS)
    found = [i for i in incidents if i is not incident and i.get("summary") and not i["cves"] and on_board(i)
             and published_at(i) >= since and len(i["id"]) <= SAME_AS_ID_CHARS]
    return sorted(found, key=published_at, reverse=True)[:SAME_AS_MAX]


def same_as_text(candidates):
    """The candidate list sent beside the input: one short line each."""
    if not candidates:
        return ""
    line = lambda i: (f"- {i['id']} | {short(i['summary'].get('en', {}).get('title', ''), 100)}"
                      f" | {short(', '.join(i['summary'].get('products') or []), 80)}")
    return "\n".join([SAME_AS_HEAD, *map(line, candidates)])


def short(text, n):
    """Model text that reaches the prompt or merge_log.json (read by an operator's agent, as plain_reason's text is):
    cut to n characters, and empty when it holds a character that is not printable."""
    return text[:n] if isinstance(text, str) and text.isprintable() else ""


def product_ids(incident):
    # The picker's keys (products_of); an os: platform is a filter, not the Product (Chrome and a Windows bug share one).
    return {p["id"] for p in products_of(incident, "en") if not p["id"].startswith("os:")}


def apply_same_as(incidents, stamp):
    """Decide each same_as answer save_reply left on an Incident: merge the two when the id was listed in that request,
    that Incident still exists without a CVE and on the Board (and so does the asker), and the two share a Product;
    the earlier first seen survives, as in link(). Returns (months changed, merge_log.json entries, oldest first): one
    for every answer that named an id or had candidates listed; an accepted one also says which Incident survived ("into").
    Either side folded away meanwhile (an earlier answer this cycle, or a link() fold before a batch came back) stands
    for the Incident that absorbed it, so answers naming each other (A names B, B names A; three rows) end as one row,
    the second answer "already one", and no Incident is folded twice."""
    changed, log = set(), []
    for asker in [i for i in incidents if "same_as" in i]:
        wish = asker.pop("same_as")
        here = holder(incidents, asker["id"])
        other = holder(incidents, wish["id"]) if wish["id"] else None
        why = ("none named" if not wish["id"] else "not listed" if wish["id"] not in wish["listed"]
               else "gone" if other is None or here is None else "already one" if other is here
               else "has a CVE now" if other["cves"] or here["cves"]
               else "not on the Board" if not (on_board(other) and on_board(here))
               else "no shared Product" if not product_ids(here) & product_ids(other) else "accepted")
        title = lambda i: short(i["summary"].get("en", {}).get("title", ""), 100) if i and i.get("summary") else ""
        log.append({"at": stamp, "incident": {"id": short(asker["id"], 300), "title": title(asker)}, "candidates": len(wish["listed"]),
                    "same_as": {"id": short(wish["id"], 300), "title": title(other)} if wish["id"] else "",
                    "accepted": why == "accepted", "why": why})
        if why == "accepted":
            survivor, gone = sorted((i for i in incidents if i is here or i is other), key=lambda i: i["first_seen"])
            log[-1]["into"] = short(survivor["id"], 300)
            survivor["merged"] = survivor.get("merged", []) + [gone["id"]]  # its re-summary trigger (needs_summary)
            fold(incidents, survivor, gone)
            changed |= {month_of(survivor["first_seen"]), month_of(gone["first_seen"])}
            print(f"summaries: same_as: merged {gone['id']} into {survivor['id']}", file=sys.stderr)
    return changed, log


def holder(incidents, incident_id):
    """The Incident with this id, else the one that absorbed it (fold), else None."""
    return (next((i for i in incidents if i["id"] == incident_id), None)
            or next((i for i in incidents if incident_id in i.get("absorbed", [])), None))
