"""Mention source: Hacker News stories from the Algolia search API."""

import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from collector.incidents import STAMP, cves_in, is_http, month_of

SEARCH_URL = "https://hn.algolia.com/api/v1/search_by_date"
ITEM_URL = "https://news.ycombinator.com/item?id="
# Algolia allows 10,000 requests/h per IP; 10 pages and one points refresh per 15-minute cycle is 44/h.
MAX_PAGES = 10

# HN buzz: the points at which an HN story counts as a Highlight signal (also in web/board.mjs).
# 100 is about where a story reaches the front page: 277 of all HN stories got there in the week to
# 2026-11-08. The real run's general security news (a bank heist, a soldier's SIM card) peaked at 93;
# sshole was at 2,910 when first seen.
BUZZ_POINTS = 100

# shortcut: a story starts an Incident only if its title or URL has a security word; others only
# join a known Incident. Misses security stories with no such word; ticket 06's Summary can judge.
# "hole" catches named holes like "sshole" but not whole/wormhole/black hole.
SECURITY_RE = re.compile(
    r"cve-\d{4}-\d+|vulnerab|exploit|\brce\b|0-?day|zero-?day|backdoor|bypass|privilege escalation"
    r"|remote code|malware|ransomware|breach|compromis|hijack|advisory|security|(?<![wm\s-])hole\b",
    re.IGNORECASE,
)


def fetch(checkpoint, http_get):
    """Return (Mention groups for stories newer than the checkpoint, next checkpoint).

    The checkpoint is the newest story's created_at_i seen so far.
    """
    since = checkpoint or 0
    hits = []
    for page in range(MAX_PAGES):
        query = {"tags": "story", "hitsPerPage": 100, "numericFilters": f"created_at_i>{since}", "page": page}
        res = json.loads(http_get(f"{SEARCH_URL}?{urlencode(query)}"))
        hits += res["hits"]
        if page + 1 >= res["nbPages"]:
            break
    return [mention_group(h) for h in hits], max([since] + [h["created_at_i"] for h in hits])


def refresh_points(incidents, now, http_get):
    """Read again the points of the HN stories in Incidents first seen in the last seven days, so buzz
    that grows after first sight counts; return the months it changed. One request a cycle (44/h with
    fetch's ten), and none when no recent Incident has a story: only stories of the last seven days at
    BUZZ_POINTS or more, as only those can change a Highlight or the instant path much.

    shortcut: one page of 1,000; 277 stories reached 100 points in the week to 2026-11-08.
    """
    since = now - timedelta(days=7)
    recent = [i for i in incidents if i["first_seen"] >= since.strftime(STAMP)
              and any(m["url"].startswith(ITEM_URL) for m in i["mentions"])]
    if not recent:
        return set()
    query = {"tags": "story", "hitsPerPage": 1000, "attributesToRetrieve": "points",
             "numericFilters": f"created_at_i>{int(since.timestamp())},points>={BUZZ_POINTS}"}
    points = {ITEM_URL + h["objectID"]: h["points"] for h in json.loads(http_get(f"{SEARCH_URL}?{urlencode(query)}"))["hits"]}
    changed = set()
    for incident in recent:
        for m in incident["mentions"]:
            if m["url"] in points and m.get("points") != points[m["url"]]:
                m["points"] = points[m["url"]]
                changed.add(month_of(incident["first_seen"]))
    return changed


def mention_group(hit):
    title = " ".join((hit.get("title") or "").split())
    link = hit.get("url")
    # Points as first seen; refresh_points reads them again while the Incident is recent.
    mentions = [{"kind": "discussion", "url": ITEM_URL + hit["objectID"], "title": title, "points": hit.get("points") or 0}]
    if is_http(link):
        mentions.append({"kind": "repo" if is_repo(link) else "writeup", "url": link})
    text = f"{title} {link or ''}"
    return {"mentions": mentions, "cves": cves_in(text), "urls": [], "text": title, "join_only": not SECURITY_RE.search(text),
            "published": datetime.fromtimestamp(hit["created_at_i"], timezone.utc).strftime(STAMP)}


def is_repo(url):
    try:
        parts = urlsplit(url)
    except ValueError:  # a malformed reference ("http://[...") is not a repo
        return False
    return parts.netloc.lower() == "github.com" and len(parts.path.strip("/").split("/")) == 2
