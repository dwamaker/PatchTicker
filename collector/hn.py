"""Mention source: Hacker News stories from the Algolia search API."""

import json
import re
from urllib.parse import urlencode, urlsplit

from collector.incidents import cves_in, is_http

SEARCH_URL = "https://hn.algolia.com/api/v1/search_by_date"
# Algolia allows 10,000 requests/h per IP; 10 pages per 15-minute cycle is 40/h.
MAX_PAGES = 10

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


def mention_group(hit):
    title = " ".join((hit.get("title") or "").split())
    link = hit.get("url")
    # shortcut: points as first seen (a story is read once), so a story that climbs later keeps its
    # early count; re-read recent stories' points if Highlights miss HN buzz.
    mentions = [{"kind": "discussion", "url": f"https://news.ycombinator.com/item?id={hit['objectID']}",
                 "title": title, "points": hit.get("points") or 0}]
    if is_http(link):
        mentions.append({"kind": "repo" if is_repo(link) else "writeup", "url": link})
    text = f"{title} {link or ''}"
    return {"mentions": mentions, "cves": cves_in(text), "urls": [], "text": title, "join_only": not SECURITY_RE.search(text)}


def is_repo(url):
    parts = urlsplit(url)
    return parts.netloc.lower() == "github.com" and len(parts.path.strip("/").split("/")) == 2
