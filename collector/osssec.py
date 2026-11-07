"""Mention source: posts to the oss-security list, from the seclists.org RSS feed."""

import html
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from email.utils import parsedate_to_datetime

from collector.incidents import cves_in, urls_in

FEED_URL = "https://seclists.org/rss/oss-sec.rss"


def fetch(checkpoint, http_get):
    """Return (Mention groups for posts newer than the checkpoint, next checkpoint).

    The checkpoint is the newest post's pubDate seen so far, as ISO-8601 UTC. One request per cycle.
    """
    groups, newest = [], checkpoint
    for item in ET.fromstring(http_get(FEED_URL)).iter("item"):
        posted = parsedate_to_datetime(item.findtext("pubDate")).strftime("%Y-%m-%dT%H:%M:%SZ")
        if checkpoint and posted <= checkpoint:
            continue
        newest = max(newest or posted, posted)
        groups.append(mention_group(item))
    return groups, newest


def mention_group(item):
    title = " ".join((item.findtext("title") or "").split())
    body = html.unescape(item.findtext("description") or "")
    return {
        "mentions": [{"kind": "discussion", "url": item.findtext("link").strip(), "title": title}],
        "cves": cves_in(f"{title} {body}"),
        "urls": urls_in(body),
        "text": title,
        # A reply that cites nothing known is thread chatter, not an Incident of its own.
        "join_only": title.lower().startswith("re:"),
    }
