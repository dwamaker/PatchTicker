"""Mention source: posts to the oss-security list, from the seclists.org RSS feed."""

import html

from collector import rss
from collector.incidents import cves_in, urls_in

FEED_URL = "https://seclists.org/rss/oss-sec.rss"


def fetch(checkpoint, http_get, stamp):
    """Return (Mention groups for posts newer than the checkpoint, next checkpoint).

    The checkpoint is the newest post's pubDate seen so far, as ISO-8601 UTC, never later than the cycle's stamp.
    One request per cycle.
    """
    return rss.read(FEED_URL, checkpoint, http_get, stamp, mention_group, "oss-security")


def mention_group(item):
    title = rss.title(item)
    body = html.unescape(item.findtext("description") or "")
    return {
        "mentions": [{"kind": "discussion", "url": item.findtext("link").strip(), "title": title}],
        "cves": cves_in(f"{title} {body}"),
        "urls": urls_in(body),
        "text": title,
        "published": rss.posted(item),
        # A reply that cites nothing known is thread chatter, not an Incident of its own.
        "join_only": title.lower().startswith("re:"),
    }
