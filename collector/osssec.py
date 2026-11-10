"""Mention source: posts to the oss-security list, from the seclists.org RSS feed."""

import html
import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from collector import rss
from collector.incidents import cves_in, urls_in

FEED_URL = "https://seclists.org/rss/oss-sec.rss"


def fetch(checkpoint, http_get, stamp):
    """Return (Mention groups for posts newer than the checkpoint, next checkpoint).

    The checkpoint is the newest post's pubDate seen so far, as ISO-8601 UTC, never later than the cycle's stamp.
    One request per cycle.
    """
    groups, newest = [], checkpoint
    try:
        items = ET.fromstring(http_get(FEED_URL)).iter("item")
    except (OSError, ET.ParseError) as err:
        # As news/curators/kisa: one bad feed skips oss-security this cycle, never the whole cycle.
        print(f"oss-security: skipped this cycle: {err!r}", file=sys.stderr)
        return [], checkpoint
    for item in items:
        try:
            posted = rss.posted(item)
            if checkpoint and posted <= checkpoint:
                continue
            group = mention_group(item)
        except (AttributeError, TypeError, ValueError, OverflowError) as err:
            print(f"oss-security: skipped an item: {err!r}", file=sys.stderr)
            continue
        newest = max(newest or posted, posted)
        groups.append(group)
    # A future-dated post must not become the checkpoint, or every real post before that date is skipped.
    return groups, newest and min(newest, stamp)


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
