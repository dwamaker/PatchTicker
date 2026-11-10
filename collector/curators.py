"""Mention source: curator RSS feeds (security newsletters). An issue only joins Incidents it cites."""

import html
import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from collector import rss
from collector.incidents import cves_in, urls_in

# tl;dr sec (RSS from its home page) and Risky Business News. ThinkstScapes has no feed (11-07).
# shortcut: Risky Business News was checked to exist (application/xml) but its items were not read; RSS 2.0 assumed.
FEEDS = ("https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml", "https://risky.biz/feeds/risky-business-news/")
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


def fetch(checkpoints, http_get, feeds):
    """Return (citations in items newer than each feed's checkpoint, next checkpoints).

    Checkpoints are {feed URL: newest pubDate seen, ISO-8601 UTC}. One request per feed per cycle;
    a feed that fails is skipped, so one dead newsletter never stops the Board.
    """
    checkpoints = dict(checkpoints or {})
    found = []
    for feed in feeds:
        try:
            items = ET.fromstring(http_get(feed)).iter("item")
            since = checkpoints.get(feed)
            for item in items:
                posted = rss.posted(item)
                if since and posted <= since:
                    continue
                checkpoints[feed] = max(checkpoints.get(feed) or posted, posted)
                found.append(citation(item))
        except (OSError, ET.ParseError, AttributeError, TypeError, ValueError, OverflowError) as err:
            print(f"curators: skipped {feed}: {err!r}", file=sys.stderr)
    return found, checkpoints


def citation(item):
    title = rss.title(item)
    body = html.unescape(f"{item.findtext('description') or ''} {item.findtext(CONTENT) or ''}")
    return {
        "mention": {"kind": "curator", "url": item.findtext("link").strip(), "title": title},
        "cves": cves_in(f"{title} {body}"),
        "urls": urls_in(body),
    }
