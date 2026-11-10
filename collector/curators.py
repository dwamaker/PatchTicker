"""Mention source: curator RSS feeds (security newsletters). An issue only joins Incidents it cites."""

import html

from collector import rss
from collector.incidents import cves_in, urls_in

# tl;dr sec (RSS from its home page) and the Risky Business News newsletter. ThinkstScapes has no feed (11-07).
# Measured 11-10: risky.biz/feeds/risky-business-news/ is the podcast (empty bodies, no CVE ID: it never cited one of
# 7,384 Mentions); news.risky.biz/rss/ is RSS 2.0, 15 issues of 47-75 KB with their links and CVE IDs (1.1 MB in all).
FEEDS = ("https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml", "https://news.risky.biz/rss/")
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


def fetch(checkpoints, http_get, feeds, stamp):
    """Return (citations in items newer than each feed's checkpoint, next checkpoints).

    Checkpoints are {feed URL: newest pubDate seen, ISO-8601 UTC}, never later than the cycle's stamp. One request per
    feed per cycle; a feed that fails is skipped, so one dead newsletter never stops the Board.
    """
    checkpoints = dict(checkpoints or {})
    found = []
    for feed in feeds:
        cited, newest = rss.read(feed, checkpoints.get(feed), http_get, stamp, citation, "curators")
        found += cited
        if newest:
            checkpoints[feed] = newest
    return found, checkpoints


def citation(item):
    title = rss.title(item)
    body = html.unescape(f"{item.findtext('description') or ''} {item.findtext(CONTENT) or ''}")
    return {
        "mention": {"kind": "curator", "url": item.findtext("link").strip(), "title": title},
        "cves": cves_in(f"{title} {body}"),
        "urls": urls_in(body),
    }
