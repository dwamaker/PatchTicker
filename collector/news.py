"""Mention source: security news sites. Their editors pick what matters, so a story they run (or an HN story linking
to one) is summarized at once, whatever its HN points. A CVE-less story still shows only once its Summary calls it an
Incident (on_board), so general news (an arrest, a scam) stays off the Board."""

from collector import rss
from collector.hn import SECURITY_RE
from collector.incidents import cves_in

# Owner, 2026-11-10: start with two feeds; more feeds bring more general news. The sites whose stories count as
# news (an HN story linking to one included) are incidents.NEWS_HOSTS.
FEEDS = ("https://www.bleepingcomputer.com/feed/", "https://www.securityweek.com/feed/")


def fetch(checkpoints, http_get, feeds, stamp):
    """Return (Mention groups for stories newer than each feed's checkpoint, next checkpoints).

    Checkpoints are {feed URL: newest pubDate seen}, never later than the cycle's stamp. A feed that fails is skipped,
    so one dead site never stops the Board.
    """
    checkpoints = dict(checkpoints or {})
    groups = []
    for feed in feeds:
        found, newest = rss.read(feed, checkpoints.get(feed), http_get, stamp,
                                 lambda item: mention_group(item, rss.posted(item)), "news")
        groups += found
        if newest:
            checkpoints[feed] = newest
    return groups, checkpoints


def mention_group(item, posted):
    title = rss.title(item)
    link = item.findtext("link").strip()
    return {"mentions": [{"kind": "writeup", "url": link, "title": title}],
            "cves": cves_in(f"{title} {item.findtext('description') or ''}"), "urls": [], "text": title,
            "join_only": not SECURITY_RE.search(title), "published": posted}  # the title only: every URL there says /security/
