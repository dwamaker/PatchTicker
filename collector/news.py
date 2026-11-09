"""Mention source: security news sites. Their editors pick what matters, so a story they run (or an HN story linking
to one) is summarized at once, whatever its HN points. A CVE-less story still shows only once its Summary calls it an
Incident (on_board), so general news (an arrest, a scam) stays off the Board."""

import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from collector import rss
from collector.hn import SECURITY_RE
from collector.incidents import cves_in

# Owner, 2026-11-10: start with two feeds; more feeds bring more general news. The sites whose stories count as
# news (an HN story linking to one included) are incidents.NEWS_HOSTS.
FEEDS = ("https://www.bleepingcomputer.com/feed/", "https://www.securityweek.com/feed/")


def fetch(checkpoints, http_get, feeds):
    """Return (Mention groups for stories newer than each feed's checkpoint, next checkpoints).

    Checkpoints are {feed URL: newest pubDate seen}. A feed that fails is skipped, so one dead site never stops the Board.
    """
    checkpoints = dict(checkpoints or {})
    groups = []
    for feed in feeds:
        try:
            since = checkpoints.get(feed)
            for item in ET.fromstring(http_get(feed)).iter("item"):
                posted = rss.posted(item)
                if since and posted <= since:
                    continue
                checkpoints[feed] = max(checkpoints.get(feed) or posted, posted)
                groups.append(mention_group(item, posted))
        except (OSError, ET.ParseError, AttributeError, TypeError, ValueError) as err:
            print(f"news: skipped {feed}: {err!r}", file=sys.stderr)
    return groups, checkpoints


def mention_group(item, posted):
    title = rss.title(item)
    link = item.findtext("link").strip()
    return {"mentions": [{"kind": "writeup", "url": link, "title": title}],
            "cves": cves_in(f"{title} {item.findtext('description') or ''}"), "urls": [], "text": title,
            "join_only": not SECURITY_RE.search(title), "published": posted}  # the title only: every URL there says /security/
