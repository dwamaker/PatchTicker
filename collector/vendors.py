"""Mention source: vendors' own security-advisory feeds (owner, 2026-11-19: Synology-SA-26:21, CVSS 9.8, had no CVE
record yet, so nothing reached the Board). An advisory on the vendor's own product is an Advisory Mention group that may
start an Incident, with or without a CVE ID, and joins an existing one by CVE ID or by its link. A post on another
project's flaw ("none of our products are affected by", a bundled library's fix) only joins, as discussion: its writer
is not that product's vendor (CONTEXT.md, Advisory), so it must never become another Incident's Lead.

Each feed is one FEEDS entry. Only RSS 2.0 with RFC-822 pubDates is read for now; Atom, JSON, ISO dates or an extra
request per item (Fortinet's CSAF link) need their own reader before such a feed is listed
(.scratch/checks/vendor-feeds-2026-11-19.md, section 4)."""

import re
import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from datetime import datetime, timezone

from collector import rss
from collector.incidents import STAMP, cves_in, stamp_ago

# Per feed: "own" matches the title of an advisory on the vendor's own product; any other item only joins (when
# unsure, join only). "other" (optional) matches title + description of a post on another project's flaw. "link"
# (optional) rewrites the item's link to the form CVE records cite, so the two join by URL.
FEEDS = {
    "https://www.synology.com/api/rssfeed/security/en-global": {
        # "Synology-SA-26:21 DSM, BeeStation OS" starts; "Synology-SA-26:17 Plex Media Server (Plex2Shell)" joins.
        "own": re.compile(r"^Synology-SA-\d+:\d+ (DSM|SRM|BSM|Bee\w*|Synology|Active Backup|Surveillance Station|C2)\b"),
        "other": re.compile(r"None of Synology's products are affected", re.I),
        # The feed links /support/security/Synology_SA_26_21; CVE records cite /security/advisory/Synology_SA_26_21.
        "link": lambda url: url.replace("/support/security/Synology_SA_", "/security/advisory/Synology_SA_"),
    },
    "https://www.drupal.org/security/rss.xml": {
        # A "Third-party libraries" release restates a bundled library's CVE (Guzzle, CKEditor). "not affected" is no
        # sign here: most core advisories say "Drupal 7 is not affected".
        "own": re.compile(r"^Drupal core - (?!.*Third-party libraries)"),
    },
}
MAX_AGE_DAYS = 30  # an unseen item older than this starts nothing: a changed guid format must not refill the Board
MAX_SEEN = 1000  # shortcut: ids kept per feed; raise it before listing a feed that holds more items than this


def fetch(checkpoints, http_get, feeds, stamp):
    """Return (Mention groups for items not seen before, next checkpoints). feeds: {feed URL: rules}, as FEEDS.

    Checkpoints are {feed URL: [guids seen]}: dates cannot order these feeds (date-only and revised dates exist). A
    feed's first read records its items and starts nothing (no backfill). A feed that fails, or reads as empty, keeps
    its checkpoint, so one dead site never stops the Board and never makes every old item new again.
    """
    checkpoints = dict(checkpoints or {})
    oldest = stamp_ago(datetime.strptime(stamp, STAMP).replace(tzinfo=timezone.utc), days=MAX_AGE_DAYS)
    groups = []
    for feed, rules in feeds.items():
        try:
            items = [(item_id(item), item) for item in ET.fromstring(http_get(feed)).iter("item")]
        except (OSError, ET.ParseError) as err:
            print(f"vendors: skipped {feed}: {err!r}", file=sys.stderr)
            continue
        items = [(key, item) for key, item in items if key]
        if not items:
            continue
        if feed not in checkpoints:
            checkpoints[feed] = [key for key, _ in items][-MAX_SEEN:]
            continue
        seen = list(checkpoints[feed])
        for key, item in items:
            if key in seen:
                continue
            try:
                group = mention_group(item, rules)
            except (AttributeError, TypeError, ValueError, OverflowError) as err:
                print(f"vendors: skipped an item: {err!r}", file=sys.stderr)
                continue  # not marked seen: the next cycle reads it again
            seen.append(key)
            if group["published"] >= oldest:
                groups.append(group)
        checkpoints[feed] = seen[-MAX_SEEN:]
    return groups, checkpoints


def item_id(item):
    return (item.findtext("guid") or item.findtext("link") or "").strip()


def mention_group(item, rules):
    title = rss.title(item)
    text = f"{title} {item.findtext('description') or ''}"
    url = item.findtext("link").strip()
    if "link" in rules:
        url = rules["link"](url)
    other = not rules["own"].search(title) or bool("other" in rules and rules["other"].search(text))
    # "urls" stays empty, as in news.py: Drupal's description is HTML full of links that would join unrelated rows.
    return {"mentions": [{"kind": "discussion" if other else "advisory", "url": url, "title": title}],
            "cves": cves_in(text), "urls": [], "text": title, "join_only": other, "published": rss.posted(item)}
