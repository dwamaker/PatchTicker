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

from collector import rss, summary_input
from collector.incidents import STAMP, cves_in, stamp_ago

# Per feed: "own" matches the title of an advisory on the vendor's own product; any other item only joins (when
# unsure, join only). "other" (optional) matches title + description of a post on another project's flaw. "link"
# (optional) rewrites the item's link to the form CVE records cite, so the two join by URL.
FEEDS = {
    "https://www.synology.com/api/rssfeed/security/en-global": {
        # "Synology-SA-26:21 DSM, BeeStation OS" starts; "Synology-SA-26:17 Plex Media Server (Plex2Shell)", Samba,
        # Linux kernel, OpenSSL, Docker, WordPress and other packaged projects only join. Measured on the 448 items of
        # 2026-11-19; a Synology product missing here only joins (its CVE record still brings it).
        "own": re.compile(r"^Synology-SA-\d+:\d+ (DSM|SRM|BSM|Bee\w*|Synology|Active\w*|C2|\w+ Station|Calendar|Chat|Contacts"
                          r"|Drive|Office|MailPlus|(Mail|Media|SSO|DNS|RADIUS|LDAP|WebDAV|CardDAV|Git|Directory) Server"
                          r"|VPN (Plus|Server)|SSL VPN Client|Safe Access|Hyper Backup|Snapshot Replication|Replication Service"
                          r"|Storage (Manager|Analyzer)|USB Copy|Antivirus Essential|Virtual Machine Manager|(Android )?Moments"
                          r"|DS \w+|Universal Search|SMB Service|Presto|Secure SignIn|VS\d+\w*)\b"),
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
FIRST_READ_DAYS = 3  # a feed's first read lets its last 3 days through (owner, 11-19: SA-26:21 must reach the Board)
MAX_AGE_DAYS = 30  # an unseen item older than this starts nothing: a changed guid format must not refill the Board
MAX_SEEN = 1000  # shortcut: ids kept per feed; raise it before listing a feed that holds more items than this


def fetch(checkpoints, http_get, feeds, stamp):
    """Return (Mention groups for items not seen before, next checkpoints). feeds: {feed URL: rules}, as FEEDS.

    Checkpoints are {feed URL: [guids seen]}: dates cannot order these feeds (date-only and revised dates exist). A
    feed's first read records its items older than FIRST_READ_DAYS as seen and reads the rest as new (no older backfill). A feed that fails, or reads as empty, keeps
    its checkpoint, so one dead site never stops the Board and never makes every old item new again.
    """
    checkpoints = dict(checkpoints or {})
    now = datetime.strptime(stamp, STAMP).replace(tzinfo=timezone.utc)
    oldest, recent = stamp_ago(now, days=MAX_AGE_DAYS), stamp_ago(now, days=FIRST_READ_DAYS)
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
            # oldest first, as later ones append; the recent ones stay unseen and go through the loop below
            checkpoints[feed] = [key for key, item in reversed(items) if not posted_since(item, recent)][-MAX_SEEN:]
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
                if not group["join_only"]:
                    read_severity(group["mentions"][0], http_get)
                groups.append(group)
        checkpoints[feed] = seen[-MAX_SEEN:]
    return groups, checkpoints


def read_severity(mention, http_get):
    """Store on an own advisory Mention the severity word its official page states (summary_input.severity_word), so a
    row with no CVSS yet that the vendor rates Critical or High is summarized at once (summaries.is_candidate), not left
    in a batch at 참고 (owner, 11-20: Synology-SA-26:21, SA-CORE-2026-017). Read here, once per new feed item: the
    checkpoint never shows the item again, so no cycle fetches it twice; the feed's own text has no such word
    (Synology's description) or has it only in the title (Drupal's), which never counts. Code reads it, never the model.
    shortcut: a page that fails to load stores nothing and the row waits for its batch as before; no retry."""
    url = mention["url"]
    page = summary_input.fetch_page(http_get, url)
    text = summary_input.page_text(page, url) if page else None
    word = summary_input.severity_word(text) if text else None
    if word:
        mention["severity"] = word


def posted_since(item, stamp):
    try:
        return rss.posted(item) >= stamp
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False  # an unreadable date counts as old: recorded, never started


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
