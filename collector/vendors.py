"""Mention source: vendors' own security-advisory feeds (owner, 2026-11-19: Synology-SA-26:21, CVSS 9.8, had no CVE
record yet, so nothing reached the Board). An advisory on the vendor's own product is an Advisory Mention group that may
start an Incident, with or without a CVE ID, and joins an existing one by CVE ID or by its link. A post on another
project's flaw ("none of our products are affected by", a bundled library's fix) only joins, as discussion: its writer
is not that product's vendor (CONTEXT.md, Advisory), so it must never become another Incident's Lead.

Each feed is one FEEDS entry and a reader for its format: RSS 2.0 (RFC-822 or ISO-8601 pubDates), Atom, or SonicWall's
JSON list (.scratch/checks/vendor-feeds-2026-11-19.md, sections 1 and 4)."""

import json
import re
import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from collector import rss, summary_input
from collector.incidents import STAMP, cves_in, stamp_ago

ATOM = "{http://www.w3.org/2005/Atom}"
FORTINET_CSAF = "{https://fortiguard.fortinet.com/rss/ns/csaf}link"
SONICWALL_ID = re.compile(r"^SNWLID-\d{4}-\d{4}$")  # summary_input.SONICWALL_ADVISORY reads the page by this id


def rss_entries(body):
    """RSS 2.0 items. The text is every field's (Grafana's CVE id is only in its link and its advisory:cve)."""
    return [{"id": (item.findtext("guid") or item.findtext("link") or "").strip(), "title": rss.title(item),
             "url": (item.findtext("link") or "").strip(), "date": item.findtext("pubDate"),
             "text": " ".join(item.itertext()), "fields": {c.tag: (c.text or "").strip() for c in item}}
            for item in ET.fromstring(body).iter("item")]


def atom_entries(body):
    """Atom entries. The text is the title only: Chrome's content lists every CVE of a roll-up (see FEEDS)."""
    entries = []
    for e in ET.fromstring(body).iter(f"{ATOM}entry"):
        title = " ".join((e.findtext(f"{ATOM}title") or "").split())
        url = next((a.get("href") or "" for a in e.iter(f"{ATOM}link") if a.get("rel") == "alternate"), "")
        entries.append({"id": (e.findtext(f"{ATOM}id") or "").strip(), "title": title, "url": url.strip(),
                        "date": e.findtext(f"{ATOM}published"), "text": title})
    return entries


def sonicwall_entries(body):
    """SonicWall's advisory list, newest first, at the vuln-detail page CVE records cite. published_when is the first
    publish time; last_updated_when is apart, so a revision never reads as new."""
    entries = []
    for a in json.loads(body):
        key = str(a.get("advisory_id") or "") if isinstance(a, dict) else ""
        if SONICWALL_ID.match(key):
            entries.append({"id": key, "title": " ".join(str(a.get("title") or "").split()),
                            "url": f"https://psirt.global.sonicwall.com/vuln-detail/{key}", "date": a.get("published_when"),
                            "text": " ".join(str(a.get(k) or "") for k in ("vuln_status", "title", "cve", "summary"))})
    return entries


def csaf_cves(entry, http_get):
    """Fortinet's own advisories name no CVE ID in the feed; each item's CSAF file does (vulnerabilities[].cve)."""
    data = json.loads(http_get(entry["fields"][FORTINET_CSAF]))
    return cves_in(" ".join(str(v.get("cve") or "") for v in data.get("vulnerabilities") or [] if isinstance(v, dict)))


# Per feed: "own" matches the title of an advisory on the vendor's own product; any other item only joins (when
# unsure, join only). "other" (optional) matches the item's text, a post on another project's flaw. "link" (optional)
# rewrites the item's link to the form CVE records cite, so the two join by URL. "read": the format's reader (RSS when
# absent). "day_only": the feed's date is a day with no time; it gates the first read and the age, and the item's
# published time is when it was first seen (a fake midnight would sort it above news that came first, and pull a joined
# Incident's time earlier than the record's). "published" (optional): a pattern for the real first-publish time in
# the text. "cves" (optional): fetches an own advisory's CVE IDs when its text names none, one request per new item.
# "hourly": read only in the cycle on the hour's first 10-minute mark (a large feed). "first_published" (optional): the
# original publish date on the advisory's own page, for a feed whose date moves on revision (read_severity).
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
    "https://filestore.fortinet.com/fortiguard/rss/ir.xml": {
        # Measured on the 50 items of 2026-11-20: the 47 Fortinet advisories are titled by their weakness ("Heap-based
        # buffer overflow") and name no CVE ID; the 3 that do name one in the title restate another project's flaw
        # ("Java4Shell Vulnerability - CVE-2026-114938", "Linux kernel RCE CVE-2026-98432", "Node2Shell CVEs").
        "own": re.compile(r"^(?!.*\bCVEs?\b)", re.I),
        # The feed links /psirt/cvrf/FG-IR-26-273 (CVRF XML); CVE records cite /psirt/FG-IR-26-273, the guid's page.
        "link": lambda url: url.replace("/psirt/cvrf/", "/psirt/"),
        "day_only": True,  # "Tue, 10 Nov 2026 00:00:00 -0800" on every item
        "cves": csaf_cves,
    },
    "https://security.paloaltonetworks.com/rss.xml": {
        # Measured on the 25 items of 2026-11-20: "CVE-2026-0331 PAN-OS: ...", "GlobalProtect App:", "Cortex XSOAR:",
        # "Checkov by Prisma Cloud:" start; "Portfolio Status: Impact of Java Vulnerability ...", "Impact of Critical
        # Vulnerabilities in PHP ..." and "PAN-SA-2026-0014 Chromium: Monthly Vulnerability Update" only join. The
        # ISO pubDate moves when an advisory is revised: a recorded guid never reads as new again, but one never
        # recorded (an old advisory revised back into the 25 items) arrives under its new date; its page's original
        # date then makes it join only (CVE-2026-0250: published May 13, dated Nov 10). If that page fails to load, it
        # starts as its feed item reads.
        "own": re.compile(r"^\S+ (PAN-OS|GlobalProtect|Prisma|Cortex|Checkov|Strata|Expedition|Panorama|Traps)\b"),
        "other": re.compile(r"Portfolio Status|Impact of|Chromium"),
        "first_published": re.compile(r"\bPublished (\d{4}-\d{2}-\d{2}) Updated\b"),  # its page: "Published 2026-05-13 Updated 2026-11-10"
    },
    "https://grafana.com/security/security-advisories/index.xml": {
        # All 100 items of 2026-11-20 are Grafana Labs' own (Grafana, its plugins, mcp-k6), each at a /cve-.../ page.
        "own": re.compile(""),
        "day_only": True,  # "Tue, 10 Nov 2026 00:00:00 +0000"
    },
    "https://psirtapi.global.sonicwall.com/api/v1/vulnsummary/?srch=&vulnerable_products=&ord=-advisory_id": {
        # Undocumented (found by the 11-19 survey); 1.3 MB, the whole list each time. Measured on the 225 advisories of
        # 2026-11-20: titles naming a SonicWall product start ("SonicWall SMA1000 Series Appliances Affected By ...",
        # "SonicOS SSLVPN ..."); "Informational Advisory: ...", titles naming OpenSSL or the Linux kernel, and those
        # marked Not Applicable or Under Investigation (CUPS, Text4shell) only join, as does a third-party flaw's title
        # naming no product (regreSSHion). 174 start, 51 join; a few own ones of 2018-2021 with no product word join.
        "read": sonicwall_entries,
        "own": re.compile(r"^(?!Informational|.*\b(OpenSSL|Linux Kernel)\b)(?=.*\b(SonicWall|SonicOS|SMA ?\d*|NetExtender"
                          r"|GMS|NSM|Email Security|Connect Tunnel|Global VPN|Capture Client|SonicWave)\b)", re.I),
        "other": re.compile(r"^(Not Applicable|Under Investigation) "),  # vuln_status leads the text
        "hourly": True,
    },
    "https://www.sophos.com/en-us/security-advisories/feed": {
        # Measured on the 10 items of 2026-11-20: Sophos's own fixes are titled "Resolved Pre-Auth RCE Vulnerability in
        # Sophos UTM (...)"; every "Advisory: ..." is about another party's flaw or incident (Java4Shell, nginx2root,
        # a Linux kernel CVE, a compromised CA) and only joins.
        "own": re.compile(r"^Resolved\b"),
        "day_only": True,  # the pubDate is the Updated day at 00:00 GMT
        "published": re.compile(r'First Published:</strong>\s*<time datetime="([^"]+)"'),
    },
    # Blogger's label feed, stable desktop posts only, over https (the default feed redirects to plain-http FeedBurner
    # and is 1.6 MB of every channel); 5 posts are ~1 MB. A stable post lists 80-200 CVE IDs, and a later one repeats
    # older ones (the 158 post of 2026-11-17 names CVE-2026-121101 of the 157 release), so the group carries none: it
    # joins its release's Incident by the post's link, which every one of those CVE records cites, or starts one that the
    # records then join (by that link, then by their shared fixed version, group_releases).
    "https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates/Desktop%20Update?max-results=5": {
        "read": atom_entries,
        "own": re.compile(r"^Stable Channel Update for Desktop$"),
        "hourly": True,
    },
}
FIRST_READ_DAYS = 3  # a feed's first read lets its last 3 days through (owner, 11-19: SA-26:21 must reach the Board)
MAX_AGE_DAYS = 30  # an unseen item older than this starts nothing: a changed guid format must not refill the Board
MAX_SEEN = 1000  # shortcut: ids kept per feed; raise it before listing a feed that holds more items than this
# Own advisories read per feed per cycle; each costs up to 2 requests (its page, Fortinet's CSAF file) of at most
# SHORT_DEADLINE (15 s). Cycles took 265-380 s of their 600 on 11-20, so 6 bound one feed's worst case (every request
# timing out) at 180 s, inside the slowest cycle's 220 s of room; at ~1 s per request it is ~12 s. A Fortinet patch day
# (47) then takes 8 cycles, 80 minutes; the rest wait unseen.
MAX_READS = 6


def fetch(checkpoints, http_get, feeds, stamp):
    """Return (Mention groups for items not seen before, next checkpoints). feeds: {feed URL: rules}, as FEEDS.

    Checkpoints are {feed URL: [ids seen]}: dates cannot order these feeds (date-only and revised dates exist). A
    feed's first read records its items older than FIRST_READ_DAYS as seen and reads the rest as new (no older backfill). A feed that fails, or reads as empty, keeps
    its checkpoint, so one dead site never stops the Board and never makes every old item new again.
    """
    checkpoints = dict(checkpoints or {})
    now = datetime.strptime(stamp, STAMP).replace(tzinfo=timezone.utc)
    oldest, recent = stamp_ago(now, days=MAX_AGE_DAYS), stamp_ago(now, days=FIRST_READ_DAYS)
    groups = []
    short = getattr(http_get, "short", http_get)  # net.make_http_get's, within SHORT_DEADLINE; a test's stub as it is
    for feed, rules in feeds.items():
        if rules.get("hourly") and now.minute >= 10:
            # shortcut: a :00 cycle that runs late skips that hour's read; give the feed a last-read stamp if that matters
            continue
        try:
            items = [(e["id"], e) for e in rules.get("read", rss_entries)(http_get(feed))]
        except (OSError, ET.ParseError, ValueError, TypeError, AttributeError) as err:  # ValueError: bad JSON
            print(f"vendors: skipped {feed}: {err!r}", file=sys.stderr)
            continue
        items = [(key, entry) for key, entry in items if key]
        if not items:
            continue
        if feed not in checkpoints:
            # oldest first, as later ones append; the recent ones stay unseen and go through the loop below
            checkpoints[feed] = [key for key, e in reversed(items) if not posted_since(e, rules, recent)][-MAX_SEEN:]
        seen, reads = list(checkpoints[feed]), 0
        for key, entry in items:
            if key in seen:
                continue
            try:
                when, published = dated(entry, rules)
                fresh = when >= oldest
                if fresh and is_own(entry, rules):
                    if reads == MAX_READS:
                        continue  # not marked seen: read in a later cycle (a Fortinet patch day posts ~47 at once)
                    reads += 1
                group = mention_group(entry, rules, published or stamp, short if fresh else None)
            except (AttributeError, TypeError, ValueError, OverflowError) as err:
                print(f"vendors: skipped an item: {err!r}", file=sys.stderr)
                continue  # not marked seen: the next cycle reads it again
            seen.append(key)
            if fresh:
                if not group["join_only"]:
                    read_severity(group, rules, short, oldest)
                groups.append(group)
        checkpoints[feed] = seen[-MAX_SEEN:]
    return groups, checkpoints


def read_severity(group, rules, http_get, oldest):
    """Store on an own advisory Mention the severity word its official page states (summary_input.severity_word), so a
    row with no CVSS yet that the vendor rates Critical or High is summarized at once (summaries.is_candidate), not left
    in a batch at 참고 (owner, 11-20: Synology-SA-26:21, SA-CORE-2026-017). Read here, once per new feed item: the
    checkpoint never shows the item again, so no cycle fetches it twice; the feed's own text has no such word
    (Synology's description) or has it only in the title or a feed field (Drupal's, Palo Alto's, Grafana's), which
    never counts. Code reads it, never the model. The same page's original publish date ("first_published") makes an
    advisory first posted before MAX_AGE_DAYS and revised back into its feed join only: it is old news.
    shortcut: a page that fails to load (http_get is the short one) stores nothing, and the advisory starts as its feed
    item reads; no retry."""
    mention = group["mentions"][0]
    url = mention["url"]
    page = summary_input.fetch_page(http_get, url)
    text = summary_input.page_text(page, url) if page else None
    word = summary_input.severity_word(text) if text else None
    if word:
        mention["severity"] = word
    first = text and "first_published" in rules and rules["first_published"].search(text)
    if first and posted(first[1]) < oldest:
        group["join_only"] = True  # still the vendor's advisory: it joins and leads that CVE's row when one is kept


def posted_since(entry, rules, stamp):
    try:
        return dated(entry, rules)[0] >= stamp
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False  # an unreadable date counts as old: recorded, never started


def dated(entry, rules):
    """(the item's time for the first-read and age gates, its published time, or None when the feed gives only a day)."""
    found = "published" in rules and rules["published"].search(entry["text"])
    if found:
        return (at := posted(found[1])), at
    at = posted(entry["date"])
    return at, None if rules.get("day_only") else at


def posted(text):
    """An RFC-822 or ISO-8601 time (Palo Alto's "2026-11-11T17:00:00.000Z") as an ISO-8601 UTC stamp."""
    text = text.strip()
    try:
        at = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        at = datetime.fromisoformat(text)
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime(STAMP)


def is_own(entry, rules):
    return bool(rules["own"].search(entry["title"])) and not ("other" in rules and rules["other"].search(entry["text"]))


def mention_group(entry, rules, published, http_get=None):
    """http_get: for an own advisory whose text names no CVE ID and whose feed has a "cves" rule; None fetches nothing."""
    title, url = entry["title"], entry["url"]
    if not url:
        raise ValueError(f"no link: {title!r}")
    if "link" in rules:
        url = rules["link"](url)
    other = not is_own(entry, rules)
    cves = cves_in(entry["text"])
    if not other and not cves and "cves" in rules and http_get:
        try:
            cves = rules["cves"](entry, http_get)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as err:
            # The row starts keyed by its link; the CVE record cites that link and joins it there.
            print(f"vendors: no CVE IDs for {url}: {err!r}", file=sys.stderr)
    # "urls" stays empty, as in news.py: Drupal's description is HTML full of links that would join unrelated rows.
    return {"mentions": [{"kind": "discussion" if other else "advisory", "url": url, "title": title}],
            "cves": cves, "urls": [], "text": title, "join_only": other, "published": published}
