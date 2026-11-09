"""Mention source: KISA 보호나라 security notices (Korea's CERT). A notice only joins Incidents it names by CVE ID: Korean
readers trust "KISA가 공지했다", and the notice is in their language. Its own kind, "notice": it restates the vendor's
advisory, so it is never the Lead, never read for a Summary and never brings a new one."""

import re
import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from collector.incidents import cves_in

FEED = "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"
NTT_ID = re.compile(r"[?&]nttId=(\d+)")


def fetch(checkpoint, http_get, feed):
    """Return (citations for notices newer than the checkpoint, next checkpoint).

    The feed gives only a title, a link and a day, so each new notice's page is read for its CVE IDs. The checkpoint is
    the highest notice number seen (nttId grows with each notice; the day alone cannot order notices of one day).
    """
    found, newest = [], checkpoint or 0
    if not feed:
        return found, checkpoint
    try:
        items = list(ET.fromstring(http_get(feed)).iter("item"))
    except (OSError, ET.ParseError) as err:
        print(f"kisa: skipped the feed: {err!r}", file=sys.stderr)
        return found, checkpoint
    notices = sorted(((int(n.group(1)), link, item) for item in items
                      for link in [(item.findtext("link") or "").strip()] for n in [NTT_ID.search(link)] if n),
                     key=lambda t: t[0])
    for number, link, item in notices:  # oldest first, so a failed page stops the checkpoint below it
        if number <= newest:
            continue
        try:
            page = http_get(link).decode("utf-8", errors="replace")
        except (OSError, ValueError) as err:
            print(f"kisa: stopped at {link}: {err!r}", file=sys.stderr)
            break  # the next cycle reads it again
        newest = number
        cves = cves_in(page)
        if cves:
            title = " ".join((item.findtext("title") or "").split())
            found.append({"mention": {"kind": "notice", "url": link, "title": f"KISA 보호나라: {title}"}, "cves": cves, "urls": []})
    return found, newest
