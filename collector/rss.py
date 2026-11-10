"""RSS feed reading shared by the RSS adapters (oss-security, news, curators)."""

import sys
import xml.etree.ElementTree as ET  # expat in Python 3.13 limits entity expansion
from datetime import timezone
from email.utils import parsedate_to_datetime

from collector.incidents import STAMP


def read(url, checkpoint, http_get, stamp, build, prefix):
    """Return (build(item) for items posted after the checkpoint, next checkpoint).

    The next checkpoint is the newest post time taken, never later than the cycle's stamp. A malformed item is skipped
    and the items after it are still read; a feed that cannot be fetched or parsed leaves the checkpoint unchanged.
    """
    try:
        items = ET.fromstring(http_get(url)).iter("item")
    except (OSError, ET.ParseError) as err:
        # One bad feed skips that feed this cycle, never the whole cycle.
        print(f"{prefix}: skipped {url}: {err!r}", file=sys.stderr)
        return [], checkpoint
    built, newest = [], checkpoint
    for item in items:
        try:
            at = posted(item)
            if checkpoint and at <= checkpoint:
                continue
            value = build(item)
        except (AttributeError, TypeError, ValueError, OverflowError) as err:
            print(f"{prefix}: skipped an item: {err!r}", file=sys.stderr)
            continue
        newest = max(newest or at, at)
        built.append(value)
    # A future-dated post must not become the checkpoint, or every real post before that date is skipped.
    return built, newest and min(newest, stamp)


def posted(item):
    """The item's pubDate as an ISO-8601 UTC stamp."""
    return parsedate_to_datetime(item.findtext("pubDate")).astimezone(timezone.utc).strftime(STAMP)


def title(item):
    return " ".join((item.findtext("title") or "").split())
