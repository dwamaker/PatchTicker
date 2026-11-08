"""RSS item fields shared by the RSS adapters (oss-security, curators)."""

from datetime import timezone
from email.utils import parsedate_to_datetime

from collector.incidents import STAMP


def posted(item):
    """The item's pubDate as an ISO-8601 UTC stamp."""
    return parsedate_to_datetime(item.findtext("pubDate")).astimezone(timezone.utc).strftime(STAMP)


def title(item):
    return " ".join((item.findtext("title") or "").split())
