"""The text a Summary request is built from (an Incident, its pages and CVE records), and reading that text back."""

import html.parser
import http.client
import json
import re
import sys
from collections import Counter
from itertools import accumulate
from urllib.parse import urlsplit

from collector import cvelist
from collector.incidents import is_news

PAGE_CHARS = 8000  # shortcut: page text past this is cut; sshhole.com's Mitigation sits at ~7,000.
MAX_PAGES = 2
PAGE_KINDS = ("advisory", "writeup", "discussion")  # in Lead order; repos and newsletters are not read
# The CVE JSON 5 record of cvelist.record_url, for one too fresh for the raw path (three 404s in the 2026-11-08 run).
CVE_API_RECORD = "https://cveawg.mitre.org/api/cve/{cve}"
# Owner, 2026-11-10: a Summary writes per-CVE lines for this many CVEs (IBM API Connect's 204 ran past MAX_TOKENS_RETRY);
# the rest go to batch requests (cve_lines).
CVE_LINES_MAX = 12
CVE_LINES_ONLY = "Per-CVE lines only for:"
# 11-11: a 734-CVE Microsoft group listed 1,471 Mentions (105,000 characters) and read all 734 CVE records (2.67 million
# characters); its request was 1,350,178 tokens, over the 1,000,000 maximum, on all three tries.
MENTIONS_MAX = 60  # Mention lines in the input; the rest are counted by kind
INPUT_CHARS_MAX = 400_000  # about 100k tokens; past it the descriptions of the CVEs after CVE_LINES_MAX are cut from the end


LEAD_MARK = " (the Lead: its numbers win when sources disagree)"


def summary_input(incident, http_get):
    lines = [
        f"Incident: {', '.join(incident['cves']) or 'no CVE yet'}",
        *([f"{CVE_LINES_ONLY} {', '.join(incident['cves'][:CVE_LINES_MAX])}"] if len(incident["cves"]) > CVE_LINES_MAX else []),
        f"CVSS: {incident.get('cvss', 'not rated yet')}",
        f"Exploited in the wild (CISA KEV): {'yes' if incident.get('kev') else 'no'}",
        f"Products: {', '.join(p['name'] for p in incident.get('products', [])) or 'unknown'}",
        f"Description: {incident['brief']['text']}",
        "Mentions:",
    ]
    lead = incident["brief"]["lead"]
    preferred = sorted(incident["mentions"], key=lambda m: (m["url"] != lead, PAGE_KINDS.index(m["kind"]) if m["kind"] in PAGE_KINDS else 99))
    # A short list keeps its stored order; a long one lists first the Mentions the pages are read from.
    listed = incident["mentions"] if len(incident["mentions"]) <= MENTIONS_MAX else preferred[:MENTIONS_MAX]
    lines += [f"- {m['kind']} {m['url']}" + (f" ({m['title']})" if m.get("title") else "") for m in listed]
    if len(listed) < len(preferred):
        kinds = Counter(m["kind"] for m in preferred[MENTIONS_MAX:]).most_common()
        lines.append(f"… and {len(preferred) - MENTIONS_MAX} more: {', '.join(f'{n} {kind}' for kind, n in kinds)}")
    # Pages come before the CVE records and the Lead is marked: CVE text can round a boundary (sshole's
    # record says "between 256 and 1024", its write-up "between 257 and 1024") and the model followed
    # whichever it read first.
    readable = [m for m in preferred if m["kind"] in PAGE_KINDS and not is_hn(m["url"])]
    for m in readable[:MAX_PAGES]:
        page = fetch_page(http_get, m["url"])
        if page:
            mark = LEAD_MARK if m["url"] == lead else ""
            lines += [f"Text of {m['url']}{mark}:", page_text(page)[:PAGE_CHARS]]
    for cve in incident["cves"][:CVE_LINES_MAX]:
        record = fetch_page(http_get, cvelist.record_url(cve)) or fetch_page(http_get, CVE_API_RECORD.format(cve=cve))
        if record:
            lines += [f"CVE record {cve}:", cve_fields(record)]
    # The rest get the Incident's own one-line description and no request. Whitespace is folded so a description
    # cannot start a line that trusted() would read as a Mention or a source block.
    texts = incident.get("cve_texts") or {}
    others = [f"{cve}: {' '.join(texts[cve].split())}" for cve in incident["cves"][CVE_LINES_MAX:] if texts.get(cve)]
    if others:
        room = INPUT_CHARS_MAX - len("\n".join(lines)) - 100  # 100: the heading and the closing line
        shown = sum(1 for total in accumulate(len(line) + 1 for line in others) if total <= room)
        lines += ["Other CVEs, each with its own description:", *others[:shown]]
        if shown < len(others):
            lines.append(f"… and {len(others) - shown} more CVEs not shown")
    return "\n".join(lines)


# Pages that draw their text with script hold nothing in their HTML; read the JSON the page itself loads instead.
# SonicWall's PSIRT page is the first such source (SNWLID-2026-0014: the fixed versions were only in its API).
SONICWALL_ADVISORY = re.compile(r"^https://psirt\.global\.sonicwall\.com/vuln-detail/(SNWLID-\d{4}-\d{4})")
SONICWALL_API = "https://psirtapi.global.sonicwall.com/api/v1/vulndetail/?advisory_id={}"
# The short tables first: the input keeps only PAGE_CHARS of a page, and a multi-CVE summary or detail can fill that
# before the fixed versions (SNWLID-2026-0014's summary lists seven CVEs).
SONICWALL_FIELDS = (("title", "Title"), ("affected_products", "Affected products"), ("fixed_software", "Fixed software"),
                    ("workaround", "Workaround"), ("summary", "Summary"), ("detail", "Detail"))


def fetch_page(http_get, url):
    """A page or record for the input, or None: a dead link must not stop the Summary."""
    advisory = SONICWALL_ADVISORY.match(url)
    if advisory:
        return sonicwall_advisory(http_get, advisory.group(1))
    try:
        raw = http_get(url)
    except (OSError, ValueError, http.client.HTTPException) as err:  # HTTPException: a cited page's malformed answer
        print(f"summaries: skipped {url}: {err!r}", file=sys.stderr)
        return None
    return None if b"\0" in raw[:1024] else raw.decode("utf-8", errors="replace")  # binary: not text


def sonicwall_advisory(http_get, advisory_id):
    """The advisory's own fields (already HTML) under plain headings, so page_text reads it like any page."""
    raw = fetch_page(http_get, SONICWALL_API.format(advisory_id))
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return "<html><body>" + "".join(f"<h2>{label}</h2><div>{data.get(key) or ''}</div>"
                                    for key, label in SONICWALL_FIELDS) + "</body></html>"


def cve_fields(raw):
    """The CVE record's relevant fields: descriptions, affected products and versions, problem types."""
    try:
        cna = json.loads(raw)["containers"]["cna"]
    except (ValueError, KeyError, TypeError):
        return ""
    keep = {k: cna[k] for k in ("title", "descriptions", "affected", "problemTypes") if k in cna}
    return json.dumps(keep, ensure_ascii=False)


class _Text(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "template"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "template") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def page_text(page):
    if "<" not in page[:2000]:
        return " ".join(page.split())  # plain text, e.g. an OpenSSH release note
    parser = _Text()
    parser.feed(page)
    return " ".join(" ".join(parser.parts).split())


def is_hn(url):
    try:
        return urlsplit(url).netloc.lower() == "news.ycombinator.com"  # a comment thread, not a write-up
    except ValueError:  # a malformed URL ("http://[...") is not HN
        return False


# summary_input's source headers, each over the one line of text it read (page_text and cve_fields hold no newline).
SOURCE_RE = re.compile(rf"^(?:Text of (\S+)({re.escape(LEAD_MARK)})?|CVE record \S+):\n(.*)$", re.M)
MENTION_LINE = re.compile(r"^- (\w+) (\S+)", re.M)


def trusted(input_text):
    """The text a command or stopgap may come from: the Lead's, the official advisories' and the CVE records'. And the
    URLs whose report of attacks counts: advisories, CVE records, curators and news sites. Not a write-up, the Lead
    included: any HN poster's page can be the Lead, with or without a CVE in the story title."""
    blocks = list(SOURCE_RE.finditer(input_text))
    head = input_text[:blocks[0].start()] if blocks else input_text  # the Mentions list; no page text can forge a line
    kinds = {url: kind for kind, url in MENTION_LINE.findall(head)}
    text = "\n".join(b[3] for b in blocks if not b[1] or b[2] or kinds.get(b[1]) == "advisory")
    reporters = {url for url, kind in kinds.items() if kind in ("advisory", "cve_record", "curator") or is_news(url)}
    return text, reporters
