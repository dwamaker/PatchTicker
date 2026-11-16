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
from collector.incidents import cve_order, is_news, top_cve

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
    # Step 4: a group's CVEs in cve_order (its Lead CVE first, the twelve records read are the highest-scored) with each
    # CVE's score; a one-CVE input stays as it was, byte for byte.
    cves, group = cve_order(incident), len(incident["cves"]) > 1
    scores = (incident.get("cve_scores") or {}) if group else {}
    top = top_cve(incident) if group else None
    listed = [c for c in cves if c in (incident.get("kev_cves") or {})] if group and incident.get("kev") else []
    lines = [
        f"Incident: {', '.join(cves) or 'no CVE yet'}",
        *([f"Lead CVE: {cves[0]}"] if group else []),
        *([f"{CVE_LINES_ONLY} {', '.join(cves[:CVE_LINES_MAX])}"] if len(cves) > CVE_LINES_MAX else []),
        f"CVSS: {incident.get('cvss', 'not rated yet')}" + (f" (highest, {top})" if top else ""),
        f"Exploited in the wild (CISA KEV): {'yes' if incident.get('kev') else 'no'}" + (f" ({', '.join(listed)})" if listed else ""),
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
        text = page_text(page, m["url"]) if page else None  # None: not loaded, or not parsed; the input goes on
        if text is not None:
            mark = LEAD_MARK if m["url"] == lead else ""
            lines += [f"Text of {m['url']}{mark}:", text[:PAGE_CHARS]]
    for cve in cves[:CVE_LINES_MAX]:
        record = fetch_page(http_get, cvelist.record_url(cve)) or fetch_page(http_get, CVE_API_RECORD.format(cve=cve))
        if record:
            lines += [f"CVE record {cve}:", cve_fields(record, scores.get(cve))]
    # The rest get the Incident's own one-line description and no request. Whitespace is folded so a description
    # cannot start a line that trusted() would read as a Mention or a source block.
    texts = incident.get("cve_texts") or {}
    others = [f"{scored(cve, scores.get(cve))}: {' '.join(texts[cve].split())}" for cve in cves[CVE_LINES_MAX:] if texts.get(cve)]
    if others:
        room = INPUT_CHARS_MAX - len("\n".join(lines)) - 100  # 100: the heading and the closing line
        shown = sum(1 for total in accumulate(len(line) + 1 for line in others) if total <= room)
        lines += ["Other CVEs, each with its own description:", *others[:shown]]
        if shown < len(others):
            lines.append(f"… and {len(others) - shown} more CVEs not shown")
    return "\n".join(lines)


def scored(cve, score):
    """An Other CVEs line's head: "CVE-X (CVSS 7.5, CVSS:3.1/...)", or the bare id without a score. Never in a "CVE record"
    header: SOURCE_RE would stop reading the record as trusted."""
    if not score:
        return cve
    vector = " ".join(score["vector"].split())  # CNA text: folded like the descriptions
    return f"{cve} (CVSS {score['cvss']}{', ' + vector if vector else ''})"


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
    # Binary, not text: a NUL early on, or a PDF, which has none in its head (11-16: Axis's advisory PDF of CVE-2026-4762).
    if b"\0" in raw[:1024] or raw.lstrip()[:5] == b"%PDF-":
        print(f"summaries: skipped {url}: not text", file=sys.stderr)
        return None
    return raw.decode("utf-8", errors="replace")


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


def cve_fields(raw, score=None):
    """The CVE record's relevant fields: descriptions, affected products and versions, problem types, and the
    solutions, workarounds and configurations some CNAs write (Fortinet's fixed versions are only in solutions). A group's
    record also carries its CVE's cve_scores entry (score), inside the JSON, as "cvss" and "vector"."""
    try:
        cna = json.loads(raw)["containers"]["cna"]
    except (ValueError, KeyError, TypeError):
        return ""
    keep = {k: cna[k] for k in ("title", "descriptions", "affected", "problemTypes") if k in cna}
    # supportingMedia repeats value as HTML or base64: more tokens, stray digits for the number check, markup in a stopgap.
    keep |= {k: [readable(i) if isinstance(i, dict) else i for i in cna[k]]
             for k in ("solutions", "workarounds", "configurations") if isinstance(cna.get(k), list)}
    if score:
        keep |= {"cvss": score["cvss"], "vector": score["vector"]}
    return json.dumps(keep, ensure_ascii=False)


URL = re.compile(r"https?://\S+")


def readable(item):
    """A solutions, workarounds or configurations item without supportingMedia. Its HTML copy's text stands in for value
    when it holds all of value but the links: IBM's value glues table cells ("6.1.0.0 - 6.1.0.46.1.0.5", CVE-2026-18525).
    Not when the copy lost something: list numbers, or an unescaped "<ASN>" the parser read as a tag (CVE-2026-121291)."""
    out = {f: v for f, v in item.items() if f != "supportingMedia"}
    html = [m["value"] for m in item.get("supportingMedia") or [] if isinstance(m, dict) and m.get("type") == "text/html"
            and not m.get("base64") and isinstance(m.get("value"), str)]
    text = " ".join(map(cell_text, html))
    flat = lambda s: "".join(s.split()).lower()  # noqa: E731
    if text and isinstance(item.get("value"), str) and flat(URL.sub("", item["value"])) in flat(text):
        out["value"] = text
    return out


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


BLOCKS = {"br", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "ol", "p", "pre", "table", "td", "th", "tr", "ul"}


class _Cells(_Text):
    """Text with a space only between blocks and table cells; inline tags ("<code>a</code>=1") join as written."""
    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        self.parts.append(" " if tag in BLOCKS else "")

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        self.parts.append(" " if tag in BLOCKS else "")


def parsed(parser, text, url):
    """Feed text to parser; False, with one line on stderr, when html.parser gives up on it."""
    try:
        parser.feed(text)
    except Exception as err:  # html.parser asserts on junk ("<![" then binary, 11-16); any input, never the cycle
        print(f"summaries: skipped {url}: {err!r}"[:300], file=sys.stderr)
        return False
    return True


def cell_text(html_text):
    parser = _Cells()
    return " ".join("".join(parser.parts).split()) if parsed(parser, html_text, "a CVE record's HTML") else ""


def page_text(page, url=""):
    """The page's text, or None when it cannot be parsed: then it counts as a page that failed to load."""
    if "<" not in page[:2000]:
        return " ".join(page.split())  # plain text, e.g. an OpenSSH release note
    parser = _Text()
    return " ".join(" ".join(parser.parts).split()) if parsed(parser, page, url) else None


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
