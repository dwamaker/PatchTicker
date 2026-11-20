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
from collector.model import CVE_ID

PAGE_CHARS = 8000  # a longer page keeps its opening and the sentences about the Incident (focused) up to this
# Owner's trial, 11-18 (variant C): 4 pages, chosen by readable() and cut by focused(), raised ground-truth facts in the
# Summary from 36% to 52% on 9 multi-source Incidents, with no wrong fixed version, for 14% more input tokens.
MAX_PAGES = 4
PAGE_KINDS = ("advisory", "writeup", "discussion")  # the Mentions list's order; repos are never read
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


def summary_input(incident, http_get, sheets=()):
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
    for m in page_mentions(incident)[:MAX_PAGES]:
        page = fetch_page(http_get, m["url"])
        text = page_text(page, m["url"], incident) if page else None  # None: not loaded, or not parsed; the input goes on
        if text is not None:
            mark = LEAD_MARK if m["url"] == lead else ""
            lines += [f"Text of {m['url']}{mark}:", text[:PAGE_CHARS]]
    descriptions = []
    for cve in cves[:CVE_LINES_MAX]:
        record = fetch_page(http_get, cvelist.record_url(cve)) or fetch_page(http_get, CVE_API_RECORD.format(cve=cve))
        if record:
            lines += [f"CVE record {cve}:", cve_fields(record, scores.get(cve))]
            descriptions += record_descriptions(record)
    # The pages' sheets (collector.sheets, gated Incidents only), merged and guarded against the records' text.
    if sheets:
        from collector.sheets import text_for  # sheets imports this module
        lines += [text for text in [text_for(sheets, incident, descriptions)] if text]
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


def host(url):
    try:
        return urlsplit(url).netloc.lower().removeprefix("www.")
    except ValueError:  # "http://[..." from scraped text
        return url


def page_mentions(incident):
    """The Mentions whose pages the input reads, in order: the Lead; vendor advisories and national CERT notices (KISA's
    held the Java group's only Java 8 and 11 fixed versions, 11-18); write-ups that are not news; news; curator
    newsletters; discussions. One page per host before a second from the same host. Never Hacker News, a repo or
    cve.org's record page (drawn by script: its HTML holds no text; the record itself is read below)."""
    lead = incident["brief"]["lead"]

    def rank(m):
        if m["url"] == lead:
            return 0
        if m["kind"] in ("advisory", "notice"):
            return 1
        if m["kind"] == "writeup":
            return 3 if is_news(m["url"]) else 2
        return 4 if m["kind"] == "curator" else 5

    pages = sorted((m for m in incident["mentions"] if m["kind"] in PAGE_KINDS + ("notice", "curator")
                    and not is_hn(m["url"]) and host(m["url"]) != "cve.org"), key=rank)
    seen, first, later = set(), [], []
    for m in pages:
        (later if host(m["url"]) in seen else first).append(m)
        seen.add(host(m["url"]))
    return first + later


def scored(cve, score):
    """An Other CVEs line's head: "CVE-X (CVSS 7.5, CVSS:3.1/...)", or the bare id without a score. Never in a "CVE record"
    header: SOURCE_RE would stop reading the record as trusted."""
    if not score:
        return cve
    own = score.get("record") or score  # a page's raise keeps the record's own score and vector under "record"
    vector = " ".join(own["vector"].split())  # CNA text: folded like the descriptions
    page = f"; {score['cvss']} given by {' '.join(score['by'].split())}" if "by" in score and own is not score else ""
    return f"{cve} (CVSS {own['cvss']}{', ' + vector if vector else ''}{page})"


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


def shared_pages(http_get):
    """(keep, take), two http_gets for one cycle: a page keep() fetched (the sheets', collector.sheets.fill) is handed to
    the next take() of it (the Summary's) instead of being fetched again, its error too; take() drops it, so the cycle
    holds at most the sheets' pages. Any other take() is a plain fetch."""
    held = {}

    def keep(url):
        try:
            held[url] = http_get(url)
        except (OSError, ValueError, http.client.HTTPException) as err:  # what fetch_page skips
            held[url] = err
            raise
        return held[url]

    def take(url):
        got = held.pop(url) if url in held else None
        if isinstance(got, Exception):
            raise got
        return got if got is not None else http_get(url)

    return keep, take


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
        own = score.get("record") or score  # the record's own pair; a page's higher score beside it, with who gave it
        keep |= {"cvss": own["cvss"], "vector": own["vector"]}
        if own is not score and "by" in score:
            keep |= {"page_cvss": score["cvss"], "page_cvss_by": score["by"]}
    fixes = record_fixes(cna)
    if fixes:
        keep["fixed_per_record"] = fixes
    return json.dumps(keep, ensure_ascii=False)


ZERO = re.compile(r"0(?:[.:\-]0)*")


def record_fixes(cna):
    """The versions a record's `affected` list gives as the fix, which its raw entries leave to be worked out (11-18:
    Imagination's Graphics DDK lists seven releases affected and then "26.3 RTM" unaffected, and a re-summary said no
    source names a fixed version): an unaffected version after an affected one of the same product, or under
    defaultStatus "affected" (AMD's EPYC firmware), an affected range's lessThan, and a change to unaffected.
    "product version" strings, in record order; never "*", a version without a digit or unaffected from 0."""
    out = []
    for a in cna.get("affected") or []:
        if not isinstance(a, dict):
            continue
        product = " ".join(str(a.get("product") or "").split())
        after_affected = a.get("defaultStatus") == "affected"
        for v in a.get("versions") or []:
            if not isinstance(v, dict):
                continue
            found = []
            if v.get("status") == "affected":
                after_affected = True
                found = [v.get("lessThan"), *(c.get("at") for c in v.get("changes") or []
                                              if isinstance(c, dict) and c.get("status") == "unaffected")]
            elif v.get("status") == "unaffected" and after_affected:
                found = [v.get("version")]
            out += [f"{product} {' '.join(f.split())}".strip() for f in found
                    if isinstance(f, str) and re.search(r"\d", f) and not ZERO.fullmatch(f.strip())]
    return list(dict.fromkeys(out))


def record_descriptions(raw):
    """The CNA's description texts of a CVE record, for the sheet's fixed-row guard."""
    try:
        cna = json.loads(raw)["containers"]["cna"]
        return [d["value"] for d in cna.get("descriptions", []) if isinstance(d.get("value"), str)]
    except (ValueError, KeyError, TypeError, AttributeError):
        return []


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


FURNITURE = {"nav", "header", "footer", "aside", "noscript", "svg", "form", "button", "select"}


class _Main(_Text):
    """The page's main content: no script or style, no navigation, header, footer, aside or forms. A line per block, so
    focused() can tell sentences apart; inline tags join their text as written."""
    def handle_starttag(self, tag, attrs):
        if tag in FURNITURE:
            self.skip += 1
        super().handle_starttag(tag, attrs)
        self.parts.append("\n" if tag in BLOCKS else "")

    def handle_endtag(self, tag):
        if tag in FURNITURE and self.skip:
            self.skip -= 1
        super().handle_endtag(tag)
        self.parts.append("\n" if tag in BLOCKS else "")


# What makes a sentence worth keeping in a long page (the trial's variant C, 11-18).
VERSION = re.compile(r"(?<![\w.])v?\d+(?:\.\d+){1,4}(?:[-_.]?[A-Za-z]*\d*)?(?![\w.])|\b\d+u\d+\b")
FOCUS_WORDS = re.compile(r"(?i)\b(?:fix(?:ed|es)?|patch(?:ed|es)?|update|upgrade|affected|vulnerab\w*|exploit\w*|"
                         r"proof.of.concept|PoC|CVSS|workaround|mitigat\w*|disable|in the wild|attack\w*|dubbed|named)\b")
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n")
GENERIC_PRODUCT_WORDS = {"oracle", "edition", "enterprise", "server"}  # in many products' names: they would match everything
OPENING_SENTENCES = 4
NEIGHBOUR_MAX = 400  # a sentence this long or longer keeps no neighbour: it is a block of its own (a table row, a list)


def focused(text, incident, limit=PAGE_CHARS):
    """A long page's opening sentences, then each sentence naming the Incident's CVE IDs, a product word or a version,
    or speaking of fixes, exploitation, scores or workarounds, with a neighbour on each side, in page order, " … " where
    sentences were skipped, up to limit. A page where nothing matches keeps its opening text up to limit."""
    terms = {c.lower() for c in incident["cves"]} | {
        w.lower() for p in incident.get("products", []) for w in re.split(r"[\s/,()]+", p["name"])
        if len(w) >= 4 and w.lower() not in GENERIC_PRODUCT_WORDS}
    sentences = [s.strip() for s in SENTENCE.split(text) if s.strip()]
    keep = set(range(min(OPENING_SENTENCES, len(sentences))))
    for n, s in enumerate(sentences):
        if any(t in s.lower() for t in terms) or VERSION.search(s) or FOCUS_WORDS.search(s):
            keep |= {n - 1, n, n + 1} if len(s) < NEIGHBOUR_MAX else {n}
    if len(keep) <= OPENING_SENTENCES:  # no match: the opening, as an uncut page would give it
        return " ".join(text.split())[:limit]
    out, total, last = [], 0, -2
    for n in sorted(k for k in keep if 0 <= k < len(sentences)):
        piece = (" … " if out and n != last + 1 else " ") + sentences[n]
        if total + len(piece) > limit:
            break
        out.append(piece)
        total, last = total + len(piece), n
    # A first sentence over the limit (a page with no stops) leaves nothing: its opening then, cut like any page.
    return " ".join("".join(out).split()) or " ".join(text.split())[:limit]


def main_text(page, url=""):
    """The page's main content (no navigation, header, footer or forms), a line per block, or None when it cannot be
    parsed."""
    if "<" not in page[:2000]:
        text = page  # plain text, e.g. an OpenSSH release note
    else:
        parser = _Main()
        if not parsed(parser, page, url):
            return None
        text = "".join(parser.parts)
        if len(text.split()) < 50:
            whole = _Text()
            parsed(whole, page, url)  # the same markup parsed once already
            # A page held whole in a <form> (ASP.NET) or a <header> lost its content: its text then, furniture and all.
            if len(text.split()) * 10 < len(" ".join(whole.parts).split()):
                text = "\n".join(whole.parts)
    return "\n".join(line for line in (" ".join(raw.split()) for raw in text.split("\n")) if line)


def page_text(page, url="", incident=None):
    """main_text() on one line, or None when it cannot be parsed: then it counts as a page that failed to load. Given
    the Incident, a page longer than PAGE_CHARS is focused() on it. page_keys() reads the raw page (fetch_page), never
    this."""
    text = main_text(page, url)
    if text is None:
        return None
    flat = " ".join(text.split())
    return focused(text, incident) if incident and len(flat) > PAGE_CHARS else flat


def is_hn(url):
    try:
        return urlsplit(url).netloc.lower() == "news.ycombinator.com"  # a comment thread, not a write-up
    except ValueError:  # a malformed URL ("http://[...") is not HN
        return False


# summary_input's source headers, each over the one line of text it read (page_text and cve_fields hold no newline).
SOURCE_RE = re.compile(rf"^(?:Text of (\S+)({re.escape(LEAD_MARK)})?|CVE record \S+):\n(.*)$", re.M)
MENTION_LINE = re.compile(r"^- (\w+) (\S+)", re.M)


def mention_kinds(input_text):
    """{url: kind} of the input's Mentions list (its head, before any page text, so no page can forge a line)."""
    blocks = list(SOURCE_RE.finditer(input_text))
    head = input_text[:blocks[0].start()] if blocks else input_text
    return {url: kind for kind, url in MENTION_LINE.findall(head)}


# Owner, 11-19: the severity word an official advisory states under its own label: "Severity Critical" (GitHub's
# advisories, Synology's), "Security risk: Critical 18 ∕ 25" (Drupal's), "Max Severity: Important" (Microsoft's). Only the
# word right after the label, so a product table's "DSM 7.4 Critical" and a sentence's "a critical component" never count.
SEVERITY_RE = re.compile(r"\b(?:severity|security risk)\s*:?\s*(highly critical|moderately critical|less critical|not critical"
                         r"|critical|high|important|moderate|medium|low)\b", re.I)
SEVERITY_WORDS = {"highly critical": "critical", "important": "high", "moderate": "medium", "moderately critical": "medium",
                  "less critical": "low", "not critical": "low"}


def advisory_severity(input_text):
    """{"severity": critical|high|medium|low, "severity_source": URL} from the first page of the input that is an official
    advisory in its Mentions list (mention_kinds) and states one (SEVERITY_RE), else {}. Read by code, never asked of the
    model: a write-up's, news page's, discussion's or CVE record's text and every Mention title never count."""
    kinds = mention_kinds(input_text)
    for block in SOURCE_RE.finditer(input_text):
        if block[1] and kinds.get(block[1]) == "advisory" and (word := severity_word(block[3])):
            return {"severity": word, "severity_source": block[1]}
    return {}


# Owner, 11-20: an official advisory's own CVSS score, read by code (Synology-SA-26:21 wrote "CVSS3 Base Score: 9.8" while
# the CVE record was not yet published, and the row stood with no score). The label must say CVSS and score ("CVSS3 Base
# Score: 9.8", "CVSS v3.1 Base Score 7.5", "CVSSv3 Score: 8.8", "CVSS Score: 5.3"); a version may stand in the label or
# in a vector right after it ("CVSS:3.1/AV:..."). A vector's own "3.1" is never a score (the "/" after it).
ADVISORY_SCORE_RE = re.compile(r"\bCVSS\s*(?:v\s*)?(?P<ver>[234](?:\.[01])?)?\s*(?:\(\s*v?(?P<ver2>[234]\.[01])\s*\))?\s*"
                               r"(?:base\s+)?score\s*[:：=]?\s*(?P<n>10(?:\.0)?|\d\.\d)(?![\d.]|\s*/)", re.I)
VECTOR_VERSION_RE = re.compile(r"CVSS:(\d\.\d)/AV:")
VECTOR_3_RE = re.compile(r"CVSS:3\.[01]/((?:[A-Z]{1,2}:[A-Z]/?){8,})")
# CVSS 3.x base metric weights (FIRST, CVSS v3.1 specification section 7.4); PR's two values: scope unchanged, changed.
CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
         "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}, "UI": {"N": 0.85, "R": 0.62},
         "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def roundup(value):
    """CVSS 3.1's Roundup (specification Appendix A): the smallest one-decimal number not below value."""
    whole = round(value * 100000)
    return whole / 100000.0 if whole % 10000 == 0 else (whole // 10000 + 1) / 10.0


def cvss3_score(vector):
    """The base score of a CVSS 3.x vector's metrics ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), or None when one is missing
    or unknown. Owner, 11-20: Adobe's APSB26-101 stated 7.8 for CVE-2026-110087 beside a vector that gives 6.7."""
    m = dict(part.split(":", 1) for part in vector.strip("/").split("/") if ":" in part)
    try:
        changed = {"U": False, "C": True}[m["S"]]
        cia = [CVSS3["CIA"][m[k]] for k in ("C", "I", "A")]
        reach = 8.22 * CVSS3["AV"][m["AV"]] * CVSS3["AC"][m["AC"]] * CVSS3["PR"][m["PR"]][changed] * CVSS3["UI"][m["UI"]]
    except KeyError:
        return None
    iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    return roundup(min((1.08 if changed else 1) * (impact + reach), 10))
SCORE_REACH = 400  # characters from a CVE ID to its score on a page naming several


def advisory_scores(input_text, cves):
    """{CVE ID: {"cvss", "version", "source"}} from the input's official advisory pages (mention_kinds), for the
    Incident's own CVEs only (page_scores); the first advisory that gives a CVE one wins. Read by code, never the model."""
    kinds, found = mention_kinds(input_text), {}
    for block in SOURCE_RE.finditer(input_text):
        if block[1] and kinds.get(block[1]) == "advisory":
            for cve, entry in page_scores(block[3], cves).items():
                found.setdefault(cve, entry | {"source": block[1]})
    return found


def page_scores(text, cves):
    """{CVE ID: {"cvss", "version"}} one advisory page's text gives its CVEs. A page naming one CVE ID gives it every score
    on the page; a page naming several gives a score to the one CVE ID named between it and the score before it (at most
    SCORE_REACH characters back), and to none when no ID or more than one stands there. A score whose own CVSS 3.x
    vector (right after it) gives another score is skipped (cvss3_score). Two different scores for one CVE stand only
    when their versions are stated and differ (the higher wins, as merge_score's rule); otherwise that CVE gets none.
    Only cves (the Incident's) are returned."""
    wanted = {c.upper() for c in cves}
    ids = [(m.start(), m[0].upper()) for m in CVE_ID.finditer(text)]
    seen, bad, last = {}, set(), 0
    found = list(ADVISORY_SCORE_RE.finditer(text))
    for n, m in enumerate(found):
        start, last = max(last, m.start() - SCORE_REACH), m.end()
        # What follows a score up to the next one (300 characters at most) is its own: its vector, its version.
        tail = text[m.end():min(m.end() + 300, found[n + 1].start() if n + 1 < len(found) else len(text))]
        if len({c for _, c in ids}) == 1:
            cve = ids[0][1]
        else:
            near = {c for p, c in ids if start <= p < m.start()}
            if len(near) != 1:  # none near, or a list ("CVE-A and CVE-B ... CVSS 9.8"): whose it is is unsaid
                continue
            cve = near.pop()
        version = m["ver2"] or (m["ver"] if m["ver"] and "." in m["ver"] else "")
        if not version and (vec := VECTOR_VERSION_RE.search(tail)):
            version = vec[1]
        if not version and m["ver"] == "4":
            version = "4.0"
        # A score its own CVSS 3.x vector contradicts is a typo on the page: neither is taken (the record's stays).
        vector = VECTOR_3_RE.search(tail) if not version.startswith("4") else None
        if vector and cvss3_score(vector[1]) not in (None, float(m["n"])):
            continue
        entry = {"cvss": float(m["n"]), "version": version}
        old = seen.get(cve)
        if old and old["cvss"] != entry["cvss"]:
            if not (old["version"] and version and old["version"] != version):
                bad.add(cve)
            elif entry["cvss"] > old["cvss"]:
                seen[cve] = entry
        elif not old:
            seen[cve] = entry
    return {c: e for c, e in seen.items() if c in wanted and c not in bad}


def severity_word(text):
    """The severity word one official advisory page's text states (SEVERITY_RE), as critical|high|medium|low, or None."""
    found = SEVERITY_RE.search(text)
    if found:
        word = " ".join(found[1].lower().split())
        return SEVERITY_WORDS.get(word, word)
    return None


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
