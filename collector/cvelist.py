"""Source adapter: new CVE records from the cvelistV5 delta log, and updates to CVEs already on the Board."""

import html
import re
import json
import sys
from urllib.parse import unquote, urlsplit

from collector.hn import is_repo
from collector.incidents import VENDORS, is_http, to_stamp

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
# CVE JSON 5 reference tags that mark the product's own advisory or release note.
OWN_TAGS = {"vendor-advisory", "release-notes"}
# GitHub's and older MITRE-format records' tag; it also marks other vendors' notes (Log4j's lists SonicWall's), so it ranks after.
ADVISORY_TAGS = OWN_TAGS | {"x_refsource_CONFIRM"}
# Tags that mark someone else's analysis or a working exploit: listed as write-ups (a repo when on GitHub).
WRITEUP_TAGS = {"third-party-advisory", "technical-description", "exploit", "x_research-advisory"}
# Words dropped before a CNA, vendor or site name is compared ("Six Apart Ltd." is sixapart.jp).
COMPANY_WORDS = {"inc", "corp", "corporation", "co", "ltd", "limited", "llc", "gmbh", "ag", "sa", "plc", "foundation"}
# Coordinator CNAs, which file for other vendors, and the site label of their own write-ups (jvn.jp).
COORDINATORS = {"jpcert": "jvn"}
# CNAs that file for themselves under a vendor name other than their own, as their records write it (owner, 11-15: kept by
# hand, matched exactly). Each was checked in the records: every affected product theirs, references on their own site.
VENDOR_CNAS = {"hpe": {"Hewlett Packard Enterprise (HPE)"}, "absolute": {"Absolute Software", "Absolute Security"},
               "unisoc": {"Unisoc (Shanghai) Technologies Co., Ltd."}, "intel": {"n/a"}, "postgresql": {"n/a"},
               "sap": {"SAP_SE"}, "netscaler": {"Citrix", "Citrix NetScaler"}, "axis": {"Axis Communications AB"},
               "octopus": {"Octopus Deploy"}, "zoom": {"Zoom Communications"}}
# Second-level labels under a country code that are not the site's own ("example.co.jp").
SECOND_LEVEL = {"co", "com", "ne", "or", "ac", "go", "gov", "net", "org", "edu"}
# A tracker, code review or forum page (Bugzilla, Jira, Phabricator, Gerrit, issues, pull requests, Discourse): outsiders
# write there. shortcut: Launchpad, Mantis and Jira's ?selectedIssue= on other hosts are missed; add them when seen.
TRACKER = re.compile(r"//(?:bugzilla|bugs?|jira|phabricator|gerrit|discuss|forums?|community)\.|show_bug|/browse/[a-z]+-\d"
                     r"|/(?:issues|work_items|pull|merge_requests|ticket)/\d", re.I)


MAX_RECORDS = 250


def fetch(checkpoint, http_get, known=frozenset(), limit=MAX_RECORDS):
    """Return (new published CVE records, next checkpoint). The checkpoint is a delta fetchTime.

    An updated record is read only when its CVE is in `known` (already on the Board), so a CNA adding
    an advisory or exploit link reaches the row without pulling the hundreds of old CVEs touched daily.
    A long gap (a backfill, a box that was down) is read oldest first, whole entries at a time, until `limit`
    records; the checkpoint stops after the last entry read, so the next cycle goes on from there (owner, 11-09: a
    7-day backfill in one cycle would have run for hours)."""
    log = json.loads(http_get(DELTA_LOG_URL))  # newest entry first
    if not log:
        return [], checkpoint
    # shortcut: with no checkpoint, start from the newest entry instead of backfilling 30 days.
    entries = [e for e in log if e["fetchTime"] > checkpoint] if checkpoint else log[:1]
    links = {}
    reached = log[0]["fetchTime"]
    for entry in reversed(entries):
        for item in entry["new"] + [u for u in entry.get("updated", []) if u["cveId"] in known]:
            links.setdefault(item["cveId"], item["githubLink"])
        if len(links) >= limit and entry is not entries[0]:
            reached = entry["fetchTime"]
            break
    records = [json.loads(http_get(url)) for url in links.values()]
    return [r for r in records if r["cveMetadata"]["state"] == "PUBLISHED"], reached


RECORD_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group}xxx/{cve}.json"


def record_url(cve):
    _, year, number = cve.split("-")
    return RECORD_URL.format(year=year, group=number[:-3], cve=cve)


MISSING_PER_CYCLE = 20
# Real CVE numbers have 4 to 7 digits; a longer token from a post must never reach int() (over 4300 digits it raises).
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.ASCII)


def fetch_missing(cves, http_get, limit=MISSING_PER_CYCLE):
    """Records of CVEs the Board cites but never read: a Mention named the CVE before the record reached the delta
    log this store started from, or an older CVE came up in discussion (11-09: nine Apache Airflow rows had no
    Product). At most `limit` a cycle, newest IDs first; one not published yet (404) is asked again next cycle."""
    records = []
    for cve in sorted(filter(CVE_ID.fullmatch, cves), key=lambda c: [int(p) for p in c.split("-")[1:]], reverse=True)[:limit]:
        try:
            record = json.loads(http_get(record_url(cve)))
        except (OSError, ValueError):
            continue
        if record.get("cveMetadata", {}).get("state") == "PUBLISHED":
            records.append(record)
    return records


def mention_groups(records):
    """One Mention group per record; a malformed record is skipped and logged, never the rest of the cycle's records."""
    groups = []
    for record in records:
        try:
            groups.append(mention_group(record))
        except (AttributeError, KeyError, TypeError, ValueError) as err:
            meta = record.get("cveMetadata") if isinstance(record, dict) else None
            cve = meta.get("cveId") if isinstance(meta, dict) else "?"
            print(f"cvelist: skipped record {cve}: {err!r}"[:300], file=sys.stderr)
    return groups


def words(name):
    return [w for w in re.findall(r"[^\W_]+", name.lower()) if w not in COMPANY_WORDS]


def site_label(url):
    """The registrable domain's own label as written: "sonicwall" for psirt.global.sonicwall.com, "sonic-wall" kept apart."""
    try:
        labels = (urlsplit(url).hostname or "").split(".")
    except ValueError:
        return ""
    # shortcut: only a country code under SECOND_LEVEL is known; other multi-label suffixes give the suffix's label.
    i = 3 if len(labels) > 2 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else 2
    return labels[-i] if len(labels) >= i else ""


def has_id(url):
    """A digit in the path or query: a list page ("www.asus.com/security-advisory") has none."""
    # shortcut: an id is taken to hold a digit, so a letter-only one (cisco-sa-cucs-rce-LzHSFRDQ) is missed;
    # upgrade if such vendors' advisories matter.
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return bool(re.search(r"[0-9]", unquote(parts.path + parts.query)))  # "%20" is not an id


def own_names(record):
    """Site labels that are the affected vendor's own: its name joined when a coordinator wrote the record; that or
    its first word ("samsung" for Samsung Semiconductor) when the vendor itself did, its CNA name being the vendor's
    in whole words (the Joomla CNA files for joomlaboat.com, which is not Joomla's) or paired with it in VENDOR_CNAS,
    and then the CNA name too (support.hpe.com for "Hewlett Packard Enterprise (HPE)"); else none."""
    cna = (record["cveMetadata"].get("assignerShortName") or "").lower()
    vendors = [a.get("vendor") or "" for a in record["containers"]["cna"].get("affected", [])]
    if cna in COORDINATORS:
        return {"".join(w) for w in map(words, vendors) if w}
    own = [w for v, w in zip(vendors, map(words, vendors)) if w and ("".join(w) == "".join(words(cna)) or v in VENDOR_CNAS.get(cna, ()))]
    return {n for w in own for n in ("".join(w), w[0], "".join(words(cna)))}


def mention_group(record):
    """The CVE record as a Mention; references it tags as an advisory, release note, analysis or exploit join it.
    A reference the CNA wrote with no tags and an id in its path joins as an advisory when it sits on the vendor's
    own site and the vendor or a coordinator wrote the record (as a write-up when it is a bug tracker entry), and as
    a write-up on the coordinator's own site; the rest only key the Incident (owner, 11-15)."""
    cve = record["cveMetadata"]["cveId"]
    # ADP containers (CISA's, mostly) add references too: sshole's sshhole.com exploit tag lives only there.
    containers = [record["containers"]["cna"], *record["containers"].get("adp", [])]
    refs = [r for c in containers for r in c.get("references", []) if is_http(r.get("url"))]
    # A URL a known tag marks anywhere in the record keeps that kind (CISA tags an Eclipse report page exploit).
    tagged = {r["url"] for r in refs if (ADVISORY_TAGS | WRITEUP_TAGS) & set(r.get("tags") or [])}
    untagged = [r["url"] for r in containers[0].get("references", [])
                if is_http(r.get("url")) and not r.get("tags") and r["url"] not in tagged and has_id(r["url"])]
    score, vector = record_cvss(containers)
    public = to_stamp(containers[0].get("datePublic"))  # M4: the day the CNA says the flaw became public
    names, coordinator = own_names(record), COORDINATORS.get((record["cveMetadata"].get("assignerShortName") or "").lower())
    own_first = sorted(refs, key=lambda r: not OWN_TAGS & set(r.get("tags") or []))  # stable: reference order otherwise
    vendor_tagged = {r["url"] for r in refs if OWN_TAGS & set(r.get("tags") or [])}
    candidates = [r["url"] for r in own_first if ADVISORY_TAGS & set(r.get("tags") or [])] + [u for u in untagged if site_label(u) in names]
    # A tracker is a write-up unless the vendor itself tagged it vendor-advisory (a CONFIRM-tagged Bugzilla bug is not).
    advisories = [u for u in candidates if u in vendor_tagged or not TRACKER.search(u)]
    writeups = ([r["url"] for r in refs if WRITEUP_TAGS & set(r.get("tags") or [])] + [u for u in candidates if u not in advisories]
                + [u for u in untagged if site_label(u) == coordinator])
    writeups = [u for u in writeups if u not in advisories]
    return {
        "mentions": [{"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"}]
        + [{"kind": "advisory", "url": u} for u in dict.fromkeys(advisories)]
        + [{"kind": "repo" if is_repo(u) else "writeup", "url": u} for u in dict.fromkeys(writeups)],
        "cves": [cve],
        "urls": [r["url"] for r in refs],
        "text": one_line_description(record),
        "published": to_stamp(record["cveMetadata"].get("datePublished")),
        "cvss": score,
        **({"cve_scores": {cve: {"cvss": score, "vector": vector}}} if score is not None else {}),
        **({"public_dates": {cve: public[:10]}} if public else {}),
        "products": record_products(record),
        "fix_keys": record_fix_keys(record),
    }


# CVSS versions in the order the Board reads them: its bands (9.0 / 7.0 / 4.0) are v3's; v4 uses the same.
CVSS_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")


def cna_products(record):
    """(key, product, affected entry) for each of the CNA's named vendor/product pairs. The product's HTML entities
    are unescaped ("Contact Form 7 &#8211; Post Fields" showed as written, 11-11); the key stays the raw one's."""
    assigner = (record.get("cveMetadata", {}).get("assignerShortName") or "").lower()
    for a in record["containers"]["cna"].get("affected", []):
        vendor, product = (a.get("vendor") or "").strip(), (a.get("product") or "").strip()
        # A CNA writing "n/a" for its own product is the vendor: a known vendor ("intel", "AI Playground software") or
        # one that leads the name ("Acme(R) Widget"), 11-11. A third party's "n/a" (WPScan, a WordPress plugin) is skipped.
        if vendor.lower() in ("", "n/a", "unknown") and assigner and product and (
                assigner in VENDORS or re.sub(r"(\(r\)|®|™)$", "", product.split()[0].lower()) == assigner):
            vendor = assigner
        if not vendor or not product or vendor.lower() in ("n/a", "unknown") or product.lower() in ("n/a", "unknown"):
            continue
        yield f"{vendor}:{product}".lower().replace(" ", "_"), html.unescape(product), a


# A range written into "version" (GitHub's records, NVIDIA's, Intel's): "< 1.4.5", ">= 8.0.0, < 8.10.2", "<= 7.0.0",
# "= 1.27.0", "before version 2.4.0", "prior to 615.71.09", "25.05.0 through 25.05.8", "11.13.1 and earlier".
UPPER_BOUND = re.compile(r"(<=|<|(?<![<>])=|\bbefore|\bprior to|\bthrough)\s*(?:version\s+)?v?(\d\S*)$", re.I)
AND_EARLIER = re.compile(r"v?(\d[^\s,]*)\s+and (?:earlier|prior)", re.I)


def stated_bound(version):
    """("<", "1.4.5") for a first fixed version, ("<=", "7.0.0") for a last affected one, or None: no range stated."""
    found = UPPER_BOUND.search(version.strip())
    if found:
        return ("<" if found[1].lower() in ("<", "before", "prior to") else "<="), found[2]
    found = AND_EARLIER.search(version)
    return ("<=", found[1]) if found else None


def record_fix_keys(record):
    """Product and first fixed version pairs ("openemr:openemr<8.3.0") from the CNA's affected ranges, so CVEs one
    release fixed together can be grouped into one Incident (incidents.group_releases)."""
    keys = set()
    for key, a in fix_key_entries(record):
        affected = [v for v in a.get("versions", []) if v.get("status") == "affected"]
        keys |= {f"{key}<{v['lessThan']}" for v in affected if v.get("lessThan")}
        stated = [(v, stated_bound(str(v["version"]))) for v in affected if v.get("version") and not v.get("lessThan")]
        keys |= {f"{key}<{bound[1]}" for _, bound in stated if bound and bound[0] == "<"}
        # No range given (VulDB lists every affected version): the last affected one stands for the fix that follows it.
        # "0 up to 1.2.11" (lessThanOrEqual, Wordfence and IBM records) counts as 1.2.11, "<= 7.0.0" as 7.0.0.
        listed = [v.get("lessThanOrEqual") or (bound[1] if bound else v["version"]) for v, bound in stated
                  if not (bound and bound[0] == "<")]
        if listed and not any(k.startswith(f"{key}<") for k in keys):
            # ASCII digits only and short: isdigit() passes "²", which int() rejects, as it does over 4300 digits.
            top = max(listed, key=lambda v: [int(p) if p.isascii() and p.isdigit() and len(p) < 20 else -1
                                             for p in re.split(r"[.\-]", v)])
            keys.add(f"{key}<={top}")
        if not any(k.startswith(f"{key}<") for k in keys):
            # 11-16, only when the affected entries gave none: the fix stated as "unaffected from X" (Mozilla: 160 up to
            # "*"; Red Hat: a package build up to "*", its packageName in the key so two packages with one version string
            # stay apart). Never a list of single versions.
            package = (a.get("packageName") or "").strip().lower().replace(" ", "_")
            package = "" if key.endswith(f":{package}") else package  # a package record's key is the package already
            keys |= {f"{key}{':' + package if package else ''}<{v['version']}" for v in a.get("versions", [])
                     if v.get("status") == "unaffected" and v.get("version") and open_above(v)}
    # Owner, 11-16: a "version" without a digit is no version ("google:android<=Android kernel" tied 159 Incidents).
    return sorted(k for k in keys if re.search(r"[0-9]", k.split("<", 1)[1]))


PURL_TYPE = re.compile(r"pkg:([a-z0-9.+-]+)/", re.I)
# Names that stand for no product: never a key's namespace.
PLACEHOLDER_PRODUCTS = {"n/a", "unknown", "all", "multiple", "multiple products", "unspecified", "various", "none"}


def fix_key_entries(record):
    """(key, affected entry) pairs the fix keys are read from: the CNA's named products (cna_products), and (11-16) the
    entries cna_products skips: a package with no vendor or product (CPANSec: "pkg:cpan/JSON-XS" gives "cpan:json-xs";
    the purl's type, else the collection's host, keeps two ecosystems' packages of one name apart), or a product a third
    party names under vendor "Unknown" or "n/a" (WPScan), keyed under that CNA's name. Never a key with neither."""
    named = list(cna_products(record))
    out, taken = [(key, a) for key, _, a in named], {id(a) for _, _, a in named}
    assigner = (record.get("cveMetadata", {}).get("assignerShortName") or "").strip()
    for a in record["containers"]["cna"].get("affected", []):
        if id(a) in taken:
            continue
        package, product = (a.get("packageName") or "").strip(), (a.get("product") or "").strip()
        purl = PURL_TYPE.match(a.get("packageURL") or "")
        where = urlsplit(a.get("collectionURL") or "")
        # The collection's host and path, not the host alone: github.com/a/x and github.com/b/x are two homes.
        ecosystem = purl[1] if purl else f"{where.hostname}{where.path.rstrip('/')}" if where.hostname else None
        name = (f"{ecosystem}:{package}" if package and ecosystem and not (a.get("vendor") or "").strip() else
                f"{assigner}:{product}" if assigner and re.search(r"[a-z]{3}", product.lower())
                and product.lower() not in PLACEHOLDER_PRODUCTS else None)
        if name and "<" not in name:
            out.append((name.lower().replace(" ", "_"), a))
    return out


def open_above(entry):
    """An unaffected entry open at the top ("*") or within its own line ("153.7" up to "153.*")."""
    top = str(entry.get("lessThan") or entry.get("lessThanOrEqual") or "")
    if re.fullmatch(r"0(?:[.:\-]0)*", str(entry["version"])):
        return False  # unaffected from 0: never affected, not a fix (it would tie every CVE of the vendor's batch)
    return top == "*" or top.endswith(".*") and str(entry["version"]).startswith(top[:-1])


def record_products(record):
    """The CNA's affected vendor/product pairs as Products, keyed like NVD's CPE ids ("sonicwall:sonicos")
    so the two sources merge; the name is the product as the CNA writes it ("SonicOS")."""
    found = {key: {"id": key, "name": product} for key, product, _ in cna_products(record)}
    return sorted(found.values(), key=lambda p: p["id"])


def record_cvss(containers):
    """(score, vector) of the record's own base score (the CNA's, else an ADP's such as CISA's), or (None, ""). NVD often
    defers its analysis, so this is the only score most new CVEs have; enrich() keeps the higher when NVD adds one. The
    vector is the same metric's vectorString as given ("" when the record has none)."""
    for key in CVSS_KEYS:
        for c in containers:
            for metric in c.get("metrics", []):
                score = metric.get(key, {}).get("baseScore")
                if isinstance(score, (int, float)):
                    vector = metric[key].get("vectorString")
                    return score, vector if isinstance(vector, str) else ""
    return None, ""


def one_line_description(record):
    for d in record["containers"]["cna"].get("descriptions", []):
        if d["lang"].startswith("en"):
            return " ".join(d["value"].split())
    return record["containers"]["cna"].get("title") or ""
