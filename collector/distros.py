"""Source adapter: what each Linux distribution's own security data says about a CVE (the Distribution table).

One line per (distribution, release, package): fixed in a version, not affected, or not fixed yet. Built by rule from
the distributions' data, never from the Summary. A release the data does not name, or one not in RELEASES, gets no line.
"""

import datetime
import gzip
import json
import re
import sys
import urllib.error
import zlib

FIXED, NOT_AFFECTED, NOT_FIXED = "fixed", "not_affected", "not_fixed"
# What a bad answer raises (read() turns a broken gzip body into ValueError): a source that raises one fails alone.
ERRORS = (OSError, ValueError, LookupError, TypeError, AttributeError)
WONT_FIX = "wont_fix"  # Ubuntu only: the distribution decided not to fix it there (owner, 2026-11-16)

# The releases shown, in display order, with the day support ends ("" = no end known). Dates as of 2026-11-16, from
# ubuntu.com/security/releases.json (standard support; ESM is Ubuntu Pro), distro-info-data debian.csv (eol-lts,
# 13: eol), alpinelinux.org/releases.json (main), Red Hat's product-life-cycles API (maintenance end), and
# suse.com/lifecycle (SLES general support). Release ids are as the source writes them (Ubuntu's and Debian's codenames).
# shortcut: kept by hand; a new release (Ubuntu April/October, Alpine May/November, RHEL, SLES 16.x each November)
# shows no line until added here. openSUSE's lifetime page refused the request, so Leap and Tumbleweed have no end.
RELEASES = {
    "Debian": [("trixie", "Debian 13 (trixie)", "2028-08-09"), ("bookworm", "Debian 12 (bookworm)", "2028-06-30")],
    "Ubuntu": [("stonking", "Ubuntu 26.10", "2027-07-15"), ("resolute", "Ubuntu 26.04 LTS", "2031-07-31"),
               ("noble", "Ubuntu 24.04 LTS", "2029-05-31"), ("jammy", "Ubuntu 22.04 LTS", "2027-04-30")],
    "Alpine": [("v3.24", "Alpine 3.24", "2028-06-01"), ("v3.23", "Alpine 3.23", "2027-11-01"),
               ("v3.22", "Alpine 3.22", "2027-05-01")],
    "Red Hat": [("10", "RHEL 10", "2035-05-31"), ("9", "RHEL 9", "2032-05-31"), ("8", "RHEL 8", "2029-05-31")],
    "SUSE": [("SUSE Linux Enterprise Server 16.1", "SLES 16.1", "2028-11-30"),
             ("SUSE Linux Enterprise Server 16.0", "SLES 16.0", "2027-11-30"),
             ("SUSE Linux Enterprise Server 15 SP7", "SLES 15 SP7", "2031-07-31"), ("openSUSE Leap 16.0", "openSUSE Leap 16.0", ""),
             ("openSUSE Tumbleweed", "openSUSE Tumbleweed", "")],
    "Arch Linux": [("rolling", "Arch Linux", "")],
}
DISTROS = list(RELEASES)
# Debian and Alpine publish whole files, not one per CVE: the caller fetches them once a day and passes their indexes.
BULK = {"Debian", "Alpine"}
DEBIAN_JSON = "https://security-tracker.debian.org/tracker/data/json"
ALPINE_SECDB = [f"https://secdb.alpinelinux.org/{branch}/{repo}.json"
                for branch, _, _ in RELEASES["Alpine"] for repo in ("main", "community")]

REDHAT_STATES = {"Affected": NOT_FIXED, "Will not fix": NOT_FIXED, "Fix deferred": NOT_FIXED,
                 "Out of support scope": NOT_FIXED, "Not affected": NOT_AFFECTED}  # Under investigation: no line
ARCH_STATES = {"Fixed": FIXED, "Not affected": NOT_AFFECTED, "Vulnerable": NOT_FIXED, "Testing": NOT_FIXED}
SUSE_STATES = {"recommended": FIXED, "known_not_affected": NOT_AFFECTED, "known_affected": NOT_FIXED}
UBUNTU_STATES = {"fixed": FIXED, "affected": NOT_FIXED, "not_affected": NOT_AFFECTED}  # under_investigation: no line
# A source package in a standard release; Ubuntu Pro builds name "esm-infra/focal" or "fips-updates/jammy" and do not
# match, so they get no line: a reader without Pro cannot install them.
UBUNTU_SOURCE = re.compile(r"pkg:deb/ubuntu/([^@]+)@[^?]*\?arch=source&distro=([a-z]+)$")
UBUNTU_REPO = "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main"
# Ubuntu's CVE API, an auxiliary source only: Canonical calls it a work in progress, subject to change, and points
# machines to its other feeds. Asked at most once a lookup, when the repository files fail or give an "affected" line.
UBUNTU_API = "https://ubuntu.com/security/cves/{cve}.json"
UBUNTU_API_STATES = {"released": FIXED, "not-affected": NOT_AFFECTED, "needed": NOT_FIXED, "pending": NOT_FIXED,
                     "deferred": NOT_FIXED, "ignored": WONT_FIX}  # needs-triage, DNE: no line
# Mainline RHEL only (minor streams like 10.3 fold in); EUS/AUS/TUS/E4S/ELS and other products have their own CPEs.
RHEL_CPE = re.compile(r"cpe:/[ao]:redhat:enterprise_linux:(\d+)(?:\.\d+)?(?::|$)")
NEVRA = re.compile(r"(.+)-(\d+):([^-]+-[^-]+?)(?:\.src\.rpm)?$")

URLS = {
    "Debian": (DEBIAN_JSON, "https://security-tracker.debian.org/tracker/{cve}"),
    "Ubuntu": (UBUNTU_REPO + "/vex/cve/{year}/{cve}.json", "https://ubuntu.com/security/{cve}"),
    "Alpine": ("https://secdb.alpinelinux.org/", "https://security.alpinelinux.org/vuln/{cve}"),
    "Red Hat": ("https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json", "https://access.redhat.com/security/cve/{cve}"),
    "SUSE": ("https://ftp.suse.com/pub/projects/security/csaf-vex/{year}/{lower}.json", "https://www.suse.com/security/cve/{cve}.html"),
    "Arch Linux": ("https://security.archlinux.org/{cve}.json", "https://security.archlinux.org/{cve}"),
}
ARCH_GROUP = "https://security.archlinux.org/{group}.json"
# The credit line under the table: each source's name, its own page, and its licence where one was found (Red Hat's
# security data page and SUSE's CSAF files say CC BY 4.0, Canonical's repository CC BY-SA 4.0; both ask for
# attribution and a link). The Debian, Alpine and Arch data's licences were not found.
CREDITS = {
    "Debian": ("Debian Security Tracker", "https://security-tracker.debian.org/tracker/", ""),
    "Ubuntu": ("Ubuntu Security Notices (Canonical)", "https://github.com/canonical/ubuntu-security-notices", "CC BY-SA 4.0"),
    "Alpine": ("Alpine Linux secdb", "https://secdb.alpinelinux.org/", ""),
    "Red Hat": ("Red Hat Security Data", "https://access.redhat.com/security/data", "CC BY 4.0"),
    "SUSE": ("SUSE CSAF VEX", "https://ftp.suse.com/pub/projects/security/csaf-vex/", "CC BY 4.0"),
    "Arch Linux": ("Arch Linux Security Tracker", "https://security.archlinux.org/", ""),
}
LICENCES = {"CC BY 4.0": "https://creativecommons.org/licenses/by/4.0/",
            "CC BY-SA 4.0": "https://creativecommons.org/licenses/by-sa/4.0/"}


def lookup(cve, http_get, today=None, bulk=None):
    """{"lines": [...], "failed": [distribution, ...]} for one CVE. A distribution that does not know the CVE (404, or
    [] in its daily index) gives no line and is not failed; any other HTTP error, network error, an answer that is not
    the expected JSON (HTML, a renamed field), or a daily index missing or not yet covering the CVE is failed, and never
    stops the other distributions. bulk: daily_index's answer."""
    today = (today or datetime.date.today()).isoformat()
    lines, failed = [], []
    for distro in DISTROS:
        data_url, page = URLS[distro]
        fmt = {"cve": cve, "year": cve.split("-")[1], "lower": cve.lower()}
        get = lambda url: read(http_get(url, {"Accept-Encoding": "gzip"}))  # noqa: E731
        try:
            if distro in BULK:
                found = bulk[distro][cve]
            elif distro == "Ubuntu":
                found = ubuntu_lines(cve, get)
            else:
                try:
                    record = get(data_url.format(**fmt))
                except urllib.error.HTTPError as err:
                    if err.code == 404:  # only the CVE's own address: a later 404 (Arch's group) is a failure
                        continue
                    raise
                found = PARSERS[distro](record, get)
        except ERRORS:
            failed.append(distro)
            continue
        shown = {r: (label, end, i) for i, (r, label, end) in enumerate(RELEASES[distro])}
        rows = {(release, package, state, version) for release, package, state, version in found
                if release in shown and (not shown[release][1] or shown[release][1] > today)}
        # A versioned fix outranks another state for the same package (SUSE lists a binary both ways).
        fixed = {(r, p) for r, p, s, _ in rows if s == FIXED}
        rows = {row for row in rows if row[2] == FIXED or row[:2] not in fixed}
        lines += [{"distro": distro, "release": r, "label": shown[r][0], "package": p, "state": s, "version": v,
                   "url": page.format(**fmt)} for r, p, s, v in sorted(rows, key=lambda row: (shown[row[0]][2], row))]
    return {"lines": lines, "failed": failed}


def read(body):
    """http_get does not undo Content-Encoding. Debian's tracker file is 90 MB plain, 15 MB gzipped (net.py stops at
    64 MB); Ubuntu's kernel VEX 1.4 MB plain, 57 KB gzipped. SUSE did not compress."""
    try:
        return json.loads(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)
    except (EOFError, zlib.error) as err:  # a cut-off or corrupt gzip body
        raise ValueError(f"bad gzip body: {err!r}") from err


def daily_index(http_get, cves):
    """The day's Debian and Alpine answers for `cves` (the CVEs the store holds): {"Debian": {cve: rows}, "Alpine": ...}
    with every CVE present, [] where the distribution does not list it, so lookup tells "not listed" from "arrived after
    the index was built" (that one fails until tomorrow's). A distribution whose files fail is left out, for the caller
    to keep yesterday's. Parsing Debian's file peaks at about 333 MB of memory."""
    get = lambda url: http_get(url, {"Accept-Encoding": "gzip"})  # noqa: E731
    builds = {"Debian": lambda: debian_index(get(DEBIAN_JSON)), "Alpine": lambda: alpine_index([get(u) for u in ALPINE_SECDB])}
    index = {}
    for distro, build in builds.items():
        try:
            rows = build()
        except Exception as err:  # noqa: BLE001 - any surprise keeps yesterday's index, never refetches every cycle
            print(f"distros: {distro}'s daily file failed: {err!r}"[:300], file=sys.stderr)
            continue
        index[distro] = {cve: rows.get(cve, []) for cve in cves}
    return index


def debian_index(body):
    """The tracker's whole JSON ({package: {cve: {"releases": {codename: ...}}}}) to {cve: rows} for RELEASES. resolved
    with fixed_version "0" is not affected, other resolved is fixed; open is not fixed yet (also when Debian rates it
    unimportant or the package end-of-life); undetermined gets no line."""
    shown = {release for release, _, _ in RELEASES["Debian"]}
    index = {}
    for package, cves in read(body).items():
        for cve, info in cves.items():
            for release, entry in info["releases"].items():
                if release not in shown or entry["status"] not in ("resolved", "open"):
                    continue
                version = entry.get("fixed_version", "") if entry["status"] == "resolved" else ""
                state = NOT_FIXED if entry["status"] == "open" else NOT_AFFECTED if version == "0" else FIXED
                index.setdefault(cve, []).append((release, package, state, "" if version == "0" else version))
    return index


def alpine_index(bodies):
    """Alpine's secdb files (ALPINE_SECDB, one per branch and repository) to {cve: rows}: a CVE listed under a version
    is fixed in it; under "0" it never applied (not affected). secdb has no "not fixed yet"."""
    index = {}
    for body in bodies:
        db = read(body)
        for package in db["packages"]:
            for version, ids in (package["pkg"].get("secfixes") or {}).items():
                for cve in {t for i in ids for t in i.split() if t.startswith("CVE-")}:  # "CVE-2016-10013 XSA-204"
                    index.setdefault(cve, []).append((db["distroversion"], package["pkg"]["name"],
                                                      NOT_AFFECTED if version == "0" else FIXED, "" if version == "0" else version))
    return index


def ubuntu(vex, get):
    """Canonical's OpenVEX for the CVE: the state of each source package per release (affected covers Ubuntu's needed
    and ignored; under_investigation, its needs-triage, and a package not in the release get no line). A VEX version is
    the build in the archive now, so a fixed line takes its first fixed version from Canonical's OSV file of the CVE."""
    rows = {}
    for statement in vex["statements"]:
        if statement["status"] in UBUNTU_STATES and statement.get("justification") != "component_not_present":
            for product in statement["products"]:
                if found := UBUNTU_SOURCE.match(product["@id"]):
                    rows[found[2], found[1]] = UBUNTU_STATES[statement["status"]]
    rows = {(r, p): s for r, p, s, _ in kernels([(r, p, s, "") for (r, p), s in rows.items()])}
    fixes = {}
    if FIXED in rows.values():
        cve = vex["statements"][0]["vulnerability"]["name"]
        for affected in get(f"{UBUNTU_REPO}/osv/cve/{cve.split('-')[1]}/UBUNTU-{cve}.json")["affected"]:
            if found := UBUNTU_SOURCE.match(affected["package"].get("purl", "")):
                fixes[found[2], found[1]] = next((e["fixed"] for r in affected["ranges"] for e in r["events"]
                                                  if "fixed" in e), "")
    return [(r, p, s, fixes.get((r, p), "") if s == FIXED else "") for (r, p), s in rows.items()]


def redhat(record, get):
    """affected_release rows are fixed builds (NEVRA); package_state rows carry the other states, without a version.
    Either list may be missing. A module or container build that is not a NEVRA is skipped."""
    rows = []
    for row in record.get("affected_release") or []:
        release, nevra = RHEL_CPE.match(row.get("cpe") or ""), NEVRA.match(row.get("package") or "")
        if release and nevra:
            name, epoch, version = nevra.groups()
            rows.append((release[1], name, FIXED, version if epoch == "0" else f"{epoch}:{version}"))
    for row in record.get("package_state") or []:
        release = RHEL_CPE.match(row.get("cpe") or "")
        if release and row["fix_state"] in REDHAT_STATES:
            rows.append((release[1], row["package_name"], REDHAT_STATES[row["fix_state"]], ""))
    return rows


def suse(record, get):
    """SUSE's CSAF VEX: product ids pair a release with a binary RPM. A fixed binary names its source package and
    version in its purl (upstream=); an unfixed or unaffected one names only the binary, so those are cut to the
    binaries that start the names of others in the same release and state (gstreamer-plugins-base for its -devel and
    -lang, not libgstapp-1_0-0).
    shortcut: a source whose binaries share no prefix shows each binary; upgrade if such tables run long."""
    purls = {}
    branches = list(record["product_tree"]["branches"])
    while branches:
        branch = branches.pop()
        branches += branch.get("branches", [])
        product = branch.get("product") or {}
        purls[product.get("product_id")] = (product.get("product_identification_helper") or {}).get("purl", "")
    pairs = {r["full_product_name"]["product_id"]: (r["relates_to_product_reference"], r["product_reference"])
             for r in record["product_tree"].get("relationships", [])}
    rows, unversioned = set(), {}
    for status, ids in record["vulnerabilities"][0]["product_status"].items():
        for pid in ids:
            if status not in SUSE_STATES or pid not in pairs:  # chost: cloud images have no release
                continue
            release, ref = pairs[pid]
            source = NEVRA.match(purls.get(ref, "").partition("upstream=")[2])
            if SUSE_STATES[status] == FIXED and source:
                name, epoch, version = source.groups()
                rows.add((release, name, FIXED, version if epoch == "0" else f"{epoch}:{version}"))
            elif SUSE_STATES[status] != FIXED:
                unversioned.setdefault((release, SUSE_STATES[status]), set()).add(ref)
    for (release, state), names in unversioned.items():
        roots = {n for n in names if any(o.startswith(n + "-") for o in names)}
        roots = {n for n in roots if not any(n.startswith(r + "-") for r in roots)} or names
        rows |= {(release, name, state, "") for name in roots}
    return list(rows)


def arch(record, get):
    """Arch is rolling: one release. The CVE names its groups (AVG); each group holds the packages, status and fix."""
    rows = []
    for group in record["groups"]:
        avg = get(ARCH_GROUP.format(group=group))
        if avg["status"] in ARCH_STATES:
            state = ARCH_STATES[avg["status"]]
            rows += [("rolling", p, state, avg["fixed"] if state == FIXED else "") for p in avg["packages"]]
    return rows


PARSERS = {"Red Hat": redhat, "SUSE": suse, "Arch Linux": arch}


def ubuntu_lines(cve, get):
    """Ubuntu's rows: Canonical's repository files, refined or replaced by the CVE API. A "not fixed yet" row the API
    marks ignored becomes WONT_FIX; nothing else of the main rows changes. When the files are missing or fail, the API's
    rows stand in; when both fail, the files' error makes Ubuntu failed."""
    vex, rows, error = None, None, None
    try:
        vex = get(URLS["Ubuntu"][0].format(cve=cve, year=cve.split("-")[1]))
    except urllib.error.HTTPError as err:
        error = None if err.code == 404 else err
    except ERRORS as err:
        error = err
    if vex is not None:
        try:
            rows = ubuntu(vex, get)  # its OSV file answering 404 is a failure, not "not known"
        except ERRORS as err:
            error = err
    if rows is not None:
        api = ubuntu_api(cve, get) if any(s == NOT_FIXED for _, _, s, _ in rows) else {}
        return [(r, p, WONT_FIX if s == NOT_FIXED and api.get((r, p), ("",))[0] == WONT_FIX else s, v) for r, p, s, v in rows]
    api = ubuntu_api(cve, get)
    if api or error is None:
        return kernels([(r, p, s, v) for (r, p), (s, v) in api.items()])
    raise error


def ubuntu_api(cve, get):
    """{(release, package): (state, version)} from Ubuntu's CVE API, or {} on any failure or unexpected shape: it may
    change without notice, so it can only add, never break a lookup. Ubuntu Pro pockets are left out."""
    try:
        rows = {}
        for package in get(UBUNTU_API.format(cve=cve))["packages"]:
            for status in package["statuses"]:
                state = UBUNTU_API_STATES.get(status["status"])
                version = status["description"] if state == FIXED else ""
                if state and status.get("pocket") in ("security", "updates", None) and isinstance(version, str):
                    rows[str(status["release_codename"]), str(package["name"])] = (state, version)
        return rows
    except Exception:  # noqa: BLE001 - the auxiliary source can only add, whatever it answers
        return {}


def kernels(rows):
    """A kernel CVE keeps the generic kernel and its HWE backports (linux-hwe-6.17), not the 50 or so cloud, OEM and
    board flavours an Ubuntu release lists."""
    if not any(p == "linux" for _, p, _, _ in rows):
        return rows
    return [row for row in rows if row[1] == "linux" or row[1].startswith("linux-hwe-")]


def merge(found):
    """The table of a grouped Incident: {cve: lookup lines} to one row per (release, package, state, version), with the
    CVEs it holds for. CVEs that agree give one row; differing versions each keep a row (no version is picked). A row
    links the distribution's page of its first CVE, one the version came from."""
    order = {(d, r[0]): (i, j) for i, d in enumerate(DISTROS) for j, r in enumerate(RELEASES[d])}
    rows = {}
    for cve, lines in found.items():
        # A release taken out of RELEASES (ended, renamed) drops from the table; its stored lines stay until re-asked.
        for line in (line for line in lines if (line["distro"], line["release"]) in order):
            key = (line["distro"], line["release"], line["package"], line["state"], line["version"])
            row = rows.setdefault(key, line | {"cves": []})
            row["cves"].append(cve)
    return sorted(rows.values(), key=lambda r: (order[r["distro"], r["release"]], r["package"], r["state"], r["version"]))


def credits(rows):
    """The credit line's entries for the distributions that have a row, in table order."""
    return [{"distro": d, "name": CREDITS[d][0], "url": CREDITS[d][1], "licence": CREDITS[d][2],
             "licence_url": LICENCES.get(CREDITS[d][2], "")} for d in DISTROS if any(r["distro"] == d for r in rows)]


def settled(lines):
    """True when every line is fixed or not affected (owner, 2026-11-15): the re-check of a CVE that got lines can stop.
    A won't-fix line is followed too, as Ubuntu can still fix it."""
    return all(line["state"] in (FIXED, NOT_AFFECTED) for line in lines)
