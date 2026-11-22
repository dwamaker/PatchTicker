"""One collection cycle: read the store, fetch each source, link Mentions, write changed files."""

import hashlib
import json
import sys
import time
from datetime import date, timedelta

import anthropic

from collector import (checks, curators, cve_lines, cvelist, discord, distros, github, hn, kev, kisa, model, news, nvd, osssec,
                       same_event, sheets, summaries, summary_input, vendors)
from collector.logfile import CycleLine
from collector.incidents import (OTHERS_DAYS, PICKER_DAYS, STAMP, board_view, cite, enrich, group_releases, highlight_score, is_exploited, link, month_of,
                                 named as reader_named, on_board, page_keys, page_slug, product_counts, product_list, published_at, rejoin, risk_level, rows_view,
                                 search_worthy, stamp_ago, summary_failures, unknown_vendors)

RECENT_DAYS = 7  # the Board opens on these days (board/recent.json); older months load on demand
# The Distribution table (step 10). CVEs looked up a cycle: each costs about 4 s and 3 to 6 requests, and changes at
# most one Incident, so this bounds both the cycle's time and the pages it rewrites (about 2,100 lookups a day).
DISTRO_PER_CYCLE = 15
# Seconds a cycle starts lookups in (11-18: 15 lookups took 192-223 s a cycle, 13-15 s each against the 4 s measured,
# from Oracle's patch day; a lookup's six sources each may take net.DEADLINE). A lookup starts only inside it, the
# first always; the rest stay due for the next cycle, in the same order.
DISTRO_SECONDS = 90
DISTRO_PAUSE = 1  # seconds between two CVEs' lookups: no distribution's server sees a burst
# Owner, 2026-11-15: a CVE is asked once a day for 7 days; one that got a line is followed 30 days more, until every
# line is fixed or not affected. That rule holds for CVEs the day's Debian or Alpine index knows; a CVE neither knows
# is not asked (owner, 2026-11-16: the newest unknown CVEs, mostly web apps, took every slot, and 40 of them asked in
# the four other sources found no line) until the index comes to know it. Never-asked CVEs seen in the last 30 days
# are how Incidents posted before step 10 get their table.
DISTRO_FIRST_DAYS, DISTRO_FOLLOW_DAYS, DISTRO_BACKFILL_DAYS = 7, 37, 30
# board/rows.json keeps these whole, the rows most likely opened first (owner, 11-10): the newest, and the week's
# Highlights as filterBoard picks them (HIGHLIGHTS, SAME_PENALTY and pickHighlights in web/board.mjs).
WHOLE_NEWEST = 100
HIGHLIGHTS = 20  # owner, 11-20: twenty is the number
SAME_PENALTY = 10
# The RSS feeds' newest search-worthy Incidents (board/feed.json; spec: Incident pages and the RSS feed). Owner, 11-17: 50
# were 14 hours, so a reader that looks once a day missed items; 200 were about 3.5 days (feed.json ~0.9 MB, ~3 ms to render).
FEED_SIZE = 200
# The whole-Board feed (board/feed-all.json, /feed/all.xml; owner, 11-17): light items of the newest Board Incidents, every
# level. In November 63 to 560 were published a day (560 on Patch Tuesday, 11-10), so 600 hold the busiest day.
FEED_ALL_SIZE = 600
# An Incident page lives this long from first seen; edge/page.mjs answers 410 after it (PAGE_DAYS in web/board.mjs). The
# store keeps an Incident as long (owner, 11-10: 90 days, really; one that gets news later may come back as a new one).
PAGE_DAYS = 90
MERGE_LOG_SIZE = 300  # merge_log.json keeps the newest same_as decisions
# Seconds a cycle spends on Incident page and check documents; the rest waits for the next cycle. 2026-11-17: a field
# added to every check document made one cycle rewrite all 3,252 one PUT after another (~2.3 a second, 25 min), so
# status.json stood still 35 min and two cycles never ran. A usual cycle takes about 3 min of its 10; 120 s is ~280 PUTs.
BULK_SECONDS = 120
# Seconds a cycle spends on instant Summaries (owner's ledger, 11-18: Oracle's patch day brought 96 Incidents at 06:40
# KST, every one a candidate, asked one after another at 16-24 s each; that cycle took 25 min 53 s and the next two never
# ran). A Summary starts only inside the budget, so one may run past it by its own length. 180 s is about 9 Summaries:
# with the sources (~2 min), the sheets (at most 10, ~36 s), the titles and BULK_SECONDS, a cycle stays inside its 10
# minutes and the Board is written before the next mark. The rest wait for the next cycle, most urgent first (priority).
INSTANT_SECONDS = 180
# 긴급 rows are asked in the cycle that sees them even past INSTANT_SECONDS and CYCLE_SECONDS, at most this many past
# either (owner, 11-20: "긴급은 우선도 강제로"; PHP's 9.2 release sat on its stale Summary while 134 kernel CVEs ran the
# clock out). A cycle that runs long only delays the next mark (compose.yaml), and each Summary is about a minute.
URGENT_PAST_LIMIT = 4
# Seconds from a cycle's start after which the Summary step starts no new work: no page sheet, instant Summary, titles
# request or batch request (11-18: cycles took 600-612 s, so every other mark was skipped; the Summary step ran 244-295
# s, the batch inputs alone fetching pages and records for 46 Incidents). At least one instant Summary, one titles
# request and one batch request still go out a cycle, so a slow source never stops them all; the rest wait, most urgent
# first. With the last Summary's own length (~50 s) and the Board (~60 s), a cycle ends near 8 1/2 minutes at worst.
CYCLE_SECONDS = 400


# A CVE-less story's page that failed to load is fetched again (11-17: openjdk.org's advisory gave nothing at 21:10Z
# and answered the next day). Each retry waits for the story's age, as a page may go up after the story: 3 tries at
# 1, 4 and 12 hours, all inside a day, the story's useful time on the Board. At most 3 fetches a cycle: each may take
# DEADLINE (120 s, 6 min in all), and on 11-17 only 11 stories of the day lacked a page, so 3 of 144 cycles clear them.
PAGE_RETRY_HOURS = (1, 4, 12)
PAGE_RETRIES_PER_CYCLE = 3


def refetch_pages(incidents, http_get, now):
    """Fetch again the linked page of each CVE-less story Incident first seen in the last day that has no Citations
    (`cites`), stories stored before this rule included; return the months changed. `page_tries` counts the retries
    (stored only, never on the Board: board_view keeps PAGE_FIELDS)."""
    changed, left, day = set(), PAGE_RETRIES_PER_CYCLE, stamp_ago(now, days=1)
    for incident in incidents:
        tries = incident.get("page_tries", 0)
        writeup = next((m["url"] for m in incident["mentions"] if m["kind"] == "writeup"), None)
        if (not left or incident["cves"] or "cites" in incident or not writeup or tries >= len(PAGE_RETRY_HOURS)
                or not day <= incident["first_seen"] <= stamp_ago(now, hours=PAGE_RETRY_HOURS[tries])):
            continue
        left -= 1
        page = summary_input.fetch_page(http_get, writeup)
        if page:
            incident["cites"] = page_keys(page, writeup)
            incident.pop("page_tries", None)
        else:
            incident["page_tries"] = tries + 1
        changed.add(month_of(incident["first_seen"]))
    return changed


OLD_CVE_YEARS = 2  # all CVE ids this many years before now's year: an old event (owner, 11-17)
OLD_EVENT_DAYS = 14  # an event_date further back than this: an old event


def old_event(view, now):
    """An Incident that stays on the Board but is no Highlight candidate (owner, 11-17: "오래된 만큼 주요 사건엔 올라오지
    못하게"; Cursor's attack of 10-29 published 11-14, Huatian's CVE-2024-58406 seen attacked in 2024): every CVE id
    OLD_CVE_YEARS or more years before now's year, or the Summary's event_date (the review's day of the reported attack
    or incident) more than OLD_EVENT_DAYS before now's day. No date counts as new. oldEvent in web/board.mjs follows."""
    years = [int(c[4:8]) for c in view.get("cves") or [] if c[4:8].isdigit()]  # "CVE-2024-58406"
    if years and max(years) <= int(now[:4]) - OLD_CVE_YEARS:
        return True
    day = (view.get("summary") or {}).get("event_date") or ""
    return bool(day) and day < (date.fromisoformat(now[:10]) - timedelta(days=OLD_EVENT_DAYS)).isoformat()


def same_key(view):
    """A port of sameKey in web/board.mjs: the first Product id's vendor with its well_known.json category, else the
    vendor, else the row."""
    vendor = ((view.get("products") or [{}])[0].get("id") or "").split(":")[0]
    if not vendor:
        return f"id:{view['id']}"
    kind = view.get("known_kind")
    return f"{vendor}|{kind}" if isinstance(kind, str) and kind else vendor


def highlights(views, since, now=None):
    """The week's Highlights as filterBoard picks them from row views (pickHighlights in web/board.mjs, where the rule is
    explained; tests/fixtures/board/highlights-case.json keeps the two in step): of the Board's rows at 위험 or above
    published since `since`, no old event, by highlight_score (newest, then the id, among equals), the best each time
    after SAME_PENALTY per chosen row of its same_key; HIGHLIGHTS in all (owner, 11-19: one score, no reserved places)."""
    # Published in the window only (owner, 11-17), and no old event (old_event; now defaults to the window's end).
    now = now or (date.fromisoformat(since[:10]) + timedelta(days=RECENT_DAYS)).isoformat() + since[10:]
    rest = sorted((v for v in views if on_board(v) and published_at(v) >= since and risk_level(v) != "notice" and not old_event(v, now)),
                  key=lambda v: v["id"])
    rest.sort(key=lambda v: (highlight_score(v, now), published_at(v)), reverse=True)  # stable: ids ascending among equals
    scored = {v["id"]: highlight_score(v, now) for v in rest}
    chosen = []
    while rest and len(chosen) < HIGHLIGHTS:
        keys = [same_key(c) for c in chosen]
        best = max(range(len(rest)), key=lambda n: scored[rest[n]["id"]] - SAME_PENALTY * keys.count(same_key(rest[n])))
        chosen.append(rest.pop(best))
    return chosen


emit = print  # where the `cycle` line goes: stdout, so the container's output and the lasting log; tests quiet it


def run_cycle(store, http_get, now, collector_id, clock=time.monotonic, **options):
    """One cycle (steps), then its one `cycle` line (logfile.CycleLine), also when the cycle fails."""
    line = CycleLine(now.strftime(STAMP), clock)
    try:
        steps(store, line.counting(http_get), now, collector_id, clock=clock, line=line, **options)
    except BaseException as err:
        emit(line.text(err))
        raise
    emit(line.text())


def steps(store, http_get, now, collector_id, sleep=time.sleep, nvd_api_key="", github_token=None,
          curator_feeds=(), news_feeds=(), vendor_feeds=None, kisa_feed=None, claude=None, notify=None, ping=None, distro_table=False,
          review=False, clock=time.monotonic, line=None):
    """claude: an anthropic.Anthropic client, or None for Briefs only. notify: discord.make_notifier's function, or None.
    ping: indexnow.make_pinger's function, or None. distro_table: look up the Distribution table (step 10); off by
    default, as its pauses and requests would reach every test cycle. clock: what times BULK_SECONDS. line: the cycle's
    CycleLine, told each stage's end, counts and skipped sources."""
    stamp = now.strftime(STAMP)
    line = line or CycleLine(stamp, clock)
    checkpoints = store.read("checkpoints.json") or {}
    index = store.read("index.json") or {"months": []}
    # Every kept month to link against: at most four calendar months, as Incidents leave after PAGE_DAYS.
    incidents = [i for m in index["months"] for i in store.read(f"months/{m}.json")["incidents"]]
    held = list(incidents)  # to delete the sheets of those that leave this cycle (sheets.forget)
    # Pruned before any source is read: cvelist reads updated records only of CVEs still held, so an aged-out CVE's
    # record updates start nothing; real news about it may (owner, 11-10).
    changed = prune(incidents, stamp_ago(now, days=PAGE_DAYS))

    held_cves = {cve for i in incidents for cve in i["cves"]}
    records, checkpoints["cvelist"], checkpoints["cvelist_missing"] = cvelist.fetch(
        checkpoints.get("cvelist"), http_get, held_cves, pending=checkpoints.get("cvelist_missing"))
    line.records_missing = len(checkpoints["cvelist_missing"])
    # CVEs of the last month's rows whose record no cycle has read (no cve_record Mention for them yet)
    read = {r["cveMetadata"]["cveId"] for r in records} | checkpoints["cvelist_missing"].keys()
    since = stamp_ago(now, days=summaries.BATCH_DAYS)
    missing = {cve for i in incidents if i["first_seen"] >= since for cve in i["cves"]
               if cve not in read and {"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"} not in i["mentions"]}
    records += cvelist.fetch_missing(missing, http_get)
    posts, checkpoints["oss-security"] = osssec.fetch(checkpoints.get("oss-security"), http_get, stamp)
    # A failed Mention source, NVD or KEV skips itself, never the cycle; its checkpoint stays, so the next cycle asks again.
    # (cvelist is the main source: a cycle stopped there shows on the page as stale, which is the honest signal.)
    try:
        stories, checkpoints["hn"] = hn.fetch(checkpoints.get("hn"), http_get)
    except (OSError, ValueError, KeyError) as err:
        print(f"hn: skipped this cycle: {err!r}", file=sys.stderr)
        line.skip("hn")
        stories = []
    try:
        repos, checkpoints["github"] = github.fetch(checkpoints.get("github"), http_get, sleep, github_token)
    except (OSError, ValueError, KeyError) as err:
        # 2026-11-11: a rate-limited search (no token) ended a cycle. Repos only join Incidents.
        print(f"github: skipped this cycle: {err!r}", file=sys.stderr)
        line.skip("github")
        repos = []
    articles, checkpoints["news"] = news.fetch(checkpoints.get("news"), http_get, news_feeds, stamp)
    advisories, checkpoints["vendors"] = vendors.fetch(checkpoints.get("vendors"), http_get, vendor_feeds or {}, stamp)

    for story in stories + articles:
        # A story with no CVE in its title may still be about a known Incident; its linked page says which.
        writeup = next((m["url"] for m in story["mentions"] if m["kind"] == "writeup"), None)
        if writeup and not story["cves"] and not story["join_only"]:
            page = summary_input.fetch_page(http_get, writeup)
            if page:
                story["page"] = page_keys(page, writeup)

    line.lap("read", "link")
    # Join-only repos go last, so they can join Incidents that started this cycle.
    # Vendor advisories after the stories: one on another project's flaw only joins, maybe a row started this cycle.
    for group in cvelist.mention_groups(records) + posts + stories + articles + advisories + repos:
        changed |= link(incidents, group, stamp)
    changed |= group_releases(incidents)
    changed |= refetch_pages(incidents, http_get, now)
    changed |= rejoin(incidents, stamp_ago(now, days=7))
    try:
        changed |= hn.refresh_points(incidents, now, http_get)
    except (OSError, ValueError, KeyError) as err:  # it reads its one answer whole before changing any points
        print(f"hn points: skipped this cycle: {err!r}", file=sys.stderr)
        line.skip("hn_points")

    line.lap("link", "read")
    try:
        enriched, checkpoints["nvd"] = nvd.fetch(checkpoints.get("nvd"), now, http_get, sleep, nvd_api_key)
    except (OSError, ValueError, KeyError) as err:
        # NVD is often down; Briefs still go out and the next cycle retries the same range.
        print(f"nvd: skipped this cycle: {err!r}", file=sys.stderr)
        line.skip("nvd")
        enriched = {}
    try:
        exploited = kev.fetch(http_get)
    except (OSError, ValueError, KeyError) as err:  # flags are only ever set below, so an empty catalog clears none
        print(f"kev: skipped this cycle: {err!r}", file=sys.stderr)
        line.skip("kev")
        exploited = {}
    citations, checkpoints["curators"] = curators.fetch(checkpoints.get("curators"), http_get, curator_feeds, stamp)
    notices, checkpoints["kisa"] = kisa.fetch(checkpoints.get("kisa"), http_get, kisa_feed)
    citations += notices
    line.lap("read", "link")
    for incident in incidents:
        before = json.dumps(incident)
        for cve in incident["cves"]:
            if cve in enriched:
                enrich(incident, enriched[cve], cve)
        listed = exploited.keys() & set(incident["cves"])
        if listed:
            incident["kev"] = True
            # Each listed CVE by name (step 4), updated, never replaced: a CVE listed once stays named and keeps its day
            # (a catalogue entry that loses its dateAdded, "", does not blank it), as absorb keeps it.
            named = incident.setdefault("kev_cves", {})
            for cve in sorted(listed):
                named[cve] = named.get(cve) or exploited[cve]
            # The earliest listing day of its CVEs: the panel's "CISA KEV 등재 · 2026-11-06" (critique 14).
            days = sorted(exploited[cve] for cve in listed if exploited[cve])
            if days:
                incident["kev_date"] = days[0]
        for c in citations:
            cite(incident, c)
        if json.dumps(incident) != before:
            changed.add(month_of(incident["first_seen"]))
    line.count("new", sum(1 for i in incidents if i["first_seen"] == stamp))
    line.lap("link", "distros")

    distro_state = None
    try:
        if distro_table:
            months, distro_state = refresh_distros(store, incidents, http_get, now, sleep, clock, line.counts)
            changed |= months
        else:
            line.mark("distros", "off")
    except Exception as err:  # noqa: BLE001 - six outside sources and an unfinished API: any surprise costs the table only
        print(f"distros: skipped this cycle: {err!r}"[:300], file=sys.stderr)
        line.mark("distros", "skipped")
        line.skip("distros")
    line.lap("distros", "summaries")

    status = {"updated": stamp, "collector": collector_id}
    batches = store.read("batches.json") or []
    decisions, stopped, resumed = [], None, False
    if claude:
        # "paused" (a budget error; the page shows a notice) or "stopped" (any other API error), as the last cycle left it.
        was = (store.read("status.json") or {}).get("summaries")
        try:
            route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe=was == "paused", review=review,
                            store=store, clock=clock, line=line, deadline=line.began + CYCLE_SECONDS)
            changed.update(month_of(i["first_seen"]) for i in summaries.recheck_exploited(incidents))  # owner 11-16
        except anthropic.APIError as err:
            # Briefs still go out; the next cycle asks again (in full after "stopped", with a probe after "paused").
            print(f"summaries: stopped this cycle: {err!r}", file=sys.stderr)
            status["summaries"] = "paused" if summaries.is_budget_error(err) else "stopped"
            line.mark("summaries", status["summaries"])
            # 2026-11-11: a rejected schema stopped every Summary for two cycles and only stderr said so. Told once.
            stopped = None if was else err
        resumed = bool(was) and "summaries" not in status
        store.write("batches.json", batches)
        # same_as answers saved above (owner, 11-10): the code decides, and every decision is kept, newest first.
        merged, decisions = same_event.apply_same_as(incidents, stamp)
        changed |= merged
        if decisions:
            store.write("merge_log.json", (decisions[::-1] + (store.read("merge_log.json") or []))[:MERGE_LOG_SIZE])
    else:
        line.mark("sheets", "off")
        line.mark("summaries", "off")
    line.lap("summaries", "board")

    kept = {month_of(i["first_seen"]) for i in incidents}  # a month left with none (pruned or merged away) is deleted below
    for m in changed & kept:
        # Incidents stay in the month they were first seen; a merge can empty an older month's row.
        store.write(f"months/{m}.json", {"month": m, "incidents": [i for i in incidents if month_of(i["first_seen"]) == m]})
    if distro_state is not None:  # after the lines it records are stored: a cycle cut short before here asks again
        store.write("distros/state.json", distro_state)
    # Everything the reader sees shows each Product by one name (owner, 11-17): the views below are written from these
    # copies; the months above keep the Summaries as stored.
    shown_incidents = reader_named(incidents)
    # Every kept month's rows as the page counts them: equals the page's own count once it has loaded every month.
    status["total"] = sum(1 for i in shown_incidents if on_board(i))
    # The page's slim files: changed months, any month not written yet, and the last week every cycle.
    for m in (changed | {m for m in index["months"] if store.read(f"board/{m}.json") is None}) & kept:
        store.write(f"board/{m}.json", {"month": m, "incidents": [board_view(i) for i in shown_incidents if month_of(i["first_seen"]) == m]})
    recent_since = stamp_ago(now, days=RECENT_DAYS)
    # status rides along so the page opens on this file alone (a failed status.json drew an error Board for Googlebot).
    week = [i for i in shown_incidents if i["first_seen"] >= recent_since]
    store.write("board/recent.json", {"since": recent_since, "status": status, "incidents": [board_view(i) for i in week]})
    # The Board draws first from row views (owner, 11-10: 9 MB of details held a phone's first row back about a second) and
    # fetches recent.json only to open a row or search. The newest and the week's Highlights (filterBoard) stay whole.
    # The Highlight window is seven days by publish time (filterBoard), the same cut as recent_since.
    shown = sorted((i for i in week if on_board(i)), key=published_at, reverse=True)
    views = {i["id"]: rows_view(i) for i in week}  # what the page reads, `known` included
    whole = {i["id"] for i in shown[:WHOLE_NEWEST] + highlights(views.values(), recent_since, stamp)}
    store.write("board/rows.json", {"since": recent_since, "status": status,
                                    "incidents": [board_view(i) if i["id"] in whole else views[i["id"]] for i in week]})
    newest = sorted((i for i in shown_incidents if search_worthy(i)), key=published_at, reverse=True)
    feed = {"incidents": [board_view(i) for i in newest[:FEED_SIZE]]}
    if store.read("board/feed.json") != feed:
        store.write("board/feed.json", feed)
    board = sorted((i for i in shown_incidents if on_board(i)), key=published_at, reverse=True)
    feed_all = {"incidents": [checks.feed_entry(i) for i in board[:FEED_ALL_SIZE]]}
    if store.read("board/feed-all.json") != feed_all:
        store.write("board/feed-all.json", feed_all)
    had_page = store.read("page_hashes.json") or {}  # the page set as the last cycle left it
    # One budget, pages first: a check document's `detail` names a page, so no check is written before every due page is.
    pages = write_pages(store, shown_incidents, had_page, now, stamp, more := bulk_budget(clock))
    write_moves(store, incidents, had_page, now, stamp)
    product_docs = write_checks(store, shown_incidents, now, more)
    # The sitemaps' document (edge/sitemap.mjs): {slug: {first_seen, changed}} of every search-worthy Incident page, and
    # the product pages with enough Incidents to be worth a search (owner, 11-17).
    sitemap = {"pages": {slug: {"first_seen": i["first_seen"], "changed": pages[slug]["changed"]} for i in incidents
                         if (slug := page_slug(i["id"])) in pages and search_worthy(i)},
               "products": checks.product_pages(product_docs)}
    if store.read("sitemap.json") != sitemap:
        store.write("sitemap.json", sitemap)
    picker_since = stamp_ago(now, days=PICKER_DAYS)
    store.write("board/products.json", {"since": picker_since, "products": product_list(shown_incidents, picker_since)})
    # M1: one small document a cycle, read by the opened row and the Incident page; a count inside each page would
    # rewrite thousands of them (owner, 11-16).
    others_since = stamp_ago(now, days=OTHERS_DAYS)
    store.write("board/others.json", {"since": others_since, "counts": product_counts(shown_incidents, others_since)})
    store.write("unknown_vendors.json", unknown_vendors(incidents, picker_since))
    # Summaries given up for good, for a person or an agent to fix by hand (docs/agents/summary-failures.md).
    failures = summary_failures(incidents, stamp_ago(now, days=summaries.BATCH_DAYS))
    known = {f["id"] for f in store.read("summary_failures.json") or []}  # as the last cycle left it: a restart repeats none
    store.write("summary_failures.json", failures)
    months = sorted((changed | set(index["months"])) & kept)
    if months != index["months"]:
        store.write("index.json", {"months": months})
    ids = {i["id"] for i in incidents}
    sheets.forget(store, [i for i in held if i["id"] not in ids])
    for m in set(index["months"]) - kept:  # after the index drops them, so a cycle cut short here never reads a missing month
        store.delete(f"months/{m}.json")
        store.delete(f"board/{m}.json")
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", status)
    # Owner, 11-10: news for the owner, last, so a failed post costs nothing else (docs/development.md).
    text = discord.message([f for f in failures if f["id"] not in known], [d for d in decisions if d["accepted"]],
                           stopped, resumed)
    if notify and text:
        notify(text)
    if ping:
        # Search-worthy pages written this cycle only (the rest say noindex): never the whole set, even on a first run.
        ping(sorted(slug for slug in sitemap["pages"] if pages[slug] != had_page.get(slug)))
    line.lap("board")


def refresh_distros(store, incidents, http_get, now, sleep, clock=time.monotonic, counts=None):
    """Step 10: look up at most DISTRO_PER_CYCLE due CVEs in the distributions' data, starting none past DISTRO_SECONDS
    by clock (the first always). Returns the months changed and the
    state for distros/state.json (the caller writes it after the months), or None when it did not change. counts: the
    cycle line's, given distros_asked and distros_kept_back (due CVEs left for a later cycle).

    distros/index.json holds the day's Debian and Alpine answers for the CVEs held (rebuilt on the day's first cycle; a
    distribution whose files fail keeps the last). The state holds, for every CVE held, the day it was first seen and
    the first and last day it was asked: a new CVE that folds into an older Incident is new by its own day. The first
    run seeds each CVE's day from its Incident's first_seen, so Incidents posted before step 10 are backfill. Only CVEs
    the index knows are asked: new, then follow-ups, then backfill; one it comes to know later is new or backfill by
    its own seen day. An Incident
    holds only its lines ("distro_lines", {cve: lines}), changed only when a line changes, so a lookup that finds
    nothing new rewrites no page. A distribution that fails keeps the lines it gave before."""
    more = bulk_budget(clock, DISTRO_SECONDS)  # from the step's start: the day's first builds the index inside it
    counts = {} if counts is None else counts
    today = now.strftime("%Y-%m-%d")
    held = {cve: i for i in incidents for cve in i["cves"]}
    index = store.read("distros/index.json") or {}
    if index.get("day") != today:
        index = {d: index[d] for d in distros.BULK if d in index} | distros.daily_index(http_get, sorted(held)) | {"day": today}
        store.write("distros/index.json", index)
    stored = store.read("distros/state.json")
    state = {cve: entry for cve, entry in (stored or {}).items() if cve in held}
    for cve, incident in held.items():
        state.setdefault(cve, {"seen": today if stored is not None else incident["first_seen"][:10]})
    age = lambda day: (date.fromisoformat(today) - date.fromisoformat(day)).days  # noqa: E731
    knows = {cve for d in distros.BULK for cve, rows in (index.get(d) or {}).items() if rows}
    new, follow, backfill = {}, {}, {}
    for cve, entry in state.items():
        lines = (held[cve].get("distro_lines") or {}).get(cve)
        if "asked" not in entry:
            if cve not in knows:
                continue
            if age(entry["seen"]) < DISTRO_FIRST_DAYS:
                new[cve] = entry["seen"]
            elif age(entry["seen"]) < DISTRO_BACKFILL_DAYS:
                backfill[cve] = entry["seen"]
        elif entry["asked"] < today and (cve in knows or lines) and (
                age(entry["first"]) < DISTRO_FIRST_DAYS
                or lines and not distros.settled(lines) and age(entry["first"]) < DISTRO_FOLLOW_DAYS):
            follow[cve] = entry["asked"]
    due = (sorted(new, key=new.get, reverse=True) + sorted(follow, key=follow.get)
           + sorted(backfill, key=backfill.get, reverse=True))
    bulk = {d: index[d] for d in distros.BULK if d in index}
    changed, asked = set(), 0
    for n, cve in enumerate(due[:DISTRO_PER_CYCLE]):
        if n and not more():
            break
        if n:
            sleep(DISTRO_PAUSE)
        asked += 1
        incident = held[cve]
        old = (incident.get("distro_lines") or {}).get(cve, [])
        try:
            found = distros.lookup(cve, http_get, date.fromisoformat(today), bulk)
        except Exception as err:  # noqa: BLE001 - an unlisted shape fails this CVE alone, like a failed distribution
            print(f"distros: {cve} failed: {err!r}"[:300], file=sys.stderr)
            found = {"lines": [], "failed": distros.DISTROS}
        kept = [line for line in old if line["distro"] in found["failed"]]
        lines = sorted(found["lines"] + kept, key=lambda line: distros.DISTROS.index(line["distro"]))
        if lines != old:
            incident.setdefault("distro_lines", {})[cve] = lines
            changed.add(month_of(incident["first_seen"]))
        state[cve] = state[cve] | {"first": state[cve].get("first", today), "asked": today}
    counts["distros_asked"] = counts.get("distros_asked", 0) + asked
    counts["distros_kept_back"] = counts.get("distros_kept_back", 0) + len(due) - asked
    return changed, (state if state != stored else None)


def prune(incidents, since):
    """Drop the Incidents first seen before `since` (a stamp) in place; return their months. Deletion cannot be undone,
    and ageing takes about 1/90 of the store a day (a 45-day outage reaches half): more than half at once is a wrong
    clock or bad data, so nothing is pruned and one line says so."""
    old = [i for i in incidents if i["first_seen"] < since]
    if 2 * len(old) > len(incidents):
        print(f"retention: {len(old)} of {len(incidents)} Incidents are past {PAGE_DAYS} days; pruned none (wrong clock or bad data?)",
              file=sys.stderr)
        return set()
    incidents[:] = [i for i in incidents if i["first_seen"] >= since]
    return {month_of(i["first_seen"]) for i in old}


def route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe, review=False, store=None,
                    clock=time.monotonic, line=None, deadline=None):
    """Collect ended batches, summarize Highlight candidates at once (within INSTANT_SECONDS by clock), title every row
    still without a Summary, batch the rest's Summaries. Lets API errors through. probe: Summaries were paused last
    cycle, so send a one-request batch to test the budget instead of building a full one that would likely fail. review
    (VR_SUMMARY_REVIEW, owner 11-16): every Summary that passes the rule checks is reviewed before it is stored: at once
    on the instant path, in a review batch sent here for a batch reply (it waits in review_pending, shown as it was
    before, and is not asked again meanwhile). store: where the page sheets are cached (sheets.fill); None makes none.
    line: the cycle's CycleLine (the sheets' time and the counts). deadline: the clock reading (CYCLE_SECONDS into the
    cycle) past which no page sheet, instant Summary, titles request or batch request starts, but the first of each;
    None, no deadline. A try that fails waits for a later cycle, never runs twice in one, but for a reply the number
    check refused: it is sent back to be edited at once (summaries.edit_now), each edit a request counted in
    summaries_asked and started only within the deadline and the instant time (the batch's within BULK_SECONDS of its
    collection), else the row waits as before."""
    line = line or CycleLine(stamp, clock)
    open_ = (lambda: True) if deadline is None else (lambda: clock() < deadline)  # noqa: E731
    before = {i["id"]: i.get("summary") for i in incidents}  # keep() stores a new dict: what changed was stored here
    edits = bulk_budget(clock)
    for pending in list(batches):
        touched = summaries.collect_batch(pending, incidents, claude, stamp, review=review, room=lambda: edits() and open_(),
                                          asked=lambda: line.count("summaries_asked"))
        if touched is not None:
            batches.remove(pending)
            changed.update(month_of(i["first_seen"]) for i in touched)
    waiting = {r["incident"] for b in batches for r in b["requests"].values() if "lines" not in r}
    # A candidate (위험 and up, KEV, buzz, curator) never waits for a batch it is already in (user, 2026-11-09).
    due = [i for i in incidents if summaries.needs_summary(i) and not i.get("review_pending")
           and (i["id"] not in waiting or summaries.is_candidate(i, now))]
    instant = sorted((i for i in due if summaries.is_candidate(i, now)), key=summaries.priority)
    same_as = lambda incident: same_event.same_as_candidates(incident, incidents, now)  # applied by run_cycle (apply_same_as)
    since = stamp_ago(now, days=summaries.BATCH_DAYS)
    rest = [i for i in due if i not in instant and i["first_seen"] >= since]
    # Page sheets of the gated Incidents due now, the instant ones first, before any Summary is asked. A missing sheet
    # never holds a Summary back: it is written from what is there. Not on a probe: one request tests the budget.
    # The Summaries take the pages the sheets fetched, not fetching them again (shared_pages).
    keep, http_get = summary_input.shared_pages(http_get)
    line.lap("summaries", "sheets")
    made = sheets.fill(store, instant + rest, claude, keep, stamp, counts=line.counts, more=open_) if store and not probe else {}
    line.lap("sheets", "summaries")
    for incident in instant + rest:
        if incident["id"] in made and sheets.page_scores(incident, made[incident["id"]]):
            changed.add(month_of(incident["first_seen"]))
    sheets_of = lambda incident: made.get(incident["id"], ())
    # Every candidate in the cycle that sees it (a breaking-news board, owner 2026-11-09), inside INSTANT_SECONDS: the
    # rest keep their Brief and quick title until a later cycle. The first is asked even past the cycle's deadline.
    more = bulk_budget(clock, INSTANT_SECONDS)
    past = 0
    for n, incident in enumerate(instant):
        if n and not (more() and open_()):
            # priority() puts every 긴급 row first, a vendor's Critical with no CVSS yet among them (stated_level)
            if past < URGENT_PAST_LIMIT and "highest" in (risk_level(incident), summaries.stated_level(incident)):
                past += 1
            else:
                line.count("summaries_kept_back", len(instant) - n)
                if not open_():
                    line.count("summaries_deadline", len(instant) - n)
                break
        line.count("summaries_asked")
        summaries.summarize_now(incident, claude, http_get, stamp, same_as(incident), review=review, sheets=sheets_of(incident),
                                room=lambda: more() and open_(), asked=lambda: line.count("summaries_asked"))
        changed.add(month_of(incident["first_seen"]))
        if (incident.get("summary") or {}).get("at") != stamp:
            line.count("summaries_failed")  # a try counted (summary_error), the stored Summary or Brief stays
    # Every row still without a Summary gets its titles now, several a request (owner, 2026-11-09): candidates whose
    # Summary failed first, then the rest of the window, those waiting in a batch included. Their Summaries go out
    # together (summaries.BATCH_MIN). A row a reply left out keeps needs_title and is asked again next cycle.
    untitled = [i for i in instant + [i for i in incidents if i not in instant and i["first_seen"] >= since]
                if summaries.needs_title(i)]
    for n in range(0, len(untitled), summaries.TITLES_PER_CALL):
        if n and not open_():
            line.count("titles_kept_back", len(untitled) - n)
            break
        summaries.title_now(untitled[n:n + summaries.TITLES_PER_CALL], claude, stamp)
        changed.update(month_of(i["first_seen"]) for i in untitled[n:n + summaries.TITLES_PER_CALL])
    oldest = min((i["first_seen"] for i in rest), default=None)
    ready = probe or len(rest) >= summaries.BATCH_MIN or (
        oldest is not None and oldest <= stamp_ago(now, hours=summaries.BATCH_WAIT_HOURS))
    limit = 1 if probe else model.MAX_PER_BATCH
    # Each request's input fetches its pages and records: the requests built past the deadline wait for a later batch.
    pending = ready and summaries.submit_batch(rest, claude, http_get, limit=limit, candidates=same_as, sheets=sheets_of, more=open_)
    if pending:
        batches.append(pending)
        line.count("summaries_batched", len(pending["requests"]))
        line.count("summaries_deadline", min(len(rest), limit) - len(pending["requests"]))
    # Per-CVE lines past the Summary's own (owner, 2026-11-10), at once: a batch is cheap and they wait for nothing else.
    asked = {r["incident"] for b in batches for r in b["requests"].values() if "lines" in r}
    lines = not probe and cve_lines.submit_lines(
        [i for i in incidents if i["first_seen"] >= since and i["id"] not in asked and cve_lines.missing_lines(i)], claude)
    if lines:
        batches.append(lines)
        changed.update(month_of(i["first_seen"]) for i in incidents if i["id"] in {r["incident"] for r in lines["requests"].values()})
    # The second round: every Summary waiting for its review and in no pending batch (one too large to review is stored
    # here, unreviewed). Switched off, a Summary left waiting is stored as it is.
    waiting_review = [i for i in incidents if i.get("review_pending")]
    if not review:
        summaries.release_reviews(incidents, batches)
    reviews = review and not probe and summaries.submit_reviews(incidents, batches, claude)
    if reviews:
        batches.append(reviews)
    changed.update(month_of(i["first_seen"]) for i in waiting_review if "review_pending" not in i)  # stored here
    # The union's lines (summaries.save_reply) in the Summaries stored this cycle, on either path.
    line.fixes_lines += sum(1 for i in incidents if i.get("summary") is not before.get(i["id"])
                            for f in (i.get("summary") or {}).get("fixes") or [] if isinstance(f, dict) and f.get("from_sheet"))
    line.fixes_flagged += sum(1 for i in incidents if i.get("summary") is not before.get(i["id"])
                              and (i.get("summary") or {}).get("fixes_flagged"))
    line.fixes_carried += sum(1 for i in incidents if i.get("summary") is not before.get(i["id"])
                              for f in (i.get("summary") or {}).get("fixes") or [] if isinstance(f, dict) and f.get("from_stored"))


def bulk_budget(clock, seconds=None):
    """A function that answers True until `seconds` (BULK_SECONDS by default) after this call."""
    deadline = clock() + (BULK_SECONDS if seconds is None else seconds)
    return lambda: clock() < deadline


def digest_of(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def write_pages(store, incidents, known, now, stamp, more=lambda: True):
    """One Incident page document per slug (pages/<slug>.json, the Board's fields) for every Incident with a Summary first
    seen in the last PAGE_DAYS; the function decides on-Board, 404 and 410 from it. A page is rewritten only when its
    fields changed: page_hashes.json keeps {slug: {hash, changed}} (known: as the last cycle left it), so a cycle reads
    one document, not one per page. The index holds only this cycle's page set, so it never grows past 90 days of
    pages; the page documents left behind are deleted by the bucket's lifecycle rule (docs/development.md).
    more(): False once the cycle's writes must stop (bulk_budget). New pages go first, then changed ones, newest first;
    the rest wait for a later cycle: a changed page keeps its old document and entry, a new one has neither yet.
    Returns the index: the pages stored, by the hash of what each holds."""
    since = stamp_ago(now, days=PAGE_DAYS)
    pages, due = {}, []
    for incident in sorted(incidents, key=lambda i: i["first_seen"], reverse=True):
        if not incident.get("summary") or incident["first_seen"] < since:
            continue
        slug, view = page_slug(incident["id"]), board_view(incident)
        digest = digest_of(view)
        if slug in known:
            pages[slug] = known[slug]
        if known.get(slug, {}).get("hash") != digest:
            due.append((slug, view, digest))
    for slug, view, digest in sorted(due, key=lambda d: d[0] in known):  # a stable sort: newest first stays
        if not more():
            break
        store.write(f"pages/{slug}.json", view)
        pages[slug] = {"hash": digest, "changed": stamp}
    if pages != known:
        store.write("page_hashes.json", pages)
    return pages


def write_checks(store, incidents, now, more=lambda: True):
    """GET /api/check's documents (collector/checks.py): a Product's check/p/<slug>.json is rewritten only when it
    changed (check_hashes.json keeps {slug: hash}, so a cycle reads one document, not one per Product), the index when
    it changed, and a Product with no Incident left loses its document, after the index stops naming it. more() as in
    write_pages: new Products first; one left unwritten keeps its old document and hash, or, new, is in no index yet; a
    delete left over keeps its hash, so a later cycle deletes it. Returns the documents stored (the sitemap's product
    pages are worked out from them)."""
    docs, index = checks.check_docs(incidents, stamp_ago(now, days=PAGE_DAYS))
    known = store.read("check_hashes.json") or {}
    hashes = {slug: known[slug] for slug in docs if slug in known}  # what the store holds: an older document still answers
    for slug in sorted((s for s in docs if known.get(s) != digest_of(docs[s])), key=lambda s: s in known):
        if not more():
            break
        store.write(f"check/p/{slug}.json", docs[slug])
        hashes[slug] = digest_of(docs[slug])
    index = {key: stored for key, slugs in index.items() if (stored := [s for s in slugs if s in hashes])}
    if store.read("check/index.json") != index:
        store.write("check/index.json", index)
    for slug in known.keys() - docs.keys():
        if more():
            store.delete(f"check/p/{slug}.json")
        else:
            hashes[slug] = known[slug]
    if hashes != known:
        store.write("check_hashes.json", hashes)
    return {slug: doc for slug, doc in docs.items() if slug in hashes}


def write_moves(store, incidents, had_page, now, stamp):
    """A "moved to" document in place of each absorbed Incident's page (pages/<slug>.json, so its old page stops
    rendering): the function answers 301 to the survivor's page, 302 to its Board row while it has no page yet, 410
    once the move or the survivor is PAGE_DAYS old. Only an absorbed Incident that had a page (in had_page, the last
    cycle's page index) moves; one without a page stays a 404. moves.json keeps {slug: {moved_to, moved_to_id, moved}},
    so a document is written only when a slug moves or its survivor is absorbed in turn (the chain ends at the last
    survivor; "moved" stays when the address first moved). Moves past PAGE_DAYS leave the index: their page answers
    410 by then, and an expired slug is no longer in had_page, so it is never written again."""
    since = stamp_ago(now, days=PAGE_DAYS)
    known = store.read("moves.json") or {}
    moves = {slug: move for slug, move in known.items() if move["moved"] >= since}
    # shortcut: an absorbed ID that is an Incident again keeps its own page and loses the move; record both if a split
    # Incident ever needs its old address to say where it went.
    live = {page_slug(i["id"]) for i in incidents}
    for incident in incidents:
        to = page_slug(incident["id"])
        for gone in incident.get("absorbed", []):
            slug = page_slug(gone)
            if slug in live or (slug not in had_page and slug not in moves) or moves.get(slug, {}).get("moved_to") == to:
                continue
            moves[slug] = {"moved_to": to, "moved_to_id": incident["id"], "moved": moves.get(slug, {}).get("moved", stamp)}
            store.write(f"pages/{slug}.json", {"id": gone, **moves[slug]})
    if moves != known:
        store.write("moves.json", moves)
