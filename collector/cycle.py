"""One collection cycle: read the store, fetch each source, link Mentions, write changed files."""

import hashlib
import json
import sys
import time
from datetime import timedelta

import anthropic

from collector import curators, cvelist, github, hn, kev, kisa, news, nvd, osssec, summaries
from collector.incidents import (PICKER_DAYS, STAMP, board_view, cite, enrich, group_releases, link, month_of, page_keys,
                                 page_slug, product_list, rejoin, search_worthy, unknown_vendors)

RECENT_DAYS = 7  # the Board opens on these days (board/recent.json); older months load on demand
FEED_SIZE = 50  # the RSS feeds' newest search-worthy Incidents (board/feed.json; spec: Incident pages and the RSS feed)
PAGE_DAYS = 90  # an Incident page lives this long from first seen; edge/page.mjs answers 410 after it (PAGE_DAYS in web/board.mjs)


def run_cycle(store, http_get, now, collector_id, sleep=time.sleep, nvd_api_key="", github_token=None,
              curator_feeds=(), news_feeds=(), kisa_feed=None, claude=None):
    """claude: an anthropic.Anthropic client, or None for Briefs only."""
    stamp = now.strftime(STAMP)
    checkpoints = store.read("checkpoints.json") or {}
    index = store.read("index.json") or {"months": []}
    # shortcut: loads every month to link against; fine for v1 volumes, revisit past a year.
    incidents = [i for m in index["months"] for i in store.read(f"months/{m}.json")["incidents"]]

    on_board = {cve for i in incidents for cve in i["cves"]}
    records, checkpoints["cvelist"] = cvelist.fetch(checkpoints.get("cvelist"), http_get, on_board)
    # CVEs of the last month's rows whose record no cycle has read (no cve_record Mention for them yet)
    read = {r["cveMetadata"]["cveId"] for r in records}
    since = (now - timedelta(days=summaries.BATCH_DAYS)).strftime(STAMP)
    missing = {cve for i in incidents if i["first_seen"] >= since for cve in i["cves"]
               if cve not in read and {"kind": "cve_record", "url": f"https://www.cve.org/CVERecord?id={cve}"} not in i["mentions"]}
    records += cvelist.fetch_missing(missing, http_get)
    posts, checkpoints["oss-security"] = osssec.fetch(checkpoints.get("oss-security"), http_get)
    stories, checkpoints["hn"] = hn.fetch(checkpoints.get("hn"), http_get)
    repos, checkpoints["github"] = github.fetch(checkpoints.get("github"), http_get, sleep, github_token)
    articles, checkpoints["news"] = news.fetch(checkpoints.get("news"), http_get, news_feeds)

    for story in stories + articles:
        # A story with no CVE in its title may still be about a known Incident; its linked page says which.
        writeup = next((m["url"] for m in story["mentions"] if m["kind"] == "writeup"), None)
        if writeup and not story["cves"] and not story["join_only"]:
            page = summaries.fetch_page(http_get, writeup)
            if page:
                story["page"] = page_keys(page, writeup)

    changed = set()
    # Join-only repos go last, so they can join Incidents that started this cycle.
    for group in [cvelist.mention_group(r) for r in records] + posts + stories + articles + repos:
        changed |= link(incidents, group, stamp)
    changed |= group_releases(incidents)
    changed |= rejoin(incidents, (now - timedelta(days=7)).strftime(STAMP))
    changed |= hn.refresh_points(incidents, now, http_get)

    try:
        enriched, checkpoints["nvd"] = nvd.fetch(checkpoints.get("nvd"), now, http_get, sleep, nvd_api_key)
    except (OSError, ValueError, KeyError) as err:
        # NVD is often down; Briefs still go out and the next cycle retries the same range.
        print(f"nvd: skipped this cycle: {err!r}", file=sys.stderr)
        enriched = {}
    exploited = kev.fetch(http_get)
    citations, checkpoints["curators"] = curators.fetch(checkpoints.get("curators"), http_get, curator_feeds)
    notices, checkpoints["kisa"] = kisa.fetch(checkpoints.get("kisa"), http_get, kisa_feed)
    citations += notices
    for incident in incidents:
        before = json.dumps(incident)
        for cve in incident["cves"]:
            if cve in enriched:
                enrich(incident, enriched[cve])
        listed = exploited.keys() & set(incident["cves"])
        if listed:
            incident["kev"] = True
            # The earliest listing day of its CVEs: the panel's "CISA KEV 등재 · 2026-11-06" (critique 14).
            days = sorted(exploited[cve] for cve in listed if exploited[cve])
            if days:
                incident["kev_date"] = days[0]
        for c in citations:
            cite(incident, c)
        if json.dumps(incident) != before:
            changed.add(month_of(incident["first_seen"]))

    status = {"updated": stamp, "collector": collector_id}
    batches = store.read("batches.json") or []
    if claude:
        was_paused = (store.read("status.json") or {}).get("summaries") == "paused"
        try:
            route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe=was_paused)
        except anthropic.APIError as err:
            # Briefs still go out; the next cycle asks again.
            print(f"summaries: stopped this cycle: {err!r}", file=sys.stderr)
            if summaries.is_budget_error(err):
                status["summaries"] = "paused"
        store.write("batches.json", batches)

    for m in changed:
        # Incidents stay in the month they were first seen; a merge can empty an older month's row.
        store.write(f"months/{m}.json", {"month": m, "incidents": [i for i in incidents if month_of(i["first_seen"]) == m]})
    # The page's slim files: changed months, any month not written yet, and the last week every cycle.
    for m in changed | {m for m in index["months"] if store.read(f"board/{m}.json") is None}:
        store.write(f"board/{m}.json", {"month": m, "incidents": [board_view(i) for i in incidents if month_of(i["first_seen"]) == m]})
    recent_since = (now - timedelta(days=RECENT_DAYS)).strftime(STAMP)
    store.write("board/recent.json", {"since": recent_since,
                                      "incidents": [board_view(i) for i in incidents if i["first_seen"] >= recent_since]})
    newest = sorted((i for i in incidents if search_worthy(i)), key=lambda i: i.get("published") or i["first_seen"], reverse=True)
    feed = {"incidents": [board_view(i) for i in newest[:FEED_SIZE]]}
    if store.read("board/feed.json") != feed:
        store.write("board/feed.json", feed)
    write_pages(store, incidents, now, stamp)
    write_moves(store, incidents, stamp)
    picker_since = (now - timedelta(days=PICKER_DAYS)).strftime(STAMP)
    store.write("board/products.json", {"since": picker_since, "products": product_list(incidents, picker_since)})
    store.write("unknown_vendors.json", unknown_vendors(incidents, picker_since))
    if changed - set(index["months"]):
        store.write("index.json", {"months": sorted(changed | set(index["months"]))})
    store.write("checkpoints.json", checkpoints)
    store.write("status.json", status)


def route_summaries(incidents, batches, claude, http_get, now, stamp, changed, probe):
    """Collect ended batches, summarize every Highlight candidate at once, title every row still without a Summary,
    batch the rest's Summaries. Lets API errors
    through. probe: Summaries were paused last cycle, so send a one-request batch to test the budget
    instead of building a full one that would likely fail."""
    for pending in list(batches):
        touched = summaries.collect_batch(pending, incidents, claude, stamp)
        if touched is not None:
            batches.remove(pending)
            changed.update(month_of(i["first_seen"]) for i in touched)
    waiting = {r["incident"] for b in batches for r in b["requests"].values()}
    # A candidate (위험 and up, KEV, buzz, curator) never waits for a batch it is already in (user, 2026-11-09).
    due = [i for i in incidents if summaries.needs_summary(i) and (i["id"] not in waiting or summaries.is_candidate(i, now))]
    instant = sorted((i for i in due if summaries.is_candidate(i, now)), key=summaries.priority)
    for incident in instant:  # every candidate in the cycle that sees it: a breaking-news board (owner, 2026-11-09)
        summaries.summarize_now(incident, claude, http_get, stamp)
        changed.add(month_of(incident["first_seen"]))
    since = (now - timedelta(days=summaries.BATCH_DAYS)).strftime(STAMP)
    rest = [i for i in due if i not in instant and i["first_seen"] >= since]
    # Every row still without a Summary gets its titles now, several a request (owner, 2026-11-09): candidates whose
    # Summary failed first, then the rest of the window, those waiting in a batch included. Their Summaries go out
    # together (summaries.BATCH_MIN). A row a reply left out keeps needs_title and is asked again next cycle.
    untitled = [i for i in instant + [i for i in incidents if i not in instant and i["first_seen"] >= since]
                if summaries.needs_title(i)]
    for n in range(0, len(untitled), summaries.TITLES_PER_CALL):
        summaries.title_now(untitled[n:n + summaries.TITLES_PER_CALL], claude, stamp)
        changed.update(month_of(i["first_seen"]) for i in untitled[n:n + summaries.TITLES_PER_CALL])
    oldest = min((i["first_seen"] for i in rest), default=None)
    ready = probe or len(rest) >= summaries.BATCH_MIN or (
        oldest is not None and oldest <= (now - timedelta(hours=summaries.BATCH_WAIT_HOURS)).strftime(STAMP))
    pending = ready and summaries.submit_batch(rest, claude, http_get, limit=1 if probe else summaries.MAX_PER_BATCH)
    if pending:
        batches.append(pending)


def write_pages(store, incidents, now, stamp):
    """One Incident page document per slug (pages/<slug>.json, the Board's fields) for every Incident with a Summary first
    seen in the last PAGE_DAYS; the function decides on-Board, 404 and 410 from it. A page is rewritten only when its
    fields changed: page_hashes.json keeps {slug: [hash, changed]}, so a cycle reads one document, not one per page."""
    since = (now - timedelta(days=PAGE_DAYS)).strftime(STAMP)
    known = store.read("page_hashes.json") or {}
    pages = {}
    for incident in incidents:
        if not incident.get("summary") or incident["first_seen"] < since:
            continue
        slug, view = page_slug(incident["id"]), board_view(incident)
        digest = hashlib.sha256(json.dumps(view, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        pages[slug] = known.get(slug)
        if (pages[slug] or [None])[0] != digest:
            pages[slug] = [digest, stamp]
            store.write(f"pages/{slug}.json", view)
    if pages != known:
        store.write("page_hashes.json", pages)


def write_moves(store, incidents, stamp):
    """A "moved to" document in place of each absorbed Incident's page (pages/<slug>.json, so its old page stops
    rendering): the function answers 301 to the survivor, 410 once the move or the survivor is PAGE_DAYS old.
    moves.json keeps {slug: [survivor slug, moved]}, so a document is written only when a slug moves or its survivor
    is absorbed in turn (the chain ends at the last survivor; "moved" stays when the address first moved)."""
    known = store.read("moves.json") or {}
    live = {page_slug(i["id"]) for i in incidents}  # shortcut: an ID that is an Incident again keeps its own page
    moves = dict(known)
    for incident in incidents:
        to = page_slug(incident["id"])
        for gone in incident.get("absorbed", []):
            slug = page_slug(gone)
            if slug in live or (known.get(slug) or [None])[0] == to:
                continue
            moves[slug] = [to, (known.get(slug) or [None, stamp])[1]]
            store.write(f"pages/{slug}.json", {"id": gone, "moved_to": to, "moved": moves[slug][1]})
    if moves != known:
        store.write("moves.json", moves)
