"""Mention source: PoC and discoverer repositories from the GitHub search API."""

import json
from urllib.parse import urlencode

from collector.incidents import cves_in, is_http

SEARCH_URL = "https://api.github.com/search/repositories"
PER_PAGE = 100
MAX_PAGES = 3
# Search allows 30 requests/min with a token and 10 without; space requests to match.
PER_MINUTE = {True: 30, False: 10}


def fetch(checkpoint, http_get, sleep, token):
    """Return (Mention groups for repositories created after the checkpoint, next checkpoint).

    The checkpoint is the newest repository's created_at seen so far. Repositories only join
    Incidents: one that cites no known CVE or URL is not an Incident of its own.
    """
    # shortcut: finds repos that say "CVE" in name, description or README; a repo that never does
    # is found only through a CVE or URL a Mention already cites.
    q = "CVE in:name,description,readme" + (f" created:>{checkpoint}" if checkpoint else "")
    headers = {"Accept": "application/vnd.github+json"} | ({"Authorization": f"Bearer {token}"} if token else {})
    items = []
    for page in range(1, MAX_PAGES + 1):
        if page > 1:
            sleep(60 / PER_MINUTE[bool(token)])
        query = {"q": q, "sort": "updated", "per_page": PER_PAGE, "page": page}
        batch = json.loads(http_get(f"{SEARCH_URL}?{urlencode(query)}", headers))["items"]
        items += batch
        if len(batch) < PER_PAGE:
            break
    return [mention_group(r) for r in items], max([checkpoint or ""] + [r["created_at"] for r in items]) or None


def mention_group(repo):
    return {
        "mentions": [{"kind": "repo", "url": repo["html_url"], "title": repo["full_name"]}],
        "cves": cves_in(f"{repo['full_name']} {repo.get('description') or ''}"),
        "urls": [repo["homepage"]] if is_http(repo.get("homepage")) else [],
        "text": repo.get("description") or repo["full_name"],
        "join_only": True,
    }
