"""IndexNow (owner, 11-11): one POST a cycle tells the search engines that take it (Bing, Naver, Yandex, Seznam and
others share one endpoint) which Incident pages the cycle wrote, so a new or changed page is crawled within minutes."""

import re
import sys
import urllib.error

ENDPOINT = "https://api.indexnow.org/indexnow"
SITE = "https://patchticker.com"
# Public by design: the engines fetch https://patchticker.com/<key>.txt (web/<key>.txt) to check that the site sent it.
KEY = re.compile(r"[a-f0-9]{32}", re.ASCII)
MAX_URLS = 10_000  # IndexNow takes at most this many URLs a request


def make_pinger(key, post):
    """A function that sends one request for a list of page slugs, or None when VR_INDEXNOW_KEY is unset (silently) or
    not 32 lowercase hex characters (one stderr line). post: net.make_http_post's http_post. A failed post is one stderr
    line, never retried; an empty list sends nothing."""
    if not key:
        return None
    if not KEY.fullmatch(key):
        print("indexnow: VR_INDEXNOW_KEY refused: not 32 lowercase hex characters; nothing is sent", file=sys.stderr)
        return None

    def ping(slugs):
        urls = [f"{SITE}{lang}/i/{slug}" for slug in slugs for lang in ("", "/en")][:MAX_URLS]
        if not urls:
            return
        try:
            post(ENDPOINT, {"host": "patchticker.com", "key": key, "keyLocation": f"{SITE}/{key}.txt", "urlList": urls})
        except (OSError, ValueError) as err:
            print(f"indexnow: post failed: {err.code if isinstance(err, urllib.error.HTTPError) else type(err).__name__}", file=sys.stderr)

    return ping
