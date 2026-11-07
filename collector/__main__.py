"""Run one collection cycle: python -m collector [path/to/envfile]  (default: .env)"""

import ipaddress
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from collector import curators
from collector.cycle import run_cycle
from collector.store import FolderStore

REQUIRED = ("VR_STORE_DIR", "VR_COLLECTOR_ID", "VR_CONTACT")
OPTIONAL = ("VR_NVD_API_KEY", "VR_GITHUB_TOKEN", "VR_CURATOR_FEEDS", "ANTHROPIC_API_KEY")


def load_settings(path):
    """KEY=VALUE lines from the env file; real environment variables win (as with Docker env_file)."""
    settings = {}
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                settings[key.strip()] = value.strip()
    settings.update({k: os.environ[k] for k in REQUIRED + OPTIONAL if os.environ.get(k)})
    missing = [k for k in REQUIRED if not settings.get(k)]
    if missing:
        sys.exit(f"missing settings in {path}: {', '.join(missing)}")
    return settings


MAX_BYTES = 64 << 20  # NVD's 2,000-result pages are the largest legitimate answer


def check_public(url):
    """Summaries read pages any HN poster can name, so refuse anything but http(s) to public addresses.

    shortcut: the name is resolved again by urlopen, so DNS rebinding can slip past; pin the
    resolved address in the connection if the collector ever runs next to sensitive services.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise urllib.error.URLError(f"refused: {url}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as err:
        raise urllib.error.URLError(f"refused: {url}: {err}") from None
    if not all(ipaddress.ip_address(info[4][0].split("%")[0]).is_global for info in infos):
        raise urllib.error.URLError(f"refused: {url} is not a public address")


class PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def make_http_get(user_agent):
    opener = urllib.request.build_opener(PublicRedirects)

    def http_get(url, headers=None):
        check_public(url)
        req = urllib.request.Request(url, headers={"User-Agent": user_agent, **(headers or {})})
        with opener.open(req, timeout=60) as res:
            body = res.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise OSError(f"{url}: response over {MAX_BYTES} bytes")
        return body

    return http_get


def main():
    settings = load_settings(sys.argv[1] if len(sys.argv) > 1 else ".env")
    key = settings.get("ANTHROPIC_API_KEY")
    run_cycle(
        FolderStore(settings["VR_STORE_DIR"]),
        make_http_get(f"vuln-radar/0.1 ({settings['VR_CONTACT']})"),
        datetime.now(timezone.utc),
        settings["VR_COLLECTOR_ID"],
        nvd_api_key=settings.get("VR_NVD_API_KEY", ""),
        github_token=settings.get("VR_GITHUB_TOKEN") or None,
        curator_feeds=[u.strip() for u in settings["VR_CURATOR_FEEDS"].split(",") if u.strip()]
        if "VR_CURATOR_FEEDS" in settings else curators.FEEDS,
        # The key is passed in, never left for the SDK to find in a login profile; no key, no Summaries.
        claude=anthropic.Anthropic(api_key=key) if key else None,
    )


if __name__ == "__main__":
    main()
