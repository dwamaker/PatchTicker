"""The collector's http_get: polite, size-capped, and only to public addresses (SSRF guard)."""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 64 << 20  # NVD's 2,000-result pages are the largest legitimate answer


def check_public(url):
    """Summaries read pages any HN poster can name, so refuse anything but http(s) to public addresses.

    shortcut: the name is resolved again by urlopen, so DNS rebinding can slip past; pin the
    resolved address in the connection if the collector ever runs next to sensitive services.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:  # "http://[..." from a scraped page: refused like any other bad address
        raise urllib.error.URLError(f"refused: {url}") from None
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
