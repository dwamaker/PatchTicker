"""The collector's http_get: polite, size-capped, and only to public addresses (SSRF guard)."""

import contextlib
import http.client
import ipaddress
import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 64 << 20  # NVD's 2,000-result pages are the largest legitimate answer
DEADLINE = 120  # seconds for one whole fetch, redirects included; the 60 s socket timeout is per read only
POST_DEADLINE = 10  # a webhook post; a slow Discord must not hold the cycle


def check_public(url):
    """Summaries read pages any HN poster can name, so refuse anything but http(s) to public addresses.

    Returns the checked addresses: the connection goes to these, never to a second DNS answer.
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
    addresses = [info[4][0].split("%")[0] for info in infos]
    if not all(ipaddress.ip_address(address).is_global for address in addresses):
        raise urllib.error.URLError(f"refused: {url} is not a public address")
    return addresses


def pinned(connection_class, req):
    """The connection keeps its host for the Host header, SNI and certificate, but dials req.addresses."""

    def connect(address, timeout, source_address=None):
        for ip in req.addresses:
            if req.expired.is_set():  # cut() has run already and would never see a socket dialled now
                break
            try:
                sock = socket.create_connection((ip, address[1]), timeout, source_address)
            except OSError as err:
                error = err
                continue
            req.sockets.append(sock.dup())  # a dup survives the TLS wrap, so the deadline can still cut it
            if req.expired.is_set():  # checked after the append, so cut() either saw this socket or ran before
                sock.close()
                break
            return sock
        else:
            raise error
        raise OSError("deadline passed")

    def make(host, **kwargs):
        conn = connection_class(host, **kwargs)
        conn._create_connection = connect
        return conn

    return make


class PinnedHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(pinned(http.client.HTTPConnection, req), req)


class PinnedHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(pinned(http.client.HTTPSConnection, req), req, context=self._context)


class PublicRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        addresses = check_public(newurl)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        new.addresses, new.sockets, new.expired = addresses, req.sockets, req.expired
        return new


def cut(sockets, expired):
    expired.set()
    for sock in sockets:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)


def make_http_get(user_agent):
    opener = urllib.request.build_opener(PinnedHTTP, PinnedHTTPS, PublicRedirects)

    def http_get(url, headers=None):
        return fetch(opener, url, {"User-Agent": user_agent, **(headers or {})})

    return http_get


def make_http_post(user_agent):
    """A JSON POST (the Discord webhook) under the same rules as http_get, within POST_DEADLINE; a non-2xx answer
    (a 429 too) is an OSError (urllib's HTTPError)."""
    opener = urllib.request.build_opener(PinnedHTTP, PinnedHTTPS, PublicRedirects)

    def http_post(url, payload):
        fetch(opener, url, {"User-Agent": user_agent, "Content-Type": "application/json"}, json.dumps(payload).encode(), POST_DEADLINE)

    return http_post


def fetch(opener, url, headers, data=None, deadline=None):
    deadline = deadline or DEADLINE  # read at call time: tests shorten DEADLINE
    addresses = check_public(url)
    req = urllib.request.Request(url, data=data, headers=headers)
    req.addresses, req.sockets, req.expired = addresses, [], threading.Event()
    timer = threading.Timer(deadline, cut, (req.sockets, req.expired))
    timer.daemon = True
    timer.start()
    try:
        with opener.open(req, timeout=min(60, deadline)) as res:
            body = res.read(MAX_BYTES + 1)
    except http.client.HTTPException as err:  # a malformed answer: callers skip OSError, not this (audit 4)
        raise OSError(f"{url}: {err!r}") from None
    finally:
        timer.cancel()
        for sock in req.sockets:
            sock.close()
        if req.expired.is_set():
            raise OSError(f"{url}: no full answer within {deadline} s")
    if len(body) > MAX_BYTES:
        raise OSError(f"{url}: response over {MAX_BYTES} bytes")
    return body
