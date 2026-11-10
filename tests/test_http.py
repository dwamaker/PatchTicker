"""The collector's real http_get reads pages that Mentions point at, so it must not reach our own network."""

import ipaddress
import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.error import URLError

from collector import net
from collector.net import make_http_get


class PrivateAddressTest(unittest.TestCase):
    def test_refuses_loopback_lan_and_link_local_addresses_without_connecting(self):
        http_get = make_http_get("vuln-radar/test")
        for url in ("http://127.0.0.1:9/", "http://localhost:9/", "https://192.168.0.10/admin",
                    "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:9/",
                    "ftp://example.com/", "file:///etc/passwd"):
            with self.subTest(url):
                with self.assertRaises(URLError):
                    http_get(url)


class Fixture(BaseHTTPRequestHandler):
    """One loopback server plays both the attacker's public host and the internal service."""

    def do_GET(self):
        self.server.paths.append(self.path)
        try:
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", f"http://rebind.test:{self.server.server_port}/secret")
                self.end_headers()
            elif self.path == "/secret":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"internal")
            elif self.path == "/drip-body":
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.drip(b"x" * 25)
            elif self.path == "/bad-status":
                self.wfile.write(b"garbage\r\n")
            elif self.path == "/drip-headers":
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                self.drip(b"X-Slow: " + b"y" * 25)
        except OSError:  # the client hung up on the drip, as it should
            pass

    def drip(self, data):
        for byte in data:  # 25 x 0.2 s: long past the test's deadline, short enough to end the test if unfixed
            self.wfile.write(bytes([byte]))
            self.wfile.flush()
            time.sleep(0.2)

    def log_message(self, *args):
        pass


class FakeNetwork(unittest.TestCase):
    """Names resolve through a scripted DNS; "public" addresses lead to the loopback fixture or nowhere."""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        self.server.paths = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_port
        # rebind.test answers public for the check, then the internal address for whoever asks next
        self.dns = {"start.test": ["93.184.216.10"], "drip.test": ["93.184.216.10"],
                    "rebind.test": ["93.184.216.34", "127.0.0.1"],
                    # one answer, several addresses: two that drop SYN, then the dripping host
                    "slow.test": [["93.184.216.99", "93.184.216.99", "93.184.216.10"]]}
        self.connected = []
        real_getaddrinfo, real_connect = socket.getaddrinfo, socket.create_connection

        def getaddrinfo(host, port, *args, **kwargs):
            try:
                ipaddress.ip_address(host)
                return real_getaddrinfo(host, port, *args, **kwargs)
            except ValueError:
                answers = self.dns[host]
                ips = answers.pop(0) if len(answers) > 1 else answers[0]
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
                        for ip in ([ips] if isinstance(ips, str) else ips)]

        def create_connection(address, timeout=None, source_address=None, **kwargs):
            ip = getaddrinfo(address[0], address[1])[0][4][0]
            self.connected.append(ip)
            if ip in ("93.184.216.10", "127.0.0.1"):
                return real_connect(("127.0.0.1", self.port), timeout)
            if ip == "93.184.216.99":
                time.sleep(1.2)  # stands in for a 60 s SYN timeout
                raise socket.timeout("timed out")
            raise OSError(f"{ip} is unreachable in tests")

        for name, fake in (("getaddrinfo", getaddrinfo), ("create_connection", create_connection)):
            patcher = mock.patch.object(socket, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.http_get = make_http_get("vuln-radar/test")


class RebindingTest(FakeNetwork):
    def test_connects_to_the_address_that_was_checked_not_a_second_answer(self):
        with self.assertRaises(URLError):
            self.http_get(f"http://rebind.test:{self.port}/secret")
        self.assertEqual(self.connected, ["93.184.216.34"])
        self.assertEqual(self.server.paths, [])

    def test_a_redirect_hop_is_pinned_to_its_checked_address_too(self):
        with self.assertRaises(URLError):
            self.http_get(f"http://start.test:{self.port}/")
        self.assertEqual(self.server.paths, ["/"])
        self.assertEqual(self.connected, ["93.184.216.10", "93.184.216.34"])

    def test_https_dials_the_checked_address_but_verifies_the_hostname(self):
        names = []

        def wrap_socket(context, sock, server_hostname=None, **kwargs):
            names.append(server_hostname)
            raise ssl.SSLError("no TLS in tests")

        with mock.patch.object(ssl.SSLContext, "wrap_socket", wrap_socket), self.assertRaises(URLError):
            self.http_get(f"https://start.test:{self.port}/")
        self.assertEqual(self.connected, ["93.184.216.10"])
        self.assertEqual(names, ["start.test"])


class MalformedAnswerTest(FakeNetwork):
    def test_a_malformed_answer_is_an_oserror_every_caller_already_skips(self):
        with self.assertRaises(OSError):  # BadStatusLine is an http.client.HTTPException, not an OSError
            self.http_get(f"http://drip.test:{self.port}/bad-status")


class DeadlineTest(FakeNetwork):
    def test_a_slow_drip_host_is_cut_off_at_the_overall_deadline(self):
        for path in ("/drip-body", "/drip-headers"):
            with self.subTest(path), mock.patch.object(net, "DEADLINE", 1):
                start = time.monotonic()
                with self.assertRaises(OSError):
                    self.http_get(f"http://drip.test:{self.port}{path}")
                self.assertLess(time.monotonic() - start, 3)

    def test_sockets_opened_after_the_deadline_are_not_dialled_or_kept(self):
        with mock.patch.object(net, "DEADLINE", 1):
            start = time.monotonic()
            with self.assertRaises(OSError):
                self.http_get(f"http://slow.test:{self.port}/drip-body")
            self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(self.connected, ["93.184.216.99"])


if __name__ == "__main__":
    unittest.main()
