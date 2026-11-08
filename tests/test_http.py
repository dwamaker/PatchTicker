"""The collector's real http_get reads pages that Mentions point at, so it must not reach our own network."""

import unittest
from urllib.error import URLError

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


if __name__ == "__main__":
    unittest.main()
