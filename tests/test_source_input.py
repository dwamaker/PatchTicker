"""Malformed or hostile source input is skipped, never stops the cycle (audit 2026-11-10, items 7, 8, 9, 11)."""

import contextlib
import io
import unittest

from collector import curators, cvelist, incidents, news, osssec

NOW = "2026-11-10T12:00:00Z"


def rss(*items):
    return ("<rss><channel>" + "".join(f"<item>{i}</item>" for i in items) + "</channel></rss>").encode()


def item(title, date="Tue, 10 Nov 2026 11:00:00 GMT", link="https://seclists.org/oss-sec/2026/q4/1"):
    return (f"<title>{title}</title>" + (f"<pubDate>{date}</pubDate>" if date else "")
            + (f"<link>{link}</link>" if link else "") + "<description>body</description>")


def feed(body):
    return lambda url, headers=None: body


class CveTokenTest(unittest.TestCase):
    def test_a_digit_run_too_long_for_a_cve_id_is_not_read_as_one(self):
        # Cut to 7 digits it would name a real but wrong CVE; whole, it would become a page file name (audit 7).
        self.assertEqual(incidents.cves_in("see CVE-2026-" + "1" * 300 + " and cve-2026-1234567, CVE-2026-12345678"),
                         ["CVE-2026-1234567"])
        self.assertEqual(incidents.cves_in("CVE-2026-１２３４５"), [])

    def test_a_cve_like_token_with_thousands_of_digits_is_not_fetched(self):
        asked = []

        def get(url, headers=None):
            asked.append(url)
            raise FileNotFoundError(url)

        cvelist.fetch_missing({"CVE-2026-" + "1" * 4301, "CVE-2026-123770"}, get)
        self.assertEqual([u.rsplit("/", 1)[-1] for u in asked], ["CVE-2026-123770.json"])


class OssSecurityFeedTest(unittest.TestCase):
    def test_a_feed_that_is_not_well_formed_is_skipped(self):
        for bad in (b"\x1b", b"&#27;"):
            body = rss(item("CVE-2026-1111 thing")).replace(b"body", bad)
            self.assertEqual(osssec.fetch("2026-11-01T00:00:00Z", feed(body), NOW), ([], "2026-11-01T00:00:00Z"))

    def test_an_item_without_a_date_or_link_is_skipped_and_the_rest_are_read(self):
        body = rss(item("CVE-2026-2222 no date", date=None), item("CVE-2026-3333 no link", link=None),
                   item("CVE-2026-4444 good"))
        groups, checkpoint = osssec.fetch(None, feed(body), NOW)
        self.assertEqual([g["cves"] for g in groups], [["CVE-2026-4444"]])
        self.assertEqual(checkpoint, "2026-11-10T11:00:00Z")

    def test_an_item_dated_past_year_9999_in_utc_is_skipped(self):
        body = rss(item("CVE-2026-6666 overflow", date="Fri, 31 Dec 9999 23:00:00 -0500"), item("CVE-2026-4444 good"))
        self.assertEqual([g["cves"] for g in osssec.fetch(None, feed(body), NOW)[0]], [["CVE-2026-4444"]])

    def test_a_future_dated_item_does_not_move_the_checkpoint_past_now(self):
        body = rss(item("CVE-2026-5555 from 2099", date="Thu, 01 Jan 2099 00:00:00 +0000"))
        self.assertEqual(osssec.fetch(None, feed(body), NOW)[1], NOW)
        # A checkpoint stored in the future before this fix comes back to now.
        self.assertEqual(osssec.fetch("2099-01-01T00:00:00Z", feed(rss()), NOW)[1], NOW)


class CveRecordTest(unittest.TestCase):
    def test_a_malformed_record_is_skipped_and_logged_and_the_rest_are_read(self):
        # Audit run-1: one CNA's broken record must not stop every record of the cycle.
        def record(cve, cna):
            return {"cveMetadata": {"cveId": cve, "state": "PUBLISHED"}, "containers": {"cna": cna}}
        records = [record("CVE-2026-1111", {}), record("CVE-2026-2222", {"descriptions": [{"value": "no lang"}]}),
                   record("CVE-2026-3333", None), record("CVE-2026-4444", {})]
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            groups = cvelist.mention_groups(records)
        self.assertEqual([g["cves"] for g in groups], [["CVE-2026-1111"], ["CVE-2026-4444"]])
        self.assertEqual(log.getvalue().count("\n"), 2)
        self.assertIn("cvelist: skipped record CVE-2026-2222: KeyError('lang')", log.getvalue())


class NewsAndCuratorFeedTest(unittest.TestCase):
    URL = "https://example.com/feed"

    def test_a_future_dated_item_does_not_move_the_checkpoint_past_now(self):
        # As oss-security (audit 11): a 2099 item would freeze the feed until 2099.
        body = rss(item("CVE-2026-5555 security flaw from 2099", date="Thu, 01 Jan 2099 00:00:00 +0000"))
        for fetch in (news.fetch, curators.fetch):
            with self.subTest(fetch.__module__):
                self.assertEqual(fetch(None, feed(body), [self.URL], NOW)[1], {self.URL: NOW})
                # A checkpoint stored in the future before this fix comes back to now.
                self.assertEqual(fetch({self.URL: "2099-01-01T00:00:00Z"}, feed(rss()), [self.URL], NOW)[1], {self.URL: NOW})


class FixKeyTest(unittest.TestCase):
    def record(self, *versions):
        return {"containers": {"cna": {"affected": [{"vendor": "acme", "product": "widget", "versions": [
            {"version": v, "status": "affected"} for v in versions]}]}}}

    def test_a_version_with_a_non_decimal_digit_does_not_stop_the_record(self):
        self.assertEqual(cvelist.record_fix_keys(self.record("7.3.²", "7.2")), ["acme:widget<=7.3.²"])

    def test_a_version_segment_too_long_for_int_does_not_stop_the_record(self):
        self.assertEqual(cvelist.record_fix_keys(self.record("1." + "9" * 5000, "1.2")), ["acme:widget<=1.2"])


if __name__ == "__main__":
    unittest.main()
