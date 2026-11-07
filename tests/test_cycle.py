"""Seam 1: one collection cycle, replayed against recorded source responses."""

import unittest
from datetime import datetime, timezone
from pathlib import Path

from collector.cycle import run_cycle
from collector.cvelist import DELTA_LOG_URL
from collector.store import MemoryStore

FIXTURES = Path(__file__).parent / "fixtures"
# Mention sources by URL prefix: (fixture folder, answer when the test gives no fixture).
MENTION_SOURCES = {
    "https://hn.algolia.com/": ("hn", b'{"hits": [], "nbPages": 0}'),
    "https://seclists.org/": ("oss-security", b"<rss><channel></channel></rss>"),
    "https://api.github.com/": ("github", b'{"items": []}'),
}

KEYCLOAK_TEXT = (
    "A flaw was found in the Keycloak server's client management component. When a client is "
    "created or imported with authorization services enabled, the system fails to properly clear "
    "an internal session attribute used during the setup process. This allows an authenticated "
    "attacker with client management permissions to bypass security controls and upload a "
    "malicious JavaScript policy, which is then executed on the server when an authorization "
    "request is made. Successful exploitation could allow the attacker to run arbitrary code on "
    "the server, potentially compromising the entire system."
)
WPTRAVELLY_TEXT = (
    "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File "
    "Inclusion') vulnerability in Magepeople inc. WpTravelly tour-booking-manager allows PHP Local "
    "File Inclusion.This issue affects WpTravelly: from n/a through 2.3.8."
)


def recorded(delta_log="deltaLog.json", hn=None, oss=None, github=None):
    """An http_get that answers from fixtures and fails on anything not recorded.

    delta_log=None serves an empty delta log; a Mention source given no fixture answers empty.
    """
    names = {"hn": hn, "oss-security": oss, "github": github}

    def get(url, headers=None):
        if url == DELTA_LOG_URL:
            return (FIXTURES / "cvelist" / delta_log).read_bytes() if delta_log else b"[]"
        for prefix, (folder, empty) in MENTION_SOURCES.items():
            if url.startswith(prefix):
                return (FIXTURES / folder / names[folder]).read_bytes() if names[folder] else empty
        return (FIXTURES / "cvelist" / url.rsplit("/", 1)[-1]).read_bytes()

    return get


def at(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def incident(cve, text, first_seen):
    url = f"https://www.cve.org/CVERecord?id={cve}"
    return {
        "id": cve,
        "cves": [cve],
        "first_seen": first_seen,
        "mentions": [{"kind": "cve_record", "url": url}],
        "urls": [f"cve.org/CVERecord?id={cve}"],
        "brief": {"text": text, "lead": url},
    }


class CycleTest(unittest.TestCase):
    def make_store(self):
        return MemoryStore()

    def setUp(self):
        self.store = self.make_store()
        # Pretend an earlier cycle already read the delta log up to 12:00.
        self.store.write("checkpoints.json", {"cvelist": "2026-11-07T12:00:00.000Z"})

    def test_cycle_writes_new_cves_into_monthly_file(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        month = self.store.read("months/2026-11.json")
        self.assertCountEqual(
            month["incidents"],
            [
                incident("CVE-2026-120984", KEYCLOAK_TEXT, "2026-11-07T13:30:00Z"),
                incident("CVE-2026-120839", WPTRAVELLY_TEXT, "2026-11-07T13:30:00Z"),
            ],
        )
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-11"]})

    def test_status_file_holds_last_update_and_collector(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")

        self.assertEqual(
            self.store.read("status.json"),
            {"updated": "2026-11-07T13:30:00Z", "collector": "test-box"},
        )

    def test_second_cycle_with_nothing_new_changes_nothing(self):
        run_cycle(self.store, recorded(), at("2026-11-07T13:30:00"), "test-box")
        month, index = self.store.read("months/2026-11.json"), self.store.read("index.json")

        run_cycle(self.store, recorded(), at("2026-11-07T13:45:00"), "test-box")

        self.assertEqual(self.store.read("months/2026-11.json"), month)
        self.assertEqual(self.store.read("index.json"), index)

    def test_new_month_gets_its_own_file_and_a_seen_again_cve_no_second_incident(self):
        run_cycle(self.store, recorded("deltaLog-early.json"), at("2026-11-30T23:50:00"), "test-box")
        run_cycle(self.store, recorded("deltaLog.json"), at("2026-12-01T00:05:00"), "test-box")

        self.assertEqual(
            self.store.read("months/2026-11.json")["incidents"],
            [incident("CVE-2026-120839", WPTRAVELLY_TEXT, "2026-11-30T23:50:00Z")],
        )
        self.assertEqual(
            self.store.read("months/2026-12.json")["incidents"],
            [incident("CVE-2026-120984", KEYCLOAK_TEXT, "2026-12-01T00:05:00Z")],
        )
        self.assertEqual(self.store.read("index.json"), {"months": ["2026-11", "2026-12"]})

    def test_first_cycle_without_checkpoint_takes_only_the_newest_delta(self):
        store = self.make_store()
        run_cycle(store, recorded("deltaLog-early.json"), at("2026-11-07T13:00:00"), "test-box")

        # The newest entry of deltaLog-early only updates a record, so nothing is new.
        self.assertIsNone(store.read("months/2026-11.json"))
        self.assertEqual(store.read("status.json")["collector"], "test-box")


if __name__ == "__main__":
    unittest.main()
