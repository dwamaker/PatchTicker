"""The Distribution table in the cycle (step 10): when CVEs are asked, what is stored, and what the page gets."""

import json
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

from collector import cycle, distros
from collector.incidents import absorb, board_view, rows_view
from collector.store import MemoryStore
from test_distros import DAILY, FILES, http_get

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
ALL = FILES | DAILY


def seen(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def incident(cves, days_ago=0):
    return {"id": f"https://www.cve.org/CVERecord?id={cves[0]}", "cves": list(cves), "first_seen": seen(days_ago)}


class Counting:
    """http_get over the fixtures that counts the requests it answers or refuses."""

    def __init__(self, answers=ALL):
        self.get, self.urls = http_get(answers), []

    def __call__(self, url, headers=None):
        self.urls.append(url)
        return self.get(url, headers)


def run(store, incidents, now=NOW, get=None):
    """One cycle's step, writing the state as run_cycle does; (months changed, the fetcher)."""
    get = get or Counting()
    changed, state = cycle.refresh_distros(store, incidents, get, now, lambda s: None)
    if state is not None:
        store.write("distros/state.json", state)
    return changed, get


def asked(store):
    return {cve for cve, entry in store.read("distros/state.json").items() if "asked" in entry}


class DistroCycleTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()

    def test_the_daily_files_are_fetched_once_a_day_and_a_failed_fetch_keeps_the_last_index(self):
        incidents = [incident(["CVE-2024-6387"])]
        _, get = run(self.store, incidents)
        self.assertEqual(get.urls.count(distros.DEBIAN_JSON), 1)
        _, get = run(self.store, incidents, NOW + timedelta(minutes=10))
        self.assertNotIn(distros.DEBIAN_JSON, get.urls)
        broken = Counting(ALL | {distros.DEBIAN_JSON: b"<html>busy</html>"})
        run(self.store, incidents, NOW + timedelta(days=1), broken)
        index = self.store.read("distros/index.json")
        self.assertEqual(index["day"], "2026-11-16")
        self.assertIn("trixie", {row[0] for row in index["Debian"]["CVE-2024-6387"]})

    def test_with_no_debian_index_a_cve_alpine_knows_is_asked_and_keeps_its_debian_lines(self):
        old = {"distro": "Debian", "release": "trixie", "label": "Debian 13 (trixie)", "package": "openssh",
               "state": "fixed", "version": "1:9.7p1-7", "url": "https://security-tracker.debian.org/tracker/CVE-2024-6387"}
        incidents = [incident(["CVE-2024-6387"]) | {"distro_lines": {"CVE-2024-6387": [old]}}]
        no_debian = Counting({u: f for u, f in ALL.items() if u != distros.DEBIAN_JSON})
        run(self.store, incidents, get=no_debian)
        lines = incidents[0]["distro_lines"]["CVE-2024-6387"]
        self.assertIn(old, lines)
        self.assertTrue({"Alpine", "Arch Linux"} <= {line["distro"] for line in lines})

    def test_a_cycle_asks_at_most_distro_per_cycle_cves_new_ones_first_then_re_checks_then_older_incidents(self):
        cves = [f"CVE-2026-{n}" for n in range(10000, 10000 + cycle.DISTRO_PER_CYCLE + 5)]
        backfill = incident(["CVE-2026-20000"], days_ago=20)
        incidents = [incident([c]) for c in cves] + [backfill]
        listed = {c: {"releases": {"trixie": {"status": "open"}}} for c in cves + ["CVE-2026-20000"]}
        many = ALL | {distros.DEBIAN_JSON: json.dumps({"pkg": listed}).encode()}  # Debian lists them all
        _, get = run(self.store, incidents, get=Counting(many))
        self.assertEqual(len(asked(self.store)), cycle.DISTRO_PER_CYCLE)
        self.assertNotIn("CVE-2026-20000", asked(self.store))
        self.assertEqual(len({u for u in get.urls if "archlinux" in u}), cycle.DISTRO_PER_CYCLE)
        run(self.store, incidents, NOW + timedelta(minutes=10), Counting(many))
        self.assertIn("CVE-2026-20000", asked(self.store))  # the backlog's turn once new CVEs are asked

    def test_a_new_cve_that_folds_into_an_older_incident_is_new_by_its_own_day(self):
        listed = {c: {"releases": {"trixie": {"status": "open"}}} for c in ("CVE-2026-30000", "CVE-2026-30001")}
        many = Counting(ALL | {distros.DEBIAN_JSON: json.dumps({"pkg": listed}).encode()})
        old = incident(["CVE-2026-30000"], days_ago=35)
        run(self.store, [old], get=many)
        self.assertEqual(asked(self.store), set())  # posted before step 10 and past the backfill window
        old["cves"].append("CVE-2026-30001")
        run(self.store, [old], NOW + timedelta(days=1), many)  # the next day's index covers it
        self.assertEqual(asked(self.store), {"CVE-2026-30001"})

    def test_a_cve_is_asked_once_a_day_for_7_days_then_only_while_a_line_waits_up_to_37(self):
        # Both known to the index; 6387's lines all settle (fixed or not affected), 123158's Debian lines wait.
        quiet, waiting = incident(["CVE-2024-6387"]), incident(["CVE-2026-123158"])
        run(self.store, [quiet, waiting])

        def asked_on(day):
            state = self.store.read("distros/state.json")
            run(self.store, [quiet, waiting], NOW + timedelta(days=day))
            after = self.store.read("distros/state.json")
            return {c for c in after if after[c].get("asked") != (state.get(c) or {}).get("asked")}

        self.assertEqual(asked_on(0), set())  # asked today already
        self.assertEqual(asked_on(1), {"CVE-2024-6387", "CVE-2026-123158"})
        self.assertEqual(asked_on(7), {"CVE-2026-123158"})
        self.assertEqual(asked_on(36), {"CVE-2026-123158"})
        self.assertEqual(asked_on(37), set())

    def test_a_cve_the_index_knows_is_asked_before_any_it_does_not(self):
        unknown = [incident([f"CVE-2026-{n}"]) for n in range(40000, 40000 + cycle.DISTRO_PER_CYCLE)]
        known = incident(["CVE-2026-123158"], days_ago=3)  # older than every unknown one
        run(self.store, unknown + [known])
        self.assertEqual(asked(self.store), {"CVE-2026-123158"})

    def test_a_cve_the_index_does_not_know_is_never_asked(self):
        plugin = incident(["CVE-2026-102435"])
        for day in (0, 1, 2):
            _, get = run(self.store, [plugin], NOW + timedelta(days=day))
            self.assertNotIn("https://security.archlinux.org/CVE-2026-102435.json", get.urls)
        self.assertEqual(asked(self.store), set())

    def test_one_the_index_starts_knowing_becomes_due(self):
        empty = ALL | {distros.DEBIAN_JSON: b"{}"} | {u: b'{"packages": [], "distroversion": "v3.24", "reponame": "main"}'
                                                       for u in distros.ALPINE_SECDB}
        sshole = incident(["CVE-2026-123158"])
        run(self.store, [sshole], get=Counting(empty))
        self.assertEqual(asked(self.store), set())
        _, get = run(self.store, [sshole], NOW + timedelta(days=1))
        self.assertIn("https://security.archlinux.org/CVE-2026-123158.json", get.urls)
        self.assertEqual(self.store.read("distros/state.json")["CVE-2026-123158"]["first"], "2026-11-16")  # 7 days from now

    def test_a_lookup_that_finds_nothing_new_leaves_the_incident_as_it_was(self):
        incidents = [incident(["CVE-2024-6387"])]
        changed, _ = run(self.store, incidents)
        self.assertEqual(changed, {"2026-11"})
        before = json.dumps(incidents)
        changed, _ = run(self.store, incidents, NOW + timedelta(days=1))
        self.assertEqual((changed, json.dumps(incidents)), (set(), before))

    def test_board_view_carries_the_merged_rows_and_their_credits_and_rows_view_does_not(self):
        one = incident(["CVE-2024-6387"]) | {"brief": {"text": "x", "lead": ""}, "mentions": []}
        run(self.store, [one])
        view = board_view(one)
        self.assertEqual(view["distro_rows"][0] | {"cves": None}, one["distro_lines"]["CVE-2024-6387"][0] | {"cves": None})
        self.assertEqual([c["distro"] for c in view["distro_credits"]],
                         ["Debian", "Alpine", "SUSE", "Arch Linux"])
        self.assertEqual(view["distro_credits"][2]["licence"], "CC BY 4.0")
        self.assertFalse({"distro_rows", "distro_credits", "distro_lines"} & set(rows_view(one)))
        self.assertNotIn("distro_rows", board_view(incident(["CVE-2026-102435"]) | {"brief": {"text": "x", "lead": ""},
                                                                                        "mentions": []}))

    def test_a_merge_carries_the_lines_of_the_cves_the_target_holds_only(self):
        mention = [{"kind": "cve_record", "url": "https://www.cve.org/CVERecord?id=CVE-1"}]
        target = incident(["CVE-1"]) | {"brief": {"text": "a", "lead": ""}, "mentions": mention, "urls": []}
        other = incident(["CVE-2"]) | {"brief": {"text": "b", "lead": ""}, "mentions": [], "urls": [],
                                         "distro_lines": {"CVE-2": ["line"], "CVE-3": ["lent"]}}
        absorb(target, other)
        self.assertEqual(target["distro_lines"], {"CVE-2": ["line"]})


class UnexpectedErrorTest(unittest.TestCase):
    def test_one_cves_lookup_raising_an_unexpected_error_keeps_the_other_cves_lines_and_asks_it_again(self):
        store, real = MemoryStore(), distros.lookup
        broken = incident(["CVE-2026-123158"])
        broken["distro_lines"] = {"CVE-2026-123158": [{"distro": "Alpine", "release": "v3.24", "label": "Alpine 3.24",
                                                       "package": "openssh", "state": "fixed", "version": "10.3_p1-r2",
                                                       "url": "u"}]}
        fine = incident(["CVE-2024-6387"])

        def lookup(cve, *args):
            if cve == "CVE-2026-123158":
                raise AssertionError("a parser met a shape nobody listed")
            return real(cve, *args)

        with unittest.mock.patch.object(distros, "lookup", lookup):
            run(store, [broken, fine])
        self.assertIn("CVE-2024-6387", fine["distro_lines"])
        self.assertEqual(len(broken["distro_lines"]["CVE-2026-123158"]), 1)
        self.assertEqual(asked(store), {"CVE-2026-123158", "CVE-2024-6387"})
        _, get = run(store, [broken, fine], NOW + timedelta(days=1))
        self.assertIn("https://security.archlinux.org/CVE-2026-123158.json", get.urls)

    def test_an_unexpected_error_inside_the_table_step_leaves_the_cycles_other_writes_intact(self):
        from test_cycle import at, recorded
        store = MemoryStore()
        with unittest.mock.patch.object(cycle, "refresh_distros", side_effect=RuntimeError("surprise")):
            cycle.run_cycle(store, recorded(), at("2026-11-07T13:30:00"), "test-box", sleep=lambda s: None, distro_table=True)
        self.assertEqual(store.read("status.json")["updated"], "2026-11-07T13:30:00Z")
        self.assertTrue(store.read("months/2026-11.json")["incidents"])
        self.assertIsNone(store.read("distros/state.json"))


class WholeCycleTest(unittest.TestCase):
    def test_a_cycle_with_every_distribution_source_failing_still_writes_its_files_and_the_state(self):
        from test_cycle import at, recorded
        store = MemoryStore()
        cycle.run_cycle(store, recorded(), at("2026-11-07T13:30:00"), "test-box", sleep=lambda s: None, distro_table=True)
        self.assertEqual(store.read("status.json")["updated"], "2026-11-07T13:30:00Z")
        state = store.read("distros/state.json")
        self.assertTrue(state and all(entry == {"seen": "2026-11-07"} for entry in state.values()))  # no index: none asked
        self.assertTrue(all("distro_lines" not in i for i in store.read("months/2026-11.json")["incidents"]))


if __name__ == "__main__":
    unittest.main()
