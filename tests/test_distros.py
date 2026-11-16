"""The Distribution table's lookups (step 10), offline on small cuts of real answers fetched on 2026-11-15 and 16."""

import datetime
import io
import pathlib
import unittest
import urllib.error

from collector import distros

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "distros"
TODAY = datetime.date(2026, 11, 15)
UBUNTU = "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main"
API_1086 = "https://ubuntu.com/security/cves/CVE-2024-1086.json"  # Ubuntu's CVE API, auxiliary
FILES = {
    f"{UBUNTU}/vex/cve/2024/CVE-2024-1086.json": "ubuntu-vex-CVE-2024-1086.json",
    f"{UBUNTU}/osv/cve/2024/UBUNTU-CVE-2024-1086.json": "ubuntu-osv-CVE-2024-1086.json",
    f"{UBUNTU}/vex/cve/2026/CVE-2026-125712.json": "ubuntu-vex-CVE-2026-125712.json",
    "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-125712.json": "redhat-CVE-2026-125712.json",
    "https://ftp.suse.com/pub/projects/security/csaf-vex/2024/cve-2024-6387.json": "suse-cve-2024-6387.json",
    "https://ftp.suse.com/pub/projects/security/csaf-vex/2026/cve-2026-125712.json": "suse-cve-2026-125712.json",
    "https://security.archlinux.org/CVE-2024-6387.json": "arch-CVE-2024-6387.json",
    "https://security.archlinux.org/AVG-2855.json": "arch-AVG-2855.json",
}
# The daily files: cuts of Debian's tracker JSON and of two Alpine secdb files; the other four secdb files list nothing.
DAILY = {distros.DEBIAN_JSON: "debian-tracker.json"} | {
    url: f"alpine-secdb-{url.split('/')[3]}-main.json" if url.endswith("main.json") and "v3.23" not in url
    else b'{"packages": [], "distroversion": "v3.23", "reponame": "community"}' for url in distros.ALPINE_SECDB}
CVES = ["CVE-2024-6387", "CVE-2026-123158", "CVE-2026-125712", "CVE-2024-1086", "CVE-2026-102435", "CVE-2026-78701",
        "CVE-2026-110875", "CVE-2023-38408"]


def http_get(answers=FILES):
    def get(url, headers=None):
        if url not in answers:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b'{"message": "Not Found"}'))
        answer = answers[url]
        return answer if isinstance(answer, bytes) else (FIXTURES / answer).read_bytes()
    return get


BULK = distros.daily_index(http_get(DAILY), CVES)


def table(cve, distro):
    result = distros.lookup(cve, http_get(), TODAY, BULK)
    assert result["failed"] == [], result["failed"]
    return [(line["label"], line["package"], line["state"], line["version"]) for line in result["lines"]
            if line["distro"] == distro]


class LookupTest(unittest.TestCase):
    def test_debian_reads_fixed_open_and_not_affected_from_the_tracker_and_skips_undetermined(self):
        self.assertEqual(table("CVE-2024-6387", "Debian"), [
            ("Debian 13 (trixie)", "openssh", "fixed", "1:9.7p1-7"),
            ("Debian 12 (bookworm)", "openssh", "fixed", "1:9.2p1-2+deb12u3"),
        ])
        self.assertEqual(table("CVE-2026-123158", "Debian"), [
            ("Debian 13 (trixie)", "openssh", "not_fixed", ""), ("Debian 12 (bookworm)", "openssh", "not_fixed", "")])
        self.assertIn(("Debian 13 (trixie)", "389-ds-base", "not_affected", ""), table("CVE-2026-78701", "Debian"))
        self.assertEqual(table("CVE-2026-110875", "Debian"), [])

    def test_ubuntu_takes_states_from_vex_first_fixes_from_osv_and_keeps_generic_and_hwe_kernels_only(self):
        self.assertEqual(table("CVE-2024-1086", "Ubuntu"), [
            ("Ubuntu 26.10", "linux", "not_affected", ""),
            ("Ubuntu 26.04 LTS", "linux", "not_affected", ""),
            ("Ubuntu 24.04 LTS", "linux", "not_affected", ""),
            ("Ubuntu 22.04 LTS", "linux", "fixed", "5.15.0-101.111"),
            ("Ubuntu 22.04 LTS", "linux-hwe-6.2", "not_fixed", ""),
            ("Ubuntu 22.04 LTS", "linux-hwe-6.5", "fixed", "6.5.0-26.26~22.04.1"),
        ])

    def test_ubuntu_gives_no_line_while_a_package_is_under_investigation_or_only_on_ubuntu_pro(self):
        self.assertEqual(table("CVE-2026-125712", "Ubuntu"), [("Ubuntu 26.10", "gst-plugins-base1.0", "not_affected", "")])

    def test_the_api_is_not_asked_when_the_main_files_answered_and_no_line_is_affected(self):
        asked = []
        get = http_get(FILES | {API_1086: "ubuntu-api-CVE-2024-1086.json"})
        distros.lookup("CVE-2026-125712", lambda url, headers=None: asked.append(url) or get(url, headers), TODAY, BULK)
        self.assertFalse([url for url in asked if url.startswith("https://ubuntu.com/")])

    def test_decided_not_to_fix_is_told_apart_only_by_the_api(self):
        with_api = distros.lookup("CVE-2024-1086", http_get(FILES | {API_1086: "ubuntu-api-CVE-2024-1086.json"}), TODAY, BULK)
        ubuntu = [(l["label"], l["package"], l["state"], l["version"]) for l in with_api["lines"] if l["distro"] == "Ubuntu"]
        self.assertIn(("Ubuntu 22.04 LTS", "linux-hwe-6.2", "wont_fix", ""), ubuntu)
        self.assertIn(("Ubuntu 22.04 LTS", "linux", "fixed", "5.15.0-101.111"), ubuntu)
        self.assertIn(("Ubuntu 22.04 LTS", "linux-hwe-6.2", "not_fixed", ""), table("CVE-2024-1086", "Ubuntu"))

    def test_a_rejected_api_shape_leaves_the_main_lines_unchanged(self):
        for bad in (b"<html>moved</html>", b'{"packages": "soon"}', b'{"packages": [{"name": "linux", "statuses": [{}]}]}'):
            result = distros.lookup("CVE-2024-1086", http_get(FILES | {API_1086: bad}), TODAY, BULK)
            self.assertEqual([l for l in result["lines"] if l["distro"] == "Ubuntu"],
                             [l for l in distros.lookup("CVE-2024-1086", http_get(), TODAY, BULK)["lines"] if l["distro"] == "Ubuntu"])

    def test_the_api_supplies_ubuntus_lines_when_the_main_files_fail(self):
        broken = FILES | {f"{UBUNTU}/vex/cve/2024/CVE-2024-1086.json": b"<html>rate limited</html>",
                          API_1086: "ubuntu-api-CVE-2024-1086.json"}
        result = distros.lookup("CVE-2024-1086", http_get(broken), TODAY, BULK)
        self.assertNotIn("Ubuntu", result["failed"])
        self.assertEqual(sorted((l["label"], l["package"], l["state"], l["version"]) for l in result["lines"] if l["distro"] == "Ubuntu"), [
            ("Ubuntu 22.04 LTS", "linux", "fixed", "5.15.0-101.111"),
            ("Ubuntu 22.04 LTS", "linux-hwe-6.2", "wont_fix", ""),
            ("Ubuntu 22.04 LTS", "linux-hwe-6.5", "fixed", "6.5.0-26.26~22.04.1"),
            ("Ubuntu 24.04 LTS", "linux", "not_affected", ""),
        ])
        both = broken | {API_1086: b"<html>busy</html>"}
        self.assertIn("Ubuntu", distros.lookup("CVE-2024-1086", http_get(both), TODAY, BULK)["failed"])

    def test_alpine_reads_secdb_fixes_and_its_never_affected_zero_key(self):
        self.assertEqual(table("CVE-2026-123158", "Alpine"), [
            ("Alpine 3.24", "openssh", "fixed", "10.3_p1-r2"),
            ("Alpine 3.22", "openssh", "fixed", "10.0_p1-r11"),
        ])
        self.assertEqual(table("CVE-2023-38408", "Alpine"), [
            ("Alpine 3.24", "openssh", "not_affected", ""), ("Alpine 3.22", "openssh", "not_affected", "")])

    def test_red_hat_gives_backported_builds_of_mainline_rhel_only(self):
        self.assertEqual(table("CVE-2026-125712", "Red Hat"), [
            ("RHEL 10", "gstreamer1-plugins-base", "fixed", "1.26.7-4.el10_3.2"),
            ("RHEL 9", "gstreamer1-plugins-base", "fixed", "1.22.12-10.el9_9.1"),
            ("RHEL 8", "gstreamer1-plugins-base", "fixed", "1.16.1-8.el8_10"),
        ])

    def test_suse_names_the_source_package_and_a_fix_outranks_not_affected(self):
        self.assertEqual(table("CVE-2024-6387", "SUSE"), [("SLES 15 SP7", "openssh", "fixed", "9.6p1-150600.6.3.1")])
        self.assertEqual(table("CVE-2026-125712", "SUSE"), [
            ("SLES 16.1", "gstreamer-plugins-base", "not_affected", ""),
            ("SLES 15 SP7", "gstreamer-plugins-base", "not_fixed", ""),
        ])

    def test_arch_reads_the_group_the_cve_names(self):
        self.assertEqual(table("CVE-2024-6387", "Arch Linux"), [("Arch Linux", "openssh", "fixed", "9.8p1-1")])

    def test_a_cve_no_distribution_knows_gives_no_line_and_a_bad_answer_fails_only_its_source(self):
        cve = "CVE-2026-102435"  # a WordPress plugin's
        self.assertEqual(distros.lookup(cve, http_get({}), TODAY, BULK), {"lines": [], "failed": []})
        html = {"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-6387.json": b"<html>maintenance</html>"} | FILES
        result = distros.lookup("CVE-2024-6387", http_get(html), TODAY, BULK)
        self.assertEqual(result["failed"], ["Red Hat"])
        self.assertTrue(any(line["distro"] == "Debian" for line in result["lines"]))
        self.assertEqual(distros.lookup("CVE-2024-6387", http_get(), TODAY)["failed"], ["Debian", "Alpine"])

    def test_the_daily_index_covers_the_cves_asked_for_and_a_cve_it_does_not_cover_fails_until_the_next(self):
        self.assertEqual(BULK["Debian"]["CVE-2026-102435"], [])
        self.assertEqual(distros.lookup("CVE-2026-99999", http_get(), TODAY, BULK)["failed"], ["Debian", "Alpine"])
        broken = DAILY | {distros.DEBIAN_JSON: b"<html>busy</html>"}
        self.assertEqual(set(distros.daily_index(http_get(broken), CVES)), {"Alpine"})

    def test_a_404_on_a_second_fetch_and_a_broken_gzip_body_fail_their_source_instead_of_saying_not_known(self):
        no_group = {u: f for u, f in FILES.items() if "AVG-" not in u}
        self.assertEqual(distros.lookup("CVE-2024-6387", http_get(no_group), TODAY, BULK)["failed"], ["Arch Linux"])
        no_osv = {u: f for u, f in FILES.items() if "/osv/" not in u}
        self.assertEqual(distros.lookup("CVE-2024-1086", http_get(no_osv), TODAY, BULK)["failed"], ["Ubuntu"])
        cut = FILES | {"https://security.archlinux.org/CVE-2024-6387.json": b"\x1f\x8b\x08\x00broken"}
        self.assertEqual(distros.lookup("CVE-2024-6387", http_get(cut), TODAY, BULK)["failed"], ["Arch Linux"])

    def test_every_line_links_its_distributions_own_page_for_that_cve(self):
        pages = {"Debian": "https://security-tracker.debian.org/tracker/", "Ubuntu": "https://ubuntu.com/security/",
                 "Alpine": "https://security.alpinelinux.org/vuln/", "Red Hat": "https://access.redhat.com/security/cve/",
                 "SUSE": "https://www.suse.com/security/cve/", "Arch Linux": "https://security.archlinux.org/"}
        lines = [(cve, line) for cve in ("CVE-2024-6387", "CVE-2026-123158", "CVE-2026-125712", "CVE-2024-1086")
                 for line in distros.lookup(cve, http_get(), TODAY, BULK)["lines"]]
        self.assertEqual({line["distro"] for _, line in lines}, set(pages))
        for cve, line in lines:
            suffix = ".html" if line["distro"] == "SUSE" else ""
            self.assertEqual(line["url"], pages[line["distro"]] + cve + suffix)


class MergeTest(unittest.TestCase):
    def test_a_grouped_incident_keeps_one_row_where_its_cves_agree_and_every_version_where_they_differ(self):
        def line(cve, release, version):
            label = {"v3.24": "Alpine 3.24", "v3.22": "Alpine 3.22"}[release]
            return {"distro": "Alpine", "release": release, "label": label, "package": "openssh", "state": "fixed",
                    "version": version, "url": f"https://security.alpinelinux.org/vuln/{cve}"}
        rows = distros.merge({"CVE-1": [line("CVE-1", "v3.22", "10.0_p1-r11"), line("CVE-1", "v3.24", "10.3_p1-r2")],
                              "CVE-2": [line("CVE-2", "v3.22", "10.0_p1-r12"), line("CVE-2", "v3.24", "10.3_p1-r2")]})
        self.assertEqual([(r["release"], r["version"], r["cves"], r["url"][-5:]) for r in rows], [
            ("v3.24", "10.3_p1-r2", ["CVE-1", "CVE-2"], "CVE-1"),
            ("v3.22", "10.0_p1-r11", ["CVE-1"], "CVE-1"),
            ("v3.22", "10.0_p1-r12", ["CVE-2"], "CVE-2"),
        ])
        self.assertTrue(distros.settled(rows))
        self.assertFalse(distros.settled(rows + [dict(rows[0], state="not_fixed")]))
        self.assertFalse(distros.settled(rows + [dict(rows[0], state="wont_fix")]))

    def test_a_stored_line_of_a_release_taken_out_of_the_table_is_left_out_of_the_merge(self):
        gone = {"distro": "Ubuntu", "release": "focal", "label": "Ubuntu 20.04 LTS", "package": "linux",
                "state": "fixed", "version": "5.4.0-174.193", "url": "u"}
        self.assertEqual(distros.merge({"CVE-1": [gone]}), [])


if __name__ == "__main__":
    unittest.main()
