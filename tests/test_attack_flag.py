"""Owner, 11-22: GL.iNet's own notice of its cloud incident ("An unauthorized party exploited the vulnerability to access
and install malicious software on some GL.iNet routers and KVM devices") left both its rows at 참고. Two rules: the
vendor's own security notice reports attacks first-hand (vendor_notice, a sheet's vendor_advisory), and the active past
form reports them (ACTIVE_EXPLOIT, ACTIVE_KO), never a researcher's own demonstration, a hedge or a denial."""
import json
import unittest

from collector import sheets, summaries, summary_input
from test_summaries import SSHOLE_SUMMARY, FakeClaude

NOTICE = "https://www.gl-inet.com/blogs/blog/glinet-security-notice-2026-11-20"
# The notice's own words (main_text of the page, 11-22), as the input carries them.
NOTICE_TEXT = ("GL.iNet Security Notice 2026-11-20 SECURITY NOTICE · CUSTOMER ADVISORY GL.iNet Router and KVM Security Incident "
               "On November 20, 2026, GL.iNet identified a vulnerability in its cloud remote management services. An "
               "unauthorized party exploited the vulnerability to access and install malicious software on some GL.iNet "
               "routers and KVM devices. The attack path has been blocked.")
KO = "공격자가 GL.iNet 클라우드 원격 관리 서비스의 취약점을 악용해 일부 라우터와 KVM 기기에 악성 소프트웨어를 설치했습니다."


class ActivePastTest(unittest.TestCase):

    def test_the_notice_and_its_summary_report_attacks(self):
        self.assertTrue(summaries.attack_reported(NOTICE_TEXT))
        self.assertTrue(summaries.attack_reported("Attackers exploited the zero-day flaw to breach several universities."))
        self.assertTrue(summaries.attack_reported("A China-linked group has exploited this vulnerability since September."))
        self.assertTrue(summaries.attack_reported("Attackers exploited the Node.js vulnerability in March."))
        self.assertTrue(summaries.attack_reported_ko(KO))
        self.assertTrue(summaries.attack_reported_ko("공격자가 제로데이를 악용했습니다."))

    def test_a_researcher_a_hedge_a_denial_and_an_adjective_do_not(self):
        for text in ("We exploited the vulnerability in our lab to get a root shell.",
                     "Researchers exploited the flaw to show remote code execution.",
                     "In a proof of concept, the attacker exploited the bug to read files.",
                     "An attacker who successfully exploited this vulnerability could run arbitrary code.",
                     "If an attacker exploited the flaw, they could read any file.",
                     "Attackers could have exploited the flaw before the fix.",
                     "There is no evidence that anyone exploited the vulnerability.",
                     "The update closes the exploited flaw class.",
                     "Files are abused this way. A code injection vulnerability follows."):
            with self.subTest(text):
                self.assertFalse(summaries.attack_reported(text))
        for text in ("연구진은 취약점을 악용해 원격으로 코드를 실행했습니다.",
                     "공격자가 취약점을 악용했다는 증거는 없습니다.",
                     "공격자가 취약점을 악용해 악성 코드를 설치할 수 있습니다."):
            with self.subTest(text):
                self.assertFalse(summaries.attack_reported_ko(text))


class VendorNoticeTest(unittest.TestCase):

    def test_the_vendors_own_security_notice(self):
        for url in (NOTICE, "https://www.gl-inet.com/en-us/blogs/blog/glinet-security-notice-2026-11-20"):
            self.assertTrue(summaries.vendor_notice(url, ["GL.iNet routers", "GL.iNet KVM"]))
        self.assertTrue(summaries.vendor_notice("https://www.toshiba.co.jp/security/notice-2026.html", ["Toshiba e-STUDIO"]))
        self.assertTrue(summaries.vendor_notice("https://security.paloaltonetworks.com/advisory/2026-1", ["Palo Alto Networks PAN-OS"]))

    def test_no_lookalike_no_user_page_no_marketing_page(self):
        names = ["GL.iNet routers"]
        for url in ("https://forum.gl-inet.com/t/regarding-the-security-notice/73057",  # customers' forum
                    "https://www.gl-inet.com/products/gl-mt6000/",  # a product page
                    "https://gl-inet-support.com/security-notice",  # not the vendor's name
                    "https://glinet.example.com/security-notice",  # a subdomain of someone else's
                    "https://example.com/gl-inet-security-notice",  # the name only in the path
                    "https://docs.gl-inet.com/router/en/4/security/",  # a manual page: "security" alone
                    "https://status.gl-inet.com/incidents/x1",  # an uptime status page
                    "https://gitlab.gl-inet.com/security/vulnerability-reports/-/work_items/9"):  # a reporter's tracker item
            with self.subTest(url):
                self.assertFalse(summaries.vendor_notice(url, names))
        self.assertFalse(summaries.vendor_notice(NOTICE, ["Router firmware"]))  # no vendor name to match


class ParseTest(unittest.TestCase):
    """The reply names the notice, a write-up, as its source: the vendor's own page states the attacks."""

    def parse(self, notice_text, products, finders=()):
        text = (f"Incident: no CVE yet\nExploited in the wild (CISA KEV): no\nProducts: unknown\nMentions:\n"
                f"- writeup {SSHOLE_SUMMARY['lead']}\n- writeup {NOTICE}\n"
                f"Text of {SSHOLE_SUMMARY['lead']}{summary_input.LEAD_MARK}:\n{json.dumps(SSHOLE_SUMMARY, ensure_ascii=False)}\n"
                f"Text of {NOTICE}:\n{notice_text}")
        reply = FakeClaude.message(SSHOLE_SUMMARY | {"exploited": True, "exploited_source": NOTICE, "products": products})
        return summaries.parse(reply, text, [SSHOLE_SUMMARY["lead"], NOTICE], finders)

    def test_the_vendors_notice_confirms_the_attacks(self):
        s = self.parse(NOTICE_TEXT, ["GL.iNet routers", "OpenSSH"])
        self.assertEqual((s["exploited"], s["exploited_source"], s.get("exploited_input")), (True, NOTICE, True))

    def test_another_products_page_or_a_notice_that_says_no_attack_does_not(self):
        self.assertFalse(self.parse(NOTICE_TEXT, ["OpenSSH"])["exploited"])
        self.assertFalse(self.parse("GL.iNet fixed a vulnerability in its cloud service.", ["GL.iNet routers"])["exploited"])

    def test_a_sheets_vendor_advisory_counts_too(self):
        got = sheets.finders([{"url": NOTICE, "facts": {"page_role": "vendor_advisory", "about_incident": True}}])
        s = self.parse(NOTICE_TEXT, ["OpenSSH"], finders=got)
        self.assertEqual((s["exploited"], s["exploited_source"]), (True, NOTICE))


if __name__ == "__main__":
    unittest.main()
