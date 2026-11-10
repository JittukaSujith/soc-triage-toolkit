import unittest

from soc_common.severity import Severity
from tests.helpers import DATA, run_cli
from tools.phishing_analyzer.cli import main
from tools.phishing_analyzer.core import analysis_iocs, analyze_bytes, analyze_file, assess_attachment, assess_link


def score_of(name):
    return analyze_file(DATA / "emails" / name)


class Components(unittest.TestCase):
    def test_link_flags(self):
        self.assertIn("ip_host", assess_link("http://198.51.100.77/verify").flags)
        self.assertIn("anchor_mismatch", assess_link("http://evil.example/x", "https://www.paypal.com/verify").flags)
        self.assertIn("shortener", assess_link("https://bit.ly/abc").flags)
        self.assertIn("userinfo_trick", assess_link("https://paypal.com@evil.example/").flags)
        self.assertIn("punycode", assess_link("http://xn--pypal-4ve.example/").flags)
        self.assertEqual(assess_link("https://www.example.org/page", "Read more").flags, [])

    def test_attachment_flags(self):
        self.assertEqual(assess_attachment("Invoice.pdf.exe", "application/octet-stream", b"x").flags, ["executable", "double_extension"])
        self.assertEqual(assess_attachment("a.docm", "x", b"x").flags, ["macro_document"])
        self.assertEqual(assess_attachment("notes.pdf", "application/pdf", b"x").flags, [])
        self.assertEqual(len(assess_attachment("a.zip", "x", b"abc").sha256), 64)

    def test_not_an_email_is_rejected(self):
        from soc_common.validation import ToolError
        with self.assertRaises(ToolError):
            analyze_bytes(b"\x00\x01 just random text with no headers")


class SampleEmails(unittest.TestCase):
    def test_legitimate_newsletter_scores_zero(self):
        a = score_of("01_legit_newsletter.eml")
        self.assertEqual((a.score, a.severity, a.spf, a.dkim, a.dmarc), (0, Severity.INFO, "pass", "pass", "pass"))

    def test_lookalike_phish_is_critical_with_reasons(self):
        a = score_of("02_phish_paypal_lookalike.eml")
        self.assertEqual((a.score, a.severity), (100, Severity.CRITICAL))
        reasons = " ".join(r for _, r in a.findings)
        for needle in ("SPF check FAILED", "DMARC check FAILED", "Reply-To", "Display name claims", "look-alike", "Pressure language", "Link:"):
            self.assertIn(needle, reasons)
        self.assertEqual(len(a.hops), 2)
        self.assertEqual(a.hops[0].ip, "198.51.100.77")          # oldest hop first = true origin

    def test_ceo_fraud_has_reply_to_mismatch(self):
        a = score_of("03_bec_ceo_wire.eml")
        self.assertGreaterEqual(a.score, 75)
        self.assertTrue(any("Reply-To" in r for _, r in a.findings))

    def test_malicious_attachment_email(self):
        a = score_of("04_malicious_attachment.eml")
        self.assertEqual(a.severity, Severity.CRITICAL)
        flags = {f for att in a.attachments for f in att.flags}
        self.assertTrue({"double_extension", "macro_document"} <= flags)
        self.assertIn("shortener", {f for l in a.links for f in l.flags})

    def test_iocs_for_hunting(self):
        iocs = analysis_iocs(score_of("02_phish_paypal_lookalike.eml"))
        self.assertIn("198.51.100.77", iocs["ip"])
        self.assertIn("paypa1-secure.example", iocs["domain"])

    def test_cli(self):
        code, out, _ = run_cli(main, [str(DATA / "emails"), "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("SUMMARY", out)
        code, _, err = run_cli(main, ["/no/such.eml"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
