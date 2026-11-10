import json
import tempfile
import unittest
from pathlib import Path

from soc_common.validation import ToolError
from tests.helpers import DATA, run_cli
from tools.intel_matcher.cli import main as intel_main
from tools.intel_matcher.core import (Indicator, domain_age_note, is_reserved_domain, load_blocklist, match_iocs,
                                      online_domain_lookup, parse_rdap_registration)
from tools.ioc_extractor.cli import main as ioc_main
from tools.ioc_extractor.core import eml_to_text, extract_iocs, to_csv, to_json


class Extraction(unittest.TestCase):
    TEXT = ("Contact bad[at]evil[.]example. Download hxxp://malware[.]example/a.exe from 203.0.113.45 (also 203.0.113.45). "
            "hash d41d8cd98f00b204e9800998ecf8427e and CVE-2024-12345. Opened report.pdf and invoice.exe. "
            "Bogus 999.1.1.1 and private 10.0.0.5. Auth: header.from=x smtp.mailfrom=y")

    def test_defanged_input_is_understood_and_deduplicated(self):
        iocs = extract_iocs(self.TEXT)
        self.assertEqual(iocs["url"], ["http://malware.example/a.exe"])
        self.assertEqual(iocs["email"], ["bad@evil.example"])
        self.assertEqual(iocs["ip"].count("203.0.113.45"), 1)
        self.assertEqual(iocs["md5"], ["d41d8cd98f00b204e9800998ecf8427e"])
        self.assertEqual(iocs["cve"], ["CVE-2024-12345"])

    def test_false_positives_are_filtered(self):
        iocs = extract_iocs(self.TEXT)
        self.assertNotIn("999.1.1.1", iocs["ip"])
        self.assertNotIn("report.pdf", iocs["domain"])
        self.assertNotIn("invoice.exe", iocs["domain"])
        self.assertFalse([d for d in iocs["domain"] if d.startswith(("header.", "smtp."))])

    def test_private_ip_option_and_type_filter(self):
        self.assertIn("10.0.0.5", extract_iocs(self.TEXT)["ip"])
        self.assertNotIn("10.0.0.5", extract_iocs(self.TEXT, exclude_private=True)["ip"])
        self.assertEqual(list(extract_iocs(self.TEXT, types=["cve"])), ["cve"])
        with self.assertRaises(ToolError):
            extract_iocs(self.TEXT, types=["bogus"])

    def test_hash_lengths_do_not_overlap(self):
        sha256 = "a" * 64
        iocs = extract_iocs("x %s y" % sha256)
        self.assertEqual(list(iocs), ["sha256"])

    def test_export_formats(self):
        iocs = extract_iocs("1.2.3.4 evil.example")
        self.assertIn("1[.]2[.]3[.]4", to_csv(iocs, defang_output=True))
        self.assertEqual(json.loads(to_json(iocs))["ip"], ["1.2.3.4"])

    def test_eml_urls_are_decoded_whole(self):
        text = eml_to_text(str(DATA / "emails" / "02_phish_paypal_lookalike.eml"))
        self.assertIn("http://198.51.100.77/verify", extract_iocs(text)["url"])

    def test_cli_text_and_errors(self):
        code, out, _ = run_cli(ioc_main, ["--text", "visit hxxp://bad[.]example", "--format", "json", "--defang"])
        self.assertEqual(code, 0)
        self.assertIn("hxxp://bad[.]example", out)
        code, _, err = run_cli(ioc_main, ["/no/such/file.txt"])
        self.assertEqual(code, 2)


class IntelMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocklist = load_blocklist(DATA / "blocklist.csv")

    def matches(self, **kw):
        return {(m.ioc, m.kind) for m in match_iocs(kw, self.blocklist)}

    def test_exact_cidr_and_miss(self):
        self.assertIn(("203.0.113.45", "exact"), self.matches(ip=["203.0.113.45"]))
        self.assertIn(("192.0.2.70", "cidr"), self.matches(ip=["192.0.2.70"]))      # inside 192.0.2.64/28
        self.assertEqual(self.matches(ip=["192.0.2.100"]), set())                  # outside it

    def test_domain_subdomain_url_and_email(self):
        m = self.matches(domain=["login.paypa1-secure.example", "good.example"], url=["http://login.paypa1-secure.example/x"], email=["a@mail-collector.example"])
        self.assertIn(("login.paypa1-secure.example", "subdomain"), m)
        self.assertIn(("http://login.paypa1-secure.example/x", "url-host"), m)
        self.assertIn(("a@mail-collector.example", "email-domain"), m)
        self.assertNotIn("good.example", {i for i, _ in m})

    def test_hash_match_and_sample_attachment(self):
        from tools.phishing_analyzer.core import analyze_file
        sha = analyze_file(DATA / "emails" / "04_malicious_attachment.eml").attachments[0].sha256
        self.assertIn((sha, "exact"), self.matches(sha256=[sha]))

    def test_domain_suffix_does_not_match_lookalikes(self):
        bl = [Indicator("evil.example", "domain")]
        self.assertEqual(match_iocs({"domain": ["notevil.example"]}, bl), [])

    def test_highest_confidence_first_and_severity(self):
        found = match_iocs({"ip": ["203.0.113.45", "192.0.2.70"]}, self.blocklist)
        self.assertEqual(found[0].ioc, "203.0.113.45")
        self.assertEqual(found[0].severity.name, "CRITICAL")
        self.assertEqual(found[-1].severity.name, "MEDIUM")

    def test_plain_text_blocklist_and_bad_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "list.txt"
            good.write_text("# my list\n203.0.113.9\nevil[.]example\n")
            self.assertEqual({i.type for i in load_blocklist(good)}, {"ip", "domain"})
            empty = Path(tmp) / "empty.txt"
            empty.write_text("# nothing\n")
            with self.assertRaises(ToolError):
                load_blocklist(empty)

    def test_cli_offline(self):
        code, out, _ = run_cli(intel_main, ["--ioc", "203.0.113.45", "--blocklist", str(DATA / "blocklist.csv"), "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("OFFLINE", out)
        self.assertIn("CRITICAL", out)


class OnlineHelpersWorkOffline(unittest.TestCase):
    def test_parse_rdap_registration(self):
        data = {"events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
                           {"eventAction": "registration", "eventDate": "2026-10-20T12:00:00Z"}]}
        self.assertEqual(parse_rdap_registration(data).strftime("%Y-%m-%d"), "2026-10-20")
        self.assertIsNone(parse_rdap_registration({"events": []}))

    def test_age_notes(self):
        self.assertIn("newly registered", domain_age_note(5))
        self.assertIn("established", domain_age_note(900))

    def test_reserved_domains_never_touch_the_network(self):
        self.assertTrue(is_reserved_domain("paypa1-secure.example"))
        result = online_domain_lookup("paypa1-secure.example")
        self.assertEqual(result["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
