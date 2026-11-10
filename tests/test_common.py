import unittest

from soc_common.domains import levenshtein, lookalike_brand, registered_domain
from soc_common.ioc_patterns import classify_ioc, defang, is_private_ip, refang
from soc_common.schema import LogEvent, iso, parse_timestamp
from soc_common.severity import Severity
from soc_common.validation import ToolError, bounded_int, is_valid_ip, require_file


class SeverityTests(unittest.TestCase):
    def test_parse_and_order(self):
        self.assertEqual(Severity.parse("High"), Severity.HIGH)
        self.assertEqual(Severity.parse(4), Severity.CRITICAL)
        self.assertLess(Severity.LOW, Severity.HIGH)
        with self.assertRaises(ValueError):
            Severity.parse("urgent")

    def test_from_score_boundaries(self):
        self.assertEqual(Severity.from_score(0), Severity.INFO)
        self.assertEqual(Severity.from_score(20), Severity.LOW)
        self.assertEqual(Severity.from_score(40), Severity.MEDIUM)
        self.assertEqual(Severity.from_score(60), Severity.HIGH)
        self.assertEqual(Severity.from_score(80), Severity.CRITICAL)

    def test_bump_caps_at_critical(self):
        self.assertEqual(Severity.HIGH.bump(5), Severity.CRITICAL)


class SchemaTests(unittest.TestCase):
    def test_parse_timestamp_variants(self):
        self.assertEqual(iso(parse_timestamp("2026-10-28T02:14:03Z")), "2026-10-28T02:14:03Z")
        self.assertEqual(iso(parse_timestamp("2026-10-28 02:14:03")), "2026-10-28T02:14:03Z")      # naive => UTC
        self.assertEqual(iso(parse_timestamp("2026-10-28T04:14:03+02:00")), "2026-10-28T02:14:03Z")
        with self.assertRaises(ValueError):
            parse_timestamp("yesterday")

    def test_event_round_trip(self):
        ev = LogEvent(parse_timestamp("2026-10-28T02:14:03Z"), "auth", "hello", user="bob", src_ip="1.2.3.4", extra={"a": 1})
        again = LogEvent.from_dict(ev.to_dict())
        self.assertEqual((again.timestamp, again.user, again.extra), (ev.timestamp, "bob", {"a": 1}))


class ValidationTests(unittest.TestCase):
    def test_bounded_int(self):
        self.assertEqual(bounded_int("5", "x", 1, 10), 5)
        with self.assertRaises(ToolError):
            bounded_int("abc", "x")
        with self.assertRaises(ToolError):
            bounded_int(0, "x", 1)

    def test_require_file_errors_are_friendly(self):
        with self.assertRaises(ToolError) as ctx:
            require_file("/definitely/not/here.log")
        self.assertIn("file not found", str(ctx.exception))

    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("203.0.113.5"))
        self.assertFalse(is_valid_ip("999.1.1.1"))


class IocPatternTests(unittest.TestCase):
    def test_defang_and_refang_round_trip(self):
        url = "http://evil.example/login"
        self.assertEqual(defang(url, "url"), "hxxp://evil[.]example/login")
        self.assertEqual(refang(defang(url, "url")), url)
        self.assertEqual(defang("a@b.example", "email"), "a[at]b[.]example")

    def test_classify(self):
        self.assertEqual(classify_ioc("203.0.113.5"), "ip")
        self.assertEqual(classify_ioc("192.0.2.64/28"), "ip")
        self.assertEqual(classify_ioc("hxxps://bad[.]example/x"), "url")
        self.assertEqual(classify_ioc("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(classify_ioc("report.pdf"), None)
        self.assertEqual(classify_ioc("CVE-2024-12345"), "cve")

    def test_private_ip_rules(self):
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertFalse(is_private_ip("203.0.113.45"))   # documentation range counts as public on purpose


class DomainTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(registered_domain("shop.example.co.uk"), "example.co.uk")

    def test_levenshtein(self):
        self.assertEqual(levenshtein("paypal", "paypa1"), 1)

    def test_lookalikes(self):
        for bad in ("paypa1.com", "rnicrosoft.com", "paypal-secure.net", "paypal.com.verify-id.biz", "gooogle.com"):
            self.assertIsNotNone(lookalike_brand(bad), bad)
        for good in ("paypal.com", "e.paypal.com", "github.com", "example.org"):
            self.assertIsNone(lookalike_brand(good), good)


if __name__ == "__main__":
    unittest.main()
