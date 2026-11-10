import unittest
from datetime import datetime, timezone

from soc_common.severity import Severity
from tests.helpers import DATA, run_cli
from tools.login_analyzer.cli import main
from tools.login_analyzer.core import LoginRecord, Settings, analyze_logins, haversine_km, load_logins

NYC, LON, MOW = (40.71, -74.01), (51.51, -0.13), (55.76, 37.62)


def rec(day_hour, user="alice", geo=NYC, country="US", device="laptop", tz=0.0, result="success", minute=0):
    d, h = day_hour
    return LoginRecord(datetime(2026, 10, d, h, minute, tzinfo=timezone.utc), user, "198.51.100.1", country, "", geo[0], geo[1], device, result, tz)


class Haversine(unittest.TestCase):
    def test_known_distance(self):
        self.assertAlmostEqual(haversine_km(*NYC, *LON), 5570, delta=40)

    def test_zero_distance(self):
        self.assertAlmostEqual(haversine_km(*NYC, *NYC), 0, places=6)


class Signals(unittest.TestCase):
    def test_impossible_travel(self):
        found = analyze_logins([rec((28, 13)), rec((28, 13), geo=MOW, country="RU", minute=20)])
        self.assertIn("impossible_travel", found[0].signals)
        self.assertGreaterEqual(found[0].severity, Severity.HIGH)

    def test_possible_travel_not_flagged(self):
        found = analyze_logins([rec((27, 13)), rec((28, 13), geo=LON, country="GB")])     # a day apart
        self.assertNotIn("impossible_travel", [s for f in found for s in f.signals])

    def test_first_login_only_builds_baseline(self):
        self.assertEqual(analyze_logins([rec((28, 13), device="unknown-phone", country="RU")]), [])

    def test_new_country_and_new_device(self):
        found = analyze_logins([rec((26, 13)), rec((28, 13), country="BR", device="tablet")])
        self.assertEqual(set(found[0].signals), {"new_country", "new_device"})

    def test_off_hours_uses_local_time(self):
        utc_night_local_day = analyze_logins([rec((28, 22), tz=11)])        # 22:00 UTC = 09:00 in UTC+11
        self.assertEqual(utc_night_local_day, [])
        genuinely_late = analyze_logins([rec((28, 3), tz=0)])
        self.assertEqual(genuinely_late[0].signals, ["off_hours"])

    def test_failed_logins_are_ignored(self):
        self.assertEqual(analyze_logins([rec((28, 3), result="failure")]), [])

    def test_weekend_flag_is_optional(self):
        saturday = rec((31, 12))                                                # 31 Oct 2026 is a Saturday
        self.assertEqual(analyze_logins([saturday]), [])
        self.assertEqual(analyze_logins([saturday], Settings(flag_weekends=True))[0].signals, ["weekend"])


class SampleData(unittest.TestCase):
    def test_sample_findings(self):
        found = {f.record.user: f for f in analyze_logins(load_logins(DATA / "logins.csv"))}
        self.assertEqual(set(found), {"alice", "bob", "carol", "dave"})
        self.assertEqual(found["alice"].severity, Severity.CRITICAL)
        self.assertEqual(set(found["alice"].signals), {"impossible_travel", "new_country", "new_device"})
        self.assertEqual(found["carol"].signals, ["new_country"])
        self.assertEqual(found["bob"].signals, ["off_hours"])
        self.assertEqual(found["dave"].signals, ["new_device"])

    def test_cli_and_bad_csv(self):
        code, out, _ = run_cli(main, [str(DATA / "logins.csv"), "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("impossible_travel", out)
        code, _, err = run_cli(main, [str(DATA / "alerts.json")])
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("error:"))


if __name__ == "__main__":
    unittest.main()
