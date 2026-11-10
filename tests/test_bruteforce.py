import unittest

from soc_common.severity import Severity
from tests.helpers import DATA, login_event, run_cli
from tools.bruteforce_detector.cli import main
from tools.bruteforce_detector.core import Thresholds, densest_window, detect
from tools.log_parser.core import parse_files
from datetime import timedelta


def fails(n, step=10, ip="203.0.113.9", users=("root",)):
    return [login_event(i * step, ip=ip, user=users[i % len(users)]) for i in range(n)]


class BruteForce(unittest.TestCase):
    def test_below_threshold_is_quiet(self):
        self.assertEqual(detect(fails(4)), [])

    def test_threshold_gives_medium_and_volume_gives_high(self):
        self.assertEqual(detect(fails(5))[0].severity, Severity.MEDIUM)
        self.assertEqual(detect(fails(15))[0].severity, Severity.HIGH)

    def test_spread_over_time_is_not_a_burst(self):
        slow = [login_event(i * 3600) for i in range(10)]          # one failure per hour
        self.assertEqual(detect(slow), [])

    def test_success_after_failures_is_critical(self):
        events = fails(6) + [login_event(120, outcome="success", user="deploy")]
        finding = detect(events)[0]
        self.assertTrue(finding.success_after)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_success_before_failures_does_not_count(self):
        events = [login_event(-60, outcome="success")] + fails(6)
        self.assertFalse(detect(events)[0].success_after)

    def test_password_spray_vs_brute_force(self):
        spray = fails(10, ip="203.0.113.50", users=tuple("user%d" % i for i in range(10)))   # 1 try per user
        found = detect(spray)
        self.assertEqual(found[0].kind, "password_spray")
        self.assertEqual(found[0].severity, Severity.HIGH)

    def test_user_targeted_from_many_ips(self):
        events = [login_event(i * 5, ip="203.0.113.%d" % (100 + i), user="admin") for i in range(6)]
        kinds = {f.kind for f in detect(events, Thresholds(ip_failures=50))}
        self.assertEqual(kinds, {"user_targeted"})

    def test_invalid_user_action_is_not_double_counted(self):
        events = fails(4) + [login_event(i, action="ssh_invalid_user") for i in range(10)]
        self.assertEqual(detect(events), [])

    def test_densest_window(self):
        evs = fails(3, step=1) + [login_event(1000 + i) for i in range(5)]
        self.assertEqual(len(densest_window(evs, timedelta(minutes=1))), 5)

    def test_sample_data_findings(self):
        events = parse_files([DATA / "auth.log", DATA / "webserver_access.log"], "auto", 2026).events
        by_key = {f.key: f for f in detect(events)}
        self.assertEqual((by_key["203.0.113.45"].failures, by_key["203.0.113.45"].severity), (22, Severity.CRITICAL))
        self.assertEqual(by_key["192.0.2.60"].kind, "password_spray")
        self.assertEqual(by_key["admin"].kind, "user_targeted")
        self.assertEqual(by_key["198.51.100.200"].severity, Severity.CRITICAL)   # web login brute force then success
        self.assertNotIn("10.0.0.25", by_key)                                    # a harmless typo is not flagged

    def test_cli_runs_and_validates(self):
        code, out, _ = run_cli(main, [str(DATA / "auth.log"), "--year", "2026", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.45", out)
        code, _, err = run_cli(main, [str(DATA / "auth.log"), "--ip-failures", "1"])
        self.assertEqual(code, 2)
        self.assertIn("--ip-failures must be", err)


if __name__ == "__main__":
    unittest.main()
