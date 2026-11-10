import unittest

from soc_common.severity import Severity
from soc_common.validation import ToolError
from tests.helpers import DATA, run_cli
from tools.alert_prioritizer.cli import main as prio_main
from tools.alert_prioritizer.core import alerts_from_dicts, load_alerts, load_assets, score_alerts
from tools.attack_mapper.cli import main as attack_main
from tools.attack_mapper.core import DEFAULT_MAPPING, behaviours_from_alerts, load_mapping, map_behaviours
from tools.log_parser.core import parse_files
from tools.timeline_builder.core import build_timeline, filter_events, render_markdown, render_text


def alert(**kw):
    base = {"id": "X-1", "title": "t", "severity": "medium", "category": "c", "asset": "web01"}
    base.update(kw)
    return base


class Prioritizer(unittest.TestCase):
    def test_higher_severity_scores_higher(self):
        scored = score_alerts(alerts_from_dicts([alert(id="a", severity="low"), alert(id="b", severity="critical")]))
        self.assertEqual([s.alert.id for s in scored], ["b", "a"])

    def test_asset_criticality_matters(self):
        alerts = alerts_from_dicts([alert(id="a", asset="printer01", category="x"), alert(id="b", asset="dc01", category="y")])
        scored = {s.alert.id: s.score for s in score_alerts(alerts, {"printer01": 1, "dc01": 5})}
        self.assertEqual(scored["b"] - scored["a"], 20)

    def test_repetition_and_cap(self):
        many = alerts_from_dicts([alert(id="r%d" % i) for i in range(10)])
        base = score_alerts(alerts_from_dicts([alert()]))[0].score
        self.assertEqual(score_alerts(many)[0].score - base, 15)       # capped at +15

    def test_tags_and_external_ip_add_points_and_reasons(self):
        s = score_alerts(alerts_from_dicts([alert(tags=["known_bad_ip", "privileged_account"], src_ip="203.0.113.5")]))[0]
        text = " ".join(s.reasons)
        self.assertIn("threat-intel blocklist", text)
        self.assertIn("privileged account", text)
        self.assertIn("outside the private network", text)

    def test_score_is_capped_at_100(self):
        s = score_alerts(alerts_from_dicts([alert(severity="critical", tags=list(["known_bad_ip", "successful_login_after_failures", "privileged_account", "impossible_travel", "malware_detected"]))]), {"web01": 5})[0]
        self.assertEqual(s.score, 100)

    def test_validation_errors(self):
        for bad in ([{"title": "no id"}], [alert(severity="urgent")], [alert(), alert()]):
            with self.assertRaises(ToolError):
                alerts_from_dicts(bad)

    def test_sample_ranking(self):
        scored = score_alerts(load_alerts(DATA / "alerts.json"), load_assets(DATA / "assets.json"))
        self.assertEqual(len(scored), 12)
        self.assertEqual(scored[0].alert.id, "A-001")
        self.assertEqual(scored[-1].alert.id, "A-010")                  # routine printer check-in ranks last
        self.assertEqual([s.score for s in scored], sorted((s.score for s in scored), reverse=True))

    def test_cli_explain(self):
        code, out, _ = run_cli(prio_main, [str(DATA / "alerts.json"), "--assets", str(DATA / "assets.json"), "--top", "3", "--explain", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("Score breakdown", out)
        self.assertIn("base points", out)


class AttackMapper(unittest.TestCase):
    def setUp(self):
        self.mapping = load_mapping()

    def test_bundled_mapping_is_valid_and_sane(self):
        self.assertGreaterEqual(len(self.mapping["behaviours"]), 20)
        for alias, target in self.mapping["aliases"].items():
            self.assertIn(target, self.mapping["behaviours"], alias)

    def test_core_mappings(self):
        found, unknown = map_behaviours(["password_spray", "Brute Force", "phishing-link", "mystery"], self.mapping)
        ids = [m.technique_id for m in found]
        self.assertEqual(ids, ["T1110", "T1110.003", "T1566.002"])
        self.assertEqual(unknown, ["mystery"])

    def test_aliases_and_dedup(self):
        found, _ = map_behaviours(["impossible_travel", "valid_account_login", "off_hours_login"], self.mapping)
        self.assertEqual([m.technique_id for m in found], ["T1078"])

    def test_subtechnique_url(self):
        found, _ = map_behaviours(["password_spray"], self.mapping)
        self.assertEqual(found[0].url, "https://attack.mitre.org/techniques/T1110/003/")

    def test_from_alerts_and_cli(self):
        import json
        with open(str(DATA / "alerts.json"), encoding="utf-8") as fh:
            items = json.load(fh)["alerts"]
        self.assertIn("c2_beaconing", behaviours_from_alerts(items))
        code, out, _ = run_cli(attack_main, ["--alerts", str(DATA / "alerts.json")])
        self.assertEqual(code, 0)
        self.assertIn("T1071", out)
        code, _, err = run_cli(attack_main, [])
        self.assertEqual(code, 2)


class Timeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = parse_files([DATA / "auth.log", DATA / "webserver_access.log", DATA / "firewall.log"], "auto", 2026).events

    def test_merged_and_sorted_across_sources(self):
        entries = build_timeline(self.events)
        stamps = [e.event.timestamp for e in entries]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual({e.event.source for e in entries}, {"auth", "web", "firewall"})

    def test_ip_filter_matches_source_or_destination(self):
        events = filter_events(self.events, ips={"198.51.100.77"})
        self.assertTrue(events)
        self.assertTrue(all("198.51.100.77" in (e.src_ip, e.dst_ip) for e in events))

    def test_key_moments_are_marked(self):
        markers = [t.marker for t in build_timeline(self.events) if t.marker]
        self.assertTrue(any(m.startswith("POSSIBLE COMPROMISE: success after 22 failures from 203.0.113.45") for m in markers))
        self.assertTrue(any("OUTBOUND" in m for m in markers))
        self.assertTrue(any("PRIVILEGED" in m for m in markers))

    def test_duplicates_removed(self):
        self.assertEqual(len(build_timeline(self.events + self.events)), len(build_timeline(self.events)))

    def test_renderers(self):
        entries = build_timeline(self.events[:5])
        self.assertEqual(len(render_text(entries).splitlines()), 5)
        self.assertTrue(render_markdown(entries).startswith("# Incident timeline"))


if __name__ == "__main__":
    unittest.main()
