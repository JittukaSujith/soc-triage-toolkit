import json
import tempfile
import unittest
from pathlib import Path

import demo
from soc_common.validation import ToolError
from tests.helpers import DATA, run_cli
from tools.alert_prioritizer.core import load_alerts, load_assets, score_alerts
from tools.report_generator.core import build_html, build_markdown, recommended_steps, validate_case
from tools.triage_dashboard.cli import main as dash_main
from tools.triage_dashboard.decisions import DECISIONS, DecisionStore, export_decisions


def case(**kw):
    base = {"title": "Test case", "summary": "Something happened.", "verdict": "True positive", "severity": "high",
            "iocs": {"ip": ["203.0.113.45"], "url": ["http://evil.example/x"]}, "categories": ["brute_force"]}
    base.update(kw)
    return base


class Reports(unittest.TestCase):
    def test_validation(self):
        for bad in (case(title=""), case(verdict="Maybe"), case(severity="spicy")):
            with self.assertRaises(ToolError):
                validate_case(bad)

    def test_markdown_defangs_iocs_and_lists_steps(self):
        md = build_markdown(case())
        self.assertIn("203[.]0[.]113[.]45", md)
        self.assertNotIn("http://evil.example", md)
        self.assertIn("hxxp://evil[.]example/x", md)
        self.assertIn("Block the attacking IP", md)

    def test_html_escapes_untrusted_text(self):
        html = build_html(case(title="<script>alert(1)</script>", summary="<img src=x onerror=alert(1)>"))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)

    def test_recommendations(self):
        fp = validate_case(case(verdict="False positive"))
        self.assertIn("Close the alert.", recommended_steps(fp))
        esc = validate_case(case(verdict="Needs escalation"))
        self.assertTrue(recommended_steps(esc)[0].startswith("Escalate"))
        custom = validate_case(case(recommendations=["Do X"]))
        self.assertEqual(recommended_steps(custom), ["Do X"])


class Decisions(unittest.TestCase):
    def test_store_behaviour(self):
        store = DecisionStore()
        store.set("A-1", "True positive", " confirmed ")
        store.set("A-2", "False positive")
        self.assertEqual(store.get("A-1")["note"], "confirmed")
        self.assertEqual(store.pending(["A-1", "A-2", "A-3"]), ["A-3"])
        self.assertEqual(store.counts(), {"True positive": 1, "False positive": 1, "Needs escalation": 0})
        with self.assertRaises(ValueError):
            store.set("A-3", "Probably fine")

    def test_export_and_resume(self):
        scored = score_alerts(load_alerts(DATA / "alerts.json"), load_assets(DATA / "assets.json"))
        store = DecisionStore()
        store.set(scored[0].alert.id, DECISIONS[2], "escalate to IR")
        with tempfile.TemporaryDirectory() as tmp:
            as_json, as_csv = str(Path(tmp) / "d.json"), str(Path(tmp) / "d.csv")
            self.assertEqual(export_decisions(as_json, scored, store), 12)
            export_decisions(as_csv, scored, store)
            self.assertTrue(Path(as_csv).read_text().startswith("rank,id,title"))
            rows = json.loads(Path(as_json).read_text())
            self.assertEqual((rows[0]["rank"], rows[0]["decision"]), (1, "Needs escalation"))
            again = DecisionStore()
            self.assertEqual(again.load(as_json), 1)
            self.assertEqual(again.get(scored[0].alert.id)["note"], "escalate to IR")

    def test_gui_modules_import_without_tkinter_and_check_mode_works(self):
        import tools.ioc_extractor.gui  # noqa: F401
        import tools.triage_dashboard.gui  # noqa: F401
        code, out, _ = run_cli(dash_main, ["--check", "--alerts", str(DATA / "alerts.json"), "--assets", str(DATA / "assets.json")])
        self.assertEqual(code, 0)
        self.assertIn("A-001", out)


class EndToEnd(unittest.TestCase):
    def test_demo_produces_complete_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_cli(demo.main, ["--output-dir", tmp])
            self.assertEqual(code, 0)
            for stage in range(1, 10):
                self.assertIn("STAGE %d" % stage, out)
            md = (Path(tmp) / "report.md").read_text()
            self.assertIn("INC-FAKE-001", md)
            self.assertIn("T1110", md)
            self.assertIn("203[.]0[.]113[.]45", md)
            self.assertIn("POSSIBLE COMPROMISE", md)
            html = (Path(tmp) / "report.html").read_text()
            self.assertTrue(html.startswith("<!DOCTYPE html>"))
            ranked = json.loads((Path(tmp) / "ranked_alerts.json").read_text())
            self.assertEqual(ranked[0]["priority"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
