# 11. Alert triage dashboard (GUI)

A Tkinter window that loads alerts, shows them ranked by the prioritizer, lets the analyst mark each True positive / False positive / Needs escalation, add notes, and export the decisions as JSON or CSV.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- Separating GUI code from logic you can unit test
- Lazy imports so the project works without a display
- How analysts record decisions for handover and audit

## Usage

Run these from the project root:

```bash
python -m tools.triage_dashboard
python -m tools.triage_dashboard --alerts sample_data/alerts.json --assets sample_data/assets.json
python -m tools.triage_dashboard --check
```

## Example output

```text
$ python -m tools.triage_dashboard --check
========================================================================
 TRIAGE DASHBOARD (headless check)
========================================================================
+----+-------+----------+-------+---------------------------------------+
| #  | score | priority | id    | title                                 |
+----+-------+----------+-------+---------------------------------------+
| 1  | 88    | CRITICAL | A-001 | SSH brute force then successful login |
| 2  | 83    | CRITICAL | A-003 | Web shell access pattern              |
| 3  | 73    | HIGH     | A-009 | WordPress login brute force           |
| 4  | 70    | HIGH     | A-008 | New admin-like account created        |
| 5  | 63    | HIGH     | A-011 | Phishing email reported by user       |
| 6  | 63    | HIGH     | A-006 | Impossible travel for alice           |
...
```

## Try it yourself

- Add a filter box for the alert title.
- Add keyboard shortcuts for the three decisions.
- Load a previous export to resume (the decision store already supports this).

## Limitations

- The window layer is not covered by automated tests (the ranking and decision logic behind it is). If you see a Tk layout problem, please open an issue.
- Needs Tkinter; use --check on a machine without a display.
