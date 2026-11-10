# 7. Alert prioritizer

Scores and ranks alerts from 0 to 100 using severity, asset importance, repetition and context tags, and explains every point.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- Why alert queues need ranking
- Explainable scoring versus a black box
- How asset criticality changes priority
- Validating input so one bad alert does not hide the rest

## Usage

Run these from the project root:

```bash
python -m tools.alert_prioritizer sample_data/alerts.json --assets sample_data/assets.json
python -m tools.alert_prioritizer sample_data/alerts.json --assets sample_data/assets.json --top 3 --explain --output ranked.csv
```

## Example output

```text
$ python -m tools.alert_prioritizer sample_data/alerts.json --assets sample_data/assets.json --top 5 --explain
========================================================================
 ALERT PRIORITIZER
========================================================================
Alerts: 12 (showing 5)

+---+-------+----------+-------+---------------------------------------+--------+
| # | score | priority | id    | title                                 | asset  |
+---+-------+----------+-------+---------------------------------------+--------+
| 1 | 88    | CRITICAL | A-001 | SSH brute force then successful login | web01  |
| 2 | 83    | CRITICAL | A-003 | Web shell access pattern              | web01  |
| 3 | 73    | HIGH     | A-009 | WordPress login brute force           | web01  |
| 4 | 70    | HIGH     | A-008 | New admin-like account created        | web01  |
...
```

## Try it yourself

- Change the weights in alert_prioritizer/core.py and see how the ranking moves.
- Add a 'time since last seen' decay.
- Add a tag for 'user is a VIP'.

## Limitations

- The weights are teaching defaults, not tuned on real data.
- Unknown assets are assumed to be criticality 2 and the explanation says so.
