# 9. Incident timeline builder

Merges events from several logs into one time-sorted timeline, with filters by IP, user and time, and marks key moments such as the first failed login and the likely compromise point.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- Why timelines turn scattered evidence into a story
- Merging and de-duplicating sorted events
- Pivoting on an indicator (an IP) across different log types

## Usage

Run these from the project root:

```bash
python -m tools.timeline_builder sample_data/auth.log sample_data/webserver_access.log sample_data/firewall.log --ip 203.0.113.45 --ip 198.51.100.77 --year 2026
python -m tools.timeline_builder sample_data/auth.log sample_data/firewall.log --year 2026 --start 2026-10-28T02:10:00Z --end 2026-10-28T02:35:00Z --output timeline.md
```

## Example output

```text
$ python -m tools.timeline_builder sample_data/auth.log sample_data/webserver_access.log sample_data/firewall.log --ip 203.0.113.45 --ip 198.51.100.77 --year 2026 --limit 6
========================================================================
 INCIDENT TIMELINE
========================================================================
48 events, 2026-10-28 02:14:01 -> 02:46:05 UTC | key moments marked with <--

2026-10-28 02:14:01  firewall allow    ALLOW TCP 203.0.113.45 -> 10.0.0.5:22
2026-10-28 02:14:03  auth     failure  SSH login failed for root from 203.0.113.45    <-- FIRST FAILED LOGIN from 203.0.113.45
2026-10-28 02:14:12  auth     failure  SSH login failed for admin from 203.0.113.45
2026-10-28 02:14:20  auth     failure  SSH attempt for non-existent user ubuntu from 203.0.113.45
2026-10-28 02:14:20  auth     failure  SSH login failed for ubuntu from 203.0.113.45
...
```

## Try it yourself

- Add a 'gap' marker when more than 10 minutes pass with no events.
- Add a --user filter combined with --ip using OR instead of AND.
- Export to HTML.

## Limitations

- Filters combine with AND.
- Key-moment markers are simple rules, not detections.
