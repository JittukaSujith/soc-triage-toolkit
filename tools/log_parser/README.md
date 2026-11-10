# 1. Log parser and normalizer

Reads auth (SSH/sudo), web server (Nginx/Apache combined) and firewall (key=value) logs and turns every line into one common event format.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- Why SOCs normalise logs before analysing them
- Parsing messy text safely with regular expressions
- Why syslog needs a year and why sshd logs both 'Invalid user' and 'Failed password'
- Separating thin command-line code from testable core logic

## Usage

Run these from the project root:

```bash
python -m tools.log_parser sample_data/auth.log sample_data/webserver_access.log sample_data/firewall.log --year 2026
python -m tools.log_parser sample_data/auth.log --year 2026 --output events.jsonl
```

## Example output

```text
$ python -m tools.log_parser sample_data/auth.log sample_data/webserver_access.log sample_data/firewall.log --year 2026 --show 3
========================================================================
 LOG PARSER
========================================================================
Lines read : 154  (parsed 151, skipped 0, comments/blank 3)
By source  : auth=75, firewall=35, web=41

+---------------------+----------+------------+------+---------------------+---------+
| time (UTC)          | source   | src_ip     | user | action              | outcome |
+---------------------+----------+------------+------+---------------------+---------+
| 2026-10-28 00:55:00 | firewall | 192.0.2.77 |      | firewall_connection | deny    |
| 2026-10-28 00:55:01 | firewall | 192.0.2.77 |      | firewall_connection | deny    |
| 2026-10-28 00:55:02 | firewall | 192.0.2.77 |      | firewall_connection | deny    |
...
```

## Try it yourself

- Add a parser for another format (for example Windows event exports as CSV).
- Add a field for GeoIP country and keep it optional.
- Make syslog year detection smarter around New Year.

## Limitations

- Syslog lines have no year or timezone: you pass --year and times are treated as UTC.
- Only sshd and sudo lines are understood from auth logs; other processes are skipped and counted.
- Web logs must be the 'combined' format.
