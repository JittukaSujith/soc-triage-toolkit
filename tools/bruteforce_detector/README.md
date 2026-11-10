# 2. Brute-force and password-spray detector

Finds repeated failed logins by IP and by user with configurable thresholds, tells brute force, password spraying and distributed attacks apart, and checks whether the attacker got in afterwards.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- The three fingerprints: many failures from one IP, many users from one IP, one user from many IPs
- Why attackers password-spray (to dodge per-account lockouts)
- The sliding-window algorithm and why it beats counting totals
- Why 'success after failures' is the most important signal

## Usage

Run these from the project root:

```bash
python -m tools.bruteforce_detector sample_data/auth.log sample_data/webserver_access.log --year 2026
python -m tools.bruteforce_detector sample_data/auth.log --year 2026 --ip-failures 10 --window-minutes 5 --output findings.csv
```

## Example output

```text
$ python -m tools.bruteforce_detector sample_data/auth.log sample_data/webserver_access.log --year 2026
========================================================================
 BRUTE-FORCE / PASSWORD-SPRAY DETECTOR
========================================================================
Events analysed: 116 | window: 10 min | thresholds: ip>=5, user>=5, spray users>=5

+----------+----------------+------------------+-------+-------+-----+--------------+
| severity | type           | source (IP/user) | fails | users | IPs | login after? |
+----------+----------------+------------------+-------+-------+-----+--------------+
| CRITICAL | ip_bruteforce  | 203.0.113.45     | 22    | 7     | 1   | YES          |
| CRITICAL | ip_bruteforce  | 198.51.100.200   | 12    | 1     | 1   | YES          |
| HIGH     | password_spray | 192.0.2.60       | 16    | 10    | 1   | no           |
| MEDIUM   | user_targeted  | admin            | 10    | 1     | 5   | no           |
...
```

## Try it yourself

- Lower --spray-users and see what new activity is flagged.
- Add a rule for failures against many different hosts from one IP.
- Print a ready-to-paste firewall block list for CRITICAL findings.

## Limitations

- Thresholds are fixed numbers, not learned baselines.
- An attacker who is slower than the window will not be flagged.
- A NAT gateway can make many users look like one IP.
