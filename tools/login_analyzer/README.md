# 3. Suspicious login analyzer

Reads a login CSV and flags impossible travel, off-hours logins, new countries and new devices, then combines the signals into a severity.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- Why stolen passwords still log in 'successfully' and context is the only clue
- The haversine formula for distance between two coordinates
- Why work hours must be judged in the user's local time
- Combining weak signals into a stronger score

## Usage

Run these from the project root:

```bash
python -m tools.login_analyzer sample_data/logins.csv
python -m tools.login_analyzer sample_data/logins.csv --flag-weekends --work-start 8 --work-end 18
```

## Example output

```text
$ python -m tools.login_analyzer sample_data/logins.csv
========================================================================
 SUSPICIOUS LOGIN ANALYZER
========================================================================
Logins read: 18 | flagged: 4

+----------+-------+-------------+-------+---------+-----------------+------------------------------------------+
| severity | score | time (UTC)  | user  | country | device          | signals                                  |
+----------+-------+-------------+-------+---------+-----------------+------------------------------------------+
| CRITICAL | 100   | 10-28 13:25 | alice | RU      | unknown-android | impossible_travel,new_country,new_device |
| MEDIUM   | 40    | 10-28 17:40 | carol | BR      | laptop-carol    | new_country                              |
| LOW      | 20    | 10-28 03:12 | bob   | GB      | laptop-bob      | off_hours                                |
| LOW      | 20    | 10-28 14:02 | dave  | US      | phone-dave      | new_device                               |
+----------+-------+-------------+-------+---------+-----------------+------------------------------------------+

...
```

## Try it yourself

- Add a column for an authentication method and flag logins without MFA.
- Add a 'VPN or known hosting provider' signal.
- Lower --max-speed and see which trips become suspicious.

## Limitations

- Needs latitude/longitude in the CSV (GeoIP is not built in).
- GeoIP is imprecise, so tiny hops under 100 km are ignored.
- VPN users can look like they teleport.
