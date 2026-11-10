# 6. Offline threat-intel matcher

Checks IOCs against a local blocklist you maintain (exact IPs, CIDR ranges, domains and sub-domains, URLs, emails, hashes). No internet needed. An optional, clearly labelled --online mode looks up domain registration dates via RDAP.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- What threat intelligence is and why a blocklist hit is not the same as a verdict
- CIDR matching with the ipaddress module
- Why domain matching must respect label boundaries (notevil.example is not evil.example)
- The privacy cost of online lookups

## Usage

Run these from the project root:

```bash
python -m tools.intel_matcher sample_data/emails/02_phish_paypal_lookalike.eml --blocklist sample_data/blocklist.csv
python -m tools.intel_matcher --ioc 192.0.2.70 --blocklist sample_data/blocklist.csv
```

## Example output

```text
$ python -m tools.intel_matcher sample_data/emails/02_phish_paypal_lookalike.eml --blocklist sample_data/blocklist.csv
========================================================================
 OFFLINE THREAT-INTEL MATCHER
========================================================================
IOCs extracted: 20 | blocklist entries: 6 | matches: 9  (mode: OFFLINE)

+----------+------------------------------------------+--------+------------------------+----------------+---------------------------+------+
| severity | ioc                                      | type   | matched by             | how            | source                    | conf |
+----------+------------------------------------------+--------+------------------------+----------------+---------------------------+------+
| CRITICAL | 198.51.100.77                            | ip     | 198.51.100.77          | exact          | Sample-Internal-Blocklist | 90   |
| CRITICAL | http://198.51.100.77/verify              | url    | 198.51.100.77          | url-host exact | Sample-Internal-Blocklist | 90   |
| HIGH     | http://login.paypa1-secure.example/ve... | url    | paypa1-secure.example  | url-host       | Sample-Phish-Feed         | 85   |
| HIGH     | login.paypa1-secure.example              | domain | paypa1-secure.example  | subdomain      | Sample-Phish-Feed         | 85   |
| HIGH     | mail.paypa1-secure.example               | domain | paypa1-secure.example  | subdomain      | Sample-Phish-Feed         | 85   |
...
```

## Try it yourself

- Add your own entries to a copy of sample_data/blocklist.csv.
- Add an expiry date column and ignore old entries.
- Cache online results so a domain is only looked up once.

## Limitations

- No match only means YOUR list does not know it.
- --online sends domain names to rdap.org and registries, so never use it on sensitive data. It was not tested here because the build environment had no internet.
- Reserved TLDs such as .example are skipped online.
