# Sample data (ALL FAKE)

Everything here is synthetic training data. Hostnames, usernames, domains and companies are invented.
IP addresses come from ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, defined in RFC 5737, and 198.18.0.0/15 from RFC 2544) plus private 10.0.0.0/24, so none of them points at a real machine. Domains use the reserved `.example` ending.
The "executable" attachment contains the text `FAKE-SAMPLE-EXECUTABLE-CONTENT - NOT REAL MALWARE - DO NOT RUN`.

**Do not add real logs, real emails, customer data or company data to this folder.** This repository is public.

| File | Used by |
|---|---|
| `auth.log` | log parser, brute-force detector, timeline builder |
| `webserver_access.log` | log parser, brute-force detector (web login attacks), timeline builder |
| `firewall.log` | log parser, timeline builder, demo |
| `logins.csv` | suspicious login analyzer |
| `emails/*.eml` | phishing analyzer, IOC extractor, intel matcher |
| `blocklist.csv` | intel matcher, demo |
| `alerts.json`, `assets.json` | alert prioritizer, ATT&CK mapper, triage dashboard |
| `case_example.json` | report generator |

The story ("INC-FAKE-001", 28 October 2026): 203.0.113.45 brute-forces SSH on web01, logs in as `deploy`, downloads a script from 198.51.100.77, plants a web shell and beacons to port 4444. A password spray, a distributed attack on `admin`, a port scan and a WordPress brute force add noise.

Regenerate everything (deterministic) with:

```bash
python sample_data/generate_sample_data.py
```
