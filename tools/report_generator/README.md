# 10. Triage report generator

Turns a structured case (JSON) into a clean incident report in Markdown and HTML: summary, evidence, defanged IOCs, ATT&CK mapping, timeline, verdict and recommended next steps.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- What a good triage report contains
- Why IOCs are defanged in reports
- Why untrusted text must be HTML-escaped (log data can contain markup)
- Mapping incident types to next steps

## Usage

Run these from the project root:

```bash
python -m tools.report_generator sample_data/case_example.json
python -m tools.report_generator sample_data/case_example.json --markdown report.md --html report.html
```

## Example output

```text
$ python -m tools.report_generator sample_data/case_example.json
# Incident triage report: SSH brute force leading to compromise of web01

| Field | Value |
|---|---|
| Case ID | INC-FAKE-001 |
| Analyst | Demo Analyst |
| Created | 2026-10-28 04:00 UTC |
| Severity | **CRITICAL** |
| Verdict | **True positive** |

## Summary

203.0.113.45 made 22 failed SSH logins against web01 within a few minutes (including several non-existent usernames), then logged in successfully as 'deploy'. Shortly afterwards the account ran curl and useradd through sudo, a web shell was requested from the same IP, and web01 began beaconing to 198.51.100.77 on port 4444. Both IPs are on the local blocklist. A separate phishing email, a password spray and a distributed attack on 'admin' were also detected.

...
```

## Try it yourself

- Write your own case JSON for a false positive and read the generated next steps.
- Add a 'lessons learned' section.
- Add a PDF export using the browser's print function.

## Limitations

- The case JSON is assembled by you or by demo.py; this tool does not investigate anything.
- The HTML has no JavaScript and basic styling only.
