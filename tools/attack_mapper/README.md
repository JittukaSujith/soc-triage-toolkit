# 8. MITRE ATT&CK mapper

Maps detected behaviours to MITRE ATT&CK technique IDs using a small local JSON file, with a plain-English reason for each mapping and a link to the official page.

Part of the [SOC Triage Toolkit](../../README.md). All sample data is fake.

## What you will learn

- What tactics and techniques are and why a shared vocabulary helps
- Reading technique IDs and sub-techniques (T1110.003)
- Keeping reference data in a file you can read and extend

## Usage

Run these from the project root:

```bash
python -m tools.attack_mapper --behaviour password_spray --behaviour phishing_link --behaviour c2_beaconing
python -m tools.attack_mapper --alerts sample_data/alerts.json
python -m tools.attack_mapper --list
```

## Example output

```text
$ python -m tools.attack_mapper --behaviour password_spray --behaviour phishing_link --behaviour c2_beaconing
========================================================================
 MITRE ATT&CK MAPPER
========================================================================
Mapped 3 technique(s) from 3 behaviour name(s)

+-----------+--------------------------------+---------------------+----------------+
| technique | name                           | tactic(s)           | from behaviour |
+-----------+--------------------------------+---------------------+----------------+
| T1071     | Application Layer Protocol     | Command and Control | c2_beaconing   |
| T1110.003 | Brute Force: Password Spraying | Credential Access   | password_spray |
| T1566.002 | Phishing: Spearphishing Link   | Initial Access      | phishing_link  |
+-----------+--------------------------------+---------------------+----------------+

Why each one:
 - T1071 Application Layer Protocol: Regular, repeated outbound connections to the same external IP and port.
   https://attack.mitre.org/techniques/T1071/
...
```

## Try it yourself

- Add new behaviours to mapping.json (copy an existing entry).
- Group results by tactic to see which attack stages were observed.
- Add a validator that checks IDs against a downloaded ATT&CK file.

## Limitations

- The mapping is a small teaching subset written from the author's knowledge. Confirm every ID and name at attack.mitre.org before quoting it in a real report.
- Mapping a log line to one technique is a judgement call.
