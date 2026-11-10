# SOC Triage Toolkit

[![tests](https://github.com/JittukaSujith/soc-triage-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/JittukaSujith/soc-triage-toolkit/actions/workflows/tests.yml)

A hands-on Python toolkit that shows how a junior SOC (Security Operations Center) analyst takes raw logs, alerts and suspicious emails and quickly decides **what is serious, what is noise, and what to do next**. It is eleven small tools, a shared helper package, fake sample data and an end-to-end demo, all using only the Python standard library.

> **Ethical use and disclaimer.** This project is for learning and for defending systems you own or are authorised to monitor. It only analyses logs and emails that **you provide**; it does not scan, probe, attack or log in to any system. The sample data is entirely fake. **Never upload real company logs, emails, customer data or credentials to a public repository.** The scoring rules are teaching examples, not a replacement for a production security product or professional judgement.

## Tools at a glance

| # | Tool | What it does | Interface |
|---|---|---|---|
| 1 | [Log parser](tools/log_parser/README.md) | Normalises auth, web and firewall logs into one event format | CLI |
| 2 | [Brute-force and spray detector](tools/bruteforce_detector/README.md) | Finds repeated failed logins by IP and user, and whether the attacker got in | CLI |
| 3 | [Suspicious login analyzer](tools/login_analyzer/README.md) | Flags impossible travel, off-hours logins, new country or device | CLI |
| 4 | [Phishing email analyzer](tools/phishing_analyzer/README.md) | Scores .eml files from headers, SPF/DKIM/DMARC, links and attachments | CLI |
| 5 | [IOC extractor](tools/ioc_extractor/README.md) | Extracts, de-duplicates and defangs IOCs; exports CSV or JSON | CLI + GUI |
| 6 | [Offline threat-intel matcher](tools/intel_matcher/README.md) | Matches IOCs to your local blocklist (optional labelled online lookup) | CLI |
| 7 | [Alert prioritizer](tools/alert_prioritizer/README.md) | Ranks alerts by severity, asset value, repetition and context, with explanations | CLI |
| 8 | [MITRE ATT&CK mapper](tools/attack_mapper/README.md) | Maps behaviours to ATT&CK technique IDs from a local file | CLI |
| 9 | [Incident timeline builder](tools/timeline_builder/README.md) | Merges several logs into one sorted, annotated timeline | CLI |
| 10 | [Triage report generator](tools/report_generator/README.md) | Writes the incident report in Markdown and HTML | CLI |
| 11 | [Alert triage dashboard](tools/triage_dashboard/README.md) | Ranked alert list; mark True positive, False positive or Needs escalation | GUI |

Playbooks for the four most common cases are in [`playbooks/`](playbooks/): [phishing](playbooks/phishing.md), [brute force](playbooks/brute_force.md), [malware alert](playbooks/malware_alert.md) and [suspicious login](playbooks/suspicious_login.md).

## Quick start

You need Python 3.9 or newer and Git. The commands below are for macOS or Linux; on Windows, activate the environment with `.venv\Scripts\activate`.

```bash
git clone https://github.com/JittukaSujith/soc-triage-toolkit.git
cd soc-triage-toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m unittest
python demo.py
```

- `python -m unittest` runs the offline tests. You should see `OK` at the end.
- `python demo.py` runs the whole triage flow on the fake sample data and writes a finished report to `demo_output/report.html`.
- Nothing needs installing: there are no third-party packages (see `requirements.txt`).

Run any single tool with `python -m tools.NAME`, for example:

```bash
python -m tools.bruteforce_detector sample_data/auth.log --year 2026
python -m tools.phishing_analyzer sample_data/emails
python -m tools.triage_dashboard
```

The two GUI tools need Tkinter (included with the python.org installer; Homebrew users run `brew install python-tk`). `python -m tools.triage_dashboard --check` prints the ranked alerts without opening a window.

## How the tools fit into a SOC triage workflow

```text
  RAW EVIDENCE                      ANALYSIS                       DECISION
  ------------                      --------                       --------
  auth / web / firewall logs --> [1 Log parser] ------+
                                                       |--> [2 Brute-force detector] --+
                                                       |--> [9 Timeline builder] ------+
  login history CSV ---------------> [3 Login analyzer] --------------------------------+
  suspicious .eml -----------------> [4 Phishing analyzer] ------------------------------+
  any text or file ----------------> [5 IOC extractor] --> [6 Intel matcher] ------------+
                                                                                          |
                                           alerts --> [7 Alert prioritizer] <-------------+
                                                         |             |
                                                         v             v
                                      [11 Triage dashboard]    [8 ATT&CK mapper]
                                      (analyst decides)               |
                                                         |             |
                                                         +------> [10 Report generator] --> verdict, evidence, IOCs,
                                                                                            ATT&CK mapping, next steps
```

In words: **normalise** the evidence, **detect** what looks wrong, **enrich** indicators with intelligence, **prioritise** alerts, **map** behaviour to ATT&CK, then **decide and report**. `demo.py` runs exactly this chain.

## Suggested learning path

1. Read the [log parser](tools/log_parser/README.md) and run it. Seeing three formats become one is the key idea.
2. Run the [brute-force detector](tools/bruteforce_detector/README.md), then change the thresholds and watch the findings change.
3. Try the [login analyzer](tools/login_analyzer/README.md), then the [phishing analyzer](tools/phishing_analyzer/README.md), reading every "why" line.
4. Extract IOCs ([5](tools/ioc_extractor/README.md)) and match them ([6](tools/intel_matcher/README.md)).
5. Rank alerts ([7](tools/alert_prioritizer/README.md)) and map them to ATT&CK ([8](tools/attack_mapper/README.md)).
6. Build a timeline ([9](tools/timeline_builder/README.md)) and write the report ([10](tools/report_generator/README.md)).
7. Open the [dashboard](tools/triage_dashboard/README.md) and make the triage decisions yourself.
8. Read the [playbooks](playbooks/) and run `python demo.py`, then read `demo.py` to see how it is all wired together.

## Project layout

```text
soc-triage-toolkit/
  README.md, LICENSE, requirements.txt, .gitignore, .gitattributes
  demo.py                  end-to-end triage flow on the sample data
  soc_common/              shared helpers: severity levels, log-event schema, IOC patterns,
                           domain look-alike checks, input validation, output formatting
  tools/                   one folder per tool: core.py (pure logic), cli.py (thin layer), README.md
  sample_data/             FAKE logs, emails, blocklist, alerts (plus the generator script)
  playbooks/               short response playbooks
  tests/                   offline unit tests (python -m unittest)
  .github/workflows/       GitHub Actions: tests on Linux, macOS and Windows
```

Design rules: core logic lives in pure, testable functions; the command-line or GUI layer on top is thin; GUI and network libraries are imported lazily, so the tests run anywhere with no display and no internet.

## Limitations

- Detection rules use fixed thresholds and simple heuristics; they are teaching examples, not tuned on real traffic.
- Parsers understand a limited set of formats (sshd and sudo, combined web logs, key=value firewall logs).
- The brand list, ATT&CK mapping and scoring weights are small and written for learning. Confirm ATT&CK IDs at attack.mitre.org before using them in a real report.
- Public-suffix handling is simplified (a few multi-part endings such as co.uk).
- The online domain lookup in the intel matcher and the two Tkinter windows are not covered by automated tests.

## Author

Built by **Sujith Kumar** ([@JittukaSujith](https://github.com/JittukaSujith)) as a hands-on learning and portfolio project for SOC analyst roles.

## License

MIT. See [LICENSE](LICENSE).
