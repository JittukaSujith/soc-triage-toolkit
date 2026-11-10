"""Triage report generator - core logic.

A triage ends with a written record: what happened, how sure are we, and what should
happen next. Writing it consistently matters - the next analyst, a manager or an auditor
will rely on it. This module turns a structured "case" (a plain dict / JSON file) into a
Markdown or HTML report. IOCs are DEFANGED in reports so nobody clicks them by accident.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Dict, List

from soc_common.ioc_patterns import IOC_TYPES, defang
from soc_common.severity import Severity
from soc_common.validation import ToolError

VERDICTS = ("True positive", "False positive", "Needs escalation")
MAX_TIMELINE_ROWS = 40

# Short, practical next steps per kind of incident (see the playbooks/ folder for the long versions).
PLAYBOOK_STEPS = {
    "brute_force": ["Block the attacking IP(s) at the firewall.", "If a login succeeded: disable the account, reset its credentials and review everything it did.",
                    "Enforce MFA and account lockout; disable password SSH where possible."],
    "phishing": ["Quarantine or delete the message from all mailboxes.", "Block the sender domain and any malicious links at the proxy or mail gateway.",
                 "Check who clicked or replied; reset credentials for anyone who entered a password."],
    "malware": ["Isolate the affected host from the network.", "Preserve evidence (memory, logs, suspicious files) before cleaning.",
                "Block C2 IPs/domains and hunt for the same indicators on other hosts."],
    "suspicious_login": ["Contact the user through a separate channel to confirm the login.", "If not confirmed: revoke sessions, reset the password and re-register MFA.",
                         "Review mailbox rules and recent activity for the account."],
}
CATEGORY_TO_PLAYBOOK = {
    "brute_force": "brute_force", "password_spray": "brute_force", "ip_bruteforce": "brute_force", "user_targeted": "brute_force",
    "phishing_email": "phishing", "phishing": "phishing", "email_impersonation": "phishing",
    "webshell": "malware", "c2_beaconing": "malware", "malware_detected": "malware", "tool_download": "malware", "account_creation": "malware",
    "impossible_travel": "suspicious_login", "off_hours_login": "suspicious_login", "valid_account_login": "suspicious_login",
}


def validate_case(case: Dict) -> Dict:
    """Check the case has what a report needs; return it (with defaults filled in)."""
    if not isinstance(case, dict):
        raise ToolError("the case must be a JSON object")
    for key in ("title", "summary", "verdict", "severity"):
        if not str(case.get(key, "")).strip():
            raise ToolError("case is missing required field %r" % key)
    if case["verdict"] not in VERDICTS:
        raise ToolError("verdict must be one of: %s (got %r)" % (", ".join(VERDICTS), case["verdict"]))
    try:
        case["severity"] = Severity.parse(case["severity"]).name
    except ValueError as exc:
        raise ToolError(str(exc))
    case.setdefault("case_id", "CASE-0001")
    case.setdefault("analyst", "Unassigned")
    case.setdefault("created", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    for key in ("evidence", "attack", "timeline", "categories", "recommendations"):
        case.setdefault(key, [])
    case.setdefault("iocs", {})
    return case


def recommended_steps(case: Dict) -> List[str]:
    """Explicit recommendations win; otherwise derive them from the incident categories and verdict."""
    if case.get("recommendations"):
        return list(case["recommendations"])
    if case["verdict"] == "False positive":
        return ["Record why this is a false positive (evidence, who confirmed it).", "Tune the rule or threshold so it does not fire again.", "Close the alert."]
    steps: List[str] = []
    for cat in case.get("categories", []):
        for step in PLAYBOOK_STEPS.get(CATEGORY_TO_PLAYBOOK.get(cat, ""), []):
            if step not in steps:
                steps.append(step)
    if not steps:
        steps = ["Continue investigating and gather more evidence."]
    if case["verdict"] == "Needs escalation":
        steps.insert(0, "Escalate to the incident response lead / Tier 2 with this report attached.")
    return steps


def _md(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _ioc_items(case: Dict):
    for kind in IOC_TYPES:
        for value in case["iocs"].get(kind, []):
            yield kind, defang(value, kind)


def build_markdown(case: Dict) -> str:
    case = validate_case(case)
    out = ["# Incident triage report: %s" % case["title"], "",
           "| Field | Value |", "|---|---|",
           "| Case ID | %s |" % _md(case["case_id"]), "| Analyst | %s |" % _md(case["analyst"]), "| Created | %s |" % _md(case["created"]),
           "| Severity | **%s** |" % case["severity"], "| Verdict | **%s** |" % case["verdict"], "",
           "## Summary", "", case["summary"], ""]
    out += ["## Evidence", ""]
    out += ["- **%s** - %s" % (e.get("title", "Evidence"), e.get("detail", "")) for e in case["evidence"]] or ["- (none recorded)"]
    out += ["", "## Indicators of compromise (defanged)", ""]
    items = list(_ioc_items(case))
    out += (["| Type | Indicator |", "|---|---|"] + ["| %s | `%s` |" % (k, v) for k, v in items]) if items else ["(none recorded)"]
    out += ["", "## MITRE ATT&CK mapping", ""]
    if case["attack"]:
        out += ["| Technique | Name | Tactic(s) | Why |", "|---|---|---|---|"]
        out += ["| [%s](%s) | %s | %s | %s |" % (a["technique_id"], a.get("url", ""), _md(a["name"]), _md(a.get("tactics", "")), _md(a.get("why", ""))) for a in case["attack"]]
    else:
        out.append("(none recorded)")
    out += ["", "## Timeline", ""]
    if case["timeline"]:
        out += ["| Time (UTC) | Event | Note |", "|---|---|---|"]
        for row in case["timeline"][:MAX_TIMELINE_ROWS]:
            out.append("| %s | %s | %s |" % (_md(row.get("timestamp", "")), _md(row.get("message", "")), _md(row.get("marker", ""))))
        if len(case["timeline"]) > MAX_TIMELINE_ROWS:
            out.append("")
            out.append("_%d more events not shown._" % (len(case["timeline"]) - MAX_TIMELINE_ROWS))
    else:
        out.append("(none recorded)")
    out += ["", "## Recommended next steps", ""] + ["%d. %s" % (i, s) for i, s in enumerate(recommended_steps(case), start=1)]
    notice = case.get("notice")
    out += ["", "---", "_Generated by soc-triage-toolkit.%s_" % ((" " + notice) if notice else ""), ""]
    return "\n".join(out)


def build_html(case: Dict) -> str:
    """Self-contained HTML report. Every value is escaped, so a malicious string in a log cannot inject markup."""
    case = validate_case(case)
    e = html.escape
    sev_color = {"CRITICAL": "#b00020", "HIGH": "#d84315", "MEDIUM": "#b26a00", "LOW": "#00695c", "INFO": "#546e7a"}[case["severity"]]
    parts = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">', "<title>%s</title>" % e(case["title"]),
             "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1c1c1c}"
             "table{border-collapse:collapse;width:100%%;margin:.5rem 0}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}"
             "th{background:#f3f3f3}code{background:#f3f3f3;padding:0 .2rem}.badge{color:#fff;padding:.1rem .5rem;border-radius:4px;background:%s}</style>" % sev_color,
             "</head><body>", "<h1>Incident triage report: %s</h1>" % e(case["title"]),
             "<table><tr><th>Case ID</th><td>%s</td><th>Analyst</th><td>%s</td></tr>"
             "<tr><th>Created</th><td>%s</td><th>Verdict</th><td><strong>%s</strong></td></tr>"
             '<tr><th>Severity</th><td colspan="3"><span class="badge">%s</span></td></tr></table>' % (
                 e(case["case_id"]), e(case["analyst"]), e(case["created"]), e(case["verdict"]), e(case["severity"])),
             "<h2>Summary</h2><p>%s</p>" % e(case["summary"]), "<h2>Evidence</h2>"]
    parts.append("<ul>%s</ul>" % "".join("<li><strong>%s</strong> - %s</li>" % (e(str(x.get("title", "Evidence"))), e(str(x.get("detail", "")))) for x in case["evidence"]) if case["evidence"] else "<p>(none recorded)</p>")
    parts.append("<h2>Indicators of compromise (defanged)</h2>")
    items = list(_ioc_items(case))
    parts.append("<table><tr><th>Type</th><th>Indicator</th></tr>%s</table>" % "".join("<tr><td>%s</td><td><code>%s</code></td></tr>" % (e(k), e(v)) for k, v in items) if items else "<p>(none recorded)</p>")
    parts.append("<h2>MITRE ATT&amp;CK mapping</h2>")
    if case["attack"]:
        rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(a["technique_id"]), e(a["name"]), e(str(a.get("tactics", ""))), e(a.get("why", ""))) for a in case["attack"])
        parts.append("<table><tr><th>Technique</th><th>Name</th><th>Tactic(s)</th><th>Why</th></tr>%s</table>" % rows)
    else:
        parts.append("<p>(none recorded)</p>")
    parts.append("<h2>Timeline</h2>")
    if case["timeline"]:
        rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(r.get("timestamp", "")), e(r.get("message", "")), e(r.get("marker", ""))) for r in case["timeline"][:MAX_TIMELINE_ROWS])
        parts.append("<table><tr><th>Time (UTC)</th><th>Event</th><th>Note</th></tr>%s</table>" % rows)
    else:
        parts.append("<p>(none recorded)</p>")
    parts.append("<h2>Recommended next steps</h2><ol>%s</ol>" % "".join("<li>%s</li>" % e(s) for s in recommended_steps(case)))
    parts.append("<hr><p><small>Generated by soc-triage-toolkit. %s</small></p></body></html>" % e(case.get("notice", "")))
    return "\n".join(parts)
