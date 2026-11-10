import tempfile
import unittest
from pathlib import Path

from soc_common.validation import ToolError
from tests.helpers import DATA, run_cli
from tools.log_parser.cli import main
from tools.log_parser.core import detect_format, parse_auth_line, parse_firewall_line, parse_files, parse_lines, parse_web_line


class LineParsers(unittest.TestCase):
    def test_failed_ssh_login(self):
        ev = parse_auth_line("Oct 28 02:14:03 web01 sshd[1234]: Failed password for invalid user test from 203.0.113.45 port 51122 ssh2", 2026)
        self.assertEqual((ev.user, ev.src_ip, ev.action, ev.outcome), ("test", "203.0.113.45", "ssh_login", "failure"))
        self.assertTrue(ev.extra["invalid_user"])
        self.assertEqual(ev.timestamp.year, 2026)

    def test_accepted_login_and_sudo(self):
        ok = parse_auth_line("Oct 28 02:17:28 web01 sshd[9]: Accepted password for deploy from 203.0.113.45 port 4000 ssh2", 2026)
        self.assertEqual(ok.outcome, "success")
        sudo = parse_auth_line("Oct 28 02:19:05 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash /tmp/x.sh", 2026)
        self.assertEqual((sudo.action, sudo.user), ("sudo", "deploy"))
        self.assertIn("/tmp/x.sh", sudo.extra["command"])

    def test_web_line_and_login_detection(self):
        line = '203.0.113.5 - - [28/Oct/2026:03:10:01 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "curl/8.0"'
        ev = parse_web_line(line)
        self.assertEqual((ev.action, ev.outcome, ev.extra["status"]), ("web_login", "failure", 401))
        page = parse_web_line('10.0.0.2 - - [28/Oct/2026:03:10:01 +0000] "GET /about HTTP/1.1" 200 10 "-" "x"')
        self.assertEqual((page.action, page.outcome), ("http_request", "success"))

    def test_firewall_line(self):
        ev = parse_firewall_line("2026-10-28T02:21:03Z host=fw01 action=ALLOW dir=OUT proto=TCP src=10.0.0.5 sport=4000 dst=198.51.100.77 dport=4444")
        self.assertEqual((ev.outcome, ev.dst_ip, ev.extra["dport"], ev.extra["direction"]), ("allow", "198.51.100.77", 4444, "OUT"))

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_auth_line("this is not a log line", 2026))
        self.assertIsNone(parse_web_line("nope"))
        self.assertIsNone(parse_firewall_line("2026-10-28T02:21:03Z nothing useful"))

    def test_detect_format(self):
        self.assertEqual(detect_format("2026-10-28T02:21:03Z action=DENY src=1.2.3.4"), "firewall")
        self.assertEqual(detect_format('1.2.3.4 - - [28/Oct/2026:03:10:01 +0000] "GET / HTTP/1.1" 200 1'), "web")
        self.assertEqual(detect_format("Oct 28 02:14:03 web01 sshd[1]: hi"), "auth")
        self.assertIsNone(detect_format("???"))


class FileParsing(unittest.TestCase):
    def test_sample_files_parse_without_skips(self):
        result = parse_files([DATA / "auth.log", DATA / "webserver_access.log", DATA / "firewall.log"], "auto", 2026)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.by_source, {"auth": 75, "web": 41, "firewall": 35})
        stamps = [e.timestamp for e in result.events]
        self.assertEqual(stamps, sorted(stamps))

    def test_skipped_and_comment_counts(self):
        result = parse_lines(["# comment", "", "garbage line", "Oct 28 02:17:28 web01 sshd[9]: Accepted password for a from 1.2.3.4 port 1 ssh2"], "auto", 2026)
        self.assertEqual((len(result.events), result.skipped, result.comments), (1, 1, 2))

    def test_bad_format_name(self):
        with self.assertRaises(ToolError):
            parse_lines(["x"], "syslog")


class Cli(unittest.TestCase):
    def test_cli_writes_jsonl_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "events.jsonl"
            code, text, _ = run_cli(main, [str(DATA / "auth.log"), "--year", "2026", "--output", str(out)])
            self.assertEqual(code, 0)
            self.assertIn("auth=75", text)
            self.assertEqual(len(out.read_text().splitlines()), 75)
            csv_out = Path(tmp) / "events.csv"
            run_cli(main, [str(DATA / "auth.log"), "--year", "2026", "--output", str(csv_out)])
            self.assertTrue(csv_out.read_text().startswith("timestamp,source"))

    def test_missing_file_is_a_clean_error(self):
        code, _, err = run_cli(main, ["/no/such/file.log"])
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("error: file not found"))


if __name__ == "__main__":
    unittest.main()
