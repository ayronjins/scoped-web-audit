import argparse
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "audit_web.py"
spec = importlib.util.spec_from_file_location("audit_web", SCRIPT)
audit_web = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit_web
spec.loader.exec_module(audit_web)
SCOPE = ("--scope-note", "Written authorization ticket DEMO-001")

class AuditWebCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)

    def test_help_is_available(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("authorized", result.stdout.lower())

    def test_authorization_is_required(self):
        result = self.run_cli("https://example.com", *SCOPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("authorization", result.stderr.lower())

    def test_scope_reference_is_required(self):
        result = self.run_cli("https://example.com", "--authorized", "--plan")
        self.assertEqual(result.returncode, 2)
        self.assertIn("scope", result.stderr.lower())

    def test_non_http_target_is_rejected(self):
        result = self.run_cli("file:///etc/passwd", "--authorized", *SCOPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("http", result.stderr.lower())

    def test_query_and_fragment_are_rejected(self):
        for target in ("https://example.com/?token=secret", "https://example.com/#private"):
            result = self.run_cli(target, "--authorized", *SCOPE, "--plan")
            self.assertEqual(result.returncode, 2)
            self.assertIn("query", result.stderr.lower())

    def test_option_like_hostname_is_rejected(self):
        result = self.run_cli("http://--script=foo/", "--authorized", *SCOPE, "--plan")
        self.assertEqual(result.returncode, 2)
        self.assertIn("hostname", result.stderr.lower())

    def test_malformed_port_is_rejected(self):
        result = self.run_cli("https://example.com:notaport/", "--authorized", *SCOPE, "--plan")
        self.assertEqual(result.returncode, 2)
        self.assertIn("port", result.stderr.lower())

    def test_passive_plan_is_exact_url_and_bounded(self):
        result = self.run_cli("https://example.com/path", "--authorized", *SCOPE, "--plan")
        self.assertEqual(result.returncode, 0)
        text = result.stdout.lower()
        self.assertIn("zero redirects", text)
        self.assertIn("256 kib", text)
        self.assertIn("one request", text)
        self.assertNotIn("nikto", text)
        self.assertNotIn("nmap", text)

    def test_safe_mode_requires_separate_host_scan_permission(self):
        result = self.run_cli("https://example.com", "--authorized", *SCOPE, "--mode", "safe", "--plan")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allow-host-scan", result.stderr.lower())

    def test_safe_plan_is_one_exact_port_probe(self):
        result = self.run_cli("https://example.com:4443/", "--authorized", *SCOPE, "--mode", "safe", "--allow-host-scan", "--plan")
        self.assertEqual(result.returncode, 0)
        text = result.stdout.lower()
        self.assertIn("single authorized port 4443", text)
        self.assertNotIn("nikto", text)
        self.assertNotIn("testssl", text)

    def test_nonzero_tool_exit_is_reported_as_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "tool.log"
            result = audit_web.run([sys.executable, "-c", "raise SystemExit(7)"], output, 5)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 7)

    def test_command_builders_enforce_network_bounds(self):
        args = argparse.Namespace(target="https://example.com/path", mode="passive", allow_host_scan=False)
        parsed = audit_web.parse_and_validate_target(args.target)
        with tempfile.TemporaryDirectory() as temp:
            commands = audit_web.build_commands(args, parsed, Path(temp))
        by_tool = {item[0][0]: item[0] for item in commands}
        curl = by_tool["curl"]
        self.assertNotIn("--location", curl)
        self.assertIn("--max-filesize", curl)
        self.assertIn("262144", curl)
        whatweb = by_tool["whatweb"]
        self.assertIn("--max-threads=1", whatweb)
        self.assertIn("--follow-redirect=never", whatweb)
        self.assertIn("--max-redirects=0", whatweb)
        self.assertIn("--aggression=1", whatweb)

if __name__ == "__main__":
    unittest.main()
