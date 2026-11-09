import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from logtriage.report import main, prepare_report, send_report, smtp_credentials


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        (self.directory / "exports").mkdir()
        self.time = datetime.now(timezone.utc)
        (self.directory / "exports/summary.json").write_text(json.dumps({"total_messages": 42, "generated_at": self.time.isoformat()}))
        (self.directory / "status.json").write_text(json.dumps({"state": "ok", "last_cycle_at": self.time.isoformat(), "poll_seconds": 300}))
        (self.directory / "exports/bilan.txt").write_text("Mode : lecture seule, aucun envoi\nÉchec de sauvegarde exemple\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_actual_report_is_used_with_single_explicit_recipient(self):
        msg = prepare_report(self.directory, "recipient@example.com", "logs@example.com", self.time)
        self.assertIn("Échec de sauvegarde exemple", msg.get_content())
        self.assertIn("rapport envoyé à la demande", msg.get_content())
        self.assertEqual(str(msg["To"]), "recipient@example.com")
        self.assertNotIn("aucun envoi", msg.get_content())

    def test_stale_or_incomplete_report_is_labelled(self):
        msg = prepare_report(self.directory, "r@example.com", "s@example.com", self.time + timedelta(hours=2))
        self.assertIn("ce bilan est ancien", msg.get_content())
        (self.directory / "status.json").write_text(json.dumps({"state": "error", "last_cycle_at": self.time.isoformat(), "collection": {"pending": 7}}))
        msg = prepare_report(self.directory, "r@example.com", "s@example.com", self.time)
        self.assertIn("en erreur ou incomplète", msg.get_content())
        self.assertIn("7 message(s)", msg.get_content())

    def test_missing_live_status_prevents_sending_sample_data(self):
        (self.directory / "status.json").unlink()
        with self.assertRaises(FileNotFoundError):
            prepare_report(self.directory, "r@example.com", "s@example.com")

    def test_tls_authentication_precedes_single_send(self):
        calls = []
        class SMTP:
            def __init__(self, host, port, timeout, context):
                self_test.assertEqual(host, "smtp.example.com")
                self_test.assertEqual(port, 465)
                self_test.assertTrue(context.check_hostname)
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def login(self, user, password): calls.append("login")
            def send_message(self, msg, from_addr, to_addrs):
                self_test.assertEqual(to_addrs, ["recipient@example.com"])
                calls.append("send")
                return {}
        self_test = self
        msg = prepare_report(self.directory, "recipient@example.com", "logs@example.com", self.time)
        send_report(msg, "smtp.example.com", 465, "user", "password", SMTP)
        self.assertEqual(calls, ["login", "send"])
        self.assertIsNotNone(msg.get_body(preferencelist=("html",)))
        self.assertIn("Échec de sauvegarde exemple", msg.get_body(preferencelist=("plain",)).get_content())

    def test_html_escapes_untrusted_log_content(self):
        from logtriage.report import report_html
        html = report_html("À EXAMINER EN PRIORITÉ\n- <img src=x> panne")
        self.assertIn("<h2", html)
        self.assertIn("&lt;img src=x&gt;", html)
        self.assertNotIn("<img", html)

    def test_preview_makes_no_network_connection(self):
        with patch.dict("os.environ", {"DATA_DIR": str(self.directory), "SMTP_USER": "logs@example.com"}, clear=True):
            with patch("smtplib.SMTP_SSL") as smtp, patch("builtins.print"):
                self.assertEqual(main(["--to", "recipient@example.com", "--preview"]), 0)
                smtp.assert_not_called()
        self.assertFalse((self.directory / "last-report-send.json").exists())

    def test_no_implicit_reuse_of_imap_credentials(self):
        with patch.dict("os.environ", {"IMAP_USER": "logs@example.com", "IMAP_PASSWORD": "secret"}, clear=True):
            with self.assertRaises(ValueError):
                smtp_credentials(False)


if __name__ == "__main__":
    unittest.main()
