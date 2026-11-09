import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from logtriage.__main__ import load_rules
from logtriage.analyze import analyze
from logtriage.private import read_json
from logtriage.settings import load_settings, save_settings
from logtriage.store import Store, atomic_json
from logtriage.web import WebApplication, WebServer, certificate


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {"WEB_PASSWORD": "test-only-password", "IMAP_USER": "logs@example.com", "IMAP_PASSWORD": "private-imap-secret"})
        self.env.start()
        self.app = WebApplication(self.directory, "http://127.0.0.1:8448", False)
        self.server = WebServer(("127.0.0.1", 0), self.app)
        self.port = self.server.server_port
        self.origin = f"http://127.0.0.1:{self.port}"
        self.app.public_url = self.origin
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = "", ""

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.env.stop()
        self.tmp.cleanup()

    def request(self, path, body=None, csrf=True, origin=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Cookie": self.cookie}
        if origin: headers["Origin"] = self.origin
        if csrf: headers["X-CSRF-Token"] = self.csrf
        if body is not None: headers["Content-Type"] = "application/json"
        connection.request("POST" if body is not None else "GET", path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        data, response_headers = response.read(), dict(response.getheaders())
        status = response.status
        connection.close()
        return status, json.loads(data) if response_headers["Content-Type"].startswith("application/json") else data, response_headers

    def login(self):
        status, result, headers = self.request("/api/login", {"username": "admin", "password": "test-only-password"})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].split(";")[0]
        self.csrf = result["csrf"]
        return headers

    def fixture(self):
        message = EmailMessage()
        message["Subject"] = "[NAS] Le planificateur de tâches a terminé une tâche planifiée"
        message["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")
        message.set_content("Tâche : backup\nÉtat actuel : 127\nDurée : 10 minutes\nDe NAS")
        store = Store(self.directory)
        store.put("test-ref", "test", analyze(message.as_bytes(), load_rules()))
        store.export()
        store.close()
        atomic_json(self.directory / "status.json", {"state": "ok", "last_cycle_at": datetime.now(timezone.utc).isoformat(), "poll_seconds": 300})
        save_settings(self.directory, {"recipient": "recipient@example.com", "sender": "logs@example.com", "smtp_host": "smtp.example.com"})

    def wait_job(self):
        deadline = time.monotonic() + 5
        while self.app.reports.job["state"] == "running" and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertNotEqual(self.app.reports.job["state"], "running")

    def test_magnifier_loads_the_summary_and_body_facts_only_after_login(self):
        self.fixture()
        row, = read_json(self.directory / "exports/checks.json")["items"]
        path = "/api/check-detail/" + row["detail_id"]
        self.assertEqual(self.request(path)[0], 401)
        self.login()
        self.assertNotIn("detail", self.request("/api/state")[1]["checks"][0])
        status, mail, _ = self.request(path)
        self.assertEqual(status, 200)
        self.assertIn("backup", mail["summary"])
        self.assertIn("État actuel : 127", mail["points"])
        self.assertIn("Durée : 10 minutes", mail["points"])
        self.assertIn("planificateur", mail["subject"])
        self.assertEqual(self.request("/api/check-detail/absent")[0], 404)

    def test_client_directory_migrates_assignments_and_keeps_clients_without_checks(self):
        from logtriage.private import write_private
        write_private(self.directory / "private/monitoring.json",
                      {"schedules": [], "rules": [], "assignments": [{"client": "Alpha", "source": []}]})
        self.assertEqual(self.request("/api/clients/create", {"name":"Beta"})[0], 401)
        self.login()
        self.assertEqual(self.request("/api/state")[1]["clients"], ["Alpha"])
        self.assertEqual(self.request("/api/clients/create", {"name":" Beta "})[1]["clients"], ["Alpha", "Beta"])
        self.assertEqual(self.request("/api/clients/create", {"name":"bEtA"})[0], 400)
        self.assertEqual(self.request("/api/clients/create", {"name":"  "})[0], 400)
        self.assertEqual(self.request("/api/assignments/preview", {"client":"Inconnu"})[0], 400)
        self.assertEqual(read_json(self.directory / "private/clients.json"), ["Alpha","Beta"])

    def test_private_data_requires_login_and_cookie_is_protected(self):
        self.assertEqual(self.request("/api/state")[0], 401)
        headers = self.login()
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        _, state, headers = self.request("/api/state")
        self.assertNotIn("private-imap-secret", json.dumps(state))
        self.assertNotIn("test-only-password", json.dumps(state))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_csrf_and_origin_are_required_before_mutation(self):
        self.login()
        self.assertEqual(self.request("/api/settings", {"max_groups": 48}, csrf=False)[0], 403)
        self.assertEqual(self.request("/api/settings", {"max_groups": 48}, origin=False)[0], 403)
        self.assertEqual(load_settings(self.directory)["max_groups"], 20)

    def test_settings_validation_and_persistence(self):
        self.login()
        self.assertEqual(self.request("/api/settings", {"max_groups": 48, "poll_seconds": 60})[0], 200)
        self.assertEqual(load_settings(self.directory)["max_groups"], 48)
        self.assertEqual(self.request("/api/settings", {"poll_seconds": 0})[0], 400)
        self.assertEqual(self.request("/api/settings", {"recipient": "r@example.com\nBcc: other@example.com"})[0], 400)
        self.assertEqual(self.request("/api/settings", {"imap_password": "new"})[0], 400)
        self.assertEqual((self.directory / "private/settings.json").stat().st_mode & 0o777, 0o600)

    def test_preview_is_network_free_and_failed_ai_keeps_canonical_facts(self):
        self.fixture()
        self.login()
        with patch("logtriage.report.smtplib.SMTP_SSL") as smtp, patch.object(self.app.chatgpt.transport, "response") as ai:
            self.assertEqual(self.request("/api/preview", {"use_ai": True})[0], 202)
            self.wait_job()
            smtp.assert_not_called()
            ai.assert_not_called()
        preview = self.app.reports.state()["preview"]
        self.assertIn("code 127", preview["body"])
        self.assertEqual(preview["ai"]["state"], "fallback")
        self.assertEqual(preview["delivery"], "not_sent")

    def test_unknown_review_requires_both_saved_opt_in_and_ai_preview(self):
        self.fixture()
        self.assertFalse(load_settings(self.directory)["ai_review_unknown"])
        save_settings(self.directory, {"ai_enabled": True, "ai_model": "test"})
        with patch.object(self.app.chatgpt, "cached_models", return_value=[{"slug": "test"}]), patch(
                "logtriage.web_reports.ReportAgent.run", return_value=({}, {})), patch(
                "logtriage.web_reports.review_unknown", return_value=({}, "Couverture des formats inconnus")) as review:
            self.app.reports._preview(True)
            save_settings(self.directory, {"ai_review_unknown": True})
            self.app.reports._preview(False)
            review.assert_not_called()
            self.app.reports._preview(True)
            review.assert_called_once()
            self.assertIn("Couverture des formats inconnus", self.app.reports.state()["preview"]["body"])

    def test_send_uses_reviewed_preview_once_and_rejects_changed_settings(self):
        self.fixture()
        self.login()
        self.request("/api/preview", {"use_ai": False})
        self.wait_job()
        identity = self.app.reports.state()["preview"]["id"]
        save_settings(self.directory, {"recipient": "changed@example.com"})
        with patch("logtriage.web_reports.send_report") as smtp:
            self.request("/api/send", {"id": identity})
            self.wait_job()
            smtp.assert_not_called()
        self.assertEqual(self.app.reports.job["state"], "error")
        self.request("/api/preview", {"use_ai": False})
        self.wait_job()
        preview = self.app.reports.state()["preview"]
        with patch("logtriage.web_reports.smtp_credentials", return_value=("user", "secret")), patch("logtriage.web_reports.send_report") as smtp:
            self.request("/api/send", {"id": preview["id"]})
            self.wait_job()
            self.assertEqual(smtp.call_count, 1)
            self.assertEqual(smtp.call_args.args[0].get_content(), preview["body"])
            self.assertEqual(self.request("/api/send", {"id": preview["id"]})[0], 400)

    def test_yesterdays_preview_is_hidden_and_cannot_be_sent(self):
        self.fixture()
        self.app.reports._preview(False)
        preview = self.app.reports.state()["preview"]
        with patch.object(self.app.reports, "report_day", return_value="2099-01-01"):
            self.assertIsNone(self.app.reports.state()["preview"])
            with self.assertRaisesRegex(ValueError, "journée en cours"):
                self.app.reports._send(preview["id"])

    def test_bulk_resolution_is_atomic_idempotent_and_only_affects_checked_rows(self):
        self.fixture()
        store = Store(self.directory)
        try:
            for name in ("archives", "certificats"):
                mail = EmailMessage()
                mail["Subject"] = "[NAS] Le planificateur de tâches a terminé une tâche planifiée"
                mail["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")
                mail.set_content(f"Tâche : {name}\nÉtat actuel : 127\nDe NAS")
                store.put(name, "test", analyze(mail.as_bytes(), load_rules()))
            store.export()
        finally:
            store.close()
        self.login()
        ids = [row["id"] for row in self.request("/api/state")[1]["incidents"]]
        self.assertEqual(len(ids), 3)
        for invalid in ([], ids[0], [ids[0], False], [ids[0], "0" * 64]):
            self.assertEqual(self.request("/api/resolve", {"ids": invalid})[0], 400)
        self.assertEqual(self.request("/api/state")[1]["summary"]["resolution_count"], 0)
        for _ in range(2):
            self.assertEqual(self.request("/api/resolve", {"ids": [ids[0], ids[1], ids[0]]})[0], 200)
        state = self.request("/api/state")[1]
        self.assertEqual([row["id"] for row in state["incidents"]], ids[2:])
        self.assertEqual(state["summary"]["resolution_count"], 2)

    def test_manual_resolution_updates_bilan_preview_and_blocks_old_send(self):
        self.fixture()
        self.login()
        item = self.request("/api/state")[1]["incidents"][0]
        self.app.reports._preview(False)
        old_id = self.app.reports.state()["preview"]["id"]
        self.assertEqual(self.request("/api/resolve", {"id": item["id"]}, csrf=False)[0], 403)
        self.assertEqual(self.request("/api/resolve", {"id": "0" * 64})[0], 400)
        self.assertEqual(self.request("/api/resolve", {"id": item["id"]})[0], 200)
        self.assertEqual(self.request("/api/resolve", {"id": item["id"]})[0], 200)
        state = self.request("/api/state")[1]
        self.assertEqual(state["incidents"], [])
        self.assertEqual(state["summary"]["resolution_count"], 1)
        self.assertIn("Validé manuellement", state["latest_digest"])
        with self.assertRaisesRegex(ValueError, "depuis cet aperçu"):
            self.app.reports._send(old_id)
        self.app.reports._preview(False)
        self.assertIn("Validé manuellement", self.app.reports.state()["preview"]["body"])

    def test_static_pages_never_serve_private_files(self):
        self.assertEqual(self.request("/")[0], 200)
        self.assertIn(b"Envoyer un rapport", self.request("/")[1])
        self.login()
        self.assertEqual(self.request("/private/web-auth.json")[0], 404)
        self.assertEqual(self.request("/../private/web-auth.json")[0], 404)

    def test_certificate_names_and_private_key_permissions(self):
        from cryptography import x509
        cert, key = certificate(self.directory, "https://192.0.2.10:8448")
        value = x509.load_pem_x509_certificate(cert.read_bytes())
        names = value.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("192.0.2.10", [str(v) for v in names.get_values_for_type(x509.IPAddress)])
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
