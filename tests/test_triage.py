import json
import copy
import os
import tempfile
import unittest
from unittest.mock import patch
from email.message import EmailMessage
from pathlib import Path

from logtriage.__main__ import Config, load_rules
from logtriage.analyze import analyze
from logtriage.collector import poll
from logtriage.store import Store


class ConfigurationTests(unittest.TestCase):
    def test_portainer_environment_password(self):
        with patch.dict(os.environ, {"IMAP_HOST": "imap.test", "IMAP_USER": "logs@test",
                                     "IMAP_PASSWORD": "test-$-literal with spaces "}, clear=True):
            config = Config.load()
        self.assertEqual(config.password, "test-$-literal with spaces ")
        self.assertEqual(config.port, 993)

    def test_explicit_secret_file_has_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "password"
            path.write_text("file-password\n")
            with patch.dict(os.environ, {"IMAP_HOST": "imap.test", "IMAP_USER": "logs@test",
                                         "IMAP_PASSWORD": "environment-password",
                                         "IMAP_PASSWORD_FILE": str(path)}, clear=True):
                self.assertEqual(Config.load().password, "file-password")

    def test_missing_explicit_file_does_not_fall_back_to_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"IMAP_HOST": "imap.test", "IMAP_USER": "logs@test",
                                         "IMAP_PASSWORD": "environment-password",
                                         "IMAP_PASSWORD_FILE": str(Path(tmp) / "missing")}, clear=True):
                with self.assertRaises(FileNotFoundError):
                    Config.load()

    def test_empty_password_is_rejected(self):
        with patch.dict(os.environ, {"IMAP_HOST": "imap.test", "IMAP_USER": "logs@test",
                                     "IMAP_PASSWORD": ""}, clear=True):
            with self.assertRaises(ValueError):
                Config.load()


def mail(subject, body, date="Mon, 09 Nov 2026 05:00:00 +0100", html=None, message_id="<test@example.com>"):
    m = EmailMessage()
    m["Subject"], m["From"], m["Date"], m["Message-ID"] = subject, "PBS <log@example.com>", date, message_id
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m.as_bytes()


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules()

    def test_scheduler_labels_and_zero_are_not_errors(self):
        raw = mail("[NAS] Le planificateur de tâches a terminé une tâche planifiée",
                   "Tâche : certs\nÉtat actuel : 0 (Normal)\nSortie/erreur standard :\nCertificat ignoré car pas plus récent.")
        self.assertEqual(analyze(raw, self.rules)["category"], "reussite_signalee")
        failed = raw.replace(b"0 (Normal)", b"1 (Failure)")
        self.assertEqual(analyze(failed, self.rules)["execution"], "failure")

    def test_failure_in_html_overrides_plain_success(self):
        raw = mail("La tâche Local backup a été effectuée avec succès sur NAS",
                   "Tâche de sauvegarde : Homes\nDe NAS",
                   html="<p>La tâche a rencontré une erreur.</p><p>De NAS</p>")
        self.assertEqual(analyze(raw, self.rules)["category"], "echec")

    def test_unknown_and_completion_do_not_close_incidents(self):
        self.assertEqual(analyze(mail("Bonjour", "Tout va bien"), self.rules)["category"], "a_verifier")
        raw = mail("Active Backup for Business - La tâche de sauvegarde VM sur NAS est terminée",
                   "La tâche de sauvegarde VM sur NAS est terminée.\nDe NAS")
        result = analyze(raw, self.rules)
        self.assertEqual(result["category"], "fin_annoncee")
        self.assertEqual(result["execution"], "completed")

    def test_wazuh_counts_are_not_doubled(self):
        raw = mail("Wazuh — Threat Hunting",
                   "host.example.com\n18 alerte(s) · niveau 13 · règle 100614\nVulnérabilité signalée\nagent.example.com — Déconnecté",
                   html="<table><tr><td>100614<br>Niveau 13</td><td>host.example.com<br>Vulnérabilité signalée</td><td>18</td></tr></table>")
        result = analyze(raw, self.rules)
        self.assertEqual(len(result["observations"]), 2)
        self.assertEqual(result["observations"][0]["occurrences"], 18)

    def test_wazuh_html_only_is_supported(self):
        raw = mail("Wazuh — Threat Hunting", "",
                   html="<table><tr><td>100614<br>Niveau 13</td><td>host.example.com<br>Vulnérabilité signalée</td><td>18</td></tr></table>")
        self.assertEqual(analyze(raw, self.rules)["observations"][0]["occurrences"], 18)

    def test_unreadable_pdf_is_visible(self):
        msg = EmailMessage()
        msg["Subject"] = "[OpenVAS] Scan terminé – test"
        msg.set_content("Aucune CVE ne répond aux critères de notification pour ce scan (score ≥ 4,0).")
        msg.add_attachment(b"not a pdf", maintype="application", subtype="pdf", filename="rapport.pdf")
        result = analyze(msg.as_bytes(), self.rules)
        self.assertEqual(result["category"], "a_verifier")
        self.assertTrue(any(x.startswith("pdf_incomplet:") for x in result["coverage_warnings"]))


class PersistenceTests(unittest.TestCase):
    def test_reimport_deduplication_and_chronological_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            try:
                rules = load_rules()
                error = analyze(mail("La tâche de sauvegarde Homes sur NAS a échoué",
                                     "La tâche de sauvegarde Homes a rencontré une erreur.\nDe NAS"), rules)
                success = analyze(mail("La tâche Local backup a été effectuée avec succès sur NAS",
                                       "Tâche de sauvegarde : Homes\nDe NAS", date="Tue, 10 Nov 2026 05:00:00 +0100"), rules)
                self.assertEqual(error["task_key"], success["task_key"])
                # Import dans l’ordre inverse : le dernier statut chronologique reste le succès.
                self.assertTrue(store.put("newer", "account", success))
                self.assertTrue(store.put("older", "account", error))
                self.assertFalse(store.put("another-reference", "account", error))
                store.export()
                tasks = json.loads((Path(tmp) / "exports/tasks.json").read_text())
                self.assertEqual(tasks[0]["state"], "resolved")
                self.assertEqual(len(tasks[0]["failures"]), 1)
                # Un message de même Message-ID mais contenu différent reste distinct.
                other = analyze(mail("La tâche de sauvegarde Homes sur NAS a échoué",
                                     "La tâche de sauvegarde Homes a rencontré une erreur.\nAutre cause\nDe NAS",
                                     date="Wed, 11 Nov 2026 05:00:00 +0100"), rules)
                self.assertTrue(store.put("latest", "account", other))
                self.assertEqual(store.export()["open_tasks"], 1)
            finally:
                store.close()

    def test_manual_closure_is_scoped_and_a_fresh_signal_reopens(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = analyze(mail("La tâche de sauvegarde VM sur NAS a échoué",
                                "La tâche de sauvegarde VM a rencontré une erreur.\nDe NAS"), load_rules())
            store = Store(tmp)
            for scope in ("first", "second"):
                store.put(scope, scope, base)
            store.export()
            def tasks():
                return {t["scope"]: t for t in json.loads((Path(tmp) / "exports/tasks.json").read_text())}
            signal = tasks()["first"]["signal_id"]
            store.export(resolve_signal=signal)
            store.close()
            store = Store(tmp)
            try:
                store.export()
                self.assertEqual(tasks()["first"]["resolved_by"], "manual")
                self.assertEqual(tasks()["second"]["state"], "open")
                store.put("new", "first", {**base, "date": "2026-11-15T00:00:00+00:00", "sha256": "next"})
                store.export(resolve_signal=signal)
                self.assertEqual(tasks()["first"]["state"], "open")
                self.assertEqual(tasks()["first"]["active_occurrences"], 1)
                current = tasks()["first"]["signal_id"]
                store.put("new2", "first", {**base, "date": "2026-11-15T00:00:00+00:00", "sha256": "another"})
                with self.assertRaisesRegex(ValueError, "a changé"):
                    store.export(resolve_signal=current)
            finally:
                store.close()

    def test_completion_does_not_resolve_and_scopes_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            try:
                base = analyze(mail("La tâche de sauvegarde VM sur NAS a échoué",
                                    "La tâche de sauvegarde VM a rencontré une erreur.\nDe NAS"), load_rules())
                store.put("1", "account1", base)
                completed = {**base, "sha256": "new", "execution": "completed", "date": "2026-11-10T00:00:00+00:00"}
                store.put("2", "account1", completed)
                success = {**completed, "sha256": "other", "execution": "success"}
                store.put("3", "account2", success)
                self.assertEqual(store.export()["open_tasks"], 1)
            finally:
                store.close()


class ReadOnlyIMAPTests(unittest.TestCase):
    def test_exact_protocol_calls_and_uidvalidity_deduplication(self):
        raw = mail("Rapport inconnu", "À vérifier")
        calls = []
        class FakeIMAP:
            validity = b"123"
            def __init__(self, host, port, ssl_context, timeout):
                self.ssl = ssl_context
            def __enter__(self): return self
            def __exit__(self, *args): calls.append("LOGOUT")
            def login(self, user, password): calls.append("LOGIN")
            def select(self, mailbox, readonly=False):
                if not readonly:
                    raise AssertionError("Ouverture en écriture interdite")
                calls.append(("EXAMINE", mailbox))
                return "OK", [b"1"]
            def response(self, name):
                self_name = name
                if self_name != "UIDVALIDITY": raise AssertionError(name)
                return "UIDVALIDITY", [self.validity]
            def uid(self, command, *args):
                calls.append((command, *args))
                if command == "SEARCH":
                    return "OK", [b"42"]
                if command == "FETCH" and args[1] == "(RFC822.SIZE)":
                    return "OK", [f"1 (RFC822.SIZE {len(raw)})".encode()]
                if command == "FETCH" and args[1] == "(UID BODY.PEEK[])":
                    return "OK", [(b"1 (UID 42 BODY[])", raw), b")"]
                raise AssertionError("Commande IMAP non autorisée : " + command)
        cfg = Config("imap.test", 993, "user", "secret", "Logs serveurs", 30, 300, 500, 1024**2, 30)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            try:
                self.assertEqual(poll(cfg, store, load_rules(), FakeIMAP)["new"], 1)
                self.assertEqual(poll(cfg, store, load_rules(), FakeIMAP)["new"], 0)
                FakeIMAP.validity = b"456"
                self.assertEqual(poll(cfg, store, load_rules(), FakeIMAP)["duplicate"], 1)
                self.assertEqual(store.export()["total_messages"], 1)
                # Une évolution de règle réanalyse l’email sans créer de doublon.
                changed_rules = copy.deepcopy(load_rules())
                changed_rules["wazuh"]["review_min_level"] = 13
                self.assertEqual(poll(cfg, store, changed_rules, FakeIMAP)["duplicate"], 1)
                self.assertEqual(store.export()["total_messages"], 1)
                self.assertIn(("EXAMINE", '"Logs serveurs"'), calls)
                self.assertTrue(any(c[0] == "FETCH" and c[2] == "(UID BODY.PEEK[])"
                                    for c in calls if isinstance(c, tuple)))
            finally:
                store.close()

    def test_oversized_message_is_not_downloaded(self):
        calls = []
        class FakeIMAP:
            def __init__(self, *args, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def login(self, *args): pass
            def select(self, *args, **kwargs): return "OK", [b"1"]
            def response(self, *args): return "UIDVALIDITY", [b"1"]
            def uid(self, command, *args):
                calls.append((command, *args))
                if command == "SEARCH": return "OK", [b"1"]
                if command == "FETCH" and args[1] == "(RFC822.SIZE)":
                    return "OK", [b"1 (RFC822.SIZE 999999)"]
                raise AssertionError("Le corps ne doit pas être téléchargé")
        cfg = Config("imap.test", 993, "user", "secret", "INBOX", 30, 300, 10, 1024, 30)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            try:
                stats = poll(cfg, store, load_rules(), FakeIMAP)
                self.assertEqual(stats["new"], 0)
                self.assertEqual(len(stats["skipped"]), 1)
                self.assertFalse(any("PEEK" in str(c) for c in calls))
            finally:
                store.close()


@unittest.skipUnless(os.environ.get("SAMPLE_EMAIL_DIR"), "Échantillon privé non fourni")
class PrivateSampleTests(unittest.TestCase):
    def test_ten_original_messages(self):
        directory = Path(os.environ["SAMPLE_EMAIL_DIR"])
        expected = json.loads((directory / "analyse/classement-exemples.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            try:
                for item in expected["messages"]:
                    result = analyze((directory / item["fichier_source"]).read_bytes(), load_rules())
                    self.assertEqual(result["category"], item["categorie_proposee"], item["objet"])
                    store.put(item["fichier_source"], "offline", result)
                summary = store.export()
                self.assertEqual(summary["total_messages"], 10)
                self.assertEqual(summary["open_tasks"], 2)
                self.assertEqual(summary["observation_groups"], 7)
                self.assertEqual(summary["categories"], expected["comptage"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
