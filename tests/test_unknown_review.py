import hashlib
import json
import unittest
from datetime import datetime, timezone
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock, patch

from logtriage.collector import mailbox_scope
from logtriage.digest import render_digest
from logtriage.openai_http import OpenAIError
from logtriage.unknown_review import extract_sample, read_samples, review_unknown, validate


class UnknownReviewTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
        self.config = SimpleNamespace(host="imap.example.test", port=993, user="tester", password="x",
                                      folder="INBOX", max_bytes=20000, timeout=5)
        self.scope = mailbox_scope(self.config)
        mail = EmailMessage()
        mail["Subject"] = "Avis équipement"
        mail.set_content("Ventilateur arrêté\nAuthorization: Bearer private-value\nhttps://example.test/sensitive")
        mail.add_attachment(b"private attachment", maintype="application", subtype="octet-stream", filename="secret.bin")
        self.raw = mail.as_bytes()
        self.message = {"scope": self.scope, "sha256": hashlib.sha256(self.raw).hexdigest(), "recognized": False,
                        "category": "a_verifier", "subject": str(mail["Subject"]), "observations": [],
                        "date": self.now.isoformat(), "coverage_warnings": [], "references": [self.scope + "|INBOX|1|42"]}
        self.sample = extract_sample(self.raw, self.message)

    def reply(self, verdict="signal", quote="Ventilateur arrêté"):
        findings = [{"summary": "Ventilation interrompue", "quote": quote}] if verdict == "signal" else []
        return json.dumps({"reviews": [{"id": self.message["sha256"], "verdict": verdict, "findings": findings}]})

    def test_only_text_is_shared_and_partial_routine_cannot_hide_message(self):
        self.assertNotIn("private", json.dumps(self.sample))
        self.assertNotIn("example.test", json.dumps(self.sample))
        self.assertFalse(self.sample["complete"])
        key = self.message["sha256"]
        self.assertEqual(validate(self.reply("routine"), [self.sample])[key]["verdict"], "incertain")
        result = validate(self.reply("routine"), [{**self.sample, "complete": True}])
        text = render_digest({"total_messages": 1}, [self.message], [], [], current_time=self.now, unknown_reviews=result)
        self.assertNotIn(self.message["subject"], text)

    def test_invalid_evidence_or_missing_identity_rejects_batch(self):
        for reply in (self.reply(quote="Tout fonctionne"), '{"reviews":[]}', self.reply().replace(self.sample["id"], "fake")):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                validate(reply, [self.sample])

    def test_read_checks_account_validity_uid_and_hash(self):
        factory = MagicMock()
        client = factory.return_value.__enter__.return_value
        client.select.return_value = ("OK", [])
        client.response.return_value = ("UIDVALIDITY", [b"1"])
        client.uid.return_value = ("OK", [(b"meta", self.raw)])
        self.assertEqual(read_samples([self.message], self.config, factory), [self.sample])
        client.select.assert_called_once_with('"INBOX"', readonly=True)
        client.uid.assert_called_once_with("FETCH", "42", "(UID BODY.PEEK[]<0.20001>)")
        client.uid.reset_mock()
        wrong_box = {**self.message, "scope": "other"}
        stale = {**self.message, "references": [self.scope + "|INBOX|2|42"]}
        self.assertEqual(read_samples([wrong_box, stale], self.config, factory), [])
        client.uid.assert_not_called()
        client.uid.return_value = ("OK", [(b"meta", self.raw + b"different")])
        self.assertEqual(read_samples([self.message], self.config, factory), [])

    def test_findings_reach_report_only_for_current_unknowns_and_fallback_is_visible(self):
        chat = Mock()
        chat.transport.response.return_value = {"output": [{"type": "message", "content": [
            {"type": "output_text", "text": self.reply()}]}]}
        inputs = [self.message, {**self.message, "recognized": True, "sha256": "recognized"},
                  {**self.message, "date": "2026-11-08T22:59:59+00:00", "sha256": "old"}]
        with patch("logtriage.unknown_review.read_samples", return_value=[self.sample]) as read, patch(
                "logtriage.unknown_review.Config.load", return_value=self.config):
            reviews, coverage = review_unknown(chat, "model", inputs, "Europe/Zurich", self.now, "profile")
            read.assert_called_once_with([self.message], self.config)
            report = render_digest({"total_messages": 1}, [self.message], [], [], current_time=self.now, unknown_reviews=reviews)
            self.assertIn("Repéré par l’IA", report)
            self.assertIn("Ventilateur arrêté", report)
            self.assertIn("Ventilation interrompue", report)
            self.assertIn("1/1", coverage)
            self.assertNotIn("tools", chat.transport.response.call_args.args[1])
            chat.transport.response.side_effect = OpenAIError("usage_limit")
            reviews, coverage = review_unknown(chat, "model", inputs, "Europe/Zurich", self.now, "profile")
            self.assertEqual(reviews, {})
            self.assertIn("1 à vérifier", coverage)
            report = render_digest({"total_messages": 1}, [self.message], [], [], current_time=self.now, unknown_reviews=reviews)
            self.assertIn("À VÉRIFIER", report)
