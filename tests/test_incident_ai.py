import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from logtriage.incident_ai import IncidentAnalyst, annotations
from logtriage.private import read_json
from logtriage.settings import load_settings, save_settings
from logtriage.store import atomic_json


class IncidentAnalysis(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.chat = Mock()
        self.account = {"active": "profile-a", "connected": True}
        self.chat.state.return_value = self.account
        self.chat.cached_models.return_value = [{"slug": "test-model"}]
        self.analyst = IncidentAnalyst(self.root, self.chat)
        self.row = {"id": "signal", "severity": "open", "client": "example.org"}
        self.open_path = self.root / "exports/open-incidents.json"
        atomic_json(self.open_path, [self.row])
        self.task = {"signal_id": "signal", "key": "backup|NAS|homes", "state": "open",
                     "summary": "Sauvegarde en échec", "evidence": ["Le volume cible est inaccessible", "password=private-test"],
                     "active_occurrences": 2, "failures": [{"secret": "never-send-history"}]}
        atomic_json(self.root / "exports/tasks.json", [self.task])
        self.note = {"constat": "La sauvegarde ne peut pas atteindre le volume cible.",
                     "preuve": "volume cible est inaccessible", "verification": "Vérifie si le volume cible est monté."}
        self.configure()
        self.response(self.note)

    def configure(self, **updates):
        return save_settings(self.root, {"ai_model": "test-model", "ai_enabled": True, "ai_incidents": True, **updates})

    def response(self, note):
        self.chat.transport.response.return_value = {"output": [{"type":"message", "content":[
            {"type":"output_text", "text":json.dumps(note, ensure_ascii=False)}]}]}

    def visible(self):
        return annotations(self.root, load_settings(self.root), self.account, [dict(self.row)])[0]

    def test_annotation_cached_and_rules_untouched(self):
        self.assertTrue(self.analyst.run_one())
        self.assertFalse(self.analyst.run_one())
        self.chat.transport.response.assert_called_once()
        payload = self.chat.transport.response.call_args.args[1]
        self.assertFalse(payload["store"])
        self.assertNotIn("tools", payload)
        self.assertNotIn("private-test", str(payload))
        self.assertNotIn("never-send-history", str(payload))
        self.assertEqual(self.visible()["analysis"], {"state":"ready", **self.note})
        self.assertEqual(read_json(self.open_path), [self.row])
        self.assertEqual(read_json(self.root / "exports/tasks.json"), [self.task])
        self.account["active"] = "another-profile"
        self.assertEqual(self.visible()["analysis"]["state"], "pending")

    def test_no_opt_in_no_analysis_and_no_routine_email_sent(self):
        self.configure(ai_incidents=False)
        self.assertFalse(self.analyst.run_one())
        self.assertNotIn("analysis", self.visible())
        self.configure()
        atomic_json(self.open_path, [])
        self.assertFalse(self.analyst.run_one())
        self.chat.transport.response.assert_not_called()

    def test_refuses_invented_evidence_and_defers_retry(self):
        self.response({**self.note, "preuve": "Disque physiquement détruit"})
        self.assertTrue(self.analyst.run_one())
        self.assertFalse(self.analyst.run_one())
        self.assertEqual(self.visible()["analysis"]["state"], "error")
        self.assertEqual(self.visible()["severity"], "open")

    def test_resolution_while_analyzing_discards_answer(self):
        def resolve(*args):
            atomic_json(self.open_path, [])
            return self.chat.transport.response.return_value
        self.chat.transport.response.side_effect = resolve
        self.analyst.run_one()
        self.assertFalse(self.analyst.path.exists())
