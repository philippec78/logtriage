from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from logtriage.__main__ import load_rules
from logtriage.analyze import analyze
from logtriage.digest import derive_state, render_digest
from logtriage.monitoring import change, identity, policy, schedule_events
from logtriage.private import read_json
from logtriage.store import Store
from logtriage.user_rules import activate, apply_rules, matched_body, simulate


UTC = timezone.utc
ZONE = "Europe/Zurich"


def at(day, hour):
    return datetime(2026, 11, day, hour, tzinfo=UTC)


def mail(subject, stamp, execution=None, scope="imap:one"):
    raw = f"From: Backup <logs@example.org>\nSubject: {subject}\nDate: {stamp:%a, %d %b %Y %H:%M:%S +0000}\n\nTexte."
    m = analyze(raw.encode(), load_rules())
    m["scope"] = scope
    if execution:
        m.update(task_key="backup|nas|homes", execution=execution, recognized=True, summary=subject)
    return m


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.row = {"id": "abc", "client": "example.org", "key": "backup|nas|homes", "scope": "imap:one", "label": "NAS Homes",
                    "since": at(6, 11).isoformat(), "time": "07:00", "days": [0, 1, 2, 3, 4]}

    def events(self, now, mails=(), **updates):
        status = {"state": "ok", "scope": "imap:one", "last_cycle_at": now.isoformat(), **updates}
        return schedule_events([self.row], mails, status, now, ZONE)

    def test_old_sender_calendar_keeps_its_incident_after_becoming_unassigned(self):
        from logtriage.monitoring import bind_old_schedules, task_options
        from logtriage.private import private_dir, write_private
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_private(private_dir(directory) / "monitoring.json", {"schedules":[self.row], "rules":[]})
            options = task_options([{**self.row, "client":"@example.org"}])
            config = bind_old_schedules(directory, options, at(9, 7))
            row, = config["schedules"]
            self.assertEqual((row["event_id"], row["client"], row["since"]), ("abc", "@example.org", self.row["since"]))
            self.assertEqual(row["id"], options[0]["id"])
            self.assertEqual(bind_old_schedules(directory, options, at(9, 8)), config)

    def test_first_deadline_only_after_complete_collection(self):
        for moment in (at(6, 20), at(7, 22), at(9, 5)):
            self.assertEqual(self.events(moment), [])
        now = at(9, 7)
        for update in ({"state": "error"}, {"state": "degraded"}, {"collection": {"pending": 1}},
                       {"last_cycle_at": at(9, 6).isoformat()}, {"checked_through": at(9, 5).isoformat()},
                       {"scope": "imap:another"}):
            self.assertEqual(self.events(now, **update), [])
        self.assertEqual([e["execution"] for e in self.events(now)], ["warning"])

    def test_early_multi_task_failed_report_is_received_and_wrong_mailbox_is_ignored(self):
        now = at(9, 8)
        batch = mail("Batch", at(8, 20))
        batch.update(received_at=at(9, 6).isoformat(), task_events=[{"task_key": self.row["key"], "execution": "failure"}])
        self.assertEqual([e["execution"] for e in self.events(now, [batch])], ["success"])
        batch["scope"] = "imap:two"
        self.assertEqual([e["execution"] for e in self.events(now, [batch])], ["warning"])

    def test_late_failure_confirms_receipt_without_recovering_backup(self):
        now = at(9, 9)
        failed = mail("La sauvegarde a échoué", at(9, 8), "failure")
        events = self.events(now, [failed])
        tasks, _ = derive_state([failed, *events])
        self.assertEqual(tasks["imap:one|backup|nas|homes"]["state"], "open")
        missing = tasks["imap:one|missing|backup|nas|homes"]
        self.assertEqual(missing["resolved_at"], failed["date"])
        report = render_digest({}, [failed], list(tasks.values()), [], current_time=now)
        self.assertIn("Réception confirmée", report)

    def test_manual_closure_and_next_due_date(self):
        first = self.events(at(9, 8))
        task = next(iter(derive_state(first)[0].values()))
        closed = {task["signal_id"]: at(9, 9).isoformat()}
        state = derive_state(self.events(at(10, 8)), closed)[0]
        task = next(iter(state.values()))
        self.assertEqual(task["state"], "warning")
        self.assertEqual(task["opened_at"], at(10, 6).isoformat())

    def test_report_order_and_repeated_escalation(self):
        history = [mail("Initial", at(6, 8), "warning"), mail("Nouvel échec", at(9, 8), "failure")]
        for title, outcome, key, day in [("Ancienne tâche", "failure", "backup|alpha|vm", 5),
                                          ("Archives", "failure", "backup|delta|vm", 5),
                                          ("Archives", "success", "backup|delta|vm", 9)]:
            m = mail(title, at(day, 10), outcome)
            m["task_key"] = key
            history.append(m)
        tasks, _ = derive_state(history)
        report = render_digest({}, history, list(tasks.values()), [], current_time=at(9, 11))
        self.assertIn("Aggravation", report)
        self.assertLess(report.index("Nouvel échec"), report.index("RÉTABLIS"))
        self.assertLess(report.index("RÉTABLIS"), report.index("Serveur / source — alpha"))
        self.assertIn("ouvert le 05.11", report)


class RuleTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = Store(self.root)
        self.addCleanup(self.store.close)
        self.messages = [mail("Job42 SUCCESS", at(9, 6)), mail("Job42 FINISHED", at(8, 6))]
        for m in self.messages:
            self.store.put(m["sha256"], m["scope"], m)
        self.store.export()
        self.form = dict(source=self.messages[0]["sha256"], scope="imap:one", family="Job42",
                         task="NAS Homes", phrase="SUCCESS", field="subject", outcome="success")

    def test_preview_then_activate_and_revert_without_altering_source(self):
        preview = simulate(self.root, self.form)
        self.assertEqual([r["result"] for r in preview["rows"]], ["Réussite confirmée", "Sans correspondance"])
        self.assertEqual(policy(self.root)["rules"], [])
        activate(self.root, preview["token"])
        self.assertEqual(self.store.export()["recognized_messages"], 1)
        rule = policy(self.root)["rules"][0]
        self.assertFalse(apply_rules({**self.messages[0], "scope": "imap:two"}, [rule])["recognized"])
        self.assertFalse(apply_rules(self.messages[0], [rule, {**rule, "id": "other"}])["recognized"])
        self.assertFalse(apply_rules({**self.messages[0], "coverage_warnings": ["incomplet"]}, [rule])["recognized"])
        change(self.root, "rules", rule["id"])
        self.assertEqual(self.store.export()["recognized_messages"], 0)

    def test_body_examples_future_mail_and_explicit_approval(self):
        sample = {"id": self.form["source"], "text": "Le disque est indisponible", "complete": True}
        form = {**self.form, "field": "body", "phrase": "disque est indisponible", "outcome": "failure"}
        with patch("logtriage.unknown_review.Config.load"), patch("logtriage.unknown_review.read_samples", return_value=[sample]):
            preview = simulate(self.root, form)
        self.assertEqual(preview["rows"][-1]["result"], "Texte indisponible")
        activate(self.root, preview["token"])
        self.assertEqual(self.store.export()["open_tasks"], 1)
        rule = policy(self.root)["rules"][0]
        m = mail("Job42 autre", at(10, 4))
        m["body_matches"] = matched_body([rule], m, sample)
        self.assertEqual(apply_rules(m, [rule])["execution"], "failure")

    def test_unmatched_source_and_stale_simulation_cannot_be_activated(self):
        self.assertIsNone(simulate(self.root, {**self.form, "phrase": "FAILED"})["token"])
        token = simulate(self.root, self.form)["token"]
        change(self.root, "rules", "other", {"id": "other"})
        with self.assertRaises(ValueError):
            activate(self.root, token)
