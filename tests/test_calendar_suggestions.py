import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logtriage.calendar_suggestions import activate_suggestions, suggestions
from logtriage.dashboard import checks
from logtriage.monitoring import policy
from logtriage.store import atomic_json

ZONE = "Europe/Zurich"
NOW = datetime(2026, 11, 9, 11, tzinfo=timezone.utc)
TASK = {"scope":"imap:one", "key":"backup|NAS|Homes", "id":"homes", "label":"Homes"}


def mail(day, hour=5):
    stamp = NOW.replace(hour=hour) - timedelta(days=day)
    return {"scope":TASK["scope"], "date":stamp.isoformat(), "task_events":[{"task_key": TASK["key"], "execution":"success"}]}


def infer(messages):
    return suggestions(messages, [TASK], "imap:one", NOW, ZONE)


class Proposals(unittest.TestCase):
    def test_weekly_schedule_across_dst_uses_receipt_and_deduplicates(self):
        messages = [mail(i) for i in [7, 14, 21, 28]]
        for m in messages:
            import zoneinfo
            date = datetime.fromisoformat(m["date"]).astimezone(zoneinfo.ZoneInfo(ZONE))
            m["received_at"] = date.replace(hour=8, minute=5).isoformat()
            m["date"] = NOW.isoformat()
        row, = infer(messages + messages + [mail(0), {**mail(1),"scope":"imap:other"}])
        self.assertEqual((row["days"],row["time"],row["observed"],row["header_dates"]), ([0],"08:45",4,0))

    def test_excludes_insufficient_stale_and_midnight_overflow(self):
        self.assertFalse(infer([mail(2)] * 40))
        self.assertFalse(infer([mail(i) for i in [8,15,22,29]]))
        rows = [mail(i) for i in [7,14,21]]
        for row in rows:
            row["received_at"] = row["date"][:10] + "T23:56:00+01:00"
        self.assertFalse(infer(rows))

    def test_only_reviewed_schedules_are_added_together(self):
        row, = infer([mail(i) for i in [1,8,15]])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            atomic_json(path/"exports/calendar-suggestions.json", [row])
            with self.assertRaises(ValueError):
                activate_suggestions(path, [row["token"], "obsolete"])
            self.assertEqual(policy(path)["schedules"], [])
            activate_suggestions(path, [row["token"]])
            original = policy(path)["schedules"]
            activate_suggestions(path, [row["token"]])
            self.assertEqual(policy(path)["schedules"], original)
            self.assertEqual(original[0]["time"], row["time"])

    def test_dashboard_limits_closed_history_and_hides_old_success(self):
        messages = [mail(1), *[mail(0) for _ in range(12)]]
        base = {"scope":"imap:one", "key":TASK["key"], "state":"ok", "last_message_date":NOW.isoformat()}
        old = {**base, "key":"backup|old|Archive", "last_message_date":mail(1)["date"]}
        rows = checks([base,old], messages, NOW, ZONE)
        self.assertEqual(len(rows),1)
        self.assertEqual(len(rows[0]["history"]),10)
        self.assertEqual(rows[0]["host"],"NAS")
        self.assertEqual(len(checks([{**old, "state":"open"}], [], NOW, ZONE)),1)
