import hashlib
import json
import unittest

from logtriage.clients import sender_domain
from logtriage.dashboard import checks
from logtriage.digest import derive_state
from logtriage.monitoring import task_options
from test_calendar_suggestions import TASK, NOW, ZONE, mail


def event(domain, day, execution):
    m = mail(day)
    m.update(sender='Serveur <logs@'+domain+'>', sha256=domain+str(day),
             category='information', summary='Copie', evidence=[], observations=[])
    m["task_events"][0]["execution"] = execution
    return m


class ClientTests(unittest.TestCase):
    def test_exact_sender_domain(self):
        self.assertEqual(sender_domain('"Nom @ autre.ch" <Logs@NAS.Client.CH>'), 'nas.client.ch')
        self.assertEqual(sender_domain('machine'), '')
        self.assertEqual(sender_domain('a@one.ch, b@two.ch'), '')
        self.assertEqual(sender_domain('logs@bad/path'), '')

    def test_colliding_task_state_history_and_manual_resolution(self):
        history = [event('one.ch', 1, 'failure'), event('two.ch', 0, 'success')]
        tasks, _ = derive_state(history)
        rows = {r['client']:r for r in checks(tasks.values(), history, NOW, ZONE)}
        self.assertEqual(rows['one.ch']['state'], 'open')
        self.assertEqual(rows['one.ch']['history'], [])
        self.assertEqual(rows['two.ch']['state'], 'ok')
        self.assertEqual(len(task_options(tasks.values())), 1)
        history = [event(client, 0, 'failure') for client in ('one.ch','two.ch')]
        tasks, _ = derive_state(history)
        token = next(t['signal_id'] for t in tasks.values() if t['client']=='one.ch')
        resolved, _ = derive_state(history, {token:NOW.isoformat()})
        self.assertEqual({t['client']:t['state'] for t in resolved.values()}, {'one.ch':'resolved','two.ch':'open'})
        payload = [TASK['scope'],TASK['key'],history[0]['date'],sorted(m['sha256'] for m in history)]
        old = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        migrated, _ = derive_state(history, {old:NOW.isoformat()})
        self.assertTrue(all(t['state']=='resolved' for t in migrated.values()))
