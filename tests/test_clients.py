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
        self.assertEqual({r["client"] for r in task_options(tasks.values())}, {"one.ch", "two.ch"})
        history = [event(client, 0, 'failure') for client in ('one.ch','two.ch')]
        tasks, _ = derive_state(history)
        token = next(t['signal_id'] for t in tasks.values() if t['client']=='one.ch')
        resolved, _ = derive_state(history, {token:NOW.isoformat()})
        self.assertEqual({t['client']:t['state'] for t in resolved.values()}, {'one.ch':'resolved','two.ch':'open'})
        payload = [TASK['scope'],TASK['key'],history[0]['date'],sorted(m['sha256'] for m in history)]
        old = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        migrated, _ = derive_state(history, {old:NOW.isoformat()})
        self.assertTrue(all(t['state']=='resolved' for t in migrated.values()))

    def test_same_control_keeps_distinct_calendars_and_arrival_times(self):
        from logtriage.calendar_suggestions import suggestions
        from logtriage.monitoring import schedule_events

        history = [event(domain, day, 'success') for domain in ('one.ch', 'two.ch') for day in (7, 14, 21)]
        for row in history:
            if 'two.ch' in row['sender']:
                row['date'] = row['date'].replace('T05:', 'T09:')
        options = task_options(derive_state(history)[0].values())
        proposals = suggestions(history, options, TASK['scope'], NOW, ZONE)
        self.assertEqual({r['client']:r['time'] for r in proposals}, {'one.ch':'07:30', 'two.ch':'11:30'})
        calendars = [{**r, 'since':history[0]['date']} for r in proposals]
        inbox = [event('one.ch', 0, 'success')]
        status = dict(state='ok', scope=TASK['scope'], last_cycle_at=NOW.isoformat())
        events = schedule_events(calendars, inbox, status, NOW, ZONE)
        today = [e for e in events if e['date'][:10] == NOW.date().isoformat()]
        self.assertEqual({e['client']:e['execution'] for e in today}, {'one.ch':'success', 'two.ch':'warning'})

    def test_client_and_check_type_are_independent_in_table(self):
        history = [event(domain, 0, 'failure') for domain in ('one.ch','two.ch')]
        for m in history:
            m['task_events'][0]['task_key'] = 'pbs|nas|garbage-collection|archive'
        rows = checks(derive_state(history)[0].values(), history, NOW, ZONE)
        self.assertEqual({r['client'] for r in rows}, {'one.ch','two.ch'})
        self.assertEqual({r['check_type'] for r in rows}, {'Nettoyage PBS'})

    def test_security_observations_stay_with_their_sender(self):
        history = [event(domain, 0, 'success') for domain in ('one.ch','two.ch')]
        for m in history:
            m['observations'] = [{'key':'wazuh|nas|42', 'summary':'Détection'}]
        observations = derive_state(history)[1].values()
        self.assertEqual({o['client']:o['reports_seen'] for o in observations}, {'one.ch':1, 'two.ch':1})
