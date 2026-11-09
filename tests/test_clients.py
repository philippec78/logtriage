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

    def test_daily_states_and_incident_mail_survive_a_later_inconclusive_mail(self):
        history = [event("one.ch", 8, "failure"), event("two.ch", 0, "success"),
                   event("one.ch", 0, "completed")]
        for m in history:
            m["subject"] = m["task_events"][0]["execution"]
        tasks, _ = derive_state(history)
        rows = {r["client"]: r for r in checks(tasks.values(), history, NOW, ZONE)}
        self.assertEqual(rows["one.ch"]["detail"]["subject"], "completed")
        self.assertEqual(rows["one.ch"]["incident_detail"]["subject"], "failure")
        self.assertEqual([state for _, state in rows["one.ch"]["daily_history"]], ["failure"] * 7)
        self.assertEqual([state for _, state in rows["two.ch"]["daily_history"]], ["none"] * 6 + ["success"])
        issue = next(t for t in tasks.values() if t["client"] == "one.ch")
        closures = {}
        tasks, _ = derive_state(history, {issue["signal_id"]: NOW.isoformat()}, manual_closures=closures)
        rows = {r["client"]: r for r in checks(tasks.values(), history, NOW, ZONE, closures)}
        self.assertEqual([state for _, state in rows["one.ch"]["daily_history"]], ["failure"] * 6 + ["success"])

    def test_daily_state_uses_local_midnight_and_last_confirmed_outcome(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        from logtriage.dashboard import daily_history, history_dates
        moment = datetime.fromisoformat("2026-10-26T12:00:00+00:00")
        signals = [("2026-10-24T21:45:00+00:00", "failure"),  # 23 h 45 le 24
                   ("2026-10-24T22:15:00+00:00", "warning"),  # 00 h 15 le 25
                   ("2026-10-25T01:30:00+00:00", "success")]
        days = history_dates(moment.date())
        states = daily_history(signals, [], days, ZoneInfo(ZONE), moment.isoformat())
        self.assertEqual([[day, state] for day, state, *_ in states[-3:]], [["2026-10-24", "failure"], ["2026-10-25", "success"], ["2026-10-26", "none"]])

    def test_day_evidence_tracks_the_mail_responsible_for_the_colour(self):
        signals = [event("one.ch", 5, "failure"), event("one.ch", 4, "warning"),
                   event("one.ch", 3, "completed"), event("one.ch", 1, "success"),
                   event("one.ch", 0, "completed")]
        for m in signals:
            m["subject"] = m["sha256"]
        tasks, _ = derive_state(signals)
        row, = checks(tasks.values(), signals, NOW, ZONE)
        days = list(row["day_reasons"].values())
        self.assertEqual([e["reason"] for e in days], ["none", "failure", "carried", "carried", "carried", "recovered", "unknown"])
        self.assertIsNone(days[0]["detail_id"])
        for n in (1, 2, 3, 4):
            details, source = row["day_details"][days[n]["detail_id"]]
            self.assertEqual(details["subject"], signals[0]["subject"])
            self.assertEqual(source["sha256"], signals[0]["sha256"])
        self.assertEqual(row["day_details"][days[5]["detail_id"]][0]["subject"], signals[3]["subject"])
        token = next(iter(derive_state(signals[:2])[0].values()))["signal_id"]
        closures = {}
        tasks, _ = derive_state(signals[:2], {token: NOW.isoformat()}, manual_closures=closures)
        row, = checks(tasks.values(), signals[:2], NOW, ZONE, closures)
        last = list(row["day_reasons"].values())[-1]
        self.assertEqual((last["reason"], last["at"]), ("manual", NOW.isoformat()))
        self.assertEqual(row["day_details"][last["detail_id"]][0]["subject"], signals[0]["subject"])

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

    def test_services_follow_the_check_family_for_each_client_and_missing_report(self):
        from logtriage.check_types import TYPES, check_service
        self.assertTrue(all(check_service(key) != 'Autres services' for key in TYPES))
        self.assertEqual(check_service('missing|pbs|nas|verification|homes'), 'Proxmox')
        self.assertEqual(check_service('custom|pbs|backup'), 'Contrôles personnalisés')
        history = [event(domain, 0, 'failure') for domain in ('one.ch', 'two.ch')]
        history[0]['task_events'][0]['task_key'] = 'synology-backup|nas|homes'
        history[1]['task_events'][0]['task_key'] = 'account-security|nas|homes'
        rows = checks(derive_state(history)[0].values(), history, NOW, ZONE)
        self.assertEqual({r['client']:r['service'] for r in rows},
                         {'one.ch':'Sauvegardes', 'two.ch':'Alertes de sécurité'})

    def test_latest_mail_of_each_client_uses_the_individual_task_result(self):
        history = [event(domain, 0, 'failure') for domain in ('one.ch', 'two.ch')]
        for mail in history:
            mail.update(subject='Lot de sauvegardes', summary='Lot en échec', evidence=['autre VM'])
            mail['task_events'][0].update(summary=sender_domain(mail['sender'])+' : VM 101 en échec',
                                          evidence=['VM 101 : disque plein', 'password=secret123'])
        old = event('one.ch', 1, 'failure')
        old['task_events'][0]['summary'] = 'Signal ancien'
        history.append(old)
        rows = checks(derive_state(history)[0].values(), history, NOW, ZONE)
        self.assertEqual(len({r['detail_id'] for r in rows}), 2)
        for r in rows:
            detail = r['detail']
            self.assertEqual(detail['summary'], r['client']+' : VM 101 en échec')
            self.assertIn('VM 101 : disque plein', detail['points'])
            self.assertNotIn('autre VM', detail['points'])
            self.assertNotIn('secret123', str(detail))
            self.assertEqual(detail['date'], history[0]['date'])

    def test_assignments_are_private_to_mailbox_source_device_and_account(self):
        from logtriage.clients import assignment_source, assign_clients, message_client
        def source(key, **fields):
            return dict(scope='imap:demo', sender='relay@vendor.test', task_key=key, sha256='id', **fields)
        ups = source('ups-monitoring|ups01 - "standard plan expires on jan 1"')
        next_date = source('ups-monitoring|ups01 – other date')
        nas = source('synology-dsm-update|nas-1')
        other = source('synology-dsm-update|nas-10')
        gh = dict(source('account-security|github|please verify your device'), sender='auto@github.com', github_login='alice')
        other_gh = dict(gh, github_login='bob')
        parent = source('')
        parent['task_events'] = [{'task_key':'pve|server|vm-backup|1'}, {'task_key':'pve|server|vm-backup|2'}]
        rules = [dict(source=assignment_source(m,e),client='client-a') for m,e in
                 [(ups,ups),(nas,nas),(gh,gh),(parent,parent['task_events'][0])]]
        assign_clients([next_date, nas, other, gh, other_gh, parent],rules)
        self.assertEqual([message_client(m) for m in (next_date,nas,other,gh,other_gh)],
                         ['client-a','client-a','@vendor.test','client-a','@github.com/bob'])
        self.assertEqual([message_client(parent,e) for e in parent['task_events']],['client-a','@vendor.test'])

    def test_confirmed_examples_learn_new_dates_and_keep_ambiguous_clients_separate(self):
        from logtriage.clients import assignment_source, assign_clients, message_client
        def alert(day, host="ups-01", imported="2026-11-20"):
            return dict(scope="imap:test", sender="relay@vendor.ch", imported_at=imported,
                        task_key=f"ups-monitoring|{host} - plan expires on nov {day}th, 2026")
        original = alert(10)
        def rule(m, client):
            source = (*assignment_source(m, m), m["task_key"])
            return {"source":source, "client":client, "learned_since":"2026-11-15"}
        rules = [rule(original, "TD")]
        future, other, old = alert(11), alert(11, "ups-02"), alert(12, imported="2026-11-01")
        assign_clients([future, other, old], rules)
        self.assertEqual([message_client(m) for m in (future,other,old)], ["TD","@vendor.ch","@vendor.ch"])
        self.assertEqual(old["suggested_client"], "TD")
        conflict, correction = alert(20), alert(13)
        assign_clients([conflict, correction], [*rules, rule(correction, "ESEDE")])
        self.assertEqual(message_client(conflict), "@vendor.ch")
        self.assertNotIn("suggested_client", conflict)
        self.assertEqual(message_client(correction), "ESEDE")
