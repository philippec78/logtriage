import copy
import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from logtriage.__main__ import load_rules
from logtriage.analyze import analyze
from logtriage.digest import derive_state, render_digest


def parse(subject, body, sender="reports@example.com", day=9):
    msg = EmailMessage()
    msg["Subject"], msg["From"] = subject, sender
    msg["Date"] = f"Mon, {day:02d} Nov 2026 10:00:00 +0000"
    msg.set_content(body)
    value = analyze(msg.as_bytes(), load_rules())
    value["scope"] = "account"
    return value


class FormatsTests(unittest.TestCase):
    def test_observed_notification_families(self):
        cases = [
            ("[monitor] Serveur hors ligne", "[CRITICAL] Serveur hors ligne – app.example.com\nConnection timed out", "echec"),
            ("[nas] Une précédente tâche d'instantané programmée est toujours en cours sur SHARE", "Le système n'a pas réussi à effectuer la tâche.\nDe NAS", "avertissement"),
            ("[nas] Échec de la prise d'un instantané pour le dossier partagé SHARE sur NAS", "De NAS", "echec"),
            ("[nas] Impossible d'activer les instantanés immuables pour SHARE", "Limite atteinte\nDe NAS", "echec"),
            ("[nas] Une tâche planifiée a été ignorée car elle est déjà en cours d'exécution", "Tâche : rapport\nLa tâche est déjà en cours d'exécution.\nDe NAS", "avertissement"),
            ("[nas] Un journal de sévérité err se trouve sur NAS", "Le contenu du journal est le suivant :\nSYSTEM: Scheduled Task [rapport] skipped because the task was already running.\nDe NAS", "avertissement"),
            ("[nas] Un journal de sévérité err se trouve sur NAS", "Le contenu du journal est le suivant :\nDISK: write failure\nDe NAS", "echec"),
            ("[nas] Le volume 1 sur NAS est à court de capacité disponible", "Capacité disponible : 20 %\nDe NAS", "avertissement"),
            ("[nas] NAS ne parvient pas à se connecter à l'hôte CMS (cms.example.com)", "De NAS", "avertissement"),
            ("[nas] DSM sur NAS est obsolète", "De NAS", "avertissement"),
            ("[nas] Une mise à jour importante de DSM avec des correctifs critiques est disponible sur NAS", "De NAS", "avertissement"),
            ("[nas] Une nouvelle mise à jour de DSM pour NAS a été détectée", "De NAS", "information"),
            ("[nas] La mise à jour automatique de DSM sur NAS est terminée", "De NAS", "information"),
            ("[nas] Les notifications par e-mail via le serveur d'e-mail de Synology ont été supprimées de DSM 7.2", "De NAS", "avertissement"),
            ("[nas] Nouvelle connexion à votre Synology NAS", "Connexion à vérifier\nDe NAS", "avertissement"),
            ("DSM a détecté un nouveau comportement de connexion sur NAS", "De NAS", "avertissement"),
            ("Modification obligatoire de votre mot de passe", "Notification", "avertissement"),
            ("Please verify your device", "Notification", "avertissement"),
            ("Détection d'une tentative d'accès à l'interface SNMP par un utilisateur non autorisé", "Nom : ups01\nAccès non autorisé à partir de 192.0.2.10.", "avertissement"),
            ("Onduleur : Autotest réussi.", "Rapport", "information"),
            ("[nas] NAS est connecté à l'onduleur", "Rapport", "information"),
            ("[nas] Rapport mensuel sur l’état de santé des disques sur NAS – Sain", "Aucun problème détecté sur les disques dans DSM.\nDe NAS", "information"),
            ("[nas] La vérification de l'intégrité pour backup sur NAS est terminée", "De NAS", "fin_annoncee"),
            ("Rapport [Synology Active Insight] NAS – 2026-11-01", "Télécharger le rapport via le lien", "information"),
            ("ECOSYS model event mail", "Counters by Function:\n<Mon 09 Nov 2026 10:00:00>\n[ ] Low Toner\n[ ] Paper Jam\n<Sun 08 Nov 2026 09:00:00>\n[*] Paper Jam", "information"),
            ("Message test de admin", "Test", "information"),
            ("Facture 123", "Message administratif", "hors_perimetre"),
            ("1er rappel facture 123", "Message administratif", "hors_perimetre"),
            ("Changelog 123: New native mobile apps", "Bulletin", "hors_perimetre"),
            ("No downtime this week!", "Bilan", "information"),
        ]
        for subject, body, category in cases:
            with self.subTest(subject=subject):
                value = parse(subject, body)
                self.assertTrue(value["recognized"])
                self.assertEqual(value["category"], category)

    def test_native_wazuh_multiple_alerts_and_safe_threshold(self):
        message = parse("Wazuh notification – (host.example.com) any – Alert level 13",
                        'Received From: (host.example.com) any->syscheck\nRule: 220100 fired (level 12) -> "Sensitive file modified: /etc/test"\n'
                        'Received From: (host.example.com) any->syscheck\nRule: 220102 fired (level 13) -> "Sensitive file deleted: /etc/other"')
        self.assertEqual(message["category"], "a_examiner")
        self.assertEqual(len(message["observations"]), 2)
        low = parse("Wazuh notification – (host.example.com) any – Alert level 3",
                    'Received From: (host.example.com) any->log\nRule: 100 fired (level 3) -> "Informational detection"')
        self.assertEqual(low["category"], "information")
        self.assertEqual(low["observations"], [])

    def test_pbs_success_and_failure_use_same_job_identity(self):
        for job in ("Verify", "Sync local", "Prune", "Garbage Collect"):
            with self.subTest(job=job):
                success = parse(f"{job} Datastore 'backup' successful", "Job ID: stable\nDatastore: backup\nVerification successful.", "Proxmox Backup Server - pbs01 <logs@example.com>")
                failure = parse(f"{job} Datastore 'backup' failed", "Job ID: stable\nDatastore: backup\nJob failed: disk error", "Proxmox Backup Server - pbs01 <logs@example.com>")
                self.assertEqual(success["task_key"], failure["task_key"])
                self.assertEqual(success["execution"], "success")
                self.assertEqual(failure["execution"], "failure")

    def test_pve_partial_success_preserves_failed_vm(self):
        first = parse("vzdump backup status (pve.example.com): backup failed",
                      "Details\n100 VM-A ok 1m 20 GiB\n101 VM-B err 1m 20 GiB\nLogs\n101: ERROR: storage unavailable", day=8)
        second = parse("vzdump backup status (pve.example.com): backup successful",
                       "Details\n100 VM-A ok 1m 20 GiB\nLogs\nJob finished", day=9)
        tasks, _ = derive_state([first, second])
        self.assertEqual(tasks["account|pve|pve.example.com|vm-backup|101"]["state"], "open")
        self.assertEqual(tasks["account|pve|pve.example.com|vm-backup|100"]["state"], "ok")

    def test_hyperbackup_failure_name_matches_later_success(self):
        failure = parse("Échec de la tâche de sauvegarde des données sur NAS", "Nom de la tâche : Cloud\nDe NAS", day=8)
        success = parse("La tâche Network backup - Cloud a été effectuée avec succès sur NAS", "Tâche de sauvegarde : Cloud\nDe NAS", day=9)
        self.assertEqual(failure["task_key"], success["task_key"])
        tasks, _ = derive_state([success, failure])
        self.assertEqual(next(iter(tasks.values()))["state"], "resolved")

    def test_english_scheduler_status_is_read_not_label_error(self):
        msg = parse("[backup] Task Scheduler has completed a scheduled task", "Task: cert-renew\nCurrent status: 0 (Normal)\nStandard output/error:\nFrom backup")
        self.assertEqual(msg["execution"], "success")
        msg = parse("[backup] Task Scheduler has completed a scheduled task", "Task: cert-renew\nCurrent status: 127 (Failed)\nFrom backup")
        self.assertEqual(msg["execution"], "failure")

    def test_printer_current_active_fault_is_visible(self):
        msg = parse("ECOSYS model event mail", "<Mon 09 Nov 2026 10:00:00>\n[*] Paper Jam\n<Sun 08 Nov 2026 10:00:00>\n[ ] Paper Jam")
        self.assertEqual(msg["category"], "avertissement")

    def test_remaining_families_from_full_mailbox_audit(self):
        cases = [
            ("[nas] A scheduled task was skipped because it is already running", "Task: report\nIt is already running\nFrom NAS", "avertissement"),
            ("[nas] L'état du cluster haute disponibilité NAS est anormal [Détails : quorum indisponible]", "Des erreurs ont été détectées\nDétails : quorum indisponible\nDe NAS", "echec"),
            ("Test notification", "Test", "information"),
            ('UPS-01 – "Standard Plan Expires on Nov 25th, 2026"', "EcoStruxure SmartConnect Notification\nEvent notifications will no longer be sent.", "avertissement"),
            ("Security Report for account: Nov 1 - Nov 8", "CrowdSec Security Report\n481 ATTACKS PREVENTED", "information"),
            ("Trying to fence node 'pve01'", "Cluster event", "avertissement"),
            ("Successfully fenced node 'pve01'", "Cluster event", "avertissement"),
            ("Rapport de quarantaine example.com", "1 message retenu", "information"),
            ("[NAS] L'adresse IP [192.0.2.1] a été bloquée par admin via VPN_SERVER", "Notification", "information"),
            ("[NAS] Le mot de passe de NAS a été modifié", "Notification", "avertissement"),
            ("[NAS] Le pare-feu a été désactivé", "De NAS", "echec"),
            ("[NAS] - La tâche Local restore a réussi sur NAS", "De NAS", "reussite_signalee"),
            ("[NAS] Monthly drive health report on NAS – Healthy", "No problems detected.", "information"),
            ("[Proxmox quotidien] 09.11.2026 – Points à contrôler", "2 tâche(s) PBS terminée(s) avec un statut différent de OK.\n08.11 | prunejob | backup | WARNINGS: 1 | durée 0:03", "avertissement"),
            ("[owner/project] Run failed: Docker checks – main (abcdef)", "Repository: owner/project\nWorkflow: Docker checks", "echec"),
        ]
        for subject, body, category in cases:
            with self.subTest(subject=subject):
                msg = parse(subject, body)
                self.assertTrue(msg["recognized"])
                self.assertEqual(msg["category"], category)


class DigestTests(unittest.TestCase):
    def test_routine_success_and_resolved_failures_are_not_open_alerts(self):
        failed = parse("[NAS] Le planificateur de tâches a terminé une tâche planifiée", "Tâche : certs\nÉtat actuel : 127\nDe NAS", day=8)
        success = parse("[NAS] Le planificateur de tâches a terminé une tâche planifiée", "Tâche : certs\nÉtat actuel : 0\nDe NAS", day=9)
        tasks, obs = derive_state([failed, success])
        text = render_digest({"total_messages": 2}, [failed, success], list(tasks.values()), list(obs.values()), current_time=datetime(2026, 11, 9, 11, tzinfo=timezone.utc))
        self.assertNotIn("ÉCHEC —", text)
        self.assertNotIn("Format non reconnu", text)
        self.assertIn("RÉTABLIS", text)

    def test_snapshot_repetitions_roll_up_without_losing_resources(self):
        messages = [parse(f"[NAS] Une précédente tâche d'instantané programmée est toujours en cours sur {folder}", "De NAS") for folder in ("a", "b", "c")]
        tasks, obs = derive_state(messages)
        text = render_digest({"total_messages": 3}, messages, list(tasks.values()), list(obs.values()), current_time=datetime(2026, 11, 9, 11, tzinfo=timezone.utc))
        self.assertEqual(text.count("ATTENTION —"), 1)
        self.assertIn("3 ressources concernées", text)

    def test_low_cvss_and_old_observations_are_not_dumped_in_email(self):
        o = {"scope": "s", "key": "openvas|low", "summary": "Low finding", "source": "pdf", "source_cvss": 2.6,
             "last_seen": "2026-11-09T10:00:00+00:00", "reports_seen": 1}
        text = render_digest({"total_messages": 10}, [], [], [o], current_time=datetime(2026, 11, 9, 11, tzinfo=timezone.utc))
        self.assertNotIn("Low finding", text)

    def test_genuinely_unknown_messages_are_grouped_and_not_silenced(self):
        messages = [parse(f"Unknown format {i}", "Unstructured data") for i in range(3)]
        text = render_digest({"total_messages": 3}, messages, [], [], current_time=datetime(2026, 11, 9, 11, tzinfo=timezone.utc))
        self.assertEqual(text.count("À VÉRIFIER —"), 1)
        self.assertIn("3 rapport(s)", text)


if __name__ == "__main__":
    unittest.main()
