"""Reconnaissance des familles observées, indépendamment de l'affichage du bilan."""
import hashlib
import re

from .analyze import norm, line_field, observation


def component(value):
    return re.sub(r"\s+", " ", norm(value)).strip(" .")


def key(*parts):
    return "|".join(component(str(p)) for p in parts)


def origin(subject, text):
    end = re.findall(r"(?im)^(?:De|From)\s+(.+)$", text)
    brackets = re.findall(r"\[([^\]]+)\]", subject)
    host = end[-1].strip() if end else ""
    if host and component(host) not in ("admin", "administrator", "root"):
        return host
    if brackets:
        return brackets[-1] if component(brackets[-1]) != "cms" else host or brackets[0]
    return host or "inconnu"


def result(fmt, category, summary, task=None, execution="unknown", evidence=None, **extra):
    return {"format": fmt, "recognized": True, "category": category, "summary": summary,
            "task_key": task, "execution": execution, "evidence": evidence or [], **extra}


def native_wazuh(subject, text, rules):
    observations = {}
    # Un email peut regrouper plusieurs alertes. Le texte et le HTML ne sont pas additionnés.
    blocks = re.split(r"(?im)(?=^Received From:)", text)
    for block in blocks:
        host_match = re.search(r"Received From:\s*\(([^)]+)\)", block, re.I)
        host = host_match[1] if host_match else None
        if not host:
            h = re.search(r"notification\s*[–—-]\s*\(([^)]+)\)", subject, re.I)
            host = h[1] if h else "wazuh-manager"
        for match in re.finditer(r'Rule:\s*(\d+)\s+(?:fired\s*)?\(level\s+(\d+)\)\s*[-=]>\s*["\']?([^\n]+)', block, re.I):
            rule, level, description = match[1], int(match[2]), match[3].strip('"\' ')
            identity = key("wazuh", host, rule)
            previous = observations.get(identity)
            if previous:
                previous["occurrences"] += 1
                if description not in previous["examples"]:
                    previous["examples"].append(description[:300])
                continue
            observations[identity] = observation(
                identity, description[:300], match[0][:700], host=host, rule=rule,
                occurrences=1, source_level=level, urgent=level >= rules["urgent_min_level"],
                report_kind="individual", examples=[description[:300]])
    if not observations:
        return result("wazuh-individual-incomplete", "a_verifier", "Notification Wazuh dont les détails ne sont pas lisibles.", evidence=[subject])
    selected = [v for v in observations.values() if v["source_level"] >= rules["review_min_level"]]
    return result("wazuh-individual", "a_examiner" if selected else "information",
                  f"Wazuh : {len(selected)} groupe(s) de détections à vérifier.", execution="completed",
                  evidence=[v["evidence"] for v in selected], observations=selected)


def pve_backup(subject, text):
    match = re.search(r"vzdump backup status\s*\(([^)]+)\)\s*:\s*(.+)$", subject, re.I)
    if not match:
        return None
    host, state = match.groups()
    events = []
    # Le tableau récapitulatif est utilisé, pas un mot « error » perdu dans l'historique.
    table = re.split(r"(?im)^\s*Logs\s*$", text)[0]
    for row in table.splitlines():
        row = re.sub(r"\s*\|\s*", " ", row).strip()
        vm = re.match(r"^(\d+)\s+(.+?)\s+(ok|err(?:or)?|failed|aborted)\s+", row, re.I)
        if vm:
            vmid, name, status = vm.groups()
            failed = status.lower() != "ok"
            events.append({"task_key": key("pve", host, "vm-backup", vmid),
                           "execution": "failure" if failed else "success", "evidence": [row[:700]],
                           "summary": f"Sauvegarde de {name} (VM {vmid}) sur {host} : {'échec' if failed else 'réussite'}.",
                           "format": "pve-vzdump"})
    errors = [line.strip() for line in text.splitlines()
              if re.search(r"\bERROR:\s*", line) and not re.search(r"\b0 errors?\b", line, re.I)]
    failed = "failed" in state.lower() or "error" in state.lower() or errors or any(e["execution"] == "failure" for e in events)
    if events:
        return result("pve-vzdump", "echec" if failed else "reussite_signalee",
                      f"Sauvegarde Proxmox sur {host} : {'échec ou résultat partiel' if failed else 'réussite signalée'}.",
                      execution="completed", task_events=events, evidence=errors[:3] or [subject])
    # Sans liste fiable des VM, un succès ne clôture aucun échec d'un autre lot.
    return result("pve-vzdump", "echec" if failed else "reussite_signalee",
                  f"Lot de sauvegarde Proxmox sur {host} : {'échec' if failed else 'réussite signalée'} ; détail des VM absent.",
                  key("pve", host, "unidentified-backup-job") if failed else None,
                  "failure" if failed else "completed", errors[:3] or [subject])


def classify(subject, sender, text, plain, html, rules):
    ns, nt = norm(subject), norm(text)
    host = origin(subject, text)
    clean_subject = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", subject)
    nclean = norm(clean_subject)
    if "wazuh notification" in ns:
        return native_wazuh(subject, plain or html, rules["wazuh"])
    pve = pve_backup(subject, plain or html)
    if pve:
        return pve
    pbs = re.search(r"^(Verify|Sync(?: local)?|Prune|Garbage Collect)\s+(?:Datastore|datastore)\s+['\"]([^'\"]+)['\"]\s+(successful|failed)", clean_subject, re.I)
    if pbs:
        action, datastore, state = pbs.groups()
        action = {"verify": "verification", "sync": "sync", "sync local": "sync-local", "prune": "prune", "garbage collect": "garbage-collection"}[action.lower()]
        h = re.search(r"Proxmox Backup Server\s*-\s*([^\s<]+)", sender, re.I)
        h = h[1] if h else line_field(text, "Hostname") or "inconnu"
        job = line_field(text, "Job ID") if action != "garbage-collection" else ""
        task = key("pbs", h, action, datastore, *([job] if job else []))
        failure_lines = [x.strip() for x in text.splitlines() if re.search(r"(?:failed:|^error:)", x, re.I)]
        failed = state.lower() == "failed" or bool(failure_lines)
        output = result("pbs-" + action, "echec" if failed else "reussite_signalee",
                        f"{action} de {datastore} sur {h} : {'échec' if failed else 'réussite'}.", task,
                        "failure" if failed else "success", failure_lines[:3] or [subject])
        if action == "garbage-collection" and failed:
            output["error_signature"] = "ENOENT" if "ENOENT" in text else "abort_requested" if "abort requested" in text else "unclassified"
        return output
    if "proxmox status report" in ns:
        h = line_field(text, "Hostname") or re.search(r"\(([^)]+)\)", subject)
        h = h if isinstance(h, str) else h[1] if h else "inconnu"
        findings = []
        for metric, threshold in (("Memory", rules.get("report", {}).get("memory_warning_percent", 95)),
                                  ("Disk", rules.get("report", {}).get("disk_warning_percent", 90))):
            value = re.search(metric + r"\s*:\s*(\d+(?:[.,]\d+)?)\s*%", text, re.I)
            if value and float(value[1].replace(",", ".")) >= threshold:
                findings.append(value[0])
        states = re.findall(r"(?im)^\s*State:\s*(\S+)", text)
        if states and any(s.upper() not in ("A", "ACTIVE", "OK") for s in states):
            findings.append("État du cluster : " + ", ".join(states))
        return result("proxmox-mail-gateway-status", "avertissement" if findings else "information",
                      f"Rapport Proxmox Mail Gateway {h}" + (" : " + "; ".join(findings) if findings else " : aucun seuil de ressource dépassé."),
                      key("pmg", h, "resources"), "warning" if findings else "success", findings or [subject])
    if "task scheduler" in ns or "planificateur de taches" in ns or "tache planifiee a ete ignoree" in ns or "a scheduled task was skipped" in ns:
        task = line_field(text, r"(?:Tâche|Task)")
        skipped = any(s in nt for s in ("deja en cours d'execution", "already running", "already in progress"))
        task_match = re.search(r"Scheduled Task\s*\[([^\]]+)\]", text, re.I)
        task = task or (task_match[1] if task_match else "inconnue")
        task_key = key("synology-scheduler", host, task)
        code = re.search(r"(?:[ÉE]tat actuel|Current status)\s*:\s*(-?\d+)", text, re.I)
        if skipped:
            return result("synology-scheduler-overlap", "avertissement", f"{host} : tâche {task} ignorée car déjà en cours.", task_key, "warning", [subject])
        explicit_error = re.search(r"(?im)^\s*(?:ERROR|FATAL|ERREUR)\s*[:\[][^\n]*", text)
        failed = bool(code and int(code[1]) not in rules["synology"]["scheduler_success_codes"]) or bool(explicit_error)
        category = "echec" if failed else "reussite_signalee" if code else "fin_annoncee"
        return result("synology-scheduler", category, f"{host} : {task}, " + (f"code {code[1]}." if code else "fin annoncée sans code."),
                      task_key, "failure" if failed else "success" if code else "completed",
                      [code[0] if code else subject] + ([explicit_error[0]] if explicit_error else []))
    if "journal de severite" in ns:
        task = re.search(r"Scheduled Task\s*\[([^\]]+)\]", text, re.I)
        if task and "already running" in nt:
            return result("synology-scheduler-overlap", "avertissement", f"{host} : tâche {task[1]} ignorée car déjà en cours.",
                          key("synology-scheduler", host, task[1]), "warning", [task[0], "already running"])
        content = re.search(r"(?is)contenu du journal est le suivant\s*:\s*(.+?)(?:\nDe\s|$)", text)
        detail = re.sub(r"\s+", " ", content[1]).strip()[:300] if content else clean_subject
        return result("synology-log-center", "echec" if "severite err" in ns else "avertissement",
                      f"{host} : {detail}", key("synology-log", host, hashlib.sha256(component(detail).encode()).hexdigest()[:12]),
                      "failure" if "severite err" in ns else "warning", [detail])
    if "instantane" in ns:
        target = re.search(r"(?:sur|pour (?:le dossier partagé )?)\s+(.+)$", clean_subject, re.I)
        target = target[1].strip() if target else "inconnu"
        target = re.split(r"\s+sur\s+", target, flags=re.I)[0]
        if "precedente tache" in ns or "toujours en cours" in ns:
            return result("synology-snapshot-overlap", "avertissement", f"{host} : instantané de {target} non effectué, tâche précédente encore en cours.",
                          key("synology-snapshot", host, target), "warning", [subject])
        failed = any(s in nclean for s in ("echec", "impossible", "echoue"))
        success = any(s in nclean for s in ("avec succes", "successful"))
        return result("synology-snapshot", "echec" if failed else "reussite_signalee" if success else "fin_annoncee",
                      f"{host} : instantanés {target}, " + ("échec." if failed else "réussite." if success else "fin annoncée."),
                      key("synology-snapshot", host, target), "failure" if failed else "success" if success else "completed", [subject])
    if "sauvegarde des donnees" in ns:
        task = line_field(text, r"(?:Nom de la tâche|Tâche de sauvegarde)")
        if task:
            failed = "echec" in ns or "a echoue" in nt
            success = "avec succes" in nt
            return result("synology-hyperbackup", "echec" if failed else "reussite_signalee" if success else "fin_annoncee",
                          f"{host} : sauvegarde {task}, " + ("échec." if failed else "réussite." if success else "fin annoncée."),
                          key("synology-backup", host, task), "failure" if failed else "success" if success else "completed", [subject])
    if "verification de l'integrite" in ns or "integrity check" in ns:
        failed = any(x in nclean for x in ("echoue", "echec", "failed"))
        target = re.search(r"(?:pour|for)\s+(.+?)\s+(?:sur|on)\s+", clean_subject, re.I)
        return result("synology-integrity-check", "echec" if failed else "fin_annoncee",
                      f"{host} : vérification d’intégrité " + ("en échec." if failed else "terminée, résultat détaillé non fourni."),
                      key("synology-integrity", host, target[1] if target else "inconnue"), "failure" if failed else "completed", [subject])
    if "serveur hors ligne" in ns or "serveur en ligne" in ns or "server is down" in ns or "server is up" in ns:
        target = re.search(r"(?:hors ligne|en ligne|is down|is up)\s*[–—-]\s*([^\s]+)", text, re.I)
        target = target[1] if target else re.sub(r"\[[^\]]+\]", "", subject).strip()
        down = "hors ligne" in ns or "is down" in ns
        return result("uptime-monitor", "echec" if down else "reussite_signalee", f"{target} : {'indisponibilité signalée' if down else 'retour en ligne signalé'}.",
                      key("uptime", target), "failure" if down else "success", [text[:300]])
    if "cluster haute disponibilite" in ns or "high-availability cluster" in ns:
        failed = "anormal" in ns or "abnormal" in ns or "des erreurs ont ete detectees" in nt
        restored = ("est normal" in ns or "is normal" in ns) and not failed
        detail = re.search(r"(?is)D[ée]tails\s*:\s*(.+?)(?:\nSi |\nVeuillez |\nDe |$)", text)
        detail = re.sub(r"\s+", " ", detail[1]).strip()[:250] if detail else clean_subject
        return result("synology-high-availability", "echec" if failed else "information" if restored else "a_verifier",
                      f"{host} : cluster haute disponibilité " + ("anormal — " + detail if failed else "rétabli." if restored else "état à confirmer."),
                      key("synology-ha", host, "cluster-health"), "failure" if failed else "success" if restored else "completed", [subject, detail])
    if re.search(r"(?:trying to fence|successfully fenced) node", ns):
        node = re.search(r"node\s+['\"]([^'\"]+)['\"]", subject, re.I)
        node = node[1] if node else "inconnu"
        return result("proxmox-ha-fencing", "avertissement", f"Proxmox : isolement du nœud {node} " + ("effectué ; retour en service à vérifier." if "successfully" in ns else "en cours."),
                      key("pve-ha", node, "fencing"), "warning", [subject])
    if "run failed:" in ns or "run succeeded:" in ns:
        repository = re.search(r"\[([^\]]+/[^\]]+)\]", subject)
        workflow = re.search(r"Run (?:failed|succeeded):\s*(.+?)\s+[–—-]\s+(.+?)\s*\([^)]+\)\s*$", subject, re.I)
        repo = repository[1] if repository else line_field(text, "Repository") or "inconnu"
        name = workflow[1] if workflow else line_field(text, "Workflow") or "inconnu"
        branch = workflow[2] if workflow else "inconnue"
        failed = "run failed:" in ns
        return result("github-actions", "echec" if failed else "reussite_signalee", f"{repo} : {name} sur {branch}, " + ("échec." if failed else "réussite."),
                      key("github-actions", repo, name, branch), "failure" if failed else "success", [subject])
    if "proxmox quotidien" in ns:
        problem_rows = [line.strip() for line in text.splitlines()
                        if re.search(r"\|\s*(?:WARNINGS\s*:\s*[1-9]\d*|ERROR[^|]*|FAILED[^|]*)\s*\|", line, re.I)]
        note = re.search(r"(\d+)\s+tâche\(s\) PBS terminée\(s\) avec un statut différent de OK", text, re.I)
        count = int(note[1]) if note else len(problem_rows)
        failed = any(re.search(r"\|\s*(?:ERROR|FAILED)", row, re.I) for row in problem_rows)
        return result("proxmox-daily-summary", "echec" if failed else "avertissement" if count else "information",
                      f"Rapport Proxmox : {count} tâche(s) avec avertissement ou échec." if count else "Rapport Proxmox : aucun résultat de tâche anormal signalé.",
                      evidence=problem_rows[:5] or [subject])
    if "security report" in ns and "crowdsec" in nt:
        # Les attaques bloquées ne démontrent ni intrusion ni panne du serveur.
        return result("crowdsec-security-summary", "information", "Bilan CrowdSec des attaques bloquées ; aucun incident confirmé par ce rapport.", evidence=[subject])
    if "rapport de quarantaine" in ns or "quarantine report" in ns:
        return result("mail-quarantine-digest", "information", "Bilan de messages retenus par le filtre antispam.", evidence=[subject])
    if "plan expires" in ns and ("smartconnect" in norm(sender) or "smartconnect" in nt):
        device = clean_subject.split(" – ")[0]
        return result("ups-monitoring-subscription", "avertissement", f"{device} : expiration annoncée de la supervision distante ; notifications à vérifier avant l’échéance.",
                      key("ups-monitoring", device), "warning", [subject])
    if "pare-feu" in ns or "firewall" in ns:
        disabled = "desactive" in ns or "disabled" in ns
        enabled = ("active" in ns or "enabled" in ns) and not disabled
        return result("synology-firewall-status", "echec" if disabled else "information" if enabled else "a_verifier",
                      f"{host} : pare-feu " + ("désactivé ; changement à vérifier." if disabled else "activé." if enabled else "état à vérifier."),
                      key("synology-firewall", host), "failure" if disabled else "success" if enabled else "completed", [subject])
    if "mot de passe" in ns and "modifie" in ns:
        return result("account-password-change", "avertissement", clean_subject + " ; intervention autorisée à vérifier.",
                      key("account-security", host, "password-change"), "warning", [subject])
    if "adresse ip" in ns and "bloquee" in ns:
        return result("synology-ip-block", "information", "Blocage d’une adresse IP signalé ; action de protection, pas preuve d’intrusion.", evidence=[subject])
    if "local restore" in ns:
        success = "a reussi" in ns or "successful" in ns
        failed = "echoue" in ns or "failed" in ns
        return result("synology-restore", "reussite_signalee" if success else "echec" if failed else "fin_annoncee", clean_subject,
                      key("synology-restore", host), "success" if success else "failure" if failed else "completed", [subject])
    if "snmp" in ns and any(s in nt for s in ("non autorise", "unauthorized")):
        target = line_field(text, "Nom") or host
        ip = re.search(r"(?:a partir de|from)\s+(\d+\.\d+\.\d+\.\d+)", norm(text))
        source = ip[1] if ip else "source inconnue"
        return result("ups-snmp-security", "avertissement", f"{target} : accès SNMP non autorisé signalé depuis {source} ; autorisation à vérifier.",
                      key("ups-snmp", target, source), "warning", [subject, source])
    if any(s in ns for s in ("onduleur", "ups self-test")):
        failed = any(s in ns for s in ("echoue", "failed", "batterie faible", "low battery", "sur batterie", "on battery"))
        success = any(s in ns for s in ("reussi", "passed", "retabli", "restored", "connecte"))
        return result("ups-status", "avertissement" if failed else "information",
                      clean_subject, key("ups", host, "self-test" if "test" in ns else "power"),
                      "warning" if failed else "success" if success else "completed", [subject])
    if "capacite disponible" in ns or "low disk" in ns or "volume" in ns and "espace" in ns:
        volume = re.search(r"(?:volume)\s+(\S+)", clean_subject, re.I)
        return result("synology-volume-capacity", "avertissement", f"{host} : capacité du volume {volume[1] if volume else '?'} à surveiller.",
                      key("synology-capacity", host, volume[1] if volume else "inconnu"), "warning", [subject, line_field(text, "Capacité disponible")])
    if "cms" in ns and ("connecter" in ns or "connecte" in ns):
        target = re.split(r" ne parvient| est connect", clean_subject, flags=re.I)[0]
        failed = "ne parvient" in ns or "impossible" in ns
        return result("synology-cms-connectivity", "avertissement" if failed else "information", clean_subject,
                      key("synology-cms", target), "warning" if failed else "success", [subject])
    if "dsm" in ns and ("mise a jour" in ns or "obsolete" in ns or "notifications par e-mail" in ns):
        critical = "critiques" in ns or "obsolete" in ns or "supprimees" in ns
        installed = any(s in ns for s in ("installee avec succes", "mise a jour reussie"))
        return result("synology-dsm-update", "avertissement" if critical else "information", clean_subject,
                      key("synology-dsm-update", host), "success" if installed else "warning" if critical else "completed", [subject])
    if any(s in ns for s in ("nouvelle connexion", "nouveau comportement de connexion", "modification obligatoire de votre mot de passe", "please verify your device")):
        return result("account-security-notice", "avertissement", clean_subject,
                      key("account-security", host, re.sub(r"\d+", "#", nclean)), "warning", [subject])
    if "rapport mensuel" in ns and "disques" in ns or "monthly drive health report" in ns:
        healthy = "aucun probleme detecte" in nt or "no problems detected" in nt or bool(re.search(r"[–—-]\s*Healthy\s*$", subject, re.I))
        unhealthy = any(s in nt for s in ("degrade", "defaillant", "secteurs defectueux")) and not healthy
        return result("synology-disk-health", "avertissement" if unhealthy else "information" if healthy else "a_verifier",
                      f"{host} : " + ("santé des disques à vérifier." if unhealthy or not healthy else "aucun problème de disque signalé."),
                      key("synology-disks", host), "warning" if unhealthy else "success" if healthy else "completed", [subject])
    if "active insight" in ns:
        return result("synology-active-insight-reference", "information", "Rapport Active Insight disponible via un lien externe ; contenu non inclus dans l’email.",
                      evidence=[subject], coverage_notes=["rapport_externe_non_analyse"])
    if "event mail" in ns and "ecosys" in ns:
        first = re.split(r"(?m)^<[^>]+>", text, maxsplit=2)
        current = first[1] if len(first) > 1 else text
        active = re.findall(r"\[\*\]\s*([^\n\[]+)", current)
        return result("kyocera-printer-status", "avertissement" if active else "information", "Imprimante : " + ("; ".join(active[:3]) if active else "compteurs et état courant, sans alerte active signalée."),
                      key("printer", re.sub(r" event mail.*", "", ns)), "warning" if active else "success", active or [subject])
    if "message test" in ns or "test message" in ns or "test notification" in ns:
        return result("notification-test", "information", "Message de test de notification.", evidence=[subject])
    if any(s in ns for s in ("facture", "changelog", "no downtime this week")):
        return result("non-log-notification", "hors_perimetre" if "no downtime" not in ns else "information", "Message administratif, bulletin ou bilan sans incident signalé.", evidence=[subject])
    if ns.startswith("logs serveurs") or "rapport ponctuel des emails de logs" in nt:
        return result("triage-report", "information", "Rapport produit par le service de tri.", evidence=[subject])
    return None
