"""État chronologique et bilan destiné à la lecture humaine."""
import collections
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def derive_state(messages):
    tasks, observations = {}, {}
    for message in sorted(messages, key=lambda m: (m["date"], m["sha256"])):
        events = ([message] if message.get("task_key") else []) + message.get("task_events", [])
        for event in events:
            identity = message["scope"] + "|" + event["task_key"]
            task = tasks.setdefault(identity, {
                "key": event["task_key"], "scope": message["scope"], "state": "unknown",
                "failures": [], "last_failure": None, "last_success": None,
                "active_occurrences": 0, "last_problem": None, "resolved_at": None})
            task.update(last_message_date=message["date"], latest_category=message["category"],
                        format=event.get("format", message.get("format", "unknown")))
            execution = event["execution"]
            if execution in ("failure", "warning"):
                task["state"] = "open" if execution == "failure" or task["state"] == "open" else "warning"
                task["active_occurrences"] += 1
                task["last_problem"] = message["date"]
                task["resolved_at"] = None
                task["summary"] = event.get("summary", message["summary"])
                task["evidence"] = event.get("evidence", message["evidence"])
                if execution == "failure":
                    task["last_failure"] = message["date"]
                    task["failures"].append({"date": message["date"], "message_sha256": message["sha256"],
                                              "evidence": task["evidence"], "signature": message.get("error_signature")})
            elif execution == "success":
                # Un succès à la même seconde qu'un problème ne l'efface pas.
                if task["state"] in ("open", "warning") and message["date"] > task["last_problem"]:
                    task["state"] = "resolved"
                    task["resolved_at"] = message["date"]
                    task["active_occurrences"] = 0
                    task["summary"] = event.get("summary", message["summary"])
                elif not task["last_problem"]:
                    task["state"] = "ok"
                    task["summary"] = event.get("summary", message["summary"])
                task["last_success"] = message["date"]
            task["message_sha256"] = message["sha256"]
        for item in message["observations"]:
            identity = message["scope"] + "|" + item["key"]
            previous = observations.get(identity)
            observations[identity] = {**item, "scope": message["scope"],
                                       "first_seen": previous["first_seen"] if previous else message["date"],
                                       "last_seen": message["date"], "message_sha256": message["sha256"],
                                       "reports_seen": (previous["reports_seen"] if previous else 0) + 1}
    return tasks, observations


def readable(value, length=330):
    return re.sub(r"\s+", " ", str(value)).strip()[:length]


def local_stamp(date, zone):
    return datetime.fromisoformat(date).astimezone(zone).strftime("%d.%m.%Y à %H:%M")


def render_digest(summary, messages, tasks, observations, tz="Europe/Zurich", config=None, current_time=None):
    config = config or {}
    current_time = current_time or datetime.now(timezone.utc)
    zone = ZoneInfo(tz)
    hours = int(config.get("window_hours", 24))
    maximum = int(config.get("max_groups", 20))
    cutoff = (current_time - timedelta(hours=hours)).isoformat()
    # Anciens exports conservés lors d'une mise à jour, avant la première collecte.
    if any("resolved_at" not in task for task in tasks):
        tasks = list(derive_state(messages)[0].values())
    recent = [m for m in messages if m["date"] >= cutoff]
    groups, older = {}, []
    for task in tasks:
        if task["state"] not in ("open", "warning"):
            continue
        if not task["last_problem"] or task["last_problem"] < cutoff:
            older.append(task)
            continue
        # Les répétitions par dossier d'un même NAS deviennent un seul point lisible.
        identity = task["key"]
        if task.get("format") in ("synology-snapshot-overlap", "synology-snapshot"):
            identity = "|".join(task["key"].split("|")[:2])
        group_id = (task["scope"], identity)
        group = groups.setdefault(group_id, {"summary": task.get("summary", task["key"]),
                                              "date": task["last_problem"], "severity": 0 if task["state"] == "open" else 1,
                                              "occurrences": 0, "resources": set()})
        group["occurrences"] += task["active_occurrences"]
        group["resources"].add(task["key"])
        group["date"] = max(group["date"], task["last_problem"])
        group["severity"] = min(group["severity"], 0 if task["state"] == "open" else 1)
    for o in observations:
        if o["last_seen"] < cutoff:
            continue
        level = o.get("source_level")
        cvss = o.get("source_cvss")
        if level is None and not o.get("urgent") and ((o.get("source") == "pdf" and cvss is None) or (o.get("source") in ("pdf", "inline") and cvss is not None and cvss < 4)):
            continue  # Constat faible/informatif conservé dans les JSON.
        groups[(o["scope"], o["key"])] = {
            "summary": (o.get("host", "") + " : " if o.get("host") else "") + o["summary"],
            "date": o["last_seen"], "severity": 0 if o.get("urgent") else 1,
            "occurrences": o["reports_seen"], "resources": set(),
            "security": True}
    # Un message réellement inconnu reste visible, une fois par modèle et non par email.
    unknown = collections.Counter()
    example = {}
    for m in recent:
        if m["category"] == "a_verifier":
            model = re.sub(r"\d+", "#", m["subject"])
            unknown[model] += 1
            example[model] = m
        elif m["category"] in ("echec", "avertissement", "a_examiner") and not m.get("task_key") and not m.get("task_events") and not m["observations"]:
            model = re.sub(r"\d+", "#", m["subject"])
            groups[(m["scope"], model)] = {"summary": m["summary"], "date": m["date"],
                                            "severity": 0 if m["category"] == "echec" else 1,
                                            "occurrences": 1, "resources": set()}
    for model, count in unknown.items():
        m = example[model]
        groups[(m["scope"], "unknown:" + model)] = {"summary": m["summary"] if m.get("recognized") else m["subject"],
                                                    "date": m["date"], "severity": 2,
                                                    "occurrences": count, "resources": set()}
    ordered = sorted(groups.values(), key=lambda g: (g["severity"], -datetime.fromisoformat(g["date"]).timestamp()))
    lines = ["Bilan des serveurs — " + current_time.astimezone(zone).strftime("%d.%m.%Y à %H:%M %Z"),
             f"{len(ordered)} point(s) à examiner sur les dernières {hours} heures.", ""]
    if ordered:
        hidden = 0
        for index, group in enumerate(ordered):
            if index >= maximum and not group["resources"]:
                hidden += 1
                continue
            label = "ÉCHEC" if group["severity"] == 0 else "À VÉRIFIER" if group["severity"] == 2 else "ATTENTION"
            line = f"- {label} — {readable(group['summary'])}"
            if len(group["resources"]) > 1:
                names = ", ".join(sorted(readable(key.split("|", 2)[-1]) for key in group["resources"]))
                line += f" ({len(group['resources'])} ressources concernées) — {names}"
            when = datetime.fromisoformat(group["date"]).astimezone(zone).strftime("%d.%m à %H:%M")
            lines += [line, f"  Dernier signal : {when} ; {group['occurrences']} rapport(s) regroupé(s)."]
        if hidden:
            lines.append(f"{hidden} autre(s) point(s) : détail conservé dans les exports locaux.")
    else:
        lines.append("Aucun échec ni avertissement récent nécessitant une vérification dans les rapports analysés.")
    if older:
        lines += ["", f"PROBLÈMES TOUJOURS OUVERTS — {len(older)} sans nouveau signal dans la période"]
        for task in sorted(older, key=lambda t: t["last_problem"] or "", reverse=True):
            label = "ÉCHEC" if task["state"] == "open" else "ATTENTION"
            when = local_stamp(task["last_problem"], zone) if task["last_problem"] else "date inconnue"
            lines.append(f"- {label} — {readable(task.get('summary') or task['key'])} (dernier signal le {when})")
    recovery_start = current_time - timedelta(hours=24)
    recovered = sorted((t for t in tasks if t["state"] == "resolved" and t["resolved_at"]
                        and recovery_start <= datetime.fromisoformat(t["resolved_at"]) <= current_time),
                       key=lambda t: t["resolved_at"], reverse=True)
    if recovered:
        lines += ["", "RÉTABLIS DANS LES DERNIÈRES 24 H"]
        for task in recovered[:5]:
            lines.append(f"- {readable(task.get('summary') or task['key'])} ({local_stamp(task['resolved_at'], zone)})")
        if len(recovered) > 5:
            lines.append(f"Et {len(recovered) - 5} autre(s) rétablissement(s) confirmé(s).")
    lines += ["", f"Couverture : {summary['total_messages']} emails analysés ; {len(recent)} dans cette période."]
    unreadable = sum(bool(m["coverage_warnings"]) for m in recent)
    if unreadable:
        lines.append(f"Lecture à compléter : {unreadable} rapport(s) comportent des données incomplètes ou des pièces jointes non analysables.")
    lines.append("Les réussites habituelles et les notifications sans incident sont conservées dans l’historique.")
    lines.append("Les détections de sécurité sont à vérifier et ne prouvent pas, seules, une compromission.")
    return "\n".join(lines) + "\n"
