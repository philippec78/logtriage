"""État chronologique et bilan destiné à la lecture humaine."""
import collections
import hashlib
import itertools
import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def derive_state(messages, resolutions=None):
    tasks, observations = {}, {}
    resolutions = resolutions or {}
    ordered = sorted(messages, key=lambda m: (m["date"], m["sha256"]))
    for date, batch in itertools.groupby(ordered, key=lambda m: m["date"]):
        signals = collections.defaultdict(set)
        for message in batch:
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
                    task.pop("resolved_by", None)
                    signals[identity].add(message["sha256"])
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
                        task["resolved_by"] = "logs"
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
        for identity, hashes in signals.items():
            task = tasks[identity]
            source = json.dumps([task["scope"], task["key"], date, sorted(hashes)])
            token = hashlib.sha256(source.encode()).hexdigest()
            task["signal_id"] = token
            if token in resolutions:
                task.update(state="resolved", resolved_at=resolutions[token], resolved_by="manual", active_occurrences=0)
    return tasks, observations


def readable(value, length=330):
    return re.sub(r"\s+", " ", str(value)).strip()[:length]


def local_stamp(date, zone):
    return datetime.fromisoformat(date).astimezone(zone).strftime("%d.%m.%Y à %H:%M")


def render_digest(summary, messages, tasks, observations, tz="Europe/Zurich", config=None, current_time=None,
                  unknown_reviews=None):
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
            review = (unknown_reviews or {}).get(m["sha256"]) if m.get("recognized") is False else None
            if review and review["verdict"] == "routine":
                continue
            if review and review["verdict"] == "signal":
                for finding in review["findings"]:
                    identity = ("ai", m["scope"], review["subject"], finding["summary"], finding["quote"])
                    group = groups.setdefault(identity, {
                        "summary": finding["summary"], "date": m["date"], "severity": 1,
                        "occurrences": 0, "resources": set(), "ai_source": review["subject"], "quote": finding["quote"]})
                    group["occurrences"] += 1
                    group["date"] = max(group["date"], m["date"])
                continue
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
    recovered = sorted((t for t in tasks if t["state"] == "resolved" and t["resolved_at"]
                        and current_time - timedelta(hours=24) <= datetime.fromisoformat(t["resolved_at"]) <= current_time),
                       key=lambda t: t["resolved_at"], reverse=True)
    def count(n, singular, plural):
        return f"{n} {singular if n == 1 else plural}"

    lines = ["Bilan des serveurs — " + current_time.astimezone(zone).strftime("%d.%m.%Y à %H:%M %Z"),
             f"{hours} h de suivi · " + count(len(recent), "email reçu", "emails reçus"), "",
             count(len(ordered), "point récent à examiner", "points récents à examiner") + " · "
             + count(len(older), "problème antérieur ouvert", "problèmes antérieurs ouverts") + " · "
             + count(len(recovered), "résolution en 24 h", "résolutions en 24 h")]
    if ordered:
        lines.extend(["", "À EXAMINER EN PRIORITÉ"])
        hidden = 0
        for index, group in enumerate(ordered):
            if index >= maximum and not group["resources"] and "ai_source" not in group:
                hidden += 1
                continue
            label = "ÉCHEC" if group["severity"] == 0 else "À VÉRIFIER" if group["severity"] == 2 else "ATTENTION"
            line = f"- {label} — {readable(group['summary'])}"
            if len(group["resources"]) > 1:
                names = ", ".join(sorted(readable(key.split("|", 2)[-1]) for key in group["resources"]))
                line += f" ({len(group['resources'])} ressources concernées) — {names}"
            when = datetime.fromisoformat(group["date"]).astimezone(zone).strftime("%d.%m à %H:%M")
            frequency = count(group["occurrences"], "signal", "signaux")
            lines += ["", line, f"  {when} · {frequency}"]
            if "ai_source" in group:
                lines.append(f"  Repéré par l’IA dans « {group['ai_source']} » — extrait : « {group['quote']} ».")
        if hidden:
            lines.append(f"{hidden} autre(s) point(s) : détail conservé dans les exports locaux.")

    if older:
        lines += ["", "PROBLÈMES TOUJOURS OUVERTS"]
        for task in sorted(older, key=lambda t: (t["state"] != "open", t["key"])):
            label = "ÉCHEC" if task["state"] == "open" else "ATTENTION"
            when = local_stamp(task["last_problem"], zone) if task["last_problem"] else "date inconnue"
            lines.append(f"- {label} — {readable(task.get('summary') or task['key'])} (dernier signal le {when})")
    if recovered:
        lines += ["", "RÉTABLIS DANS LES DERNIÈRES 24 H"]
        for task in recovered:
            origin = "Validé manuellement" if task.get("resolved_by") == "manual" else "Confirmé par les logs"
            lines.append(f"- {readable(task.get('summary') or task['key'])} — {origin} le {local_stamp(task['resolved_at'], zone)}")

    unreadable = sum(bool(m["coverage_warnings"]) for m in recent)
    if unreadable:
        lines.append(f"Lecture à compléter : {unreadable} rapport(s) comportent des données incomplètes ou des pièces jointes non analysables.")
    if any(g.get("security") for g in ordered):
        lines.extend(["", "Les détections de sécurité nécessitent une vérification."])
    return "\n".join(lines) + "\n"
