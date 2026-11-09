"""Calendriers locaux des notifications attendues."""
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from .clients import message_client
from .private import locked, private_dir, read_json, write_private


def identity(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def policy(directory):
    return read_json(directory / "private/monitoring.json", {"schedules": [], "rules": []})


def change(directory, section, key, item=None, previous=None):
    root = private_dir(directory)
    with locked(root / "monitoring.lock"):
        data = policy(directory)
        if previous is not None and previous != identity(data[section]):
            raise ValueError("Les règles ont changé. Teste à nouveau la règle.")
        rows = [row for row in data[section] if row["id"] != key]
        if item is not None:
            if len(rows) >= 500:
                raise ValueError("La limite de 500 entrées est atteinte.")
            rows.append(item)
        data[section] = rows
        write_private(root / "monitoring.json", data)


def task_options(tasks):
    keys = dict.fromkeys((t["scope"], t["key"], t.get("client", "")) for t in tasks
                         if t["scope"].startswith("imap:") and t.get("format") != "missing-report")
    return [{"id": identity(scope, key, client), "key": key, "scope": scope, "client": client,
             "label": (client or "Domaine indéterminé") + " — " + " · ".join(key.split("|"))}
            for scope, key, client in keys]


def bind_old_schedules(directory, options, moment):
    root = private_dir(directory)
    with locked(root / "monitoring.lock"):
        config = policy(directory)
        by_task = defaultdict(list)
        for task in options:
            by_task[task["scope"], task["key"]].append(task)
        scoped = {r["id"] for r in config["schedules"] if "client" in r}
        rows = []
        for row in config["schedules"]:
            matches = by_task[row["scope"], row["key"]]
            if "client" in row or not matches:
                rows.append(row)
                continue
            for match in matches:
                if match["id"] in scoped:
                    continue
                bound = {**row, **match}
                if len(matches) == 1:
                    bound["event_id"] = row["id"]  # Préserve les résolutions des échéances existantes.
                else:
                    bound["since"] = moment.isoformat()
                rows.append(bound)
        if rows != config["schedules"]:
            config["schedules"] = rows
            write_private(root / "monitoring.json", config)
        return config


def schedule(directory, values):
    tasks = read_json(directory / "exports/monitor-options.json", [])
    task = next((t for t in tasks if t["id"] == values.get("id")), None)
    days, limit = values.get("days"), values.get("time")
    if not task or not isinstance(days, list) or not days or not all(type(n) is int and 0 <= n <= 6 for n in days):
        raise ValueError("Choisis une tâche et au moins un jour de surveillance.")
    if not isinstance(limit, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", limit):
        raise ValueError("Indique une heure limite valide.")
    row = {**task, "days": sorted(set(days)), "time": limit}
    previous = next((s for s in policy(directory)["schedules"] if s["id"] == task["id"]), {})
    if all(previous.get(k) == v for k, v in row.items()):
        return
    row["since"] = datetime.now(timezone.utc).isoformat()
    change(directory, "schedules", row["id"], row)


def reliable(status, moment):
    if not status or status.get("state") != "ok" or status.get("collection", {}).get("pending"):
        return False
    age = (moment - datetime.fromisoformat(status["last_cycle_at"])).total_seconds()
    return 0 <= age <= max(180, int(status.get("poll_seconds", 300)) * 3)


def schedule_events(schedules, messages, status, moment, tz):
    if not schedules or not reliable(status, moment):
        return []
    # Une échéance n'est décidée qu'après une recherche IMAP complète postérieure.
    until = datetime.fromisoformat(status.get("checked_through", status["last_cycle_at"]))
    zone = ZoneInfo(tz)
    arrivals = defaultdict(dict)
    for m in messages:
        stamp = datetime.fromisoformat(m.get("received_at") or m["date"])
        if stamp > until:
            continue
        for event in [m, *m.get("task_events", [])]:
            if event.get("task_key"):
                key = (m["scope"], event["task_key"], message_client(m, event))
                arrivals[key][stamp] = m["sha256"]
    events = []
    for row in schedules:
        if row["scope"] != status.get("scope"):
            continue
        since = datetime.fromisoformat(row["since"])
        day = since.astimezone(zone).date()
        client = row.get("client", "")
        times = sorted(arrivals[row["scope"], row["key"], client])
        first_arrivals = {}
        # La première arrivée du jour permet de reconnaître aussi un retard rattrapé.
        for stamp in times:
            first_arrivals.setdefault(stamp.astimezone(zone).date(), stamp)
        task = "missing|" + row["key"]
        def event(stamp, execution, summary):
            return {"sha256": identity(row.get("event_id", row["id"]), row["since"], stamp.isoformat(), execution),
                    "scope": row["scope"], "date": stamp.astimezone(timezone.utc).isoformat(),
                    "category": "avertissement" if execution == "warning" else "information",
                    "format": "missing-report", "client": client, "task_key": task, "execution": execution,
                    "observations": [], "evidence": [], "summary": summary}
        for stamp in times:
            if stamp > since:
                received = event(stamp, "success", "Rapport reçu pour " + row["label"])
                received["source_sha256"] = arrivals[row["scope"], row["key"], client][stamp]
                events.append(received)
        while day <= until.astimezone(zone).date():
            if day.weekday() in row["days"]:
                limit = datetime.combine(day, time.fromisoformat(row["time"]), zone).astimezone(timezone.utc)
                if since <= limit <= until and (day not in first_arrivals or first_arrivals[day] > limit):
                    events.append(event(limit, "warning", f"Rapport manquant — {row['label']} (attendu à {row['time']})"))
            day += timedelta(days=1)
    return events
