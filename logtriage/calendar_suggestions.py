"""Propositions hebdomadaires calculées localement sur les arrivées observées."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from math import ceil
from zoneinfo import ZoneInfo

from .clients import message_client
from .monitoring import identity, policy
from .private import locked, private_dir, read_json, write_private


def suggestions(messages, options, scope, moment, tz):
    zone = ZoneInfo(tz)
    today = moment.astimezone(zone).date()
    start = today - timedelta(days=56)
    arrivals = defaultdict(dict)
    for message in messages:
        if not scope or message["scope"] != scope:
            continue
        received = message.get("received_at")
        if not received and "date_absente_ou_invalide_utilisation_date_import" in message.get("coverage_warnings", []):
            continue
        stamp = datetime.fromisoformat(received or message["date"]).astimezone(zone)
        day = stamp.date()
        if not start <= day < today:
            continue
        for event in [message, *message.get("task_events", [])]:
            key = event.get("task_key")
            if not key:
                continue
            by_day = arrivals[key, message_client(message, event)]
            minute = stamp.hour * 60 + stamp.minute + stamp.second / 60
            if day not in by_day or minute < by_day[day][0]:
                by_day[day] = (minute, bool(received))
    rows = []
    for task in options:
        if task["scope"] != scope:
            continue
        dates = arrivals.get((task["key"], task.get("client", "")))
        if not dates or (today - max(dates)).days > 7:
            continue
        counts = Counter(day.weekday() for day in dates)
        first = min(dates)
        potential = Counter((first + timedelta(days=i)).weekday() for i in range((today - first).days))
        days = sorted(d for d, n in counts.items() if n >= 3 and n >= .75 * potential[d])
        selected = [entry for day, entry in dates.items() if day.weekday() in days]
        if not selected or len(selected) < .8 * len(dates):
            continue
        minutes = sorted(minute for minute, _ in selected)
        late = minutes[ceil(.9 * len(minutes)) - 1]
        early = minutes[ceil(.1 * len(minutes)) - 1]
        if late - early > 240 or late + 30 > 1439:
            continue
        limit = min(1439, 15 * ceil((late + 30) / 15))
        hour = f"{limit // 60:02d}:{limit % 60:02d}"
        rows.append({**task, "days": days, "time": hour, "observed": len(selected),
                     "expected": sum(potential[d] for d in days), "from": first.isoformat(),
                     "to": (today - timedelta(days=1)).isoformat(),
                     "header_dates": sum(not receipt for _, receipt in selected),
                     "token": identity(task["id"], days, hour)})
    return sorted(rows, key=lambda row: row["label"].casefold())


def activate_suggestions(directory, tokens):
    if not isinstance(tokens, list) or not 1 <= len(tokens) <= 500 or not all(isinstance(t, str) for t in tokens):
        raise ValueError("Coche les calendriers à activer.")
    root = private_dir(directory)
    with locked(directory / "export.lock"), locked(root / "monitoring.lock"):
        config = policy(directory)
        available = {row["token"]: row for row in read_json(directory / "exports/calendar-suggestions.json", [])}
        active = {row["id"]: row for row in config["schedules"]}
        additions = []
        for token in dict.fromkeys(tokens):
            row = available.get(token)
            if row is None:
                raise ValueError("Une proposition a changé. Vérifie les jours et l’heure avant de réessayer.")
            existing = active.get(row["id"])
            if existing:
                if existing["days"] == row["days"] and existing["time"] == row["time"]:
                    continue
                raise ValueError("Un calendrier a déjà été configuré pour cette tâche. Vérifie la sélection.")
            additions.append({k: row[k] for k in ("id", "scope", "key", "label", "days", "time", "client") if k in row})
        if len(active) + len(additions) > 500:
            raise ValueError("La limite est de 500 calendriers actifs.")
        if additions:
            since = datetime.now(timezone.utc).isoformat()
            config["schedules"].extend({**row, "since": since} for row in additions)
            write_private(root / "monitoring.json", config)
