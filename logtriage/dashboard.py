"""Lecture compacte des contrôles, de leur dernier signal et de leur historique du jour."""
from collections import defaultdict, deque
from .digest import day_bounds


def checks(tasks, messages, moment, tz):
    start, end = day_bounds(moment, tz)
    history = defaultdict(lambda: deque(maxlen=10))
    for m in sorted(messages, key=lambda row: row["date"]):
        if start <= m["date"] <= end:
            for e in [m, *m.get("task_events", [])]:
                if e.get("task_key"):
                    history[m["scope"], e["task_key"]].append([m["date"], e["execution"]])
    rows = []
    for t in tasks:
        missing = t.get("format") == "missing-report"
        state = t["state"]
        stamp = max(t["last_message_date"], t.get("resolved_at") or "")
        if state not in ("open", "warning") and not start <= stamp <= end:
            continue
        if missing and state not in ("open", "warning", "resolved"):
            continue
        parts = t["key"].removeprefix("missing|").split("|")
        host = parts[1] if len(parts) > 1 else "Source non identifiée"
        name = " · ".join([parts[0], *parts[2:]])
        rows.append({"host": host, "name": ("Rapport attendu · " if missing else "") + name,
                     "state": state, "missing": missing, "date": stamp,
                     "history": list(history[t["scope"], t["key"]])})
    return sorted(rows, key=lambda r: (r["host"].casefold(), r["name"].casefold()))
