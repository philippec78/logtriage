"""Lecture compacte des contrôles, de leur dernier signal et de leur historique du jour."""
from collections import defaultdict, deque
from .check_types import check_service, check_type
from .clients import assignment_source, message_client
from .digest import day_bounds, readable
from .monitoring import identity


def mail_detail(message, event):
    # Nettoyer avant de raccourcir pour éviter de couper un secret au milieu.
    from .unknown_review import scrub

    def compact(value, limit):
        return readable(scrub(value), limit) if isinstance(value, str) else ""

    subject = compact(message.get("subject"), 320)
    summary = compact(event.get("summary") or message.get("summary"), 520)
    facts = list(event.get("evidence", []))
    if event is message:
        facts.extend(message.get("report_fields", []))
        facts.extend(o.get("summary") for o in message.get("observations", [])[:5])
    points = []
    for fact in facts:
        text = compact(fact, 280)
        if text and text not in (subject, summary) and text not in points:
            points.append(text)
            if len(points) == 5:
                break
    return {"kind": "mail", "subject": subject, "summary": summary, "date": message["date"],
            "execution": event["execution"], "points": points, "assignment_source": assignment_source(message, event)}


def checks(tasks, messages, moment, tz):
    start, end = day_bounds(moment, tz)
    history = defaultdict(lambda: deque(maxlen=10))
    sources = {}
    assignable = set()
    for m in sorted(messages, key=lambda row: row["date"]):
        for e in [m, *m.get("task_events", [])]:
            if e.get("task_key"):
                key = (m["scope"], e["task_key"], message_client(m, e))
                if m.get("format") != "missing-report" and assignment_source(m, e):
                    assignable.add(key)
                sources[(*key, m.get("sha256"))] = (m, e)
                if start <= m["date"] <= end:
                    history[key].append([m["date"], e["execution"]])
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
        name = " · ".join(parts[2:]) or host
        key = (t["scope"], t["key"], t.get("client", ""))
        source = sources.get((*key, t.get("message_sha256")))
        detail = None
        if source:
            message, event = source
            if missing:
                original = sources.get((key[0], key[1].removeprefix("missing|"), key[2], message.get("source_sha256")))
                if original:
                    detail = mail_detail(*original)
                else:
                    detail = {"kind": "schedule", "summary": message["summary"], "date": message["date"]}
            else:
                detail = mail_detail(message, event)
        regular = (key[0], key[1].removeprefix("missing|"), key[2])
        rows.append({"client": t.get("client", ""), "family": parts[0], "service": check_service(t["key"]), "check_type": check_type(t["key"]), "host": host, "name": ("Rapport attendu · " if missing else "") + name,
                     "state": state, "missing": missing, "date": stamp,
                     "bulk_id": identity(*regular) if regular in assignable else None,
                     "detail_id": identity(*key, t.get("message_sha256")), "detail": detail,
                     "history": list(history[t["scope"], t["key"], t.get("client", "")])})
    return sorted(rows, key=lambda r: (r["host"].casefold(), r["name"].casefold()))
