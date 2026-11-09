"""Lecture compacte des contrôles, de leur dernier signal et de leur historique du jour."""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
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
            "execution": event["execution"], "points": points, "assignment_source": assignment_source(message, event),
            "suggested_client": event.get("suggested_client")}


HISTORY_DAYS = 7


def history_dates(today):
    return [(today - timedelta(days=offset)).isoformat() for offset in reversed(range(HISTORY_DAYS))]


def daily_history(signals, closures, days, zone, end):
    """Retenir ensemble la couleur et la source qui la justifie."""
    priority = {"success": 1, "warning": 2, "failure": 3}
    outcomes = {}
    for index, (stamp, result) in enumerate(signals):
        if stamp not in outcomes or priority.get(result, 0) > priority.get(outcomes[stamp][0], 0):
            outcomes[stamp] = (result, index)
    timeline = [(stamp, 0, result, index) for stamp, (result, index) in outcomes.items()]
    timeline.extend((stamp, 1, "manual", source) for stamp, source in closures)
    last_problem = None
    active = None
    by_day = {}
    for stamp, _, result, source in sorted(timeline):
        if stamp > end:
            break
        day = datetime.fromisoformat(stamp).astimezone(zone).date().isoformat()
        if result in ("failure", "warning"):
            last_problem = stamp
            if not active or result == "failure" or active[0] != "failure":
                active = (result, result, source, stamp)
            entry = active
        elif result == "success":
            entry = ("success", "recovered" if active else "success", source, stamp)
            last_problem = active = None
        elif result == "manual":
            if source != last_problem:
                continue
            entry = ("success", "manual", active[2], stamp)
            last_problem = active = None
        elif active:
            entry = active
        elif day in by_day and by_day[day][0][0] == "success":
            continue
        else:
            entry = ("unknown", "unknown", source, stamp)
        by_day[day] = (entry, active)
    earlier = max((day for day in by_day if day < days[0]), default=None)
    carried = by_day[earlier][1] if earlier else None
    entries = []
    for day in days:
        entry, carried = by_day.get(day, (carried, carried))
        if not entry:
            entries.append((day, "none", "none", None, None))
            continue
        state, reason, source, stamp = entry
        if carried and datetime.fromisoformat(stamp).astimezone(zone).date().isoformat() < day:
            reason = "carried"
        entries.append((day, state, reason, source, stamp))
    return entries


def source_detail(source, sources, key):
    message, event = source
    if message.get("format") == "missing-report":
        original = sources.get((key[0], key[1].removeprefix("missing|"), key[2], message.get("source_sha256")))
        if not original:
            return {"kind": "schedule", "summary": message["summary"], "date": message["date"]}, None
        message, event = original
    return mail_detail(message, event), message


def incident_detail_id(task):
    return identity("incident", task["scope"], task["key"], task.get("client", ""), task.get("problem_sha256"))


def checks(tasks, messages, moment, tz, manual_closures=None):
    zone = ZoneInfo(tz)
    days = history_dates(moment.astimezone(zone).date())
    daily_sources = defaultdict(list)
    problem_sources = {}

    start, end = day_bounds(moment, tz)
    history = defaultdict(lambda: deque(maxlen=10))
    sources = {}
    assignable = set()
    for m in sorted(messages, key=lambda row: row["date"]):
        for position, e in enumerate([m, *m.get("task_events", [])]):
            if e.get("task_key"):
                key = (m["scope"], e["task_key"], message_client(m, e))
                if m.get("format") != "missing-report" and assignment_source(m, e):
                    assignable.add(key)
                sources[(*key, m.get("sha256"))] = (m, e)
                daily_sources[key].append((m, e, position))
                if e["execution"] in ("failure", "warning"):
                    problem_sources[(*key, m.get("sha256"))] = (m, e)
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
        detail = source_detail(source, sources, key)[0] if source else None
        archive = daily_sources[key]
        signals = [(m["date"], e["execution"]) for m, e, _ in archive]
        days_info = daily_history(signals, (manual_closures or {}).get(key, []), days, zone, end)
        day_details, day_reasons = {}, {}
        for day, _, reason, index, at in days_info:
            detail_id = None
            if index is not None:
                m, e, position = archive[index]
                detail_id = identity("day-mail", *key, m.get("sha256"), position)
                if detail_id not in day_details:
                    facts, original = source_detail((m, e), sources, key)
                    locator = None
                    if original:
                        locator = {k: original.get(k) for k in ("scope", "sha256", "subject")}
                        locator["references"] = original.get("references", [])
                        facts["sender"] = original.get("sender", "")
                    day_details[detail_id] = (facts, locator)
            day_reasons[day] = {"reason": reason, "at": at, "detail_id": detail_id}
        issue_detail = None
        if t.get("signal_id") and state in ("open", "warning"):
            issue_source = problem_sources.get((*key, t.get("problem_sha256")))
            if issue_source:
                message, event = issue_source
                issue_detail = ({"kind": "schedule", "summary": message["summary"], "date": message["date"]}
                                if missing else mail_detail(message, event))
        regular = (key[0], key[1].removeprefix("missing|"), key[2])
        rows.append({"client": t.get("client", ""), "family": parts[0], "service": check_service(t["key"]), "check_type": check_type(t["key"]), "host": host, "name": ("Rapport attendu · " if missing else "") + name,
                     "state": state, "missing": missing, "date": stamp,
                     "suggested_client": source[1].get("suggested_client") if source else None,
                     "bulk_id": identity(*regular) if regular in assignable else None,
                     "detail_id": identity(*key, t.get("message_sha256")), "detail": detail,
                     "incident_detail_id": incident_detail_id(t) if issue_detail else None, "incident_detail": issue_detail,
                     "daily_history": [[day, state] for day, state, *_ in days_info],
                     "day_reasons": day_reasons, "day_details": day_details,
                     "history": list(history[key])})
    return sorted(rows, key=lambda r: (r["host"].casefold(), r["name"].casefold()))
