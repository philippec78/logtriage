import collections
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .calendar_suggestions import suggestions
from .check_types import check_service, check_type
from .clients import message_client
from .dashboard import checks
from .digest import day_messages, derive_state, render_digest
from .user_rules import apply_rules
from .monitoring import bind_old_schedules, identity, policy, reliable, schedule_events, task_options
from .private import locked, read_json


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def daily_counts(messages, moment, tz):
    today = day_messages(messages, moment, tz)
    by_client = {}
    for message in today:
        counts = by_client.setdefault(message_client(message), {"messages": 0, "unknown": 0})
        counts["messages"] += 1
        counts["unknown"] += not message.get("recognized")
    return {"clients_today": by_client, "report_day": moment.astimezone(ZoneInfo(tz)).date().isoformat(), "today_messages": len(today),
            "today_unknown": sum(not m.get("recognized") for m in today)}


def current_bilan(directory, moment, tz, settings):
    """À minuit, présenter le nouveau jour même si la collecte suivante n’a pas encore eu lieu."""
    export = directory / "exports"
    with locked(directory / "export.lock"):
        summary = read_json(export / "summary.json")
        if not summary:
            return {}, ""
        available = reliable(read_json(directory / "status.json", {}), moment) if summary.get("expected_reports_enabled") else None
        refresh_health = available is False and summary.get("monitoring_available")
        if refresh_health:
            summary["monitoring_available"] = False
        if not refresh_health and summary.get("report_day") == moment.astimezone(ZoneInfo(tz)).date().isoformat():
            return summary, (export / "bilan.txt").read_text(encoding="utf-8")
        messages = read_json(export / "messages.json", [])
        summary.update(daily_counts(messages, moment, tz))
        return summary, render_digest(summary, messages, read_json(export / "tasks.json", []),
                                     read_json(export / "observations.json", []), tz, settings, moment)


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory / "history.sqlite3", timeout=30)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS messages (
                scope TEXT NOT NULL, sha TEXT NOT NULL, result TEXT NOT NULL,
                imported_at TEXT NOT NULL, PRIMARY KEY(scope, sha)
            );
            CREATE TABLE IF NOT EXISTS refs (
                ref TEXT PRIMARY KEY, scope TEXT NOT NULL, sha TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resolutions (
                signal TEXT PRIMARY KEY, scope TEXT NOT NULL, task TEXT NOT NULL, resolved_at TEXT NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def seen(self, reference, revision=None, body_revision=None):
        row = self.db.execute("SELECT m.result FROM refs r JOIN messages m ON "
                              "r.scope=m.scope AND r.sha=m.sha WHERE r.ref=?", (reference,)).fetchone()
        if row is None:
            return False
        message = json.loads(row[0])
        return ((revision is None or message.get("analysis_revision") == revision)
                and (not body_revision or message.get("recognized") or message.get("body_revision") == body_revision))

    def set_setting(self, key, value):
        with self.db:
            self.db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (key, value))

    def setting(self, key, default):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, default))
        return self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()[0]

    def put(self, reference, scope, result):
        with self.db:
            before = self.db.total_changes
            self.db.execute("INSERT OR IGNORE INTO messages VALUES (?,?,?,?)",
                            (scope, result["sha256"], json.dumps(result, ensure_ascii=False), now()))
            inserted = self.db.total_changes > before
            if not inserted:
                self.db.execute("UPDATE messages SET result=? WHERE scope=? AND sha=?",
                                (json.dumps(result, ensure_ascii=False), scope, result["sha256"]))
            self.db.execute("INSERT OR IGNORE INTO refs VALUES (?,?,?)", (reference, scope, result["sha256"]))
        return inserted

    def export(self, tz="Europe/Zurich", report_config=None, resolve_signal=None, *, resolve_signals=(), collection_status=None):
        signals = (resolve_signal,) if resolve_signal is not None else resolve_signals
        with locked(self.directory / "export.lock"):
            return self._export(tz, report_config, signals, collection_status)

    def _export(self, tz, report_config, signals, collection_status):
        rows = self.db.execute("SELECT scope,sha,result,imported_at FROM messages").fetchall()
        messages = []
        for scope, sha, payload, imported in rows:
            result = json.loads(payload)
            result.update(scope=scope, imported_at=imported,
                          references=[r[0] for r in self.db.execute(
                              "SELECT ref FROM refs WHERE scope=? AND sha=? ORDER BY ref", (scope, sha))])
            messages.append(result)
        messages.sort(key=lambda r: (r["date"], r["sha256"]))
        # Recalcul chronologique : un email ancien importé tardivement ne rouvre pas
        # un incident dont une réussite plus récente est déjà connue.
        moment = datetime.now(timezone.utc)
        config = policy(self.directory)
        status = collection_status if collection_status is not None else read_json(self.directory / "status.json", {})
        messages = [apply_rules(m, config["rules"]) for m in messages] if config["rules"] else messages
        if any("client" not in row for row in config["schedules"]):
            options = task_options({"scope": m["scope"], "key": e["task_key"], "client": message_client(m)}
                                   for m in messages for e in [m, *m.get("task_events", [])] if e.get("task_key"))
            config = bind_old_schedules(self.directory, options, moment)
        scheduled = schedule_events(config["schedules"], messages, status, moment, tz)
        state_events = messages + scheduled
        resolutions = dict(self.db.execute("SELECT signal,resolved_at FROM resolutions"))
        tasks, observations = derive_state(state_events, resolutions)
        pending_ids = set(signals).difference(resolutions)
        if pending_ids:
            open_tasks = {t["signal_id"]: t for t in tasks.values() if t["state"] in ("open", "warning")}
            if not pending_ids.issubset(open_tasks):
                raise ValueError("Un incident sélectionné a changé. Vérifie ta sélection avant de réessayer.")
            at = now()
            with self.db:
                self.db.executemany("INSERT INTO resolutions VALUES (?,?,?,?)",
                                    [(key, open_tasks[key]["scope"], open_tasks[key]["key"], at) for key in pending_ids])
            resolutions.update(dict.fromkeys(pending_ids, at))
            tasks, observations = derive_state(state_events, resolutions)
        export = self.directory / "exports"
        counts = dict(collections.Counter(m["category"] for m in messages))
        summary = {**daily_counts(messages, moment, tz), "generated_at": moment.isoformat(), "mode": "read_only", "total_messages": len(messages),
                   "categories": counts, "open_tasks": sum(t["state"] == "open" for t in tasks.values()),
                   "resolution_count": len(resolutions),
                   "observation_groups": len(observations), "expected_reports_enabled": bool(config["schedules"]),
                   "policy_id": identity(config), "monitoring_available": reliable(status, moment),
                   "recognized_messages": sum(bool(m.get("recognized")) for m in messages),
                   "unrecognized_messages": sum(not m.get("recognized") for m in messages),
                   "formats": dict(collections.Counter(m.get("format", "unknown") for m in messages)),
                   "outgoing_notifications_enabled": False}
        atomic_json(export / "messages.json", messages)
        atomic_json(export / "tasks.json", list(tasks.values()))
        options = task_options(tasks.values())
        atomic_json(export / "monitor-options.json", options)
        atomic_json(export / "calendar-suggestions.json", suggestions(messages, options, status.get("scope"), moment, tz))
        check_rows = checks(tasks.values(), state_events, moment, tz)
        details = {row["detail_id"]: row.pop("detail") for row in check_rows}
        atomic_json(export / "check-details.json", details)
        atomic_json(export / "checks.json", {"day": summary["report_day"], "items": check_rows})
        unknown = [{"id": m["sha256"], "scope": m["scope"], "subject": m["subject"], "sender": m["sender"]}
                   for m in reversed(day_messages(messages, moment, tz)) if m.get("recognized") is False]
        atomic_json(export / "rule-options.json", {"day": summary["report_day"], "items": unknown})
        pending = [{"id": t["signal_id"], "client": t["client"], "service": check_service(t["key"]), "check_type": check_type(t["key"]), "summary": t.get("summary") or t["key"],
                    "missing": t.get("format") == "missing-report", "severity": t["state"], "date": t["last_problem"]} for t in tasks.values()
                   if t["state"] in ("open", "warning")]
        pending.sort(key=lambda t: t["date"], reverse=True)
        pending.sort(key=lambda t: t["severity"] != "open")
        atomic_json(export / "open-incidents.json", pending)
        atomic_json(export / "observations.json", list(observations.values()))
        atomic_json(export / "summary.json", summary)
        local_day = summary["report_day"]
        text = render_digest(summary, messages, list(tasks.values()), list(observations.values()), tz, report_config, moment)
        export.mkdir(parents=True, exist_ok=True)
        temporary = export / "bilan.txt.tmp"
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, export / "bilan.txt")
        (export / "daily").mkdir(exist_ok=True)
        (export / "daily" / f"{local_day}.txt").write_text(text, encoding="utf-8")
        return summary
