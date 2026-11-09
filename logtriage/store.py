import collections
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .digest import derive_state, render_digest


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


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
        """)

    def close(self):
        self.db.close()

    def seen(self, reference, revision=None):
        row = self.db.execute("SELECT m.result FROM refs r JOIN messages m ON "
                              "r.scope=m.scope AND r.sha=m.sha WHERE r.ref=?", (reference,)).fetchone()
        return row is not None and (revision is None or json.loads(row[0]).get("analysis_revision") == revision)

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

    def export(self, tz="Europe/Zurich", report_config=None):
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
        tasks, observations = derive_state(messages)
        export = self.directory / "exports"
        counts = dict(collections.Counter(m["category"] for m in messages))
        summary = {"generated_at": now(), "mode": "read_only", "total_messages": len(messages),
                   "categories": counts, "open_tasks": sum(t["state"] == "open" for t in tasks.values()),
                   "observation_groups": len(observations), "expected_reports_enabled": False,
                   "recognized_messages": sum(bool(m.get("recognized")) for m in messages),
                   "unrecognized_messages": sum(not m.get("recognized") for m in messages),
                   "formats": dict(collections.Counter(m.get("format", "unknown") for m in messages)),
                   "outgoing_notifications_enabled": False}
        atomic_json(export / "messages.json", messages)
        atomic_json(export / "tasks.json", list(tasks.values()))
        atomic_json(export / "observations.json", list(observations.values()))
        atomic_json(export / "summary.json", summary)
        local_day = datetime.now(ZoneInfo(tz)).date().isoformat()
        text = render_digest(summary, messages, list(tasks.values()), list(observations.values()), tz, report_config)
        export.mkdir(parents=True, exist_ok=True)
        temporary = export / "bilan.txt.tmp"
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, export / "bilan.txt")
        (export / "daily").mkdir(exist_ok=True)
        (export / "daily" / f"{local_day}.txt").write_text(text, encoding="utf-8")
        return summary
