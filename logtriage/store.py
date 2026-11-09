import collections
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


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

    def export(self, tz="Europe/Zurich"):
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
        tasks, observations = {}, {}
        for m in messages:
            if m["task_key"]:
                identity = m["scope"] + "|" + m["task_key"]
                task = tasks.setdefault(identity, {"key": m["task_key"], "scope": m["scope"],
                                                    "state": "unknown", "failures": [],
                                                    "last_failure": None, "last_success": None})
                task["last_message_date"] = m["date"]
                if m["execution"] == "failure":
                    task["state"] = "open"
                    task["last_failure"] = m["date"]
                    task["failures"].append({"date": m["date"], "message_sha256": m["sha256"],
                                              "evidence": m["evidence"],
                                              "signature": m.get("error_signature")})
                elif m["execution"] == "success":
                    # En cas d’horodatage identique : conserver l’échec comme ouvert.
                    if not task["last_failure"] or m["date"] > task["last_failure"]:
                        task["state"] = "resolved" if task["last_failure"] else "ok"
                    task["last_success"] = m["date"]
                task["latest_category"] = m["category"]
            for item in m["observations"]:
                identity = m["scope"] + "|" + item["key"]
                old = observations.get(identity)
                observations[identity] = {**item, "scope": m["scope"],
                                           "first_seen": old["first_seen"] if old else m["date"],
                                           "last_seen": m["date"], "message_sha256": m["sha256"],
                                           "reports_seen": (old["reports_seen"] if old else 0) + 1}
        export = self.directory / "exports"
        counts = dict(collections.Counter(m["category"] for m in messages))
        summary = {"generated_at": now(), "mode": "read_only", "total_messages": len(messages),
                   "categories": counts, "open_tasks": sum(t["state"] == "open" for t in tasks.values()),
                   "observation_groups": len(observations), "expected_reports_enabled": False,
                   "outgoing_notifications_enabled": False}
        atomic_json(export / "messages.json", messages)
        atomic_json(export / "tasks.json", list(tasks.values()))
        atomic_json(export / "observations.json", list(observations.values()))
        atomic_json(export / "summary.json", summary)
        local_day = datetime.now(ZoneInfo(tz)).date().isoformat()
        # Le bilan courant inclut les incidents ouverts, même anciens.
        lines = [f"Bilan local du {local_day} ({tz})", "Mode : lecture seule, aucun envoi",
                 f"Emails analysés : {len(messages)}", f"Tâches en échec ouvert : {summary['open_tasks']}",
                 "", "TÂCHES EN ÉCHEC"]
        for task in tasks.values():
            if task["state"] == "open":
                lines.append(f"- {task['key']} : {len(task['failures'])} échec(s) dans l’historique ; dernier {task['last_failure']}")
                for failure in task["failures"][-3:]:
                    lines.append("  " + failure["date"] + " : " + "; ".join(failure["evidence"]))
        lines += ["", "OBSERVATIONS À VÉRIFIER (historiques ; résolution non confirmée)"]
        lines += [f"- {o['key']} : {o['summary']} (dernier rapport {o['last_seen']})"
                  for o in observations.values()]
        lines += ["", "EMAILS À VÉRIFIER / AVERTISSEMENTS DE COUVERTURE"]
        lines += [f"- {m['subject']} : {m['summary']} ; " + ", ".join(m["coverage_warnings"])
                  for m in messages if m["category"] == "a_verifier" or m["coverage_warnings"]]
        lines += ["", "Les absences de rapport ne sont pas surveillées tant que les calendriers ne sont pas définis.",
                  "Les compteurs Wazuh sont des détections, pas des incidents uniques."]
        text = "\n".join(lines) + "\n"
        export.mkdir(parents=True, exist_ok=True)
        temporary = export / "bilan.txt.tmp"
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, export / "bilan.txt")
        (export / "daily").mkdir(exist_ok=True)
        (export / "daily" / f"{local_day}.txt").write_text(text, encoding="utf-8")
        return summary
