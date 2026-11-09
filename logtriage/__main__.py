import argparse
import json
import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analyze import analyze
from .collector import poll
from .store import Store, atomic_json, now

LOG = logging.getLogger("logtriage")


def integer(name, default, minimum=1):
    value = int(os.environ.get(name, str(default)))
    if value < minimum:
        raise ValueError(f"{name} doit être >= {minimum}")
    return value


@dataclass
class Config:
    host: str
    port: int
    user: str
    password: str
    folder: str
    lookback_days: int
    interval: int
    batch_size: int
    max_bytes: int
    timeout: int

    @classmethod
    def load(cls):
        host, user = os.environ.get("IMAP_HOST", ""), os.environ.get("IMAP_USER", "")
        if not host or not user or host == "imap.example.com" or user == "logs@example.com":
            raise ValueError("Renseigne les variables IMAP_HOST et IMAP_USER")
        secret_file = os.environ.get("IMAP_PASSWORD_FILE")
        if secret_file:
            # Un fichier explicitement demandé reste prioritaire, sans repli silencieux.
            password = Path(secret_file).read_text(encoding="utf-8").rstrip("\r\n")
        elif "IMAP_PASSWORD" in os.environ:
            # Variables de stack Portainer : pas de fichier secret dans le dépôt Git.
            password = os.environ["IMAP_PASSWORD"]
        else:
            password = Path("/run/secrets/imap_password").read_text(encoding="utf-8").rstrip("\r\n")
        if not password or "\n" in password or "\r" in password:
            raise ValueError("Le mot de passe doit être renseigné sur une seule ligne")
        return cls(host, integer("IMAP_PORT", 993), user, password,
                   os.environ.get("IMAP_FOLDER", "INBOX"), integer("INITIAL_LOOKBACK_DAYS", 30),
                   integer("POLL_SECONDS", 300, 10), integer("MAX_MESSAGES_PER_POLL", 500),
                   integer("MAX_MESSAGE_BYTES", 20 * 1024**2), integer("IMAP_TIMEOUT_SECONDS", 45))


def load_rules():
    default = Path(__file__).resolve().parent.parent / "config" / "rules.json"
    rules = json.loads(Path(os.environ.get("RULES_FILE", str(default))).read_text(encoding="utf-8"))
    if rules["synology"].get("completion_is_recovery"):
        raise ValueError("La clôture par simple fin de tâche n’est pas autorisée dans cette version")
    if rules.get("expected_reports", {}).get("enabled"):
        raise ValueError("La surveillance des rapports manquants n’est pas implémentée dans cette version")
    if not 1 <= rules["wazuh"]["review_min_level"] <= rules["wazuh"]["urgent_min_level"]:
        raise ValueError("Seuils Wazuh invalides")
    if not 0 <= rules["openvas"]["notification_cvss"] <= 10:
        raise ValueError("Seuil OpenVAS invalide")
    for field in ("timeout_seconds", "max_pages", "max_characters"):
        if rules["pdf"][field] <= 0:
            raise ValueError("Limite PDF invalide")
    return rules


def health(directory):
    try:
        status = json.loads((directory / "status.json").read_text())
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(status["last_cycle_at"])).total_seconds()
        return 0 if status["state"] == "ok" and 0 <= age <= max(180, status["poll_seconds"] * 3) else 1
    except (OSError, ValueError, KeyError):
        return 1


def run_cycle(config, store, rules):
    from .settings import load_settings
    options = load_settings(store.directory)
    report_config = {**rules.get("report", {}), "max_groups": options["max_groups"]}
    status = {"last_cycle_at": now(), "poll_seconds": config.interval,
              "mode": "read_only", "state": "error"}
    try:
        stats = poll(config, store, rules)
        summary = store.export(os.environ.get("TZ", "Europe/Zurich"), report_config)
        status.update(last_cycle_at=now(), last_success_at=now(),
                      state="degraded" if stats["failures"] or stats["skipped"] else "ok",
                      collection=stats, summary=summary)
        LOG.info("Collecte terminée : %s nouveaux, %s doublons, %s en attente, %s non analysés",
                 stats["new"], stats["duplicate"], stats["pending"],
                 len(stats["failures"]) + len(stats["skipped"]))
    except Exception as exc:
        # Éviter d’afficher les réponses du serveur ou les secrets dans les logs.
        status["error_type"] = type(exc).__name__
        LOG.error("Collecte impossible (%s). Vérifie la connexion et la configuration.", type(exc).__name__)
        # Les résultats des messages déjà importés restent consultables.
        store.export(os.environ.get("TZ", "Europe/Zurich"), report_config)
    atomic_json(store.directory / "status.json", status)
    return status["state"] == "ok"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tri des logs email en lecture seule")
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("watch", "once", "export", "health", "web"):
        sub.add_parser(cmd)
    importer = sub.add_parser("import-eml")
    importer.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    directory = Path(os.environ.get("DATA_DIR", "/data"))
    if args.command == "health":
        return health(directory)
    if args.command == "web":
        from .web import start
        server = start(directory)
        stopped = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stopped.set())
        stopped.wait()
        server.application.stopped.set()
        server.shutdown()
        server.server_close()
        return 0
    store = None
    try:
        rules = load_rules()
        store = Store(directory)
        if args.command == "export":
            print(json.dumps(store.export(os.environ.get("TZ", "Europe/Zurich")), ensure_ascii=False))
            return 0
        if args.command == "import-eml":
            if not args.directory.is_dir():
                raise ValueError("Dossier source introuvable")
            paths = sorted(args.directory.glob("*.eml"))
            if not paths:
                raise ValueError("Aucun fichier .eml dans ce dossier")
            added = 0
            for path in paths:
                if path.stat().st_size > integer("MAX_MESSAGE_BYTES", 20 * 1024**2):
                    raise ValueError("Un fichier .eml dépasse MAX_MESSAGE_BYTES")
                result = analyze(path.read_bytes(), rules)
                reference = f"file:{path.resolve()}#{result['sha256']}"
                added += store.put(reference, "offline", result)
            print(json.dumps({"new": added, **store.export(os.environ.get("TZ", "Europe/Zurich"))}, ensure_ascii=False))
            return 0
        config = Config.load()
        if args.command == "once":
            return 0 if run_cycle(config, store, rules) else 1
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        web_server = None
        if os.environ.get("WEB_ENABLED", "false").lower() == "true":
            from .web import start
            web_server = start(directory)
        LOG.info("Démarrage en lecture seule : collecte toutes les %s secondes ; envoi uniquement à la demande.", config.interval)
        while not stop.is_set():
            from .settings import load_settings
            config.interval = load_settings(directory)["poll_seconds"]
            rules = load_rules()
            run_cycle(config, store, rules)
            status = json.loads((store.directory / "status.json").read_text())
            # Vider l'import et les réanalyses par lots, puis reprendre le rythme normal.
            pending = status.get("collection", {}).get("pending", 0)
            stop.wait(min(5, config.interval) if status["state"] == "ok" and pending else config.interval)
        if web_server:
            web_server.application.stopped.set()
            web_server.shutdown()
            web_server.server_close()
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        LOG.error("Configuration ou fichier invalide (%s). Consulte le guide de démarrage.", type(exc).__name__)
        return 2
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
