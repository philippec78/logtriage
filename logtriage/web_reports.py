"""Prévisualisation figée puis envoi explicite, sans écriture dans la boîte IMAP."""
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from .ai_report import ReportAgent, annotate
from .digest import render_digest
from .openai_http import OpenAIError
from .private import private_dir, read_json, write_private
from .report import prepare_report, send_report, smtp_credentials
from .settings import load_settings
from .store import atomic_json
from .unknown_review import review_unknown

ERRORS = {"usage_limit": "La limite d’utilisation ChatGPT est atteinte. Gère ton utilisation dans ChatGPT ou utilise le bilan classique.",
          "login_required": "Reconnecte ton compte ChatGPT pour utiliser l’IA.",
          "plan_permission_missing": "L’autorisation d’utiliser ton abonnement ChatGPT n’a pas été accordée.",
          "identity_not_verified": "L’identité du compte ChatGPT n’a pas pu être vérifiée.",
          "account_changed": "Le compte ChatGPT a changé. Prépare à nouveau le rapport."}


def error_message(error):
    return ERRORS.get(getattr(error, "code", ""), "L’analyse IA est indisponible ou n’a pas pu être validée. Le bilan classique est conservé.")


def settings_digest(settings):
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()


class WebReports:
    def __init__(self, directory, chatgpt):
        self.directory, self.chatgpt = Path(directory), chatgpt
        self.root = private_dir(directory)
        self.path = self.root / "report-preview.json"
        self.lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.job = {"state": "idle"}
        previous = read_json(self.path, {})
        if previous.get("delivery") == "sending":
            previous.update(delivery="uncertain", delivery_message="Le service a redémarré pendant un envoi. Vérifie ta boîte avant de préparer un autre envoi.")
            write_private(self.path, previous)

    def state(self):
        return {"job": dict(self.job), "preview": read_json(self.path),
                "last_send": read_json(self.directory / "last-report-send.json")}

    def _background(self, action):
        if not self.lock.acquire(blocking=False):
            raise ValueError("Une préparation ou un envoi est déjà en cours.")
        self.job = {"state": "running", "kind": action[0]}
        def work():
            try:
                action[1]()
                self.job = {"state": "done", "kind": action[0]}
            except Exception as exc:
                message = str(exc) if type(exc) is ValueError else "Opération non confirmée. Vérifie les réglages et réessaie."
                self.job = {"state": "error", "kind": action[0], "message": message}
            finally:
                self.lock.release()
        threading.Thread(target=work, daemon=True, name="report-job").start()

    def preview(self, use_ai):
        self._background(("preview", lambda: self._preview(use_ai)))

    def _preview(self, use_ai):
        settings = load_settings(self.directory)
        if not settings["recipient"] or not settings["sender"]:
            raise ValueError("Renseigne le destinataire et l’expéditeur dans les réglages.")
        export = self.directory / "exports"
        summary = read_json(export / "summary.json")
        messages = read_json(export / "messages.json", [])
        tasks = read_json(export / "tasks.json", [])
        observations = read_json(export / "observations.json", [])
        if not summary or not summary.get("total_messages"):
            raise ValueError("Attends la première collecte avant de préparer un rapport.")
        # Le rapport est régénéré à partir des exports disponibles, sans lancer de collecte concurrente.
        import os
        now = datetime.now(timezone.utc)
        digest_args = (summary, messages, tasks, observations, os.environ.get("TZ", "Europe/Zurich"), settings, now)
        report = render_digest(*digest_args)
        ai = {"requested": use_ai, "state": "disabled", "message": "", "usage": {}}
        if use_ai:
            try:
                if not settings["ai_enabled"]:
                    raise ValueError("Active l’IA dans les réglages pour utiliser ton abonnement ChatGPT.")
                if settings["ai_model"] not in {m["slug"] for m in self.chatgpt.cached_models()}:
                    raise ValueError("Actualise les modèles et sélectionne un modèle disponible dans les réglages.")
                profile = self.chatgpt.state()["active"]
                if settings["ai_review_unknown"]:
                    reviews, coverage = review_unknown(self.chatgpt, settings["ai_model"], messages,
                                                       settings["window_hours"], now, profile)
                    if coverage:
                        report = render_digest(*digest_args, unknown_reviews=reviews) + "\n" + coverage + "\n"
                notes, usage = ReportAgent(self.chatgpt, settings["ai_model"], report, messages,
                                           settings["ai_instructions"], profile=profile).run()
                report = annotate(report, notes)
                ai.update(state="completed", usage=usage)
            except (OpenAIError, ValueError) as exc:
                ai.update(state="fallback", message=str(exc) if type(exc) is ValueError else error_message(exc))
        msg = prepare_report(self.directory, settings["recipient"], settings["sender"], report_text=report)
        write_private(self.path, {"id": secrets.token_urlsafe(24), "created_at": datetime.now(timezone.utc).isoformat(),
            "recipient": settings["recipient"], "sender": settings["sender"], "subject": str(msg["Subject"]),
            "body": msg.get_content(), "ai": ai, "settings_digest": settings_digest(settings), "delivery": "not_sent"})

    def send(self, identity):
        preview = read_json(self.path, {})
        if preview.get("id") != identity or preview.get("delivery") != "not_sent":
            raise ValueError("Ce rapport a déjà été envoyé ou remplacé. Prépare un nouvel aperçu si nécessaire.")
        self._background(("send", lambda: self._send(identity)))

    def _send(self, identity):
        from email.message import EmailMessage
        from email.utils import format_datetime, make_msgid
        preview = read_json(self.path, {})
        settings = load_settings(self.directory)
        if preview.get("id") != identity or preview.get("delivery") != "not_sent" or preview.get("settings_digest") != settings_digest(settings):
            raise ValueError("Les réglages ou l’aperçu ont changé. Prépare à nouveau le rapport.")
        created = datetime.fromisoformat(preview["created_at"])
        if (datetime.now(timezone.utc) - created).total_seconds() > 900:
            raise ValueError("L’aperçu a plus de 15 minutes. Prépare un bilan actualisé.")
        if not settings["smtp_host"]:
            raise ValueError("Renseigne le serveur SMTP dans les réglages.")
        # Les contrôles de disponibilité précèdent la marque d'envoi non réessayable.
        user, password = smtp_credentials(settings["use_imap_credentials"])
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = preview["sender"], preview["recipient"], preview["subject"]
        msg["Date"] = format_datetime(datetime.now(timezone.utc))
        msg["Message-ID"] = make_msgid(domain=preview["sender"].split("@")[1])
        msg["Auto-Submitted"] = "auto-generated"
        msg.set_content(preview["body"])
        preview["delivery"] = "sending"
        write_private(self.path, preview)
        try:
            send_report(msg, settings["smtp_host"], settings["smtp_port"], user, password)
        except Exception:
            preview.update(delivery="uncertain", delivery_message="Envoi non confirmé. Vérifie ta boîte avant de recommencer ; aucun nouvel essai automatique n’est effectué.")
            write_private(self.path, preview)
            raise ValueError(preview["delivery_message"]) from None
        receipt = {"accepted_at": datetime.now(timezone.utc).isoformat(), "recipient": preview["recipient"],
                   "message_id": str(msg["Message-ID"]), "smtp_host": settings["smtp_host"], "status": "accepted_by_smtp"}
        atomic_json(self.directory / "last-report-send.json", receipt)
        preview.update(delivery="accepted", delivery_message="Rapport accepté par le serveur SMTP.")
        write_private(self.path, preview)
