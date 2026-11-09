"""Envoi ponctuel d’un bilan existant. Aucun envoi depuis le collecteur."""
import argparse
import json
import os
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path
from zoneinfo import ZoneInfo

from .__main__ import Config
from .store import atomic_json


def email_address(value):
    if "\r" in value or "\n" in value:
        raise ValueError("Adresse email invalide")
    address = Address(addr_spec=value)
    if not address.username or not address.domain:
        raise ValueError("Adresse email complète requise")
    return address.addr_spec


def prepare_report(directory, recipient, sender, current_time=None, report_text=None):
    recipient, sender = email_address(recipient), email_address(sender)
    current_time = current_time or datetime.now(timezone.utc)
    summary = json.loads((directory / "exports/summary.json").read_text(encoding="utf-8"))
    status = json.loads((directory / "status.json").read_text(encoding="utf-8"))
    report = report_text if report_text is not None else (directory / "exports/bilan.txt").read_text(encoding="utf-8")
    if not summary.get("total_messages"):
        raise ValueError("Aucun email analysé : attends la première collecte")
    generated = datetime.fromisoformat(summary["generated_at"])
    cycle = datetime.fromisoformat(status["last_cycle_at"])
    if generated.tzinfo is None or cycle.tzinfo is None:
        raise ValueError("Horodatage du rapport invalide")
    warnings = []
    age = (current_time - generated).total_seconds()
    if age > max(900, int(status.get("poll_seconds", 300)) * 3):
        warnings.append("ATTENTION : ce bilan est ancien ; vérifie la collecte dans Portainer.")
    if status.get("state") != "ok":
        warnings.append("ATTENTION : la dernière collecte est en erreur ou incomplète. Le bilan reflète les résultats disponibles.")
    pending = status.get("collection", {}).get("pending", 0)
    if pending:
        warnings.append(f"ATTENTION : {pending} message(s) restent en attente d’analyse.")
    zone = ZoneInfo(os.environ.get("TZ", "Europe/Zurich"))
    header = ["Rapport ponctuel des emails de logs", "",
              f"Bilan généré le {generated.astimezone(zone):%d.%m.%Y à %H:%M:%S %Z}.",
              *warnings, ""]
    report = report.replace("Mode : lecture seule, aucun envoi",
                            "Mode : boîte consultée en lecture seule ; rapport envoyé à la demande.")
    msg = EmailMessage()
    msg["From"], msg["To"] = sender, recipient
    msg["Subject"] = f"Logs serveurs — bilan du {current_time.astimezone(zone):%d.%m.%Y à %H:%M}"
    msg["Date"], msg["Message-ID"] = format_datetime(current_time), make_msgid(domain=sender.split("@")[1])
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content("\n".join(header) + "\n" + report)
    return msg


def smtp_credentials(use_imap):
    if use_imap:
        config = Config.load()
        return config.user, config.password
    user = os.environ.get("SMTP_USER", "")
    password_file = os.environ.get("SMTP_PASSWORD_FILE")
    password = (Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
                if password_file else os.environ.get("SMTP_PASSWORD", ""))
    if not user or not password or "\r" in password or "\n" in password:
        raise ValueError("Renseigne SMTP_USER et SMTP_PASSWORD, ou choisis explicitement les identifiants IMAP")
    return user, password


def send_report(msg, host, port, username, password, factory=None):
    if not host or not 1 <= port <= 65535:
        raise ValueError("Serveur ou port SMTP invalide")
    factory = factory or smtplib.SMTP_SSL
    with factory(host, port, timeout=45, context=ssl.create_default_context()) as smtp:
        smtp.login(username, password)
        refused = smtp.send_message(msg, from_addr=str(msg["From"]), to_addrs=[str(msg["To"])])
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Envoyer une fois le bilan réel du conteneur par SMTP sur TLS")
    parser.add_argument("--to", required=True, help="Adresse destinataire unique")
    parser.add_argument("--from", dest="sender", default=os.environ.get("SMTP_FROM", ""))
    parser.add_argument("--smtp-host", default=os.environ.get("SMTP_HOST", ""))
    parser.add_argument("--smtp-port", type=int, default=int(os.environ.get("SMTP_PORT", "465")))
    parser.add_argument("--use-imap-credentials", action="store_true")
    parser.add_argument("--preview", action="store_true", help="Afficher le bilan sans connexion SMTP")
    args = parser.parse_args(argv)
    directory = Path(os.environ.get("DATA_DIR", "/data"))
    try:
        # Lecture des exports existants seulement : pas de collecte ni de réécriture
        # concurrente de la base et des bilans utilisés par le processus principal.
        sender = args.sender or os.environ.get("IMAP_USER" if args.use_imap_credentials else "SMTP_USER", "")
        msg = prepare_report(directory, args.to, sender)
        if args.preview:
            print(msg.get_content())
            return 0
        username, password = smtp_credentials(args.use_imap_credentials)
        send_report(msg, args.smtp_host, args.smtp_port, username, password)
        atomic_json(directory / "last-report-send.json",
                    {"accepted_at": datetime.now(timezone.utc).isoformat(), "recipient": args.to,
                     "message_id": str(msg["Message-ID"]), "smtp_host": args.smtp_host,
                     "status": "accepted_by_smtp"})
        print("Rapport accepté par le serveur SMTP pour " + args.to + ".")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Pas de contenu de message ni de réponse serveur potentiellement sensible.
        print(f"Envoi non confirmé ({type(exc).__name__}). Vérifie le bilan et la configuration SMTP.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
