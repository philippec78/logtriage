"""Réglages de présentation et d'envoi, distincts des secrets IMAP."""
import os
import re
from pathlib import Path

from .private import locked, private_dir, read_json, write_private


def defaults():
    return {"max_groups": 20, "poll_seconds": int(os.environ.get("POLL_SECONDS", "300")),
            "recipient": os.environ.get("REPORT_TO", ""), "sender": os.environ.get("SMTP_FROM") or os.environ.get("IMAP_USER", ""),
            "smtp_host": os.environ.get("SMTP_HOST", ""), "smtp_port": int(os.environ.get("SMTP_PORT", "465")),
            "use_imap_credentials": os.environ.get("SMTP_USE_IMAP_CREDENTIALS", "false").lower() == "true",
            "ai_model": "", "ai_instructions": "", "ai_enabled": False, "ai_review_unknown": False}


def load_settings(directory):
    saved = read_json(Path(directory) / "private/settings.json", {})
    return {**defaults(), **{k: v for k, v in saved.items() if k in defaults()}}


def save_settings(directory, update):
    from .report import email_address
    if not isinstance(update, dict) or set(update) - set(defaults()):
        raise ValueError("Réglage non reconnu.")
    root = private_dir(directory)
    with locked(root / "settings.lock"):
        value = {**load_settings(directory), **update}
        for name, low, high in (("max_groups", 1, 100), ("poll_seconds", 30, 86400), ("smtp_port", 1, 65535)):
            if type(value[name]) is not int or not low <= value[name] <= high:
                raise ValueError(f"Valeur hors limites : {name}.")
        for name in ("ai_enabled", "ai_review_unknown", "use_imap_credentials"):
            if type(value[name]) is not bool:
                raise ValueError("Choix invalide.")
        for name in ("recipient", "sender", "smtp_host", "ai_model", "ai_instructions"):
            if not isinstance(value[name], str):
                raise ValueError("Texte attendu.")
            value[name] = value[name].strip()
        for name in ("recipient", "sender"):
            if value[name]:
                value[name] = email_address(value[name])
        if value["smtp_host"] and not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", value["smtp_host"]):
            raise ValueError("Nom du serveur SMTP invalide.")
        if value["ai_model"] and not re.fullmatch(r"[a-zA-Z0-9._:-]{1,120}", value["ai_model"]):
            raise ValueError("Modèle invalide.")
        if len(value["ai_instructions"]) > 1500:
            raise ValueError("Les consignes sont limitées à 1 500 caractères.")
        write_private(root / "settings.json", value)
        return value
