"""Domaine exact de l'expéditeur du message, utilisé pour le classement par client."""
import re
from email.utils import getaddresses
from functools import lru_cache


@lru_cache(maxsize=1024)
def sender_domain(header):
    addresses = getaddresses([header or ""])
    if len(addresses) != 1:
        return ""
    local, sep, domain = addresses[0][1].rpartition("@")
    if not local or not sep:
        return ""
    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    return domain if len(domain) <= 253 and re.fullmatch(label + r"(?:\." + label + r")*", domain) else ""


def message_client(message, event=None):
    if event is not None and "assigned_client" in event:
        return event["assigned_client"]
    if "assigned_client" in message:
        return message["assigned_client"]
    if message.get("format") == "missing-report":
        return message.get("client", "")
    return sender_domain(message.get("sender", ""))


def github_login(body):
    match = re.search(r"(?im)^\s*(?:hey|hello|hi|bonjour)\s+@?([a-z0-9][a-z0-9-]{0,38})[!,]\s*$", body)
    return match[1].lower() if match else ""


def assignment_source(message, event):
    """Critère exact dans une boîte et un domaine d'origine, indépendant du client attribué."""
    domain = sender_domain(message.get("sender", ""))
    key = event.get("task_key", "")
    if not key or not domain:
        return None
    family, _, tail = key.partition("|")
    host = tail.partition("|")[0]
    kind, value = "Contrôle", key
    if family.startswith("synology-") and host not in ("", "inconnu", "inconnue"):
        kind, value = "NAS", host
    elif family == "ups-monitoring" and host:
        kind, value = "Onduleur", re.split(r"\s+[-–—]\s+", host, maxsplit=1)[0]
    elif domain == "github.com" and family == "account-security":
        account = message.get("github_login")
        kind, value = ("Compte GitHub", account) if account else ("Mail", message["sha256"])
    return (message["scope"], domain, kind, value)


def assign_clients(messages, rules):
    targets = {tuple(row["source"]): row["client"] for row in rules}
    for message in messages:
        owners = set()
        for event in [message, *message.get("task_events", [])]:
            if not event.get("task_key"):
                continue
            source = assignment_source(message, event)
            client = None
            if source:
                client = targets.get((*source, event["task_key"]), targets.get(source))
            owner = client or sender_domain(message.get("sender", ""))
            if client or event is not message:
                event["assigned_client"] = owner
            owners.add(owner)
        if len(owners) == 1:
            message["assigned_client"] = owners.pop()
