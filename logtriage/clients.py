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


def message_client(message):
    if message.get("format") == "missing-report":
        return message.get("client", "")
    return sender_domain(message.get("sender", ""))
