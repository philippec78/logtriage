"""Domaine exact de l'expéditeur du message, utilisé pour le classement par client."""
import re
from collections import defaultdict
from difflib import SequenceMatcher
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
    if not key:
        return None
    if not domain:
        return (message["scope"], "", "Mail", message["sha256"]) if message.get("sha256") else None
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


def client_label(owner):
    if not owner or owner.startswith("@"):
        return "Non attribués"
    return owner


def device_key(source):
    scope, domain, kind, value = source[:4]
    if kind in ("NAS", "Onduleur", "Compte GitHub"):
        return scope, domain, kind, value
    if kind == "Contrôle":
        family, _, tail = value.partition("|")
        host = tail.partition("|")[0]
        if host and host not in ("inconnu", "inconnue", "unknown"):
            return scope, domain, family, host
    return None


@lru_cache(maxsize=4096)
def pattern(key):
    # Seules les dates complètes sont variables. Les numéros de VM et de NAS restent discriminants.
    value = re.sub(r"\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[./-]\d{1,2}[./-]\d{4})\b", " date ", key.casefold())
    value = re.sub(r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?[,]?\s+\d{4}\b", " date ", value)
    return tuple(re.findall(r"\w+", value))


class AssignmentLearner:
    """Plus proche exemple confirmé pour le même équipement ou compte."""
    def __init__(self, rules, start):
        self.examples = defaultdict(list)
        for row in rules:
            source = row["source"]
            if len(source) not in (4, 5):
                continue
            device = device_key(source)
            if device and (len(source) == 5 or source[2] == "Contrôle"):
                self.examples[device].append((pattern(source[-1]), row["client"], row.get("learned_since", start)))

    def predict(self, source, key, first_seen):
        examples = self.examples.get(device_key(source), ())
        if not examples:
            return None, None
        query = pattern(key)
        scores = {}
        equivalent = {}
        for sample, client, since in examples:
            if query == sample:
                equivalent[client] = min(equivalent.get(client, since), since)
            score = SequenceMatcher(None, query, sample, autojunk=False).ratio()
            scores[client] = max(scores.get(client, 0), score)
        if len(equivalent) == 1:
            owner, since = next(iter(equivalent.items()))
            if first_seen and first_seen >= since:
                return owner, None
        leaders = sorted(scores, key=scores.get, reverse=True)
        best = leaders[0]
        if scores[best] >= 0.5 and (len(leaders) == 1 or scores[best] - scores[leaders[1]] >= 0.2):
            return None, best
        return None, None


def assign_clients(messages, rules, start=""):
    targets = {tuple(row["source"]): row["client"] for row in rules}
    learner = AssignmentLearner(rules, start)
    first_seen = {}
    for m in messages:
        for e in [m, *m.get("task_events", [])]:
            if e.get("task_key") and m.get("imported_at"):
                key = (assignment_source(m, e), e["task_key"])
                first_seen[key] = min(first_seen.get(key, m["imported_at"]), m["imported_at"])
    predictions = {}
    for message in messages:
        fallback = "@" + sender_domain(message.get("sender", ""))
        owners = set()
        for event in [message, *message.get("task_events", [])]:
            if not event.get("task_key"):
                continue
            event.pop("suggested_client", None)
            source = assignment_source(message, event)
            client = None
            if source:
                key = event["task_key"]
                client = targets.get((*source, key), targets.get(source))
                if not client:
                    pair = source, key
                    if pair not in predictions:
                        predictions[pair] = learner.predict(source, key, first_seen.get(pair))
                    client, suggestion = predictions[pair]
                    if suggestion:
                        event["suggested_client"] = suggestion
            origin = fallback + "/" + source[3] if source and source[2] == "Compte GitHub" else fallback
            event["assigned_client"] = client or origin
            owners.add(event["assigned_client"])
        if len(owners) == 1:
            message["assigned_client"] = owners.pop()
        elif not message.get("task_key"):
            message["assigned_client"] = fallback
