"""Règles locales proposées sur un format inconnu puis essayées sur des exemples."""
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

from .analyze import norm
from .monitoring import change, identity, policy
from .private import locked, private_dir, read_json, write_private

OUTCOMES = {"failure": ("echec", "Échec"), "warning": ("avertissement", "Avertissement"),
            "completed": ("fin_annoncee", "Fin annoncée"), "success": ("reussite_signalee", "Réussite confirmée")}


def sender(message):
    return parseaddr(message.get("sender", ""))[1].casefold()


def literal(phrase, text):
    pattern = re.escape(norm(phrase))
    return re.search(r"(?<!\w)" + pattern + r"(?!\w)", norm(text)) is not None


def family(rule, message):
    return (rule["scope"] == message.get("scope") and sender(message) == rule["sender"]
            and literal(rule["family"], message["subject"]))


def body_revision(rules):
    return identity(sorted(r["id"] for r in rules if r["field"] == "body"))


def matched_body(rules, message, sample):
    return [r["id"] for r in rules if r["field"] == "body" and family(r, message)
            and literal(r["phrase"], sample["text"]) and (sample["complete"] or r["outcome"] in ("failure", "warning"))]


def apply_rules(message, rules):
    if message.get("recognized") is not False or message["category"] != "a_verifier":
        return message
    matches = []
    for rule in rules:
        if not family(rule, message):
            continue
        if rule["field"] == "subject":
            match = literal(rule["phrase"], message["subject"])
        else:
            match = rule["id"] in message.get("body_matches", []) or message["sha256"] in rule.get("examples", [])
        if match:
            matches.append(rule)
    if len(matches) != 1:
        return message
    rule = matches[0]
    category, label = OUTCOMES[rule["outcome"]]
    if rule["outcome"] in ("success", "completed") and (message.get("coverage_warnings") or message.get("attachments")):
        return message
    return {**message, "recognized": True, "format": "user-rule", "execution": rule["outcome"],
            "category": category, "summary": f"{rule['task']} — {label}", "evidence": [rule["phrase"]],
            "task_key": "|".join(("custom", rule["sender"], rule["task"].casefold()))}


def text_field(values, name):
    value = values.get(name)
    if not isinstance(value, str) or not 2 <= len(value.strip()) <= 240 or not value.isprintable() or "|" in value:
        raise ValueError("Chaque champ doit contenir entre 2 et 240 caractères imprimables, sans barre verticale.")
    return value.strip()


def simulate(directory, values):
    from .unknown_review import Config, read_samples
    messages = read_json(directory / "exports/messages.json", [])
    source = next((m for m in messages if m["sha256"] == values.get("source") and not m.get("recognized")
                   and m["scope"] == values.get("scope")), None)
    if not source or not sender(source):
        raise ValueError("Ce format inconnu est indisponible ou son expéditeur est absent.")
    rule = {k: text_field(values, k) for k in ("family", "phrase", "task")}
    rule.update(sender=sender(source), scope=source["scope"], field=values.get("field"), outcome=values.get("outcome"))
    if rule["field"] not in ("subject", "body") or rule["outcome"] not in OUTCOMES:
        raise ValueError("Choisis le texte à examiner et le résultat attendu.")
    rule["id"] = identity(rule)
    active = policy(directory)["rules"]
    if any(r["id"] == rule["id"] for r in active):
        raise ValueError("Cette règle existe déjà.")
    if not family(rule, source):
        raise ValueError("Le texte commun doit figurer dans l’objet de l’exemple choisi.")
    # Les exemples d'une règle existante sont aussi inclus pour détecter les recouvrements.
    candidates = [m for m in reversed(messages) if (not m.get("recognized") or m["format"] == "user-rule") and family(rule, m)]
    batch = [source, *[m for m in candidates if m["sha256"] != source["sha256"]][:11]]
    samples = {}
    if rule["field"] == "body":
        samples = {s["id"]: s for s in read_samples(batch, Config.load())}
    hits, rows, conflict = [], [], False
    for m in batch:
        sample = samples.get(m["sha256"])
        match = (literal(rule["phrase"], m["subject"]) if rule["field"] == "subject" else
                 bool(sample and matched_body([rule], m, sample)))
        if match and rule["outcome"] in ("success", "completed") and (m.get("attachments") or m.get("coverage_warnings")):
            match = False
        if match:
            hits.append(m["sha256"])
            conflict |= m.get("format") == "user-rule"
        result = OUTCOMES[rule["outcome"]][1] if match else "Sans correspondance"
        if rule["field"] == "body" and not sample:
            result = "Texte indisponible"
        rows.append({"subject": m["subject"], "date": m["date"], "result": result})
    allowed = source["sha256"] in hits and not conflict
    token = identity(rule, rows, hits, active)
    if allowed:
        if rule["field"] == "body":
            rule["examples"] = hits
        root = private_dir(directory)
        for old in root.glob("rule-preview-*.json"):
            try:
                if time.time() - old.stat().st_mtime > 900:
                    old.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        write_private(root / ("rule-preview-" + token + ".json"),
                      {"rule": rule, "previous": identity(active), "until": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()})
    return {"rows": rows, "token": token if allowed else None,
            "message": ("Une règle active couvre déjà un exemple. Précise les critères." if conflict else
                        "L’exemple sélectionné doit correspondre pour activer la règle." if not allowed else
                        f"{len(hits)} correspondance(s) sur {len(rows)} exemple(s) testé(s).")}


def activate(directory, token):
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Teste la règle avant de l’activer.")
    root = private_dir(directory)
    path = root / ("rule-preview-" + token + ".json")
    with locked(root / "rule-activation.lock"):
        preview = read_json(path, {})
        if (not preview or datetime.fromisoformat(preview["until"]) < datetime.now(timezone.utc)
                or preview["previous"] != identity(policy(directory)["rules"])):
            raise ValueError("Le test a expiré ou les règles ont changé. Teste à nouveau la règle.")
        rule = preview["rule"]
        change(directory, "rules", rule["id"], rule, previous=preview["previous"])
        path.unlink(missing_ok=True)
