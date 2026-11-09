"""Attribution privée des contrôles à partir d'une fiche du tableau de bord."""
import re
import unicodedata
from datetime import datetime, timezone

from .clients import assignment_source, message_client
from .monitoring import identity, policy
from .private import locked, private_dir, read_json, write_private


def client_names(directory, create=None):
    root = private_dir(directory)
    path = root / "clients.json"
    with locked(root / "clients.lock"):
        names = read_json(path)
        first_use = names is None
        if first_use:
            names = sorted({r["client"] for r in policy(directory).get("assignments", [])}, key=str.casefold)
        if create is not None:
            if not isinstance(create, str):
                raise ValueError("Indique le nom du client.")
            name = unicodedata.normalize("NFC", " ".join(create.split()))
            if not re.fullmatch(r"[\w][\w .&'’-]{0,79}", name):
                raise ValueError("Indique un nom ou un domaine valide de 80 caractères maximum.")
            if any(n.casefold() == name.casefold() for n in names):
                raise ValueError("Ce client figure déjà dans la liste.")
            names = sorted([*names, name], key=str.casefold)
        if first_use or create is not None:
            write_private(path, names)
        return names


def review_assignment(directory, values, save=False):
    client = values.get("client")
    if client not in client_names(directory):
        raise ValueError("Choisis un client enregistré dans Réglages → Clients.")
    root = private_dir(directory)
    export = directory / "exports"
    with locked(directory / "export.lock"), locked(root / "monitoring.lock"):
        bulk = "check_ids" in values
        selected = set()
        source = None
        if bulk:
            ids = values["check_ids"]
            if not isinstance(ids, list) or not ids or not all(isinstance(k, str) for k in ids):
                raise ValueError("Coche au moins un contrôle.")
            selected = set(ids)
            visible = read_json(export / "checks.json", {}).get("items", [])
            if not selected.issubset({row.get("bulk_id") for row in visible}):
                raise ValueError("La sélection a changé. Actualise le tableau de bord.")
        else:
            detail = read_json(export / "check-details.json", {}).get(values.get("detail_id")) or {}
            if not detail.get("assignment_source"):
                raise ValueError("Actualise le tableau de bord et rouvre la fiche du contrôle.")
            source = tuple(detail["assignment_source"])
        config = policy(directory)
        exported_policy = read_json(export / "summary.json", {}).get("policy_id")
        if exported_policy and exported_policy != identity(config):
            raise ValueError("Le tableau de bord se met à jour. Réessaie après son actualisation.")
        matches, other, keys, rules_to_set = set(), set(), set(), set()
        for m in read_json(export / "messages.json", []):
            for e in [m, *m.get("task_events", [])]:
                key = e.get("task_key")
                if not key:
                    continue
                task = (m["scope"], key, message_client(m, e))
                base = assignment_source(m, e)
                chosen = identity(*task) in selected if bulk else base == source
                if not chosen:
                    other.add(task)
                    continue
                if base is None:
                    raise ValueError("La source de ce contrôle est incomplète.")
                matches.add((m["scope"], m["sha256"]))
                keys.add(task)
                rules_to_set.add((*base, key) if bulk else base)
        if not matches or (bulk and {identity(*task) for task in keys} != selected):
            raise ValueError("Les contrôles ont changé. Vérifie la sélection.")
        token = identity(config, sorted(rules_to_set), client, sorted(matches), sorted(keys))
        result = {"token": token, "count": len(matches), "checks": sorted({k[1] for k in keys})}
        if bulk:
            result["affected"] = [{"client": owner, "key": key} for _, key, owner in sorted(keys)]
        else:
            result["criterion"] = source[2] + " · " + (source[3] if source[2] != "Mail" else "ce message uniquement")
        if not save:
            return result
        if values.get("token") != token:
            raise ValueError("L’historique ou les réglages ont changé. Vérifie à nouveau l’aperçu.")
        schedules = config["schedules"]
        for row in schedules:
            task = (row["scope"], row["key"], row.get("client"))
            if task not in keys or row.get("client") == client:
                continue
            new_id = identity(row["scope"], row["key"], client)
            if task in other or any(s["id"] == new_id for s in schedules):
                raise ValueError("Ce calendrier est partagé. Retire-le puis configure les calendriers par client.")
            row.setdefault("event_id", row["id"])
            row.update(client=client, id=new_id, label=client+" — "+" · ".join(row["key"].split("|")))
        rules = [r for r in config.get("assignments", []) if tuple(r["source"]) not in rules_to_set
                 and (bulk or tuple(r["source"][:4]) != source)]
        at = datetime.now(timezone.utc).isoformat()
        previous = {tuple(r["source"]): r for r in config.get("assignments", [])}
        rules.extend({"source": list(rule), "client": client, "learned_since": previous.get(rule, {}).get("learned_since", at)}
                     for rule in sorted(rules_to_set))
        config["assignments"] = rules
        write_private(root / "monitoring.json", config)
        return result
