"""Attribution privée des contrôles à partir d'une fiche du tableau de bord."""
import re
from collections import defaultdict

from .clients import assignment_source, message_client
from .monitoring import identity, policy
from .private import locked, private_dir, read_json, write_private


def review_assignment(directory, values, save=False):
    client = values.get("client")
    if not isinstance(client, str) or not re.fullmatch(r"[\w][\w .&'’-]{0,79}", client.strip()):
        raise ValueError("Indique le nom ou le domaine du client.")
    client = client.strip()
    root = private_dir(directory)
    export = directory / "exports"
    with locked(directory / "export.lock"), locked(root / "monitoring.lock"):
        detail = read_json(export / "check-details.json", {}).get(values.get("detail_id")) or {}
        source = detail.get("assignment_source")
        if not source:
            raise ValueError("Actualise le tableau de bord et rouvre la fiche du contrôle.")
        config = policy(directory)
        matches, other = set(), set()
        keys = set()
        for m in read_json(export / "messages.json", []):
            if m["scope"] != source[0]:
                continue
            for e in [m, *m.get("task_events", [])]:
                if not e.get("task_key"):
                    continue
                task = (m["scope"], e["task_key"], message_client(m, e))
                if assignment_source(m, e) == tuple(source):
                    matches.add(m["sha256"])
                    keys.add(task)
                else:
                    other.add(task)
        if not matches:
            raise ValueError("La source de ce contrôle a changé. Rouvre sa fiche.")
        token = identity(config, source, client, sorted(matches), sorted(keys))
        result = {"token": token, "count": len(matches), "checks": sorted({k[1] for k in keys}),
                  "criterion": source[2] + " · " + (source[3] if source[2] != "Mail" else "ce message uniquement")}
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
        rules = [r for r in config.get("assignments", []) if r["source"] != source]
        rules.append({"source": source, "client": client})
        config["assignments"] = rules
        write_private(root / "monitoring.json", config)
        return result
