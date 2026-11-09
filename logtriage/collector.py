import hashlib
import imaplib
import logging
import re
import ssl
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone

from .monitoring import policy
from .user_rules import body_revision, matched_body
from .analyze import analyze, rules_revision

LOG = logging.getLogger(__name__)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def imap_date(date):
    return f"{date.day:02d}-{MONTHS[date.month - 1]}-{date.year}"


def quoted_mailbox(mailbox):
    # imaplib requiert des arguments déjà cités pour les espaces et caractères spéciaux.
    # Les dossiers non ASCII doivent être fournis sous leur nom IMAP modified UTF-7.
    mailbox.encode("ascii")
    if any(c in mailbox for c in "\r\n\x00"):
        raise ValueError("Nom de dossier IMAP invalide")
    return '"' + mailbox.replace('\\', '\\\\').replace('"', '\\"') + '"'


def mailbox_scope(config):
    return "imap:" + hashlib.sha256(
        f"{config.host.lower()}:{config.port}|{config.user}|{config.folder}".encode()).hexdigest()[:24]


def poll(config, store, rules, factory=imaplib.IMAP4_SSL):
    scope = mailbox_scope(config)
    stats = {"new": 0, "duplicate": 0, "pending": 0, "skipped": [], "failures": []}
    # Cette fonction ne possède aucune voie d’écriture IMAP : ni SELECT en écriture,
    # ni STORE/COPY/MOVE/EXPUNGE. EXAMINE et BODY.PEEK[] sont imposés dans le code.
    with factory(config.host, config.port, ssl_context=ssl.create_default_context(),
                 timeout=config.timeout) as client:
        client.login(config.user, config.password)
        status, _ = client.select(quoted_mailbox(config.folder), readonly=True)
        if status != "OK":
            raise RuntimeError("Impossible d’ouvrir le dossier en lecture seule")
        _, validity = client.response("UIDVALIDITY")
        if not validity or not validity[0] or not re.fullmatch(rb"\d+", validity[0]):
            raise RuntimeError("UIDVALIDITY absent : arrêt pour éviter un suivi ambigu")
        uidvalidity = validity[0].decode("ascii")
        anchor = store.setting(scope + ":since", imap_date(
            datetime.now(timezone.utc) - timedelta(days=config.lookback_days)))
        status, data = client.uid("SEARCH", None, "SINCE", anchor)
        if status != "OK" or not data or data[0] is None:
            raise RuntimeError("Recherche IMAP impossible")
        uids = data[0].split()
        pending = [(uid, f"{scope}|{config.folder}|{uidvalidity}|{uid.decode('ascii')}")
                   for uid in uids if re.fullmatch(rb"\d+", uid)]
        revision = rules_revision(rules)
        body_rules = [r for r in policy(store.directory)["rules"] if r["scope"] == scope and r["field"] == "body"]
        body_version = body_revision(body_rules) if body_rules else None
        pending = [(uid, ref) for uid, ref in pending if not store.seen(ref, revision, body_version)]
        # Rotation des tentatives : un groupe d’emails illisibles ne bloque pas la suite.
        cursor_key = scope + ":cursor:" + uidvalidity
        cursor = int(store.setting(cursor_key, "0"))
        pending.sort(key=lambda item: (int(item[0]) <= cursor, int(item[0])))
        stats["pending"] = max(0, len(pending) - config.batch_size)
        for uid, reference in pending[:config.batch_size]:
            try:
                status, metadata = client.uid("FETCH", uid, "(RFC822.SIZE INTERNALDATE)")
                raw_metadata = b" ".join(x for x in metadata if isinstance(x, bytes))
                size = re.search(rb"RFC822.SIZE\s+(\d+)", raw_metadata)
                if status != "OK" or not size:
                    raise ValueError("Taille indisponible")
                if int(size[1]) > config.max_bytes:
                    # Pas de marquage « traité » : réessayable après relèvement de la limite.
                    stats["skipped"].append({"uid": uid.decode(), "reason": "message_trop_volumineux"})
                    continue
                status, parts = client.uid("FETCH", uid, "(UID BODY.PEEK[])")
                literals = [p[1] for p in parts if isinstance(p, tuple) and isinstance(p[1], bytes)]
                if status != "OK" or len(literals) != 1:
                    raise ValueError("Message non disponible")
                raw = literals[0]
                if len(raw) > config.max_bytes:
                    raise ValueError("Message trop volumineux")
                result = analyze(raw, rules)
                if body_version and not result.get("recognized"):
                    from .unknown_review import extract_sample
                    sample = extract_sample(raw, result)
                    result["body_matches"] = matched_body(body_rules, {**result, "scope": scope}, sample)
                    result["body_revision"] = body_version
                internal = re.search(rb'INTERNALDATE "([^"]+)"', raw_metadata)
                if internal:
                    stamp = parsedate_to_datetime(internal[1].decode("ascii").replace("-", " ", 2))
                    result["received_at"] = stamp.astimezone(timezone.utc).isoformat()
                inserted = store.put(reference, scope, result)
                stats["new" if inserted else "duplicate"] += 1
            except (ValueError, TypeError, LookupError):
                # Pas de validation du message en base : nouvelle tentative au cycle suivant.
                stats["failures"].append({"uid": uid.decode(), "reason": "message_non_analyse"})
            finally:
                store.set_setting(cursor_key, uid.decode("ascii"))
        # LOGOUT est émis par le contexte ; ne pas utiliser CLOSE (peut expurger).
    return stats
