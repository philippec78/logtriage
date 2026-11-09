import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

from . import __version__


def rules_revision(rules):
    return hashlib.sha256((__version__ + json.dumps(rules, sort_keys=True)).encode()).hexdigest()


def norm(value):
    return "".join(c for c in unicodedata.normalize("NFKD", value)
                   if not unicodedata.combining(c)).lower().replace("\xa0", " ")


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.skip += 1
        if tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4"):
            self.parts.append("\n")
        if tag in ("td", "th"):
            self.parts.append(" | ")

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.skip = max(0, self.skip - 1)
        if tag in ("p", "div", "tr", "li", "h1", "h2", "h3", "h4"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def clean(text):
    return "\n".join(re.sub(r"[ \t\xa0]+", " ", line).strip()
                     for line in text.splitlines() if line.strip())


def line_field(text, label):
    match = re.search(r"(?im)^\s*" + label + r"\s*[:：]\s*(.+)$", text)
    return match.group(1).strip() if match else ""


def pdf_text(payload, rules):
    try:
        run = subprocess.run(
            [sys.executable, "-m", "logtriage.pdf_worker",
             str(rules["max_pages"]), str(rules["max_characters"])],
            input=payload, capture_output=True, timeout=rules["timeout_seconds"], check=True)
        return json.loads(run.stdout)
    except (subprocess.SubprocessError, ValueError, OSError):
        return {"text": "", "incomplete": True, "error": "extraction_pdf_incomplete"}


def observation(key, summary, evidence, **kwargs):
    return {"key": key, "summary": summary, "evidence": evidence,
            "status": "a_verifier", **kwargs}


def wazuh_observations(plain, html, rules):
    results = {}
    host = ""
    lines = plain.splitlines()
    for index, line in enumerate(lines):
        if re.fullmatch(r"[\w-]+(?:\.[\w-]+)+", line):
            host = line
        group = re.search(r"([\d ]+) alerte\(s\).*?niveau (\d+).*?r[eè]gle (\d+)", line, re.I)
        if host and group:
            count, level, rule = int(group[1].replace(" ", "")), int(group[2]), group[3]
            if level >= rules["review_min_level"]:
                key = f"wazuh|{host}|{rule}"
                desc = lines[index + 1] if index + 1 < len(lines) else "Détection Wazuh"
                results[key] = observation(key, desc, line, host=host, rule=rule,
                                           occurrences=count, source_level=level,
                                           urgent=level >= rules["urgent_min_level"])
    # La version HTML sert aussi de secours si le texte est absent ou incomplet.
    pattern = (r"\|\s*(\d{3,})\s+Niveau\s+(\d+)\s*\|\s*"
               r"([\w-]+(?:\.[\w-]+)+)\s+(.*?)\s*\|\s*([\d ]+)(?=\n|$)")
    for m in re.finditer(pattern, html, re.I | re.S):
        rule, level, host, desc, count = m.groups()
        level = int(level)
        if level >= rules["review_min_level"]:
            key = f"wazuh|{host}|{rule}"
            item = observation(key, clean(desc), clean(m[0]), host=host, rule=rule,
                               occurrences=int(count.replace(" ", "")), source_level=level,
                               urgent=level >= rules["urgent_min_level"])
            if key in results and (results[key]["occurrences"] != item["occurrences"]
                                   or results[key]["source_level"] != level):
                results[key]["variant_conflict"] = True
            else:
                results.setdefault(key, item)
    for m in re.finditer(r"([\w-]+(?:\.[\w-]+)+)\s*(?:—|-|\|)\s*D[eé]connect[eé]", plain + "\n" + html, re.I):
        host = m[1]
        key = f"wazuh|{host}|agent-deconnecte"
        results[key] = observation(key, "Agent non connecté ; durée inconnue", m[0], host=host)
    return list(results.values())


def analyze(raw, rules):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject, sender = str(message.get("Subject", "")), str(message.get("From", ""))
    plain, html, attachments, warnings = [], [], [], []
    for part in message.walk():
        content_type = part.get_content_type()
        if part.is_multipart():
            continue
        if content_type in ("text/plain", "text/html") and part.get_content_disposition() != "attachment":
            try:
                text = part.get_content()
                if content_type == "text/html":
                    parser = HTMLText()
                    parser.feed(text)
                    html.append(clean("".join(parser.parts)))
                else:
                    plain.append(clean(text))
            except (LookupError, UnicodeError, ValueError):
                warnings.append("corps_illisible")
        elif part.get_filename() or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            item = {"name": str(part.get_filename() or "sans-nom"), "type": content_type,
                    "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            # Les PDF de tout rapport sont lus ; aucun lien de l’email n’est ouvert.
            if content_type == "application/pdf" or item["name"].lower().endswith(".pdf"):
                if rules["openvas"]["inspect_pdf"]:
                    item.update(pdf_text(payload, rules["pdf"]))
                    if item.get("incomplete"):
                        warnings.append("pdf_incomplet:" + item["name"])
                else:
                    warnings.append("pdf_non_analyse:" + item["name"])
            attachments.append(item)
    plain, html = "\n".join(plain), "\n".join(html)
    # Tous les corps sont considérés pour les erreurs ; les compteurs restent structurés.
    text = "\n".join(dict.fromkeys(x for x in (plain, html) if x))
    combined = subject + "\n" + text
    normalized = norm(combined)
    try:
        date_header = str(message.get("Date", ""))
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            # -0000 exprime l’heure UTC sans préciser le fuseau local de l’expéditeur.
            if date_header.rstrip().endswith("-0000"):
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                raise ValueError("Date sans fuseau")
        date = dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        date = datetime.now(timezone.utc).isoformat()
        warnings.append("date_absente_ou_invalide_utilisation_date_import")
    result = {"subject": subject, "sender": sender, "date": date,
              "message_id": str(message.get("Message-ID", "")),
              "sha256": hashlib.sha256(raw).hexdigest(), "rules_version": rules["version"],
              "analysis_revision": rules_revision(rules),
              "category": "a_verifier", "execution": "unknown", "task_key": None,
              "summary": "Format non reconnu : vérification nécessaire.",
              "evidence": [], "observations": [], "coverage_warnings": warnings}
    def set_result(category, summary, key=None, execution="unknown", evidence=None):
        result.update(category=category, summary=summary, task_key=key,
                      execution=execution, evidence=evidence or [])

    ns = norm(subject)
    if "wazuh" in ns:
        observations = wazuh_observations(plain, html, rules["wazuh"])
        result["observations"] = observations
        elevated = re.search(r"Alertes niveaux 12[–-]14\s*:\s*([\d ]+)", text, re.I)
        severe = re.search(r"Alertes niveau 15 ou sup[eé]rieur\s*:\s*([\d ]+)", text, re.I)
        elevated_count = int(elevated[1].replace(" ", "")) if elevated else None
        severe_count = int(severe[1].replace(" ", "")) if severe else None
        result["source_counts"] = {"levels_12_14": elevated_count, "level_15_plus": severe_count}
        set_result("a_examiner" if observations or elevated_count or severe_count else "a_verifier",
                   f"Rapport Wazuh : {len(observations)} éléments extraits, détections à vérifier.",
                   execution="completed", evidence=[x[0:1000] for x in text.splitlines()
                                                       if x.startswith(("Alertes niveau", "Agents non connectés"))][:4])
        if not observations:
            warnings.append("wazuh_details_non_reconnus")
        if any(x.get("variant_conflict") for x in observations):
            warnings.append("compteurs_texte_html_differents")
    elif "openvas" in ns:
        pdfs = [a for a in attachments if "text" in a]
        pdf = "\n".join(a.get("text", "") for a in pdfs)
        target = re.sub(r"^.*?Scan termin[eé]\s*[–—-]\s*", "", subject, flags=re.I)
        key = "openvas|" + target
        scores = [float(x.replace(",", ".")) for x in re.findall(r"CVSS\s+(\d{1,2}[.,]\d+)\s*/\s*10", pdf, re.I)]
        max_score = max(scores) if scores else None
        no_notifiable_cve = "aucune cve ne repond aux criteres" in normalized
        if not pdfs:
            warnings.append("openvas_rapport_pdf_absent_ou_non_analyse")
        observations = []
        if "horodatages tcp" in norm(pdf):
            observations.append(observation(key + "|tcp-timestamps", "Horodatages TCP signalés", "Horodatages TCP", source="pdf", source_cvss=max_score))
        if "ne correspond pas aux noms" in norm(pdf) or "certificat different du nom" in norm(pdf):
            observations.append(observation(key + "|certificat-nom", "Écart certificat / nom utilisé par le scan ; contexte à vérifier", "ne correspond pas aux noms couverts", source="pdf"))
        if max_score is not None and max_score >= rules["openvas"]["notification_cvss"]:
            observations.append(observation(key + "|cvss", "Constat PDF atteignant le seuil de revue", f"CVSS {max_score}/10", source="pdf", source_cvss=max_score))
        if no_notifiable_cve:
            summary = "Scan terminé : aucune CVE au seuil de notification ; consulter les observations du PDF."
            category = "information_avec_observations" if observations else "information"
        else:
            summary, category = "Scan OpenVAS : résultats à examiner.", "a_examiner"
        if max_score is not None and max_score >= rules["openvas"]["notification_cvss"]:
            category = "a_examiner"
        if warnings:
            category = "a_verifier"
        set_result(category, summary, key, "completed", [subject])
        result["observations"], result["max_observed_cvss"] = observations, max_score
        if "controle generique des applications web est desactive" in norm(pdf):
            warnings.append("openvas_controle_generique_web_desactive_dans_le_scan")
    elif re.search(r"Garbage Collect Datastore ['\"]", subject, re.I):
        store = line_field(text, "Datastore") or "inconnu"
        host_match = re.search(r"Proxmox Backup Server\s*-\s*([^\s<]+)", sender, re.I)
        host = host_match[1] if host_match else "inconnu"
        key = f"pbs|{host}|garbage-collection|{store}"
        failure = next((x for x in text.splitlines() if x.lower().startswith("garbage collection failed:")), None)
        if "failed" in ns or failure:
            set_result("echec", f"Échec du nettoyage {store} sur {host}.", key, "failure", [failure or subject])
            result["error_signature"] = "ENOENT" if "ENOENT" in text else "abort_requested" if "abort requested" in text else "unclassified"
        else:
            set_result("fin_annoncee", "Notification de nettoyage PBS : statut à confirmer.", key, "completed", [subject])
    elif any(x in normalized for x in ("active backup for business", "tache de sauvegarde", "planificateur de taches", "tache de replication")):
        origin = re.search(r"(?m)^De\s+(.+)$", text)
        host = line_field(text, "De") or (origin[1].strip() if origin else "")
        failure_patterns = rules["synology"]["failure_patterns"]
        failure = next((p for p in failure_patterns if norm(p) in normalized), None)
        output_error = re.search(r"(?im)^\s*(?:ERROR|FATAL|ERREUR)\s*[:\[][^\n]*", text)
        failure = failure or (output_error[0] if output_error else None)
        if "planificateur de taches" in normalized:
            match = re.search(r"\[([^\]]+)\]", subject)
            host = match[1] if match else host or "inconnu"
            task = line_field(text, "Tâche") or "inconnue"
            key = f"synology-scheduler|{host}|{task}"
            code = re.search(r"[ÉE]tat actuel\s*:\s*(-?\d+)", text)
            if code and int(code[1]) not in rules["synology"]["scheduler_success_codes"]:
                failure = code[0]
            if failure:
                set_result("echec", f"Échec ou erreur explicite de {task} sur {host}.", key, "failure", [failure])
            elif code:
                set_result("reussite_signalee", f"{task} sur {host} : code {code[1]}.", key, "success", [code[0]])
            else:
                set_result("fin_annoncee", f"{task} : code de sortie absent.", key, "completed", [subject])
        elif "tache de replication" in normalized:
            source, dest = line_field(text, "Serveur source"), line_field(text, "Serveur de destination")
            key = f"synology-replication|{host or 'inconnu'}|{source or 'inconnu'}|{dest or 'inconnu'}"
            set_result("echec" if failure else "fin_annoncee", f"Réplication {source} vers {dest} : " + ("échec." if failure else "fin annoncée."), key, "failure" if failure else "completed", [failure or subject])
        else:
            task = line_field(text, "Tâche de sauvegarde")
            match = re.search(r"tâche de sauvegarde (.+?) (?:sur |a rencontré|est |a échoué)", combined, re.I)
            task = task or (match[1].strip() if match else "inconnue")
            if not host:
                h = re.search(r" sur (.+?) (?:est terminée|a échoué|a été)", combined, re.I)
                host = h[1] if h else "inconnu"
            product = "synology-abb" if "active backup for business" in normalized else "synology-backup"
            key = f"{product}|{host}|{task}"
            success = next((p for p in rules["synology"]["success_patterns"] if norm(p) in normalized), None)
            if failure:
                set_result("echec", f"Échec de {task} sur {host}.", key, "failure", [failure])
                if "%ERROR_REASON%" in text:
                    warnings.append("cause_absente_variable_ERROR_REASON_non_resolue")
            elif success:
                set_result("reussite_signalee", f"Réussite annoncée de {task} sur {host}.", key, "success", [subject])
            else:
                set_result("fin_annoncee", f"{task} sur {host} : fin annoncée, statut à confirmer.", key, "completed", [subject])
        if "inconnu" in result["task_key"]:
            warnings.append("identite_tache_incomplete_pas_de_cloture_automatique")
            if result["execution"] == "success":
                result["execution"] = "completed"
    # Ne pas conserver le texte intégral des pièces jointes dans les exports.
    result["attachments"] = [{k: v for k, v in a.items() if k != "text"} for a in attachments]
    if warnings and result["category"] in ("reussite_signalee", "fin_annoncee", "information"):
        result["category"] = "a_verifier"
        if result["execution"] == "success":
            result["execution"] = "completed"
    return result
