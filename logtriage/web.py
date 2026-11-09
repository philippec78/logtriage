"""Interface d'administration privée, HTTPS et session avec protection CSRF."""
import base64
import hashlib
import hmac
import http.server
import io
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path

from . import __version__
from .chatgpt import ChatGPT
from .openai_http import OpenAIError
from .private import private_dir, read_json, write_private
from .settings import load_settings, save_settings
from .web_reports import WebReports, error_message

LOG = logging.getLogger("logtriage.web")
STATIC = Path(__file__).parent / "static"


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000).hex()


def credentials(directory):
    root = private_dir(directory)
    path = root / "web-auth.json"
    saved = read_json(path)
    configured = os.environ.get("WEB_PASSWORD", "")
    if saved:
        # Le mot de passe enregistré reste stable après redéploiement.
        return saved
    if configured and len(configured) < 12:
        raise ValueError("WEB_PASSWORD doit contenir au moins 12 caractères.")
    password = configured or secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    saved = {"username": os.environ.get("WEB_USER", "admin"), "salt": salt.hex(), "hash": password_hash(password, salt)}
    write_private(path, saved)
    if not configured:
        fd = os.open(root / "web-initial-password.txt", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(password + "\n")
        LOG.info("Accès web initial : identifiant admin ; mot de passe dans /data/private/web-initial-password.txt (aucun secret dans les logs).")
    return saved


def certificate(directory, public_url):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    root = private_dir(directory)
    cert_path, key_path = root / "web-cert.pem", root / "web-key.pem"
    host = urllib.parse.urlsplit(public_url).hostname or "localhost"
    names = set([host, "localhost", "127.0.0.1"] + [n.strip() for n in os.environ.get("WEB_TLS_NAMES", "").split(",") if n.strip()])
    renew = not cert_path.exists() or not key_path.exists()
    if not renew:
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            saved_names = existing.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            covered = set(saved_names.get_values_for_type(x509.DNSName)) | {str(v) for v in saved_names.get_values_for_type(x509.IPAddress)}
            renew = not names <= covered or existing.not_valid_after_utc < datetime.now(timezone.utc) + timedelta(days=7)
        except (ValueError, x509.ExtensionNotFound):
            renew = True
    if renew:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "logtriage")])
        alternatives = []
        for name in names:
            try:
                alternatives.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                alternatives.append(x509.DNSName(name))
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=365)).add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
                .sign(key, hashes.SHA256()))
        for path, data in ((key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                           (cert_path, cert.public_bytes(serialization.Encoding.PEM))):
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(data)
    return cert_path, key_path


class WebApplication:
    def __init__(self, directory, public_url, secure=True):
        self.directory = Path(directory)
        self.public_url, self.secure = public_url.rstrip("/"), secure
        parsed = urllib.parse.urlsplit(self.public_url)
        if parsed.scheme != ("https" if secure else "http") or not parsed.netloc or parsed.username or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("WEB_PUBLIC_URL doit être l’adresse exacte de l’interface.")
        if not secure and parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("HTTP est réservé aux essais locaux. Active HTTPS pour le serveur.")
        self.auth = credentials(directory)
        self.chatgpt = ChatGPT(directory)
        self.reports = WebReports(directory, self.chatgpt)
        self.sessions, self.attempts = {}, {}
        self.mutex = threading.Lock()
        self.certificate = ""
        self.stopped = threading.Event()

    def session(self, cookie):
        try:
            parsed = SimpleCookie()
            parsed.load(cookie or "")
            token = parsed["logtriage"].value
        except (KeyError, ValueError):
            return None
        with self.mutex:
            self.sessions = {k: v for k, v in self.sessions.items() if v["expires"] > time.time()}
            return self.sessions.get(token)

    def login(self, address, username, password):
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 512:
            raise ValueError("Identifiant ou mot de passe incorrect.")
        with self.mutex:
            self.attempts = {k: v for k, v in self.attempts.items() if v["until"] > time.time()}
            if len(self.attempts) > 1000:
                raise ValueError("Trop de tentatives. Réessaie plus tard.")
            attempt = self.attempts.setdefault(address, {"count": 0, "until": time.time() + 300})
            if attempt["count"] >= 5:
                raise ValueError("Trop de tentatives. Réessaie dans cinq minutes.")
            attempt["count"] += 1
            valid = hmac.compare_digest(username, self.auth["username"]) and hmac.compare_digest(password_hash(password, bytes.fromhex(self.auth["salt"])), self.auth["hash"])
            if not valid:
                raise ValueError("Identifiant ou mot de passe incorrect.")
            self.attempts.pop(address, None)
            if len(self.sessions) >= 50:
                self.sessions.clear()
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {"csrf": csrf, "expires": time.time() + 8 * 3600}
            return token, csrf

    def state(self):
        import os
        return {"version": __version__, "settings": load_settings(self.directory),
                "status": read_json(self.directory / "status.json"),
                "summary": read_json(self.directory / "exports/summary.json"),
                "incidents": read_json(self.directory / "exports/open-incidents.json", []),
                "latest_digest": (self.directory / "exports/bilan.txt").read_text(encoding="utf-8") if (self.directory / "exports/bilan.txt").exists() else "",
                "chatgpt": self.chatgpt.state(), "models": self.chatgpt.cached_models(),
                "report": self.reports.state(), "mailbox": {"host": os.environ.get("IMAP_HOST", ""),
                    "user": os.environ.get("IMAP_USER", ""), "folder": os.environ.get("IMAP_FOLDER", "INBOX")}}

    def maintenance(self):
        while not self.stopped.wait(60):
            try:
                if self.chatgpt.state()["connected"]:
                    self.chatgpt.access_token()
            except OpenAIError:
                pass  # État consultable dans l'interface, aucun jeton dans les logs.
            except Exception as exc:
                LOG.warning("Renouvellement non confirmé (%s).", type(exc).__name__)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "logtriage"
    sys_version = ""

    @property
    def app(self):
        return self.server.application

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def reply(self, status, value, content_type="application/json; charset=utf-8", extra=None):
        raw = json.dumps(value, ensure_ascii=False).encode() if content_type.startswith("application/json") else value
        self.send_response(status)
        for key, val in {"Content-Type": content_type, "Content-Length": str(len(raw)), "Cache-Control": "no-store",
                         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                         "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                         **(extra or {})}.items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(raw)

    def same_origin(self):
        return self.headers.get("Host", "").lower() == urllib.parse.urlsplit(self.app.public_url).netloc.lower()

    def body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Requête non prise en charge.")
        length = int(self.headers.get("Content-Length", "0"))
        if not 1 <= length <= 65536 or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ValueError("Requête invalide ou trop volumineuse.")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("Objet attendu.")
        return value

    def do_GET(self):
        try:
            if not self.same_origin():
                return self.reply(403, {"error": "Adresse de l’interface non autorisée."})
            path = urllib.parse.urlsplit(self.path).path
            assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "application/javascript; charset=utf-8"),
                      "/app.css": ("app.css", "text/css; charset=utf-8")}
            if path in assets:
                name, kind = assets[path]
                return self.reply(200, (STATIC / name).read_bytes(), kind)
            session = self.app.session(self.headers.get("Cookie"))
            if not session:
                return self.reply(401, {"error": "Connecte-toi à l’interface."})
            if path == "/api/state":
                return self.reply(200, {**self.app.state(), "csrf": session["csrf"]})
            return self.reply(404, {"error": "Page introuvable."})
        except Exception:
            self.close_connection = True
            self.reply(500, {"error": "Lecture indisponible. Vérifie que la collecte a démarré."})

    def do_POST(self):
        try:
            if not self.same_origin():
                return self.reply(403, {"error": "Adresse non autorisée."})
            path = urllib.parse.urlsplit(self.path).path
            values = self.body()
            if path == "/auth/relay":
                self.app.chatgpt.finish(values, self.headers.get("X-Logtriage-Pair", ""))
                return self.reply(200, {"ok": True})
            if self.headers.get("Origin") != self.app.public_url:
                return self.reply(403, {"error": "Origine de la requête non autorisée."})
            if path == "/api/login":
                token, csrf = self.app.login(self.client_address[0], values.get("username", ""), values.get("password", ""))
                cookie = "logtriage=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800" + ("; Secure" if self.app.secure else "")
                return self.reply(200, {"csrf": csrf}, extra={"Set-Cookie": cookie})
            session = self.app.session(self.headers.get("Cookie"))
            if not session:
                return self.reply(401, {"error": "Ta session a expiré. Reconnecte-toi."})
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
                return self.reply(403, {"error": "Recharge la page avant de réessayer."})
            if path == "/api/logout":
                with self.app.mutex:
                    self.app.sessions = {k: v for k, v in self.app.sessions.items() if v is not session}
                return self.reply(200, {"ok": True}, extra={"Set-Cookie": "logtriage=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if self.app.secure else "")})
            if path == "/api/settings":
                save_settings(self.app.directory, values)
                return self.reply(200, {"ok": True})
            if path == "/api/resolve":
                self.app.reports.resolve(values.get("id"))
                return self.reply(200, {"ok": True})
            if path == "/api/chatgpt/connect":
                helper = self.app.chatgpt.helper(self.app.public_url, self.app.certificate, values.get("profile"))
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                    info = zipfile.ZipInfo("logtriage-chatgpt.command")
                    info.create_system = 3
                    info.external_attr = 0o100700 << 16
                    archive.writestr(info, helper.encode())
                return self.reply(200, {"archive": base64.b64encode(output.getvalue()).decode()})
            if path == "/api/chatgpt/select":
                self.app.chatgpt.select(values.get("profile"))
                return self.reply(200, {"ok": True})
            if path == "/api/chatgpt/disconnect":
                confirmed = self.app.chatgpt.disconnect()
                return self.reply(200, {"ok": True, "message": "Compte déconnecté." if confirmed else "Compte déconnecté localement. Révocation distante non confirmée ; retire aussi l’accès dans les réglages ChatGPT."})
            if path == "/api/models":
                return self.reply(200, {"models": self.app.chatgpt.models()})
            if path == "/api/preview":
                if type(values.get("use_ai")) is not bool:
                    raise ValueError("Choisis le type de rapport.")
                self.app.reports.preview(values["use_ai"])
                return self.reply(202, {"ok": True})
            if path == "/api/send":
                self.app.reports.send(values.get("id"))
                return self.reply(202, {"ok": True})
            return self.reply(404, {"error": "Action introuvable."})
        except OpenAIError as exc:
            return self.reply(400, {"error": error_message(exc)})
        except ValueError as exc:
            message = str(exc) if not isinstance(exc, json.JSONDecodeError) else "Requête invalide."
            return self.reply(400, {"error": message})
        except (TypeError, KeyError):
            return self.reply(400, {"error": "Réglage ou demande invalide. Vérifie les champs et réessaie."})
        except Exception:
            return self.reply(500, {"error": "Opération non confirmée. Vérifie les réglages et réessaie."})


class WebServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, application):
        self.application = application
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def start(directory):
    port = int(os.environ.get("WEB_PORT_INTERNAL", "8448"))
    secure = os.environ.get("WEB_TLS", "true").lower() == "true"
    public_url = os.environ.get("WEB_PUBLIC_URL", f"https://localhost:{port}")
    app = WebApplication(directory, public_url, secure)
    server = WebServer((os.environ.get("WEB_HOST", "0.0.0.0"), port), app)
    if secure:
        cert, key = certificate(directory, public_url)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        app.certificate = cert.read_text(encoding="utf-8")
    threading.Thread(target=server.serve_forever, daemon=True, name="web-interface").start()
    threading.Thread(target=app.maintenance, daemon=True, name="chatgpt-refresh").start()
    LOG.info("Interface protégée démarrée ; collecte IMAP toujours en lecture seule.")
    return server
