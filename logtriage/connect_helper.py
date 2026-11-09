"""Assistant local : aucun jeton ChatGPT n'est reçu ou enregistré sur le Mac."""
import base64
import http.client
import http.server
import json
import ssl
import time
import urllib.parse
import webbrowser


def main():
    config = json.loads(base64.b64decode("CONFIG_PLACEHOLDER"))
    server_url = urllib.parse.urlsplit(config["server"])

    class Callback(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Le code d'autorisation ne doit pas apparaître dans les logs.

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/auth/callback" or self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                self.send_error(404)
                return
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("state") != [config["state"]] or any(len(v) != 1 for v in query.values()):
                self.send_error(400, "Autorisation non verifiable")
                return
            values = {k: v[0] for k, v in query.items() if k in ("code", "state", "client_id", "error")}
            values["redirect_uri"] = redirect
            # Le certificat fourni par l'interface protège aussi un serveur auto-hébergé.
            # Vérification de chaîne ET du nom conservée, aucune option TLS insecure.
            context = ssl.create_default_context()
            if config.get("certificate"):
                context.load_verify_locations(cadata=config["certificate"])
            try:
                connection = http.client.HTTPSConnection(server_url.hostname, server_url.port or 443, context=context, timeout=60)
                connection.request("POST", "/auth/relay", body=json.dumps(values), headers={
                    "Content-Type": "application/json", "X-Logtriage-Pair": config["ticket"]})
                response = connection.getresponse()
                success = response.status == 200
                response.read(4096)
                connection.close()
            except (OSError, ValueError):
                success = False
            text = ("Connexion transmise à logtriage. Retourne dans ses réglages. Tu peux fermer cette fenêtre et éteindre ton Mac."
                    if success else "Connexion non confirmée. Retourne dans les réglages de logtriage et recommence la connexion.")
            body = ("<!doctype html><html lang='fr'><meta charset='utf-8'><title>Connexion logtriage</title><h1>" + text + "</h1></html>").encode()
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.server.finished = True

    try:
        listener = http.server.HTTPServer(("127.0.0.1", 1455), Callback)
    except OSError:
        listener = http.server.HTTPServer(("127.0.0.1", 0), Callback)
    listener.timeout, listener.finished = 1, False
    redirect = f"http://127.0.0.1:{listener.server_port}/auth/callback"
    query = {**config["query"], "redirect_uri": redirect}
    print("Connexion à ChatGPT : autorise logtriage dans le navigateur qui s’ouvre.")
    webbrowser.open(config["authorize"] + "?" + urllib.parse.urlencode(query))
    deadline = time.monotonic() + 600
    while not listener.finished and time.monotonic() < deadline:
        listener.handle_request()
    listener.server_close()
    print("Assistant terminé. Consulte les réglages de logtriage pour vérifier la connexion.")


if __name__ == "__main__":
    main()
