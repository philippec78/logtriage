"""Connexion officielle SIWC : PKCE, identité vérifiée et renouvellement côté serveur."""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path

import jwt

from .openai_http import OpenAIError, OpenAIHTTP
from .private import locked, private_dir, read_json, write_private

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"


def verify_identity(encoded, client_id, nonce, transport, expected_subject=None):
    try:
        header = jwt.get_unverified_header(encoded)
        if header.get("alg") not in ("RS256", "ES256") or not header.get("kid"):
            raise ValueError()
        jwks = transport.json(ISSUER + "/.well-known/jwks.json")
        candidates = [k for k in jwks["keys"] if k.get("kid") == header["kid"] and k.get("use", "sig") == "sig"]
        if len(candidates) != 1:
            raise ValueError()
        key = jwt.PyJWK.from_dict(candidates[0], algorithm=header["alg"]).key
        claims = jwt.decode(encoded, key, algorithms=[header["alg"]], audience=client_id, issuer=ISSUER,
                            leeway=5, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise ValueError()
        if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise ValueError()
        if expected_subject is not None and not hmac.compare_digest(claims["sub"], expected_subject):
            raise ValueError()
        if claims.get("azp", client_id) != client_id:
            raise ValueError()
        return claims
    except (ValueError, KeyError, TypeError, jwt.PyJWTError):
        raise OpenAIError("identity_not_verified") from None


class ChatGPT:
    def __init__(self, directory, transport=None):
        self.root = private_dir(directory)
        self.path = self.root / "chatgpt.json"
        self.transport = transport or OpenAIHTTP()
        self.pending = {}
        self.mutex = threading.RLock()
        with locked(self.root / "chatgpt.lock"):
            if not self.path.exists():
                write_private(self.path, {"host_id": "urn:uuid:" + str(uuid.uuid4()), "active": None, "profiles": {}})

    def state(self):
        data = read_json(self.path)
        profiles = [{"id": key, "label": p.get("email") or "Compte ChatGPT", "needs_login": p.get("needs_login", False)}
                    for key, p in data["profiles"].items()]
        active = data["profiles"].get(data["active"], {})
        return {"active": data["active"], "profiles": profiles,
                "connected": bool(active.get("access_token")) and not active.get("needs_login", False)}

    def start(self, selected=None):
        with self.mutex:
            self.pending = {k: v for k, v in self.pending.items() if v["expires"] > time.time()}
            if len(self.pending) >= 10:
                raise ValueError("Trop de connexions en attente. Réessaie dans quelques minutes.")
            data = read_json(self.path)
            if selected is not None and selected not in data["profiles"]:
                raise ValueError("Compte introuvable.")
            verifier, nonce, state, ticket = [secrets.token_urlsafe(32) for _ in range(4)]
            record = {"verifier": verifier, "nonce": nonce, "state": state,
                      "ticket_hash": hashlib.sha256(ticket.encode()).hexdigest(),
                      "client_id": selected, "expires": time.time() + 600}
            self.pending[state] = record
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            query = {"client_id": selected or "dynamic_agent_client", "ext_agent_host_id": data["host_id"],
                     "response_type": "code", "scope": SCOPES, "resource": RESOURCE,
                     "state": state, "nonce": nonce, "code_challenge_method": "S256", "code_challenge": challenge}
            if selected is None:
                query["agent_name_hint"] = "logtriage"
            return {"authorize": ISSUER + "/api/accounts/authorize", "query": query,
                    "ticket": ticket, "state": state}

    def finish(self, values, ticket):
        state = values.get("state", "")
        with self.mutex:
            pending = self.pending.get(state)
            if not pending or pending["expires"] <= time.time() or not hmac.compare_digest(pending["ticket_hash"], hashlib.sha256(ticket.encode()).hexdigest()):
                raise ValueError("Autorisation expirée ou non vérifiable. Recommence la connexion.")
            # Une seule tentative d'échange après vérification du ticket et du state.
            del self.pending[state]
        if values.get("error"):
            raise ValueError("Connexion refusée. Tu peux réessayer depuis les réglages.")
        callback = urllib.parse.urlsplit(values.get("redirect_uri", ""))
        if callback.scheme != "http" or callback.hostname != "127.0.0.1" or callback.path != "/auth/callback" or not callback.port or callback.query or callback.fragment or callback.username:
            raise ValueError("Adresse de retour invalide.")
        issued = values.get("client_id") or pending["client_id"]
        if not isinstance(issued, str) or not issued.startswith("oaiapp_") or len(issued) > 200 or (pending["client_id"] and issued != pending["client_id"]):
            raise ValueError("Enregistrement ChatGPT incomplet ou différent du compte sélectionné.")
        if not isinstance(values.get("code"), str) or not 1 <= len(values["code"]) <= 4096:
            raise ValueError("Code d’autorisation absent.")
        tokens = self.transport.json(ISSUER + "/api/accounts/oauth/token", form=True, body={
            "grant_type": "authorization_code", "client_id": issued, "code": values["code"],
            "code_verifier": pending["verifier"], "redirect_uri": values["redirect_uri"], "resource": RESOURCE})
        with locked(self.root / "chatgpt.lock"):
            data = read_json(self.path)
            previous = data["profiles"].get(issued)
            claims = verify_identity(tokens.get("id_token", ""), issued, pending["nonce"], self.transport,
                                     previous.get("subject") if previous else None)
            profile = self._credentials(tokens, previous or {})
            profile.update(client_id=issued, subject=claims["sub"], issuer=claims["iss"], email=claims.get("email", ""), needs_login=False)
            data["profiles"][issued] = profile
            data["active"] = issued
            write_private(self.path, data)
        return self.state()

    @staticmethod
    def _credentials(tokens, previous):
        scopes = tokens.get("scope", " ".join(previous.get("scopes", []))).split()
        if not {"chatgpt.tokens.use.direct", "resource.invoke", "offline_access"} <= set(scopes):
            raise OpenAIError("plan_permission_missing")
        if tokens.get("token_type", "").lower() != "bearer":
            raise OpenAIError("invalid_token_response")
        if not all(isinstance(tokens.get(k), str) and tokens[k] and "\n" not in tokens[k] and "\r" not in tokens[k] for k in ("access_token", "refresh_token")):
            raise OpenAIError("invalid_token_response")
        expiry = tokens.get("expires_in")
        if type(expiry) is not int or not 1 <= expiry <= 86400:
            raise OpenAIError("invalid_token_response")
        earliest = tokens.get("earliest_refresh_at", 0)
        if isinstance(earliest, str):
            try:
                earliest = datetime.fromisoformat(earliest.replace("Z", "+00:00")).timestamp()
            except ValueError:
                earliest = 0
        return {**previous, "access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"],
                "id_token": tokens.get("id_token", previous.get("id_token", "")), "scopes": scopes,
                "expires_at": time.time() + expiry, "earliest_refresh_at": earliest if isinstance(earliest, (float, int)) else 0,
                "saved_at": time.time()}

    def access_token(self, expected_profile=None):
        with self.mutex, locked(self.root / "chatgpt.lock"):
            data = read_json(self.path)
            active = data["active"]
            if expected_profile is not None and active != expected_profile:
                raise OpenAIError("account_changed")
            profile = data["profiles"].get(active)
            if not profile or profile.get("needs_login"):
                raise OpenAIError("login_required")
            if profile["expires_at"] <= time.time() + 300 and profile.get("earliest_refresh_at", 0) <= time.time():
                try:
                    tokens = self.transport.json(ISSUER + "/api/accounts/oauth/token", form=True, body={
                        "grant_type": "refresh_token", "client_id": active,
                        "refresh_token": profile["refresh_token"], "resource": RESOURCE})
                    if tokens.get("id_token"):
                        verify_identity(tokens["id_token"], active, None, self.transport, profile["subject"])
                    profile = self._credentials(tokens, profile)
                    data["profiles"][active] = profile
                    write_private(self.path, data)
                except OpenAIError as exc:
                    if exc.code in ("login_required", "unauthorized", "plan_permission_missing"):
                        data["profiles"][active]["needs_login"] = True
                        write_private(self.path, data)
                    raise
            if profile["expires_at"] <= time.time():
                raise OpenAIError("login_required")
            return profile["access_token"]

    def select(self, selected):
        with self.mutex, locked(self.root / "chatgpt.lock"):
            data = read_json(self.path)
            if selected not in data["profiles"]:
                raise ValueError("Compte introuvable.")
            data["active"] = selected
            write_private(self.path, data)

    def disconnect(self):
        confirmed = True
        with self.mutex, locked(self.root / "chatgpt.lock"):
            data = read_json(self.path)
            profile = data["profiles"].get(data["active"])
            if profile and profile.get("refresh_token"):
                try:
                    discovery = self.transport.json(ISSUER + "/.well-known/openid-configuration")
                    with self.transport.open(discovery["revocation_endpoint"], form=True, body={
                        "token": profile["refresh_token"], "token_type_hint": "refresh_token", "client_id": profile["client_id"]}):
                        pass
                except (OpenAIError, KeyError):
                    confirmed = False
                data["profiles"][data["active"]] = {k: v for k, v in profile.items() if k not in ("access_token", "refresh_token", "id_token", "expires_at")}
                data["profiles"][data["active"]]["needs_login"] = True
            write_private(self.path, data)
        return confirmed

    def models(self):
        active = self.state()["active"]
        catalog = self.transport.json(RESOURCE + "/models", token=self.access_token(active))
        models = [{"slug": item["slug"], "display_name": item.get("display_name", item["slug"])}
                  for item in catalog.get("models", []) if item.get("visibility") == "list" and isinstance(item.get("slug"), str)]
        if not models:
            raise OpenAIError("no_models")
        write_private(self.root / "models.json", {"profile": active, "models": models})
        return models

    def cached_models(self):
        cached = read_json(self.root / "models.json", {})
        return cached.get("models", []) if cached.get("profile") == self.state()["active"] else []

    def helper(self, public_url, certificate, selected=None):
        parsed = urllib.parse.urlsplit(public_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Renseigne une adresse HTTPS pour l’interface dans WEB_PUBLIC_URL.")
        config = {**self.start(selected), "server": public_url.rstrip("/"), "certificate": certificate}
        encoded = base64.b64encode(json.dumps(config).encode()).decode()
        source = (Path(__file__).parent / "connect_helper.py").read_text(encoding="utf-8")
        return "#!/bin/sh\nexec python3 - <<'LOGTRIAGE_PY'\n" + source.replace("CONFIG_PLACEHOLDER", encoded) + "\nLOGTRIAGE_PY\n"
