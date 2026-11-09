import hashlib
import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from logtriage.ai_report import ReportAgent, annotate, facts_from_report, validate_notes
from logtriage.chatgpt import ChatGPT, SCOPES
from logtriage.openai_http import OpenAIError, OpenAIHTTP
from logtriage.private import read_json, write_private


class Transport:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk.update(kid="test-key", use="sig")
        self.nonce = ""
        self.requests = []
        self.fail_refresh = False

    def json(self, url, **kwargs):
        self.requests.append((url, kwargs))
        if url.endswith("jwks.json"):
            return {"keys": [self.jwk]}
        if url.endswith("/oauth/token"):
            body = kwargs["body"]
            if body["grant_type"] == "refresh_token":
                if self.fail_refresh:
                    raise OpenAIError("login_required")
                return {"access_token": "rotated-access", "refresh_token": "rotated-refresh", "expires_in": 3600,
                        "token_type": "Bearer", "scope": SCOPES}
            claims = {"iss": "https://auth.openai.com", "sub": "test-user", "aud": body["client_id"],
                      "iat": int(time.time()), "exp": int(time.time()) + 3600, "nonce": self.nonce, "email": "user@example.com"}
            return {"access_token": "test-access", "refresh_token": "test-refresh", "expires_in": 3600,
                    "token_type": "Bearer", "scope": SCOPES,
                    "id_token": jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test-key"})}
        if url.endswith("/models"):
            return {"models": [{"slug": "test-model", "display_name": "Test", "visibility": "list"}]}
        raise AssertionError(url)


class ChatGPTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.http = Transport()
        self.client = ChatGPT(self.root, self.http)

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self):
        pending = self.client.start()
        self.http.nonce = pending["query"]["nonce"]
        values = {"state": pending["state"], "code": "test-code", "client_id": "oaiapp_test",
                  "redirect_uri": "http://127.0.0.1:1455/auth/callback"}
        self.client.finish(values, pending["ticket"])
        return pending, values

    def test_pkce_host_identity_and_verified_credentials(self):
        host = read_json(self.client.path)["host_id"]
        pending, values = self.connect()
        self.assertEqual(pending["query"]["client_id"], "dynamic_agent_client")
        self.assertEqual(pending["query"]["agent_name_hint"], "logtriage")
        self.assertEqual(self.client.state()["active"], "oaiapp_test")
        self.assertEqual(self.client.access_token(), "test-access")
        self.assertEqual(self.client.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            self.client.finish(values, pending["ticket"])
        returning = self.client.start("oaiapp_test")
        self.assertEqual(returning["query"]["ext_agent_host_id"], host)
        self.assertNotIn("agent_name_hint", returning["query"])
        self.assertEqual(returning["query"]["client_id"], "oaiapp_test")

    def test_wrong_state_or_pairing_ticket_never_exchanges_code(self):
        pending = self.client.start()
        for state, ticket in (("wrong", pending["ticket"]), (pending["state"], "wrong")):
            with self.assertRaises(ValueError):
                self.client.finish({"state": state}, ticket)
        self.assertEqual(self.http.requests, [])

    def test_nonce_mismatch_does_not_replace_connection(self):
        pending = self.client.start()
        self.http.nonce = "different-nonce"
        with self.assertRaises(OpenAIError):
            self.client.finish({"state": pending["state"], "code": "code", "client_id": "oaiapp_test",
                                "redirect_uri": "http://127.0.0.1:1455/auth/callback"}, pending["ticket"])
        self.assertFalse(self.client.state()["connected"])

    def test_returning_callback_cannot_substitute_client(self):
        self.connect()
        pending = self.client.start("oaiapp_test")
        count = len(self.http.requests)
        with self.assertRaises(ValueError):
            self.client.finish({"state": pending["state"], "client_id": "oaiapp_other",
                                "redirect_uri": "http://127.0.0.1:1455/auth/callback"}, pending["ticket"])
        self.assertEqual(len(self.http.requests), count)

    def test_parallel_instances_refresh_once_and_persist_rotation(self):
        self.connect()
        data = read_json(self.client.path)
        data["profiles"]["oaiapp_test"]["expires_at"] = time.time() - 1
        write_private(self.client.path, data)
        other = ChatGPT(self.root, self.http)
        with ThreadPoolExecutor(2) as pool:
            values = list(pool.map(lambda client: client.access_token(), [self.client, other]))
        self.assertEqual(values, ["rotated-access", "rotated-access"])
        calls = [k for _, k in self.http.requests if k.get("body", {}).get("grant_type") == "refresh_token"]
        self.assertEqual(len(calls), 1)
        self.assertNotIn("scope", calls[0]["body"])
        self.assertEqual(read_json(self.client.path)["profiles"]["oaiapp_test"]["refresh_token"], "rotated-refresh")

    def test_revoked_session_requests_login_instead_of_retrying(self):
        self.connect()
        data = read_json(self.client.path)
        data["profiles"]["oaiapp_test"]["expires_at"] = 0
        write_private(self.client.path, data)
        self.http.fail_refresh = True
        with self.assertRaises(OpenAIError):
            self.client.access_token()
        self.assertFalse(self.client.state()["connected"])

    def test_model_catalog_is_bound_to_selected_account(self):
        self.connect()
        self.assertEqual(self.client.models()[0]["slug"], "test-model")
        self.assertEqual(self.client.cached_models()[0]["slug"], "test-model")
        self.assertNotIn("test-access", json.dumps(self.client.state()))


class Stream:
    def __init__(self, events): self.events = events
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def __iter__(self):
        for event in self.events:
            yield ("data: " + json.dumps(event) + "\n").encode()
            yield b"\n"


class StreamTests(unittest.TestCase):
    def test_partial_text_requires_completed_terminal_event(self):
        http = OpenAIHTTP()
        http.open = lambda *a, **k: Stream([{"type": "response.output_text.delta", "delta": "partial"}])
        with self.assertRaises(OpenAIError):
            http.response("token", {})

    def test_usage_limit_after_stream_start_fails_without_output(self):
        http = OpenAIHTTP()
        http.open = lambda *a, **k: Stream([{"type": "response.failed", "response": {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}}])
        with self.assertRaises(OpenAIError) as result:
            http.response("token", {})
        self.assertEqual(result.exception.code, "usage_limit")

    def test_completed_stream_returns_only_completed_response(self):
        http = OpenAIHTTP()
        http.open = lambda *a, **k: Stream([{"type": "response.completed", "response": {"status": "completed", "output": []}}])
        self.assertEqual(http.response("token", {})["status"], "completed")


class AgentTests(unittest.TestCase):
    def test_invented_alert_id_or_changed_shape_is_rejected(self):
        facts = facts_from_report("- ÉCHEC — Backup failed.\n")
        with self.assertRaises(OpenAIError):
            validate_notes('{"notes":[{"id":"invented","note":"Tout va bien"}]}', facts)
        identity = next(iter(facts))
        notes = validate_notes(json.dumps({"notes": [{"id": identity, "note": "Consulte le journal de sauvegarde."}]}), facts)
        result = annotate("- ÉCHEC — Backup failed.\n", notes)
        self.assertIn("- ÉCHEC — Backup failed.", result)
        self.assertIn("Consulte le journal", result)

    def test_agent_uses_supported_namespace_and_keeps_history(self):
        report = "- ÉCHEC — Sauvegarde en échec.\n"
        identity = next(iter(facts_from_report(report)))
        payloads = []
        class Client:
            def state(self): return {"active": "profile"}
            def access_token(self, expected=None): return "token"
            def response(self, token, payload):
                payloads.append(json.loads(json.dumps(payload)))
                if len(payloads) == 1:
                    return {"output": [{"type": "function_call", "name": "get_report", "namespace": "logtriage", "arguments": "{}", "call_id": "call1"}]}
                return {"output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({"notes": [{"id": identity, "note": "Vérifie le stockage de destination."}]})}]}]}
        client = Client()
        client.transport = client
        notes, usage = ReportAgent(client, "test-model", report, []).run()
        self.assertIn(identity, notes)
        self.assertEqual(usage["tool_calls"], 1)
        self.assertFalse(payloads[0]["store"])
        self.assertTrue(payloads[0]["stream"])
        self.assertEqual(payloads[0]["tools"][0]["type"], "namespace")
        self.assertNotIn("max_output_tokens", payloads[0])
        self.assertEqual(payloads[1]["input"][-1]["call_id"], "call1")


if __name__ == "__main__":
    unittest.main()
