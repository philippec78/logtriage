"""Transport HTTPS limité aux points d'accès officiels OpenAI."""
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class OpenAIError(Exception):
    def __init__(self, code="unavailable"):
        self.code = code
        super().__init__(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OpenAIHTTP:
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def open(self, url, *, body=None, token=None, form=False):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in ("auth.openai.com", "api.openai.com") or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise OpenAIError("invalid_endpoint")
        headers = {"Accept": "application/json", "User-Agent": "logtriage/0.3"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        else:
            data = None
        try:
            return self.opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=45)
        except urllib.error.HTTPError as exc:
            code = "unauthorized" if exc.code in (401, 403) else "usage_limit" if exc.code == 429 else "unavailable"
            try:
                error = json.loads(exc.read(16384)).get("error", {})
                remote = error.get("code") if isinstance(error, dict) else error
                if remote == "invalid_grant":
                    code = "login_required"
                elif remote in ("subscription_sharing_usage_limit_exceeded", "subscription_sharing_usage_unavailable", "credit_balance_exhausted"):
                    code = "usage_limit"
            except (ValueError, OSError):
                pass
            raise OpenAIError(code) from None
        except (OSError, ValueError):
            raise OpenAIError() from None

    def json(self, url, **kwargs):
        with self.open(url, **kwargs) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise OpenAIError("oversized_response")
        try:
            return json.loads(raw)
        except ValueError:
            raise OpenAIError("invalid_response") from None

    def response(self, token, payload):
        # Un flux interrompu ou refusé ne produit jamais un rapport partiel.
        started, size, lines = time.monotonic(), 0, []
        with self.open("https://api.openai.com/v1/responses", body=payload, token=token) as response:
            for raw in response:
                size += len(raw)
                if size > 4_000_000 or time.monotonic() - started > 120:
                    raise OpenAIError("response_limit")
                line = raw.decode("utf-8").rstrip("\r\n")
                if line.startswith("data:"):
                    lines.append(line[5:].lstrip())
                elif not line and lines:
                    try:
                        event = json.loads("\n".join(lines))
                    except ValueError:
                        raise OpenAIError("invalid_response") from None
                    lines = []
                    kind = event.get("type")
                    if kind == "response.completed":
                        result = event.get("response", {})
                        if result.get("status") != "completed":
                            raise OpenAIError("incomplete_response")
                        return result
                    if kind in ("response.failed", "response.incomplete", "error"):
                        code = event.get("response", {}).get("error", {}).get("code", "")
                        raise OpenAIError("usage_limit" if code.startswith("subscription_sharing_") else "incomplete_response")
        raise OpenAIError("interrupted_stream")
