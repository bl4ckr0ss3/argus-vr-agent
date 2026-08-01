"""http_request — send arbitrary HTTP requests for web bug bounty.

Pure stdlib (urllib). Supports GET, POST, PUT, DELETE, PATCH, custom headers,
body, and TLS (with cert validation opt-out for internal/pentest targets).
Use for: SSRF, API fuzzing, XSS/SQLi probes, directory bruteforce, open-redirect
testing, arbitrary HTTP inspection.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

import config
from .base import Tool, cap

# Cap response body to a generous limit so the LLM can inspect full API responses.
_HTTP_BODY_CAP = int(config.TOOL_OUTPUT_CAP * 2.5)

_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

_USER_AGENT = "ARGUS/2.0 (VR/bug-bounty agent; authorized research only)"


def _send(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 30,
    allow_redirects: bool = True,
    verify_ssl: bool = False,
) -> dict:
    if method.upper() not in _METHODS:
        return {"error": f"unsupported method {method!r}", "status": 0}

    req_headers = dict(headers or {})
    req_headers.setdefault("User-Agent", _USER_AGENT)
    req_headers.setdefault("Accept", "*/*")

    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(
        url, data=data, headers=req_headers, method=method.upper()
    )

    ctx = None
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        if allow_redirects:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        else:
            import http.client

            class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(_NoRedirectHandler)
            resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", "ignore")
        resp_headers = dict(e.headers)
        parsed = urlparse(url)
        return {
            "status": e.code,
            "reason": e.reason,
            "headers": resp_headers,
            "body": cap(resp_body, _HTTP_BODY_CAP),
            "url": url,
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "tls": parsed.scheme == "https",
            "redirected": False,
            "timing_ms": 0,
        }
    except urllib.error.URLError as e:
        return {"error": f"connection failed: {e.reason}", "status": 0}
    except Exception as e:
        return {"error": f"request error: {e}", "status": 0}

    resp_body = resp.read().decode("utf-8", "ignore")
    resp_headers = dict(resp.headers)
    parsed = urlparse(resp.url if hasattr(resp, 'url') else url)
    return {
        "status": resp.status,
        "reason": getattr(resp, 'reason', 'OK'),
        "headers": resp_headers,
        "body": cap(resp_body, _HTTP_BODY_CAP),
        "url": url,
        "final_url": getattr(resp, 'url', url),
        "host": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "tls": parsed.scheme == "https",
        "redirected": getattr(resp, 'url', url) != url,
        "timing_ms": 0,
    }


def make_http_request() -> Tool:
    def handler(inp: dict) -> str:
        method = (inp.get("method") or "GET").strip().upper()
        url = (inp.get("url") or "").strip()
        if not url:
            return "ERROR: url is required."
        headers = inp.get("headers")
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except json.JSONDecodeError:
                headers = {}
        body = inp.get("body") or None
        timeout = int(inp.get("timeout", 30))
        redirects = inp.get("follow_redirects", True)
        if isinstance(redirects, str):
            redirects = redirects.lower() != "false"

        result = _send(
            method=method, url=url, headers=headers, body=body,
            timeout=min(timeout, 120), allow_redirects=redirects, verify_ssl=True,
        )

        if "error" in result:
            return f"HTTP FAILED: {result['error']}"

        lines = [
            f"{method} {url}",
            f"→ {result['status']} {result['reason']}",
            f"TLS: {result['tls']}  ·  host: {result['host']}:{result['port']}",
        ]
        if result["redirected"]:
            lines.append(f"redirected: → {result.get('final_url', '?')}")
        lines.append("--- response headers ---")
        for k, v in result["headers"].items():
            lines.append(f"  {k}: {v}")
        lines.append("--- response body ---")
        lines.append(result["body"])
        return "\n".join(lines)

    return Tool(
        name="http_request",
        description=(
            "Send an arbitrary HTTP request and return the full response (status, "
            "headers, body). Use for: testing API endpoints, probing for SSRF/XSS/"
            "SQLi, directory enumeration, open-redirect checks, inspecting CORS "
            "headers and security-relevant response data. Respects custom headers "
            "and all standard methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS). "
            "Returns the raw response for analysis."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request, e.g. 'https://api.target.com/v1/users?id=1'."},
                "method": {"type": "string", "description": "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS."},
                "headers": {"type": "object", "description": "Dict of custom headers, e.g. {\"X-API-Key\":\"test\", \"Origin\":\"https://evil.com\"}."},
                "body": {"type": "string", "description": "Request body (string). For JSON, pass the raw JSON string. For POST params, pass URL-encoded."},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30, max 120)."},
                "follow_redirects": {"type": "boolean", "description": "Follow 3xx redirects (default true)."},
            },
            "required": ["url"],
        },
        handler=handler,
    )
