"""Tests for the web console token auth + fail-closed binding."""
import pytest

import config
import web.server as ws


def _handler(headers, path):
    h = ws.Handler.__new__(ws.Handler)   # bypass socket __init__
    h.headers = headers
    h.path = path
    return h


def test_no_token_config_is_open(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "")
    assert _handler({}, "/api/stats")._authed() is True


def test_missing_token_denied(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "secret")
    assert _handler({}, "/api/stats")._authed() is False


def test_bearer_header(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "secret")
    assert _handler({"Authorization": "Bearer secret"}, "/api/stats")._authed() is True
    assert _handler({"Authorization": "Bearer wrong"}, "/api/stats")._authed() is False


def test_query_token(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "secret")
    assert _handler({}, "/api/hunt?task=x&token=secret")._authed() is True
    assert _handler({}, "/api/hunt?task=x&token=nope")._authed() is False


def test_cookie_token(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "secret")
    assert _handler({"Cookie": "argus_token=secret"}, "/api/stats")._authed() is True
    assert _handler({"Cookie": "other=1; argus_token=secret"}, "/api/stats")._authed() is True
    assert _handler({"Cookie": "argus_token=bad"}, "/api/stats")._authed() is False


def test_guard_refuses_public_without_token(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "")
    ws._guard_binding("127.0.0.1")          # local is fine
    ws._guard_binding("localhost")
    with pytest.raises(SystemExit):
        ws._guard_binding("0.0.0.0")        # public without token -> refuse


def test_guard_allows_public_with_token(monkeypatch):
    monkeypatch.setattr(config, "WEB_TOKEN", "a-long-secret")
    ws._guard_binding("0.0.0.0")            # token set -> allowed
