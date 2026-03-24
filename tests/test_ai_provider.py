import pytest
import requests

import services.ai_provider as ai_provider_module
from core.config import config_manager
from services.ai_provider import AITunnelProvider, extract_json_payload


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status={self.status_code}")

    def json(self):
        return self._payload


def _set_provider_config(monkeypatch, **overrides):
    defaults = {
        "AITUNNEL_API_KEY": "",
        "AITUNNEL_BASE_URL": "https://api.aitunnel.ru/v1/",
        "AITUNNEL_MODEL": "gemini-3-flash-preview",
        "AITUNNEL_TIMEOUT": 5,
        "AITUNNEL_MAX_RETRIES": 1,
        "AITUNNEL_TEMPERATURE": 0.2,
        "AITUNNEL_VERIFY_SSL": True,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        monkeypatch.setitem(config_manager.settings, key, value)


def test_extract_json_payload_supports_fenced_json():
    payload = extract_json_payload("""```json\n{"answer": 42}\n```""")
    assert payload == {"answer": 42}


def test_aitunnel_provider_status_fallback(monkeypatch):
    _set_provider_config(monkeypatch, AITUNNEL_API_KEY="")
    provider = AITunnelProvider()

    status = provider.status()
    assert status["configured"] is False
    assert status["mode"] == "fallback"
    assert "AITUNNEL_API_KEY" in status["reason"]


def test_aitunnel_provider_chat_success(monkeypatch):
    _set_provider_config(monkeypatch, AITUNNEL_API_KEY="test-key")

    def fake_post(url, json=None, headers=None, timeout=None, verify=None):
        assert url == "https://api.aitunnel.ru/v1/chat/completions"
        assert headers["Authorization"] == "Bearer test-key"
        assert json["model"] == "gemini-3-flash-preview"
        return _FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": "analysis ready",
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr(ai_provider_module.requests, "post", fake_post)
    provider = AITunnelProvider()

    result = provider.chat(user_prompt="hello")

    assert result == "analysis ready"


def test_aitunnel_provider_chat_retries_and_raises(monkeypatch):
    _set_provider_config(monkeypatch, AITUNNEL_API_KEY="test-key", AITUNNEL_MAX_RETRIES=1)
    attempts = {"count": 0}

    def fake_post(*args, **kwargs):
        attempts["count"] += 1
        raise requests.RequestException("network down")

    monkeypatch.setattr(ai_provider_module.requests, "post", fake_post)
    monkeypatch.setattr(ai_provider_module.time, "sleep", lambda *_args, **_kwargs: None)
    provider = AITunnelProvider()

    with pytest.raises(RuntimeError, match="AITUNNEL request failed"):
        provider.chat(user_prompt="hello")

    assert attempts["count"] == 2
