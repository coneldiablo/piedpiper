#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenAI-compatible AITUNNEL provider adapter.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from core.config import config_manager

logger = logging.getLogger("ai_provider")


def extract_json_payload(content: str) -> Optional[Dict[str, Any]]:
    if not content:
        return None
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if "\n" in stripped:
            stripped = stripped.split("\n", 1)[1]
        if stripped.endswith("```"):
            stripped = stripped[:-3].strip()
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


class AITunnelProvider:
    """Thin requests-based adapter for the OpenAI-compatible AITUNNEL API."""

    def __init__(self) -> None:
        self.api_key = config_manager.get("AITUNNEL_API_KEY", "")
        self.base_url = str(config_manager.get("AITUNNEL_BASE_URL", "https://api.aitunnel.ru/v1/")).rstrip("/") + "/"
        self.model = str(config_manager.get("AITUNNEL_MODEL", "gemini-3-flash-preview"))
        self.timeout = int(config_manager.get("AITUNNEL_TIMEOUT", 45) or 45)
        self.max_retries = int(config_manager.get("AITUNNEL_MAX_RETRIES", 2) or 2)
        self.temperature = float(config_manager.get("AITUNNEL_TEMPERATURE", 0.2) or 0.2)
        self.verify_ssl = bool(config_manager.get("AITUNNEL_VERIFY_SSL", True))

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def status(self) -> Dict[str, Any]:
        return {
            "provider": "aitunnel",
            "configured": self.is_configured(),
            "base_url": self.base_url,
            "model": self.model,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "verify_ssl": self.verify_ssl,
            "mode": "llm" if self.is_configured() else "fallback",
            "reason": "" if self.is_configured() else "AITUNNEL_API_KEY is not set",
        }

    def chat(
        self,
        *,
        messages: Optional[List[Dict[str, str]]] = None,
        system_prompt: Optional[str] = None,
        user_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not self.is_configured():
            raise RuntimeError("AITUNNEL provider is not configured")

        payload_messages = list(messages or [])
        if system_prompt:
            payload_messages.insert(0, {"role": "system", "content": system_prompt})
        if user_prompt:
            payload_messages.append({"role": "user", "content": user_prompt})
        if not payload_messages:
            raise ValueError("messages or user_prompt must be provided")

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": payload_messages,
            "temperature": self.temperature if temperature is None else temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if response_format is not None:
            payload["response_format"] = response_format

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    self.base_url + "chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if response.status_code >= 500 and attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices") or []
                if not choices:
                    raise RuntimeError("AITUNNEL returned an empty choices list")
                message = choices[0].get("message") or {}
                content = message.get("content")
                if isinstance(content, list):
                    content = "".join(
                        chunk.get("text", "") if isinstance(chunk, dict) else str(chunk)
                        for chunk in content
                    )
                if not isinstance(content, str):
                    raise RuntimeError("AITUNNEL returned non-text content")
                return content.strip()
            except Exception as exc:  # pragma: no cover - runtime/network dependent
                last_error = exc
                logger.warning("AITUNNEL request attempt %d failed: %s", attempt + 1, exc)
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))

        raise RuntimeError(f"AITUNNEL request failed: {last_error}")


__all__ = ["AITunnelProvider", "extract_json_payload"]
