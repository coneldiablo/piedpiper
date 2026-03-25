#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor configuration manager.

Loads `config.json`, then applies environment-only secret overrides and
selected runtime defaults used by the API, retro-hunt, AI provider, and
other subsystems.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any, Iterable, Optional

logger = logging.getLogger("config")
logger.setLevel(logging.DEBUG)


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_scalar(value: str, expected_type: type) -> Any:
    if expected_type is bool:
        return _parse_bool(value)
    if expected_type is int:
        return int(value)
    if expected_type is float:
        return float(value)
    return value


class ConfigManager:
    """
    Lightweight JSON + environment configuration manager.
    """

    _DIRECT_ENV_OVERRIDES = {
        "THREATINQ_VT_KEY": ("VIRUSTOTAL_API_KEY", str),
        "THREATINQ_FRIDA_OPTS": ("FRIDA_OPTIONS", str),
        "AITUNNEL_API_KEY": ("AITUNNEL_API_KEY", str),
        "AITUNNEL_BASE_URL": ("AITUNNEL_BASE_URL", str),
        "AITUNNEL_MODEL": ("AITUNNEL_MODEL", str),
        "AITUNNEL_TIMEOUT": ("AITUNNEL_TIMEOUT", int),
        "AITUNNEL_MAX_RETRIES": ("AITUNNEL_MAX_RETRIES", int),
        "AITUNNEL_TEMPERATURE": ("AITUNNEL_TEMPERATURE", float),
        "AITUNNEL_VERIFY_SSL": ("AITUNNEL_VERIFY_SSL", bool),
        "ABUSECH_AUTH_KEY": ("ABUSECH_AUTH_KEY", str),
        "THREATFOX_API_KEY": ("THREATFOX_API_KEY", str),
        "URLHAUS_API_KEY": ("URLHAUS_API_KEY", str),
        "MALWAREBAZAAR_API_KEY": ("MALWAREBAZAAR_API_KEY", str),
        "QDRANT_ENABLED": ("QDRANT_ENABLED", bool),
        "QDRANT_ENDPOINT": ("QDRANT_ENDPOINT", str),
        "QDRANT_API_KEY": ("QDRANT_API_KEY", str),
        "QDRANT_COLLECTION": ("QDRANT_COLLECTION", str),
        "QDRANT_TIMEOUT": ("QDRANT_TIMEOUT", int),
        "QDRANT_VERIFY_SSL": ("QDRANT_VERIFY_SSL", bool),
        "QDRANT_DISTANCE": ("QDRANT_DISTANCE", str),
    }

    _NESTED_ENV_OVERRIDES = {
        "RETRO_HUNT_SIEM_ENDPOINT": ("RETRO_HUNT", "siem", "endpoint", str),
        "RETRO_HUNT_SIEM_TOKEN": ("RETRO_HUNT", "siem", "token", str),
        "RETRO_HUNT_SIEM_TIMEOUT": ("RETRO_HUNT", "siem", "timeout", int),
        "RETRO_HUNT_SIEM_VERIFY_SSL": ("RETRO_HUNT", "siem", "verify_ssl", bool),
        "RETRO_HUNT_SIEM_ENABLED": ("RETRO_HUNT", "siem", "enabled", bool),
        "RETRO_HUNT_EDR_ENDPOINT": ("RETRO_HUNT", "edr", "endpoint", str),
        "RETRO_HUNT_EDR_TOKEN": ("RETRO_HUNT", "edr", "token", str),
        "RETRO_HUNT_EDR_TIMEOUT": ("RETRO_HUNT", "edr", "timeout", int),
        "RETRO_HUNT_EDR_VERIFY_SSL": ("RETRO_HUNT", "edr", "verify_ssl", bool),
        "RETRO_HUNT_EDR_ENABLED": ("RETRO_HUNT", "edr", "enabled", bool),
        "RETRO_HUNT_SANDBOX_ENDPOINT": ("RETRO_HUNT", "sandbox", "endpoint", str),
        "RETRO_HUNT_SANDBOX_TOKEN": ("RETRO_HUNT", "sandbox", "token", str),
        "RETRO_HUNT_SANDBOX_TIMEOUT": ("RETRO_HUNT", "sandbox", "timeout", int),
        "RETRO_HUNT_SANDBOX_VERIFY_SSL": ("RETRO_HUNT", "sandbox", "verify_ssl", bool),
        "RETRO_HUNT_SANDBOX_ENABLED": ("RETRO_HUNT", "sandbox", "enabled", bool),
    }

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file if config_file else os.path.join(os.getcwd(), "config.json")
        self.settings: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        self.settings = {}
        self._load_config()
        self._apply_runtime_defaults()
        self._override_with_env()

    def _load_config(self) -> None:
        if not os.path.isfile(self.config_file):
            logger.warning("[Config] File not found: %s. Using empty settings.", self.config_file)
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:
            logger.error("[Config] Error reading %s: %s", self.config_file, exc)
            return

        if not isinstance(data, dict):
            logger.warning("[Config] %s is not a dict JSON.", self.config_file)
            return

        self.settings.update(data)
        logger.debug("[Config] Loaded settings from %s", self.config_file)

    def _apply_runtime_defaults(self) -> None:
        self.settings.setdefault("AITUNNEL_BASE_URL", "https://api.aitunnel.ru/v1/")
        self.settings.setdefault("AITUNNEL_MODEL", "gemini-3-flash-preview")
        self.settings.setdefault("AITUNNEL_TIMEOUT", 45)
        self.settings.setdefault("AITUNNEL_MAX_RETRIES", 2)
        self.settings.setdefault("AITUNNEL_TEMPERATURE", 0.2)
        self.settings.setdefault("AITUNNEL_VERIFY_SSL", True)
        self.settings.setdefault("QDRANT_ENABLED", False)
        self.settings.setdefault("QDRANT_ENDPOINT", "http://127.0.0.1:6333")
        self.settings.setdefault("QDRANT_COLLECTION", "pied_piper_ml_profiles")
        self.settings.setdefault("QDRANT_TIMEOUT", 15)
        self.settings.setdefault("QDRANT_VERIFY_SSL", True)
        self.settings.setdefault("QDRANT_DISTANCE", "Manhattan")

        retro_hunt = self.settings.setdefault("RETRO_HUNT", {})
        if not isinstance(retro_hunt, dict):
            retro_hunt = {}
            self.settings["RETRO_HUNT"] = retro_hunt

        for connector_name, timeout in (("siem", 20), ("edr", 20), ("sandbox", 60)):
            connector_cfg = retro_hunt.setdefault(connector_name, {})
            if not isinstance(connector_cfg, dict):
                connector_cfg = {}
                retro_hunt[connector_name] = connector_cfg
            connector_cfg.setdefault("endpoint", "")
            connector_cfg.setdefault("timeout", timeout)
            connector_cfg.setdefault("verify_ssl", True)
            connector_cfg.setdefault("enabled", False)

    def _set_nested(self, path: Iterable[str], value: Any) -> None:
        keys = list(path)
        if not keys:
            return
        target = self.settings
        for key in keys[:-1]:
            existing = target.get(key)
            if not isinstance(existing, dict):
                existing = {}
                target[key] = existing
            target = existing
        target[keys[-1]] = value

    def _override_with_env(self) -> None:
        for env_name, (config_key, expected_type) in self._DIRECT_ENV_OVERRIDES.items():
            env_value = os.environ.get(env_name)
            if env_value is None or env_value == "":
                continue
            try:
                self.settings[config_key] = _parse_scalar(env_value, expected_type)
                logger.debug("[Config] Overriding %s from env %s", config_key, env_name)
            except Exception as exc:
                logger.warning("[Config] Failed to parse %s from env %s: %s", config_key, env_name, exc)

        for env_name, mapping in self._NESTED_ENV_OVERRIDES.items():
            env_value = os.environ.get(env_name)
            if env_value is None or env_value == "":
                continue
            *path, expected_type = mapping
            try:
                parsed = _parse_scalar(env_value, expected_type)
                self._set_nested(path, parsed)
                logger.debug("[Config] Overriding %s from env %s", ".".join(path), env_name)
            except Exception as exc:
                logger.warning("[Config] Failed to parse nested override %s: %s", env_name, exc)

    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

    def get_copy(self, key: str, default: Any = None) -> Any:
        return copy.deepcopy(self.settings.get(key, default))

    def set(self, key: str, value: Any) -> None:
        self.settings[key] = value
        logger.debug("[Config] Set %s=%s", key, value)

    def save_config(self, path: Optional[str] = None) -> bool:
        output_file = path if path else self.config_file
        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(self.settings, handle, indent=2, ensure_ascii=False)
            logger.debug("[Config] Saved config to %s", output_file)
            return True
        except Exception as exc:
            logger.error("[Config] Error saving config to %s: %s", output_file, exc)
            return False


config_manager = ConfigManager()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("[Config Test] Current settings:", json.dumps(config_manager.settings, ensure_ascii=False, indent=2))
