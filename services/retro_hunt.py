#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Retro-hunt orchestration across external telemetry providers (SIEM, EDR, sandboxes).

The orchestrator replays extracted IoCs and aggregates the feedback to
strengthen ThreatInquisitor scoring and confidence assessments.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

import requests

from core.config import config_manager

logger = logging.getLogger("retro_hunt")


@dataclass
class HuntResult:
    connector: str
    status: str
    hits: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def hit_count(self) -> int:
        return len(self.hits)


class RetroHuntConnector:
    """Base connector with minimal lifecycle helpers."""

    def __init__(
        self,
        name: str,
        endpoint: Optional[str],
        *,
        token: Optional[str] = None,
        timeout: int = 15,
        verify_ssl: bool = True,
        enabled: Optional[bool] = None,
    ) -> None:
        self.name = name
        self.endpoint = endpoint
        self.token = token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._explicit_enabled = enabled

    def is_enabled(self) -> bool:
        if self._explicit_enabled is not None:
            return self._explicit_enabled
        return bool(self.endpoint)

    def execute(self, iocs: Iterable[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> HuntResult:
        raise NotImplementedError

    def _prepare_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


class SIEMConnector(RetroHuntConnector):
    """Posts IoC bundles to a SIEM search endpoint."""

    def execute(self, iocs: Iterable[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> HuntResult:
        if not self.is_enabled():
            return HuntResult(self.name, "skipped", metadata={"reason": "connector disabled"})
        payload = {
            "operation": "retro_hunt",
            "iocs": list(iocs),
            "context": context or {},
        }
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=self._prepare_headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            data = response.json()
            hits = data.get("hits", [])
            return HuntResult(
                self.name,
                "success",
                hits=hits,
                metadata={
                    "search_id": data.get("search_id"),
                    "took_ms": data.get("took_ms"),
                },
            )
        except Exception as exc:
            logger.error("SIEM connector failure: %s", exc)
            return HuntResult(self.name, "error", metadata={"error": str(exc)})


class EDRConnector(RetroHuntConnector):
    """Queries endpoint detections for matches."""

    def execute(self, iocs: Iterable[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> HuntResult:
        if not self.is_enabled():
            return HuntResult(self.name, "skipped", metadata={"reason": "connector disabled"})
        payload = {
            "indicator_set": list(iocs),
            "lookback_hours": (context or {}).get("lookback_hours", 72),
        }
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=self._prepare_headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            data = response.json()
            detections = data.get("detections", [])
            return HuntResult(
                self.name,
                "success",
                hits=detections,
                metadata={
                    "agents_touched": data.get("agents_touched", 0),
                    "query": data.get("query"),
                },
            )
        except Exception as exc:
            logger.error("EDR connector failure: %s", exc)
            return HuntResult(self.name, "error", metadata={"error": str(exc)})


class SandboxConnector(RetroHuntConnector):
    """Uploads IoCs or samples to sandbox automation for replay."""

    def execute(self, iocs: Iterable[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> HuntResult:
        if not self.is_enabled():
            return HuntResult(self.name, "skipped", metadata={"reason": "connector disabled"})
        payload = {
            "artifacts": list(iocs),
            "profile": (context or {}).get("profile", "default"),
        }
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=self._prepare_headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            data = response.json()
            sessions = data.get("sessions", [])
            return HuntResult(
                self.name,
                "success",
                hits=sessions,
                metadata={
                    "sandbox_profile": payload["profile"],
                    "session_count": len(sessions),
                },
            )
        except Exception as exc:
            logger.error("Sandbox connector failure: %s", exc)
            return HuntResult(self.name, "error", metadata={"error": str(exc)})


class RetroHuntOrchestrator:
    """
    Coordinated orchestration across the configured hunting backends.

    Example:
        orchestrator = RetroHuntOrchestrator()
        summary = orchestrator.run(iocs, context={"case_id": "INC-42"})
    """

    def __init__(
        self,
        connectors: Optional[List[RetroHuntConnector]] = None,
        *,
        max_workers: Optional[int] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._config = config or config_manager.get("RETRO_HUNT", {})
        self.connectors = connectors or self._build_default_connectors(self._config)
        self.max_workers = max_workers or max(1, len(self.connectors))

    def _build_default_connectors(self, cfg: Dict[str, Any]) -> List[RetroHuntConnector]:
        connectors: List[RetroHuntConnector] = []

        siem_cfg = cfg.get("siem", {})
        connectors.append(
            SIEMConnector(
                "siem",
                siem_cfg.get("endpoint"),
                token=siem_cfg.get("token"),
                timeout=siem_cfg.get("timeout", 20),
                verify_ssl=siem_cfg.get("verify_ssl", True),
                enabled=siem_cfg.get("enabled"),
            )
        )

        edr_cfg = cfg.get("edr", {})
        connectors.append(
            EDRConnector(
                "edr",
                edr_cfg.get("endpoint"),
                token=edr_cfg.get("token"),
                timeout=edr_cfg.get("timeout", 20),
                verify_ssl=edr_cfg.get("verify_ssl", True),
                enabled=edr_cfg.get("enabled"),
            )
        )

        sandbox_cfg = cfg.get("sandbox", {})
        connectors.append(
            SandboxConnector(
                "sandbox",
                sandbox_cfg.get("endpoint"),
                token=sandbox_cfg.get("token"),
                timeout=sandbox_cfg.get("timeout", 60),
                verify_ssl=sandbox_cfg.get("verify_ssl", True),
                enabled=sandbox_cfg.get("enabled"),
            )
        )

        return connectors

    def run(
        self,
        iocs: Iterable[Dict[str, Any]],
        *,
        context: Optional[Dict[str, Any]] = None,
        result_callback: Optional[Callable[[HuntResult], None]] = None,
    ) -> Dict[str, Any]:
        ioc_list = list(iocs)
        if not ioc_list:
            return {"status": "no_iocs", "results": [], "confidence_boost": 0.0}

        active_connectors = [c for c in self.connectors if c.is_enabled()]
        if not active_connectors:
            logger.warning("Retro-hunt aborted: no enabled connectors")
            return {"status": "no_connectors", "results": [], "confidence_boost": 0.0}

        results: List[HuntResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(conn.execute, ioc_list, context): conn
                for conn in active_connectors
            }
            for future in as_completed(futures):
                connector = futures[future]
                try:
                    result = future.result()
                    logger.debug("Connector %s finished with %s", connector.name, result.status)
                except Exception as exc:
                    logger.exception("Connector %s raised unexpected error", connector.name)
                    result = HuntResult(connector.name, "error", metadata={"error": str(exc)})
                results.append(result)
                if result_callback:
                    try:
                        result_callback(result)
                    except Exception as callback_exc:
                        logger.error("Retro-hunt callback error: %s", callback_exc)

        confidence_boost = self._derive_confidence(results)

        aggregated = {
            "status": "completed",
            "results": [r.__dict__ for r in results],
            "confidence_boost": confidence_boost,
            "total_hits": sum(r.hit_count() for r in results if r.status == "success"),
        }
        return aggregated

    @staticmethod
    def _derive_confidence(results: List[HuntResult]) -> float:
        successful = [r for r in results if r.status == "success"]
        if not successful:
            return 0.0
        hit_connectors = sum(1 for r in successful if r.hit_count() > 0)
        ratio = hit_connectors / len(successful)
        return round(min(1.0, 0.2 + ratio * 0.6), 3)

