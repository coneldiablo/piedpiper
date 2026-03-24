#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Live threat simulation utilities for spinning up disposable sandboxes,
replaying captured samples, and harvesting behavioural telemetry.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("threat_simulation")


class LiveThreatSimulator:
    """
    High-level helper that manages the lifecycle of temporary sandboxes
    and returns structured telemetry ready for downstream analytics.
    """

    def __init__(
        self,
        *,
        sandbox_root: Optional[Path] = None,
        retain_artifacts: bool = False,
    ) -> None:
        self.sandbox_root = sandbox_root or Path(tempfile.gettempdir()) / "threatinq_sandboxes"
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.retain_artifacts = retain_artifacts

    def run_simulation(
        self,
        artifact: str,
        *,
        profile: str = "default",
        duration_seconds: int = 60,
        capture_network: bool = True,
        capture_syscalls: bool = True,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        sandbox_id = self._create_sandbox(profile)
        start_ts = time.time()
        logger.info("Sandbox %s created for artifact %s", sandbox_id, artifact)

        try:
            artifact_path = self._stage_artifact(sandbox_id, artifact)
            session_id = f"SIM-{uuid.uuid4().hex[:12]}"
            metadata = {
                "sandbox_id": sandbox_id,
                "session_id": session_id,
                "profile": profile,
                "artifact": artifact,
                "artifact_path": str(artifact_path),
                "notes": notes or "",
            }

            telemetry: Dict[str, Any] = {
                "syscalls": [],
                "network": [],
                "artifacts": [],
            }

            if capture_syscalls:
                telemetry["syscalls"] = self._record_syscalls(artifact_path, duration_seconds)
            if capture_network:
                telemetry["network"] = self._record_network_flow(artifact_path, duration_seconds)

            telemetry["artifacts"] = self._catalog_artifacts(sandbox_id)

            summary = {
                "metadata": metadata,
                "telemetry": telemetry,
                "duration_seconds": max(1, int(time.time() - start_ts)),
            }
            self._persist_summary(sandbox_id, summary)
            logger.info("Simulation %s finished", session_id)
            return summary
        finally:
            if not self.retain_artifacts:
                self._destroy_sandbox(sandbox_id)

    def _create_sandbox(self, profile: str) -> str:
        sandbox_id = f"{profile}-{uuid.uuid4().hex[:8]}"
        (self.sandbox_root / sandbox_id).mkdir(parents=True, exist_ok=True)
        return sandbox_id

    def _stage_artifact(self, sandbox_id: str, artifact: str) -> Path:
        sandbox_path = self.sandbox_root / sandbox_id
        artifact_path = Path(artifact)
        if artifact_path.exists():
            staged = sandbox_path / artifact_path.name
            shutil.copy2(artifact_path, staged)
            return staged
        staged = sandbox_path / f"artifact_{uuid.uuid4().hex[:6]}.bin"
        staged.write_bytes(artifact.encode("utf-8"))
        return staged

    def _record_syscalls(self, artifact_path: Path, duration: int) -> List[Dict[str, Any]]:
        """Simulate syscall capture output (placeholder until real integration)."""
        simulated = [
            {
                "timestamp": time.time(),
                "process": artifact_path.name,
                "call": "NtCreateFile",
                "arguments": {"path": "C:\\\\Windows\\\\Temp\\\\stage.tmp"},
            },
            {
                "timestamp": time.time() + 0.01,
                "process": artifact_path.name,
                "call": "NtWriteFile",
                "arguments": {"bytes": 4096},
            },
            {
                "timestamp": time.time() + 0.02,
                "process": artifact_path.name,
                "call": "NtCreateProcessEx",
                "arguments": {"target": "rundll32.exe"},
            },
        ]
        logger.debug("Simulated %d syscalls for %s", len(simulated), artifact_path)
        return simulated

    def _record_network_flow(self, artifact_path: Path, duration: int) -> List[Dict[str, Any]]:
        """Simulate network capture rows (placeholder)."""
        simulated = [
            {
                "timestamp": time.time(),
                "src": "10.0.2.15",
                "dst": "198.51.100.42",
                "protocol": "TCP",
                "dst_port": 443,
                "bytes_sent": 512,
                "bytes_recv": 128,
            },
            {
                "timestamp": time.time() + 5,
                "src": "10.0.2.15",
                "dst": "203.0.113.77",
                "protocol": "TCP",
                "dst_port": 8080,
                "bytes_sent": 2048,
                "bytes_recv": 256,
            },
        ]
        logger.debug("Simulated %d network flows for %s", len(simulated), artifact_path)
        return simulated

    def _catalog_artifacts(self, sandbox_id: str) -> List[str]:
        sandbox_path = self.sandbox_root / sandbox_id
        return [str(item) for item in sandbox_path.glob("**/*") if item.is_file()]

    def _persist_summary(self, sandbox_id: str, summary: Dict[str, Any]) -> None:
        sandbox_path = self.sandbox_root / sandbox_id
        report_path = sandbox_path / "summary.json"
        try:
            report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to persist sandbox summary: %s", exc)

    def _destroy_sandbox(self, sandbox_id: str) -> None:
        sandbox_path = self.sandbox_root / sandbox_id
        if sandbox_path.exists():
            try:
                shutil.rmtree(sandbox_path, ignore_errors=True)
                logger.debug("Sandbox %s removed", sandbox_id)
            except Exception as exc:
                logger.warning("Failed to remove sandbox %s: %s", sandbox_id, exc)

