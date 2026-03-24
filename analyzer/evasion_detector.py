#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Heuristic detection of sandbox-evasion behaviour.

The detector operates on API call traces collected during dynamic analysis
and highlights patterns that typically indicate attempts to fingerprint
analysis environments (VM checks, timing attacks, debugger detection, etc.).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List


class EvasionDetector:
    """Analyse API call sequences and flag sandbox-evasion techniques."""

    VM_CHECK_APIS = {
        "GetSystemFirmwareTable",
        "GetFirmwareEnvironmentVariableA",
        "GetFirmwareEnvironmentVariableW",
        "GetAdaptersInfo",
        "GetSystemInfo",
        "GetNativeSystemInfo",
        "NtQuerySystemInformation",
        "RegQueryValueExA",
        "RegQueryValueExW",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "CreateToolhelp32Snapshot",
    }

    VM_REGISTRY_PATTERNS = [
        r"SOFTWARE\\\\(Oracle|VirtualBox)",
        r"SYSTEM\\\\CurrentControlSet\\\\Services\\\\(VBox|vmware)",
        r"SOFTWARE\\\\Microsoft\\\\Virtual Machine",
        r"SYSTEM\\\\CurrentControlSet\\\\Enum\\\\PCI\\\\VEN_15AD",
    ]

    VM_PROCESSES = [
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vboxservice.exe",
        "vboxtray.exe",
    ]

    TIMING_APIS = {
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "GetTickCount",
        "GetTickCount64",
        "NtDelayExecution",
        "Sleep",
        "SleepEx",
    }

    def detect_vm_checks(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a list of detections describing VM fingerprinting behaviour."""
        detections: List[Dict[str, Any]] = []

        for call in api_calls:
            api_name = str(call.get("api") or call.get("function") or "").strip()
            if api_name in self.VM_CHECK_APIS:
                detections.append(
                    {
                        "type": "vm_api_call",
                        "api": api_name,
                        "args": call.get("args", {}),
                        "timestamp": call.get("timestamp"),
                        "details": "Direct VM artifact check",
                    }
                )

            # Registry access heuristics
            path = ""
            args = call.get("args", {})
            if isinstance(args, dict):
                path = str(args.get("subKey") or args.get("lpSubKey") or args.get("lpValueName") or "")

            for pattern in self.VM_REGISTRY_PATTERNS:
                if path and re.search(pattern, path, re.IGNORECASE):
                    detections.append(
                        {
                            "type": "vm_registry_probe",
                            "api": api_name,
                            "path": path,
                            "timestamp": call.get("timestamp"),
                            "details": f"Matched pattern: {pattern}",
                        }
                    )

            # Process enumeration hints
            target_process = ""
            if isinstance(args, dict):
                target_process = str(args.get("lpModuleName") or args.get("process") or "")
            if target_process.lower() in self.VM_PROCESSES:
                detections.append(
                    {
                        "type": "vm_process_lookup",
                        "process": target_process,
                        "timestamp": call.get("timestamp"),
                        "details": "Lookup for virtualization-related process",
                    }
                )

        return detections

    def detect_timing_attacks(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect timing anomalies such as excessive sleeps or counter checks."""
        detections: List[Dict[str, Any]] = []
        sleep_calls = []

        for call in api_calls:
            api_name = str(call.get("api") or call.get("function") or "").strip()
            if api_name not in self.TIMING_APIS:
                continue

            args = call.get("args", {})
            duration = None
            if isinstance(args, dict):
                duration = args.get("dwMilliseconds") or args.get("milliseconds") or args.get("DelayInterval")
            if isinstance(duration, (int, float)) and duration >= 10_000:
                detections.append(
                    {
                        "type": "long_sleep",
                        "api": api_name,
                        "duration_ms": int(duration),
                        "timestamp": call.get("timestamp"),
                        "details": "Sleep longer than 10 seconds",
                    }
                )
            elif api_name in {"Sleep", "SleepEx"}:
                sleep_calls.append(api_name)

        sleep_stats = Counter(sleep_calls)
        if sleep_stats and sum(sleep_stats.values()) >= 5:
            detections.append(
                {
                    "type": "sleep_loop",
                    "details": f"Detected repeated sleeps: {dict(sleep_stats)}",
                }
            )

        return detections

    def analyse(self, api_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Return a structured report combining all sandbox evasion detections."""
        vm_checks = self.detect_vm_checks(api_calls)
        timing = self.detect_timing_attacks(api_calls)
        score = len(vm_checks) * 2 + len(timing)

        return {
            "score": score,
            "vm_checks": vm_checks,
            "timing_attacks": timing,
            "summary": self._build_summary(score, vm_checks, timing),
        }

    @staticmethod
    def _build_summary(score: int, vm_checks: List[Dict[str, Any]], timing: List[Dict[str, Any]]) -> str:
        if score == 0:
            return "No sandbox evasion behaviour detected."
        messages = []
        if vm_checks:
            messages.append(f"{len(vm_checks)} VM artifact checks observed")
        if timing:
            messages.append(f"{len(timing)} timing anomalies observed")
        return "; ".join(messages)


__all__ = ["EvasionDetector"]

