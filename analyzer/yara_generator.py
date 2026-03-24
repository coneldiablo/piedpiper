#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Machine-learning assisted YARA rule generator.

This module consumes aggregated analysis data (static/dynamic/Ioc/risk)
and produces a YARA rule that highlights the most discriminating strings
and indicators. The implementation reuses the heuristics from the legacy
scoring pipeline so that it can operate even when an ML model is absent.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set

from analyzer.ml_detector import MalwareMLDetector


class YARAGenerator:
    """Build YARA rules from analysis artefacts."""

    def __init__(self) -> None:
        self._detector = MalwareMLDetector()

    def generate_rule_ml(self, analysis_data: Dict[str, Any], rule_name: str) -> str:
        """
        Generate a YARA rule using ML-assisted heuristics.
        """
        static_section = analysis_data.get("static") or analysis_data.get("static_data") or {}
        dynamic_section = analysis_data.get("dynamic") or analysis_data.get("dynamic_data") or {}
        iocs = analysis_data.get("iocs") or []

        ml_probability: Optional[float] = None
        ml_details: Dict[str, Any] = {}
        try:
            ml_probability, ml_details = self._detector.predict_probability(
                static_section if isinstance(static_section, dict) else {},
                dynamic_section if isinstance(dynamic_section, dict) else {},
                iocs if isinstance(iocs, list) else [],
            )
        except Exception:
            ml_probability = None
            ml_details = {}

        contributions = ml_details.get("contributions", {}) if isinstance(ml_details, dict) else {}
        import_names = self._extract_import_names(static_section)
        candidates = self._collect_candidate_strings(static_section, dynamic_section, iocs)
        if not candidates:
            candidates.add("ThreatInquisitorMarker")

        scored_candidates = [
            (self._score_candidate_string(value, contributions, import_names), value)
            for value in candidates
        ]
        scored_candidates.sort(reverse=True)
        selected_strings = [value for _, value in scored_candidates[:6]]

        yara_strings = [
            f"        $s{idx} = {self._format_yara_string(value)}"
            for idx, value in enumerate(selected_strings)
        ]
        if not yara_strings:
            yara_strings.append('        $s0 = "auto_generated_indicator" ascii')

        required_hits = 1 if len(selected_strings) <= 2 else 2 if len(selected_strings) <= 4 else 3
        highlighted_imports = [
            name for name in import_names
            if any(api.lower() in name.lower() for api in MalwareMLDetector.SUSPICIOUS_APIS)
        ]
        condition_terms: List[str] = [f"{required_hits} of them"]
        condition_expression = " and ".join(condition_terms)

        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        meta_lines = [
            "        description = \"Auto-generated YARA rule from ThreatInquisitor\"",
            f"        generated_at = \"{generated_at}\"",
            "        author = \"ThreatInquisitor YARAGenerator\"",
            f"        ml_probability = \"{ml_probability:.3f}\"" if ml_probability is not None else "        ml_probability = \"unknown\"",
        ]
        if contributions:
            top_contrib = sorted(contributions.items(), key=lambda item: item[1], reverse=True)[:3]
            meta_lines.append(
                "        ml_top_features = \""
                + ", ".join(f"{key}:{value:.2f}" for key, value in top_contrib)
                + "\""
            )
        if highlighted_imports:
            meta_lines.append(
                "        highlighted_imports = \""
                + ", ".join(highlighted_imports[:3])
                + "\""
            )

        rule_lines: List[str] = [
            f"rule {self._sanitize_rule_name(rule_name)} {{",
            "    meta:",
            *meta_lines,
            "    strings:",
            *yara_strings,
            "    condition:",
            f"        {condition_expression}",
            "}",
        ]

        return "\n".join(rule_lines)

    def _collect_candidate_strings(
        self,
        static_section: Dict[str, Any],
        dynamic_section: Dict[str, Any],
        iocs: List[Dict[str, Any]],
    ) -> Set[str]:
        candidates: Set[str] = set()
        strings = static_section.get("strings")
        if isinstance(strings, list):
            for item in strings:
                if isinstance(item, str):
                    cleaned = item.strip()
                    if 4 <= len(cleaned) <= 120:
                        candidates.add(cleaned)

        for ioc in iocs or []:
            if isinstance(ioc, dict):
                value = ioc.get("value") or ioc.get("indicator") or ioc.get("data")
                if isinstance(value, str):
                    cleaned = value.strip()
                    if cleaned:
                        candidates.add(cleaned)

        if isinstance(dynamic_section, dict):
            api_calls = dynamic_section.get("api_calls") or []
            if isinstance(api_calls, list):
                for call in api_calls:
                    if isinstance(call, dict):
                        api_name = call.get("api") or call.get("function")
                        if isinstance(api_name, str):
                            candidates.add(api_name)
                        args = call.get("args")
                        if isinstance(args, dict):
                            for arg_value in args.values():
                                if isinstance(arg_value, str) and 4 <= len(arg_value) <= 120:
                                    candidates.add(arg_value)

        candidates.update(self._extract_import_names(static_section))
        return candidates

    def _extract_import_names(self, static_section: Dict[str, Any]) -> List[str]:
        imports = static_section.get("imports")
        names: List[str] = []
        if isinstance(imports, list):
            for entry in imports:
                if isinstance(entry, str):
                    names.append(entry.split("!")[-1])
                elif isinstance(entry, dict):
                    for value in entry.values():
                        if isinstance(value, str):
                            names.append(value.split("!")[-1])
        elif isinstance(imports, dict):
            for value in imports.values():
                if isinstance(value, str):
                    names.append(value.split("!")[-1])
        dedup: List[str] = []
        for name in names:
            cleaned = name.strip()
            if cleaned and cleaned not in dedup:
                dedup.append(cleaned)
        return dedup

    @staticmethod
    def _sanitize_rule_name(name: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9_]", "_", name)
        if not sanitized:
            sanitized = "TI_auto_rule"
        if sanitized[0].isdigit():
            sanitized = f"rule_{sanitized}"
        return sanitized

    @staticmethod
    def _format_yara_string(value: str) -> str:
        printable = all(32 <= ord(ch) < 127 for ch in value)
        if printable:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            flags = ["ascii"]
            if re.search(r"[A-Za-z]", value):
                flags.append("wide")
            if not (any(ch.islower() for ch in value) and any(ch.isupper() for ch in value)):
                flags.append("nocase")
            return f"\"{escaped}\" " + " ".join(flags)
        hex_bytes = " ".join(f"{b:02x}" for b in value.encode("utf-8", errors="ignore"))
        return "{ " + hex_bytes + " }"

    def _score_candidate_string(
        self,
        value: str,
        contributions: Dict[str, Any],
        import_names: List[str],
    ) -> float:
        score = 0.1
        lowered = value.lower()
        if re.search(r"https?://", value):
            score += 0.6
        if any(keyword in lowered for keyword in ("powershell", "cmd.exe", "shell", "download", "mimikatz", "regsvr32")):
            score += 0.4
        if len(value) > 32:
            score += 0.2
        if any(name.lower() in lowered for name in import_names):
            score += 0.3
        if contributions.get("suspicious_imports") and any(name.lower() in lowered for name in import_names):
            score += contributions["suspicious_imports"]
        if contributions.get("ioc_density") and re.search(r"[0-9]{2,}", value):
            score += contributions["ioc_density"] * 0.5
        return score


__all__ = ["YARAGenerator"]
