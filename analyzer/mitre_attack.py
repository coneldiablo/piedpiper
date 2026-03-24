#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/mitre_attack.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    from core.config import config_manager
except Exception:  # pragma: no cover - fallback when config layer unavailable
    config_manager = None  # type: ignore

logger = logging.getLogger("mitre_attack")

DEFAULT_ENTERPRISE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "mitre_cache"

TACTIC_NAME_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

DEFAULT_INDICATOR_HINTS: Dict[str, Dict[str, List[str]]] = {
    "T1059.001": {"indicators": ["powershell.exe", "Invoke-Expression", "DownloadString"]},
    "T1059.003": {"indicators": ["cmd.exe", "cmd /c", "cmd /k"]},
    "T1106": {"indicators": ["CreateProcess", "CreateRemoteThread", "NtCreateThread"]},
    "T1547.001": {"indicators": ["CurrentVersion\\Run", "CurrentVersion\\RunOnce", "RegCreateKey"]},
    "T1053.005": {"indicators": ["schtasks", "Task Scheduler", "at.exe"]},
    "T1543.003": {"indicators": ["CreateService", "sc.exe create", "OpenSCManager"]},
    "T1055": {"indicators": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "SetThreadContext"]},
    "T1070.004": {"indicators": ["DeleteFile", "del /f", "Remove-Item"]},
    "T1140": {"indicators": ["base64", "FromBase64String", "certutil -decode"]},
    "T1003.001": {"indicators": ["lsass.exe", "mimikatz", "ProcDump", "MiniDumpWriteDump"]},
    "T1555": {"indicators": ["Credential Manager", "Windows Vault", "logins.json"]},
    "T1082": {"indicators": ["systeminfo", "GetSystemInfo", "ver", "wmic computersystem"]},
    "T1083": {"indicators": ["dir", "FindFirst", "FindNext", "tree"]},
    "T1057": {"indicators": ["tasklist", "Get-Process", "EnumProcesses", "ps"]},
    "T1005": {"indicators": ["ReadFile", "CopyFile", "xcopy", "robocopy"]},
    "T1113": {"indicators": ["BitBlt", "GetDC", "screenshot", "ScreenShot"]},
    "T1115": {"indicators": ["GetClipboardData", "SetClipboardData", "OpenClipboard"]},
    "T1071.001": {"indicators": ["http://", "https://", "HttpSendRequest", "WinHttpOpen"]},
    "T1573": {"indicators": ["SSL", "TLS", "WinHttpSetOption"]},
    "T1095": {"indicators": ["socket", "WSASocket", "bind", "listen"]},
    "T1041": {"indicators": ["POST", "PUT", "send", "transmit"]},
    "T1486": {"indicators": ["CryptEncrypt", "encrypt", ".encrypted", ".locked", "ransom"]},
    "T1490": {"indicators": ["vssadmin delete", "bcdedit", "wbadmin delete"]},
}

CATEGORY_WEIGHTS: Dict[str, float] = {
    "string": 0.5,
    "suspicious_string": 0.75,
    "import": 1.3,
    "file": 1.0,
    "process_name": 1.1,
    "process_cmdline": 1.6,
    "registry": 1.8,
    "network": 1.2,
}

SYNERGY_BONUSES: List[tuple[Set[str], float]] = [
    ({"process_cmdline", "registry"}, 1.2),
    ({"process_cmdline", "process_name"}, 0.6),
    ({"process_cmdline", "network"}, 0.5),
    ({"registry", "file"}, 0.5),
]

WEIGHT_TO_CONFIDENCE_FACTOR = 18.0


class MITREAttackMapper:
    def __init__(
        self,
        source: Optional[str] = None,
        cache_dir: Optional[os.PathLike[str] | str] = None,
        platform_filter: Optional[Set[str]] = None,
        indicator_hints_source: Optional[os.PathLike[str] | str] = None,
        use_cache: bool = True,
    ):
        self.source = source or DEFAULT_ENTERPRISE_BUNDLE_URL
        self.use_cache = use_cache
        self._cache_dir = Path(cache_dir or DEFAULT_CACHE_DIR)
        self._cache_dir = self._cache_dir.expanduser()
        self.platform_filter = {p.lower() for p in platform_filter} if platform_filter else None
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self._all_tactics: Set[str] = set()
        self.detected_techniques: List[str] = []
        config_indicator_path: Optional[str] = None
        if config_manager is not None:
            config_indicator_path = (
                config_manager.get("MITRE_INDICATOR_HINTS_PATH")
                or config_manager.get("INDICATOR_HINTS_PATH")
            )
        self.indicator_hints_source = indicator_hints_source or config_indicator_path
        self.indicator_hints: Dict[str, Dict[str, List[str]]] = {}
        self._load_indicator_hints()
        self._load_techniques()

    def map_behavior(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "techniques": [],
            "tactics": set(),
            "kill_chain_phases": [],
            "coverage": {},
        }

        indicator_entries = self._extract_indicators(analysis_data)

        for technique_id, metadata in self.techniques.items():
            hints = self.indicator_hints.get(technique_id)
            if not hints:
                continue
            matches: List[Dict[str, Any]] = []
            used_entries: Set[tuple[str, str, str, str]] = set()
            for indicator in hints.get("indicators", []):
                indicator_lower = indicator.lower()
                for entry in indicator_entries:
                    candidate_value = entry["value"]
                    if indicator_lower in candidate_value.lower():
                        dedupe_key = (
                            indicator_lower,
                            entry.get("normalized", candidate_value.lower()),
                            entry["category"],
                            entry.get("source_type", ""),
                        )
                        if dedupe_key in used_entries:
                            continue
                        used_entries.add(dedupe_key)
                        matches.append(
                            {
                                "indicator": indicator,
                                "matched_value": candidate_value,
                                "category": entry["category"],
                                "weight": entry["weight"],
                                "source": entry.get("source"),
                                "source_type": entry.get("source_type"),
                                "count": entry.get("count", 1),
                                "first_seen": entry.get("first_seen"),
                                "last_seen": entry.get("last_seen"),
                                "samples": entry.get("samples", []),
                            }
                        )
                        break

            if not matches:
                continue

            tactics = metadata.get("tactics") or ["Unspecified"]

            categories = {match["category"] for match in matches}
            base_weight = sum(match["weight"] for match in matches)
            synergy_bonus = 0.0
            for combo, bonus in SYNERGY_BONUSES:
                if combo.issubset(categories):
                    synergy_bonus += bonus
            diversified_multiplier = 1.0 + max(len(categories) - 1, 0) * 0.15
            adjusted_weight = (base_weight + synergy_bonus) * diversified_multiplier
            confidence = min(int(round(adjusted_weight * WEIGHT_TO_CONFIDENCE_FACTOR)), 100)

            supporting_artifacts = [
                {
                    "indicator": match["indicator"],
                    "matched_value": match["matched_value"],
                    "category": match["category"],
                    "source": match.get("source"),
                    "source_type": match.get("source_type"),
                    "weight": round(match["weight"], 2),
                    "count": match.get("count", 1),
                    "first_seen": match.get("first_seen"),
                    "last_seen": match.get("last_seen"),
                    "samples": match.get("samples", []),
                }
                for match in matches
            ]

            rationale_parts = []
            for artifact in supporting_artifacts:
                snippet = artifact["matched_value"]
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                source = artifact.get("source")
                source_type = artifact.get("source_type")
                source_tokens = []
                if source_type:
                    source_tokens.append(source_type)
                if source:
                    source_tokens.append(str(source))
                source_part = f" from {'/'.join(source_tokens)}" if source_tokens else ""
                count = artifact.get("count", 1)
                count_part = f" x{count}" if count and count > 1 else ""
                timeline: str = ""
                first_seen = artifact.get("first_seen")
                last_seen = artifact.get("last_seen")
                if first_seen and last_seen and first_seen != last_seen:
                    timeline = f" [{first_seen} -> {last_seen}]"
                elif first_seen:
                    timeline = f" [{first_seen}]"
                rationale_parts.append(
                    f"{artifact['indicator']} matched {artifact['category']}{source_part}{count_part} ({snippet}){timeline}"
                )
            confidence_rationale = "; ".join(rationale_parts)

            results["techniques"].append(
                {
                    "id": technique_id,
                    "name": metadata.get("name", technique_id),
                    "tactics": tactics,
                    "tactic": tactics[0],
                    "platforms": metadata.get("platforms", []),
                    "is_subtechnique": metadata.get("is_subtechnique", False),
                    "parent": metadata.get("parent"),
                    "matched_indicators": [match["indicator"] for match in matches],
                    "confidence": confidence,
                    "confidence_rationale": confidence_rationale,
                    "confidence_breakdown": {
                        "base_weight": round(base_weight, 2),
                        "synergy_bonus": round(synergy_bonus, 2),
                        "diversified_multiplier": round(diversified_multiplier, 2),
                        "adjusted_weight": round(adjusted_weight, 2),
                        "unique_categories": sorted(categories),
                    },
                    "supporting_artifacts": supporting_artifacts,
                }
            )
            results["tactics"].update(tactics)

        results["tactics"] = sorted(results["tactics"])

        for tactic in sorted(self._all_tactics):
            tactic_techniques = [
                t for t in results["techniques"] if tactic in t.get("tactics", [])
            ]
            results["coverage"][tactic] = len(tactic_techniques)

        results["kill_chain_phases"] = [
            phase for phase in KILL_CHAIN_ORDER if phase in results["tactics"]
        ]

        logger.info("Detected %d MITRE ATT&CK techniques", len(results["techniques"]))

        return results

    def _extract_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        aggregated: Dict[tuple[str, str, str], Dict[str, Any]] = {}

        def register(
            value: Any,
            category: str,
            source_type: str,
            source_detail: Optional[str],
            record: Optional[Dict[str, Any]] = None,
        ) -> None:
            if value is None:
                return
            text = str(value).strip()
            if not text:
                return

            normalized = self._normalize_indicator(category, text)
            if not normalized:
                return

            timestamp = self._coerce_timestamp(self._extract_timestamp(record))
            key = (category, normalized, source_type)

            if key not in aggregated:
                aggregated[key] = {
                    "value": text,
                    "normalized": normalized,
                    "category": category,
                    "source_type": source_type,
                    "source": source_detail,
                    "weight": CATEGORY_WEIGHTS.get(category, 1.0),
                    "count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "samples": [text],
                }
            entry = aggregated[key]
            entry["count"] += 1

            if text not in entry["samples"] and len(entry["samples"]) < 5:
                entry["samples"].append(text)
            entry["value"] = entry["samples"][0]

            if timestamp is not None:
                entry_first = entry["first_seen"]
                entry_last = entry["last_seen"]
                if entry_first is None or self._is_timestamp_before(timestamp, entry_first):
                    entry["first_seen"] = timestamp
                if entry_last is None or self._is_timestamp_before(entry_last, timestamp):
                    entry["last_seen"] = timestamp

        for item in data.get("strings", []):
            register(item, "string", "string", "strings")

        for item in data.get("suspicious_strings", []):
            register(item, "suspicious_string", "string", "suspicious_strings")

        for imp in data.get("imports", []):
            if isinstance(imp, dict):
                register(imp.get("name"), "import", "process", "imports", imp)
            else:
                register(imp, "import", "process", "imports", None)

        for op in data.get("file_operations", []):
            register(op.get("path"), "file", "file", op.get("operation", "file_operations"), op)

        for proc in data.get("processes", []):
            register(proc.get("name"), "process_name", "process", "processes.name", proc)
            register(proc.get("cmdline"), "process_cmdline", "process", "processes.cmdline", proc)

        for reg in data.get("registry", []):
            register(reg.get("key"), "registry", "registry", "registry", reg)

        for net in data.get("network", []):
            register(net.get("url"), "network", "network", "network.url", net)
            register(net.get("host"), "network", "network", "network.host", net)
            register(net.get("endpoint"), "network", "network", "network.endpoint", net)

        indicators = list(aggregated.values())
        indicators.sort(key=lambda item: (-item["weight"], -item["count"], item["normalized"]))
        return indicators

    @staticmethod
    def _normalize_indicator(category: str, value: str) -> str:
        text = value.strip()
        if not text:
            return ""

        normalized = text.lower()
        if category in {"process_name", "process_cmdline"}:
            normalized = normalized.replace("\\", "/")
        if category == "process_name":
            normalized = normalized.split("/")[-1]
        elif category == "process_cmdline":
            normalized = " ".join(normalized.split())
        elif category == "file":
            normalized = normalized.replace("\\\\", "\\").replace("//", "/").rstrip("\\/")
        elif category == "registry":
            normalized = normalized.replace("\\\\", "\\").rstrip("\\")
        elif category == "network":
            normalized = normalized.replace("\\\\", "\\").strip()
        return normalized

    @staticmethod
    def _extract_timestamp(record: Optional[Dict[str, Any]]) -> Optional[Any]:
        if not record or not isinstance(record, dict):
            return None
        candidates = [
            "timestamp",
            "time",
            "first_seen",
            "last_seen",
            "observed",
            "observed_at",
            "created",
            "start_time",
            "end_time",
            "ts",
            "logged_at",
        ]
        for key in candidates:
            if key in record:
                return record.get(key)
        return None

    @staticmethod
    def _coerce_timestamp(value: Any) -> Optional[Any]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        return text

    @staticmethod
    def _is_timestamp_before(left: Any, right: Any) -> bool:
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left < right
        return str(left) < str(right)

    def _group_by_parent(
        self, techniques_for_tactic: List[Dict[str, Any]]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        groups: Dict[str, Dict[str, Any]] = {}
        ordered: List[Tuple[str, Dict[str, Any]]] = []
        for tech in sorted(techniques_for_tactic, key=lambda item: item["name"].lower()):
            meta = self.techniques.get(tech["id"], {})
            parent_id = meta.get("parent")
            parent_meta = self.techniques.get(parent_id) if parent_id else None
            if parent_id and parent_meta:
                group_id = parent_id
                parent_meta_ref = parent_meta
            else:
                group_id = tech["id"]
                parent_meta_ref = meta
            group = groups.get(group_id)
            if group is None:
                group = {"parent_meta": parent_meta_ref or {"id": group_id, "name": group_id}, "children": []}
                groups[group_id] = group
                ordered.append((group_id, group))
            group["children"].append((tech, meta))
        ordered.sort(key=lambda item: item[1]["parent_meta"].get("name", item[0]).lower())
        return ordered

    def _format_technique_lines(self, tech: Dict[str, Any], meta: Dict[str, Any], indent: int) -> List[str]:
        indent_str = " " * indent
        detail_indent = " " * (indent + 3)
        lines = [
            f"{indent_str}-> {tech['id']}: {tech['name']} (confidence: {tech['confidence']}%)"
        ]
        indicators = ", ".join(tech.get("matched_indicators", [])[:3]) or "n/a"
        lines.append(f"{detail_indent}Indicators: {indicators}")
        rationale = tech.get("confidence_rationale")
        if rationale:
            lines.append(f"{detail_indent}Evidence: {self._shorten(rationale, 180)}")
        lines.extend(self._format_context_lines(meta, indent=indent + 3))
        return lines

    def _format_context_lines(
        self, meta: Optional[Dict[str, Any]], indent: int = 2, include_sub_header: bool = False
    ) -> List[str]:
        if not meta:
            return []
        indent_str = " " * indent
        lines: List[str] = []
        detection = meta.get("detection")
        if detection:
            lines.append(f"{indent_str}Detection: {self._shorten(detection, 180)}")
        mitigations = meta.get("mitigations") or []
        if mitigations:
            mitigations_repr = ", ".join(self._shorten_list(mitigations))
            lines.append(f"{indent_str}Mitigations: {mitigations_repr}")
        elif include_sub_header:
            lines.append(f"{indent_str}Mitigations: (refer to MITRE ATT&CK guidance)")
        data_sources = meta.get("data_sources") or []
        if data_sources:
            data_repr = ", ".join(self._shorten_list(data_sources))
            lines.append(f"{indent_str}Data sources: {data_repr}")
        return lines

    def _navigator_entry(self, tech: Dict[str, Any], meta: Dict[str, Any], tactic: Optional[str]) -> Dict[str, Any]:
        breakdown = tech.get("confidence_breakdown", {})
        adjusted_weight = breakdown.get("adjusted_weight")
        confidence = max(0, min(int(tech.get("confidence", 0)), 100))
        comment_parts: List[str] = []
        if meta and meta.get("detection"):
            comment_parts.append(f"Detection: {self._shorten(meta['detection'], 140)}")
        mitigations = meta.get("mitigations") if meta else None
        if mitigations:
            mitigations_repr = ", ".join(self._shorten_list(mitigations))
            comment_parts.append(f"Mitigations: {mitigations_repr}")
        rationale = tech.get("confidence_rationale")
        if rationale:
            comment_parts.append(f"Evidence: {self._shorten(rationale, 140)}")
        comment = " | ".join(part for part in comment_parts if part)
        tactic_slug = (tactic or "").lower().replace(" ", "-")
        color = self._confidence_to_color(confidence, adjusted_weight)
        return {
            "techniqueID": tech["id"],
            "tactic": tactic_slug,
            "score": confidence,
            "color": color,
            "comment": comment,
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False,
        }

    @staticmethod
    def _initialise_navigator_layer() -> Dict[str, Any]:
        return {
            "name": "ThreatInquisitor Weighted Confidence",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Layer generated by ThreatInquisitor with weighted confidence scoring.",
            "filters": {"platforms": ["windows"]},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

    @staticmethod
    def _shorten(text: Any, limit: int = 160) -> str:
        if not text:
            return ""
        normalised = " ".join(str(text).split())
        return normalised if len(normalised) <= limit else normalised[: limit - 3] + "..."

    @staticmethod
    def _shorten_list(items: Sequence[Any], limit: int = 3) -> List[str]:
        cleaned: List[str] = []
        for item in items:
            value = str(item).strip()
            if value and value not in cleaned:
                cleaned.append(value)
        if len(cleaned) > limit:
            remaining = len(cleaned) - limit
            return cleaned[:limit] + [f"+{remaining} more"]
        return cleaned

    @staticmethod
    def _confidence_to_color(confidence: float, adjusted_weight: Optional[float] = None) -> str:
        score = max(0.0, min(float(confidence), 100.0))
        stops = [
            (0.0, (0xFF, 0x66, 0x66)),
            (50.0, (0xFF, 0xE7, 0x66)),
            (100.0, (0x8E, 0xC8, 0x43)),
        ]
        for idx in range(len(stops) - 1):
            left_score, left_color = stops[idx]
            right_score, right_color = stops[idx + 1]
            if score <= right_score or idx == len(stops) - 2:
                if right_score == left_score:
                    ratio = 0.0
                else:
                    ratio = (score - left_score) / (right_score - left_score)
                r = int(round(left_color[0] + ratio * (right_color[0] - left_color[0])))
                g = int(round(left_color[1] + ratio * (right_color[1] - left_color[1])))
                b = int(round(left_color[2] + ratio * (right_color[2] - left_color[2])))
                break
        else:
            r, g, b = stops[-1][1]

        if adjusted_weight is not None:
            weight_factor = max(0.0, min(float(adjusted_weight) / 5.0, 1.0))
        else:
            weight_factor = score / 100.0
        mix_factor = 0.2 * (1.0 - weight_factor)
        r = int(round(r + (255 - r) * mix_factor))
        g = int(round(g + (255 - g) * mix_factor))
        b = int(round(b + (255 - b) * mix_factor))
        return f"#{r:02x}{g:02x}{b:02x}"

    def generate_attack_matrix(
        self, results: Dict[str, Any], include_navigator_layer: bool = False
    ) -> Union[str, Tuple[str, Dict[str, Any]]]:
        matrix_lines: List[str] = ["=== MITRE ATT&CK Matrix ===", ""]

        if not results.get("techniques"):
            matrix_lines.append("No techniques detected.")
            matrix = "\n".join(matrix_lines)
            if include_navigator_layer:
                return matrix, self._initialise_navigator_layer()
            return matrix

        tactics_dict: Dict[str, List[Dict[str, Any]]] = {}
        for technique in results["techniques"]:
            for tactic in technique.get("tactics", [technique.get("tactic")]):
                tactics_dict.setdefault(tactic, []).append(technique)

        navigator_layer = self._initialise_navigator_layer() if include_navigator_layer else None

        for tactic in results.get("kill_chain_phases", []):
            techniques_for_tactic = tactics_dict.get(tactic, [])
            if not techniques_for_tactic:
                continue
            matrix_lines.append(f"[{tactic}]")
            grouped = self._group_by_parent(techniques_for_tactic)

            for group_id, group in grouped:
                parent_meta = group["parent_meta"]
                children = group["children"]
                parent_is_self = group_id == children[0][0]["id"] and len(children) == 1
                if parent_is_self:
                    tech, meta = children[0]
                    matrix_lines.extend(self._format_technique_lines(tech, meta, indent=2))
                    if navigator_layer is not None:
                        navigator_layer["techniques"].append(
                            self._navigator_entry(tech, meta, tactic)
                        )
                else:
                    parent_name = parent_meta.get("name", group_id)
                    max_conf = max(child[0]["confidence"] for child in children)
                    matrix_lines.append(
                        f"  * {group_id}: {parent_name} (max confidence: {max_conf}%)"
                    )
                    matrix_lines.extend(
                        self._format_context_lines(parent_meta, indent=4, include_sub_header=True)
                    )
                    matrix_lines.append("    Subtechniques:")
                    for tech, meta in sorted(
                        children, key=lambda item: item[0]["name"].lower()
                    ):
                        matrix_lines.extend(self._format_technique_lines(tech, meta, indent=6))
                        if navigator_layer is not None:
                            navigator_layer["techniques"].append(
                                self._navigator_entry(tech, meta, tactic)
                            )
            matrix_lines.append("")

        matrix = "\n".join(line.rstrip() for line in matrix_lines if line is not None)
        if include_navigator_layer:
            return matrix, navigator_layer
        return matrix

    def _load_techniques(self) -> None:
        try:
            bundle = self._load_attack_bundle()
        except (OSError, ValueError, HTTPError, URLError) as exc:
            logger.error("Failed to load MITRE ATT&CK bundle from %s: %s", self.source, exc)
            raise

        objects = bundle.get("objects", [])
        stix_to_attack_id: Dict[str, str] = {}
        attack_patterns: List[Dict[str, Any]] = []
        course_of_actions: Dict[str, str] = {}

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type == "attack-pattern":
                attack_patterns.append(obj)
                attack_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                        attack_id = ref["external_id"]
                        break
                if not attack_id:
                    continue
                stix_to_attack_id[obj["id"]] = attack_id
            elif obj_type == "course-of-action":
                name = obj.get("name")
                if name:
                    course_of_actions[obj["id"]] = name

        mitigation_map: Dict[str, List[str]] = {}
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "mitigates":
                continue
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")
            attack_id: Optional[str] = None
            mitigation_name: Optional[str] = None
            if source_ref in course_of_actions and target_ref in stix_to_attack_id:
                mitigation_name = course_of_actions[source_ref]
                attack_id = stix_to_attack_id[target_ref]
            elif target_ref in course_of_actions and source_ref in stix_to_attack_id:
                mitigation_name = course_of_actions[target_ref]
                attack_id = stix_to_attack_id[source_ref]
            if attack_id and mitigation_name:
                mitigation_map.setdefault(attack_id, []).append(mitigation_name)

        techniques: Dict[str, Dict[str, Any]] = {}
        all_tactics: Set[str] = set(TACTIC_NAME_MAP.values())

        for obj in attack_patterns:
            attack_id = stix_to_attack_id.get(obj["id"])
            if not attack_id:
                continue

            tactics = sorted(
                {
                    self._normalise_tactic_name(str(phase.get("phase_name", "")))
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
                }
            )
            if tactics:
                all_tactics.update(tactics)

            platforms_raw = [str(p).lower() for p in obj.get("x_mitre_platforms", []) if p]
            platforms = sorted(set(platforms_raw))

            if self.platform_filter and platforms:
                if not any(p in self.platform_filter for p in platforms):
                    continue

            parent_attack_id = None
            if obj.get("x_mitre_is_subtechnique"):
                parent_ref = obj.get("x_mitre_parent_attack_pattern_ref")
                if parent_ref:
                    parent_attack_id = stix_to_attack_id.get(parent_ref)

            detection_note = obj.get("x_mitre_detection")
            mitigations = sorted({m for m in mitigation_map.get(attack_id, [])})
            data_sources = obj.get("x_mitre_data_sources", []) or []

            techniques[attack_id] = {
                "id": attack_id,
                "name": obj.get("name", attack_id),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": platforms,
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "parent": parent_attack_id,
                "detection": detection_note,
                "mitigations": mitigations,
                "data_sources": data_sources,
            }

        for attack_id, info in techniques.items():
            if info.get("is_subtechnique") and not info.get("parent") and "." in attack_id:
                parent_candidate = attack_id.split(".")[0]
                if parent_candidate in techniques:
                    info["parent"] = parent_candidate

        self.techniques = techniques
        self._all_tactics = all_tactics

    def _load_indicator_hints(self) -> None:
        resolved_source: Optional[Path] = None
        if self.indicator_hints_source:
            resolved_source = Path(self.indicator_hints_source).expanduser()
        else:
            default_path = DEFAULT_CACHE_DIR.parent / "indicator_hints.json"
            if default_path.exists():
                resolved_source = default_path

        hints: Dict[str, Dict[str, List[str]]] = {}
        if resolved_source and resolved_source.is_file():
            try:
                with resolved_source.open("r", encoding="utf-8") as handle:
                    hints = json.load(handle)
            except (OSError, ValueError) as exc:
                logger.warning("Failed to load indicator hints from %s: %s", resolved_source, exc)

        if not hints:
            hints = DEFAULT_INDICATOR_HINTS

        self.indicator_hints = hints

    def _load_attack_bundle(self) -> Dict[str, Any]:
        parsed = urlparse(self.source)
        if parsed.scheme in {"http", "https"}:
            return self._download_remote_bundle(self.source)
        path = Path(self.source)
        return self._read_local_bundle(path)

    def _download_remote_bundle(self, url: str) -> Dict[str, Any]:
        cache_file: Optional[Path] = None
        if self.use_cache:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
            cache_file = self._cache_dir / f"{digest}.json"
            if cache_file.exists():
                with cache_file.open("r", encoding="utf-8") as handle:
                    return json.load(handle)

        request = Request(url, headers={"User-Agent": "ThreatInquisitor/1.0"})
        with urlopen(request) as response:
            data = response.read().decode("utf-8")

        if cache_file:
            cache_file.write_text(data, encoding="utf-8")

        return json.loads(data)

    @staticmethod
    def _read_local_bundle(path: Path) -> Dict[str, Any]:
        if not path.is_file():
            raise FileNotFoundError(f"MITRE bundle not found at {path}")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _normalise_tactic_name(name: str) -> str:
        if not name:
            return "Unspecified"
        key = name.strip().lower().replace("_", "-")
        if key in TACTIC_NAME_MAP:
            return TACTIC_NAME_MAP[key]
        alt_key = key.replace("-", " ")
        if alt_key in TACTIC_NAME_MAP:
            return TACTIC_NAME_MAP[alt_key]
        fallback = key.replace("-", " ").title()
        fallback = fallback.replace(" And ", " and ").replace(" Of ", " of ")
        return fallback


def map_to_mitre_attack(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    mapper = MITREAttackMapper()
    return mapper.map_behavior(analysis_data)


map_to_mitre = map_to_mitre_attack


def export_navigator_json(analysis_data: Dict[str, Any], output_path: str) -> None:
    mapper = MITREAttackMapper()
    mitre_results = mapper.map_behavior(analysis_data)

    _, navigator_json = mapper.generate_attack_matrix(
        mitre_results, include_navigator_layer=True
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(navigator_json, handle, indent=2, ensure_ascii=False)

    logger.info("ATT&CK Navigator JSON exported to %s", output_path)


if __name__ == "__main__":
    import json as _json

    logging.basicConfig(level=logging.INFO)

    test_data = {
        "suspicious_strings": [
            "powershell.exe",
            "cmd.exe /c",
            "CurrentVersion\\Run",
            "http://malicious-c2.com",
        ],
        "imports": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
        "registry": [{"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}],
    }

    print("=== MITRE ATT&CK Mapping ===")
    results = map_to_mitre_attack(test_data)
    print(_json.dumps(results, indent=2, ensure_ascii=False, default=list))

    mapper = MITREAttackMapper()
    print("\n" + mapper.generate_attack_matrix(results))
