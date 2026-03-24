#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Canonical non-ML analysis pipeline shared by API and GUI.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from analyzer.ai_analyst import get_ai_analyst
from analyzer.behavioral_analysis import analyze_behavior
from analyzer.dynamic_analysis import dynamic_analysis
from analyzer.ioc_extractor import extract_iocs
from analyzer.mitre_attack import map_to_mitre_attack
from analyzer.scoring import calculate_risk
from analyzer.static_analysis import static_analysis
from core.threat_intel import ThreatIntelligence
from services.intel_fusion import IntelFusionWorkspace, map_mitre_to_d3fend_controls
from services.retro_hunt import RetroHuntOrchestrator

logger = logging.getLogger("analysis_pipeline")

ProgressCallback = Optional[Callable[[int, str], None]]


def _emit_progress(callback: ProgressCallback, value: int, stage: str) -> None:
    if callback:
        callback(int(value), stage)


def _risk_level_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _normalise_ioc_type(ioc_type: str) -> Optional[str]:
    lowered = str(ioc_type or "").lower()
    if lowered in {"ip"}:
        return "ip"
    if lowered in {"url"}:
        return "url"
    if lowered in {"domain"}:
        return "domain"
    if lowered.startswith("hash_") or lowered in {"sha256", "sha1", "md5", "hash"}:
        return "hash"
    return None


def _iter_enrichable_iocs(iocs: Iterable[Dict[str, Any]], limit: int) -> List[Tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    selected: List[Tuple[str, str]] = []
    for entry in iocs:
        if not isinstance(entry, dict):
            continue
        query_type = _normalise_ioc_type(str(entry.get("type", "")))
        value = str(entry.get("value", "")).strip()
        if not query_type or not value:
            continue
        marker = (query_type, value)
        if marker in seen:
            continue
        seen.add(marker)
        selected.append(marker)
        if len(selected) >= limit:
            break
    return selected


def _service_status_for_ti(ti: ThreatIntelligence) -> Dict[str, Any]:
    return {
        "virustotal": bool(getattr(ti, "vt_api_key", "")),
        "otx": bool(getattr(ti, "otx_api_key", "")),
        "abuseipdb": bool(getattr(ti, "abuseipdb_key", "")),
        "greynoise": bool(getattr(ti, "greynoise_key", "")),
        "threatfox": True,
        "malwarebazaar": True,
    }


def enrich_with_threat_intelligence(iocs: List[Dict[str, Any]], *, limit: int = 8) -> Dict[str, Any]:
    selected = _iter_enrichable_iocs(iocs, limit)
    if not selected:
        return {
            "status": "no_iocs",
            "lookups": [],
            "summary": {"malicious": 0, "suspicious": 0, "unknown": 0},
            "service_status": {},
        }

    ti = ThreatIntelligence()
    lookups: List[Dict[str, Any]] = []
    summary = {"malicious": 0, "suspicious": 0, "unknown": 0}
    for query_type, value in selected:
        try:
            if query_type == "ip":
                result = ti.check_ip(value)
            elif query_type in {"url", "domain"}:
                result = ti.check_url(value)
            else:
                result = ti.check_hash(value)
        except Exception as exc:  # pragma: no cover - network/runtime dependent
            logger.warning("Threat-intel enrichment failed for %s %s: %s", query_type, value, exc)
            result = {"error": str(exc), "verdict": "unknown", "threat_score": 0}

        verdict = str(result.get("verdict", "unknown")).lower()
        if verdict not in summary:
            verdict = "unknown"
        summary[verdict] += 1
        lookups.append(
            {
                "type": query_type,
                "value": value,
                "verdict": verdict,
                "threat_score": result.get("threat_score", 0),
                "result": result,
            }
        )

    return {
        "status": "completed",
        "lookups": lookups,
        "summary": summary,
        "service_status": _service_status_for_ti(ti),
    }


def _retrohunt_connector_status(retro_hunt: Dict[str, Any]) -> List[Dict[str, Any]]:
    statuses: List[Dict[str, Any]] = []
    for result in retro_hunt.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        statuses.append(
            {
                "connector": result.get("connector"),
                "status": result.get("status"),
                "hits": len(result.get("hits", []) or []),
            }
        )
    return statuses


def build_fusion_workspace(
    *,
    file_path: str,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    iocs: List[Dict[str, Any]],
    behavioral: List[Dict[str, Any]],
    mitre: Dict[str, Any],
    ti_enrichment: Dict[str, Any],
    retro_hunt: Dict[str, Any],
) -> Dict[str, Any]:
    workspace = IntelFusionWorkspace()
    technique_ids = [item.get("id") for item in mitre.get("techniques", []) if isinstance(item, dict) and item.get("id")]

    yara_matches = static_result.get("yara_matches") or []
    static_summary = (
        f"Static analysis of {os.path.basename(file_path)} "
        f"detected type={static_result.get('file_type', 'unknown')}, "
        f"YARA matches={len(yara_matches)}, IoCs={len(iocs)}."
    )
    workspace.add_observation(
        "static",
        static_summary,
        severity=_risk_level_from_score(float(len(yara_matches) * 15 + len(iocs) * 2)),
        mitre_techniques=technique_ids[:6],
        artifacts=[file_path],
        extra={"tags": [str(static_result.get("file_type", "unknown")), "static"]},
    )

    api_calls = dynamic_result.get("api_calls") or []
    dynamic_summary = (
        f"Dynamic analysis captured {len(api_calls)} API calls, "
        f"{len(behavioral)} behavioral patterns, and "
        f"{len(dynamic_result.get('memory_dumps') or [])} memory dumps."
    )
    workspace.add_observation(
        "dynamic",
        dynamic_summary,
        severity="high" if behavioral else "medium",
        mitre_techniques=technique_ids[:8],
        artifacts=[str(call.get("api")) for call in api_calls[:5] if isinstance(call, dict)],
        extra={"tags": ["dynamic", "runtime"]},
    )

    for lookup in ti_enrichment.get("lookups", []) or []:
        if not isinstance(lookup, dict):
            continue
        verdict = str(lookup.get("verdict", "unknown")).lower()
        severity = "high" if verdict == "malicious" else "medium" if verdict == "suspicious" else "low"
        workspace.add_observation(
            f"ti:{lookup.get('type')}",
            f"Threat-intel verdict for {lookup.get('value')}: {verdict}.",
            severity=severity,
            mitre_techniques=technique_ids[:3],
            artifacts=[str(lookup.get("value"))],
            extra={"tags": ["threat_intelligence", verdict]},
        )

    if retro_hunt.get("results"):
        workspace.add_observation(
            "retro_hunt",
            f"External retro-hunt completed with {retro_hunt.get('total_hits', 0)} hits "
            f"and confidence boost {retro_hunt.get('confidence_boost', 0.0)}.",
            severity="high" if retro_hunt.get("total_hits", 0) else "medium",
            mitre_techniques=technique_ids[:5],
            artifacts=[status.get("connector", "") for status in _retrohunt_connector_status(retro_hunt)],
            extra={"tags": ["retrohunt", retro_hunt.get("status", "unknown")]},
        )

    return workspace.export_summary()


def run_canonical_pipeline(
    file_path: str,
    *,
    run_dynamic: bool = True,
    timeout: int = 20,
    enable_threat_intel: bool = True,
    enable_retrohunt: bool = True,
    progress_callback: ProgressCallback = None,
) -> Dict[str, Any]:
    file_path = os.path.abspath(file_path)
    _emit_progress(progress_callback, 5, "static")
    static_result = static_analysis(file_path)

    _emit_progress(progress_callback, 25, "dynamic")
    dynamic_result = dynamic_analysis(file_path, timeout=timeout) if run_dynamic else {
        "status": "skipped",
        "reason": "dynamic_disabled",
        "api_calls": [],
        "behavioral_patterns": [],
        "memory_dumps": [],
        "errors": [],
        "runtime_capabilities": {"frida_available": False, "reason": "dynamic_disabled"},
        "hook_catalog": [],
        "hook_catalog_size": 0,
    }

    _emit_progress(progress_callback, 40, "iocs")
    iocs = extract_iocs(static_result, dynamic_result)

    _emit_progress(progress_callback, 55, "behavioral")
    behavioral = dynamic_result.get("behavioral_patterns")
    if not isinstance(behavioral, list):
        behavioral = analyze_behavior(dynamic_result.get("api_calls", []))
    dynamic_result["behavioral_patterns"] = behavioral

    pipeline_input = {
        "static": static_result,
        "dynamic": dynamic_result,
        "iocs": iocs,
        "behavioral": behavioral,
    }

    _emit_progress(progress_callback, 65, "mitre")
    mitre = map_to_mitre_attack(pipeline_input)
    technique_ids = [item.get("id") for item in mitre.get("techniques", []) if isinstance(item, dict) and item.get("id")]
    d3fend_controls = map_mitre_to_d3fend_controls(technique_ids)
    d3fend = {
        "controls": d3fend_controls,
        "recommendations": {control: 1 for control in d3fend_controls},
        "source_techniques": technique_ids,
    }

    _emit_progress(progress_callback, 75, "threat_intel")
    ti_enrichment = (
        enrich_with_threat_intelligence(iocs)
        if enable_threat_intel
        else {
            "status": "disabled",
            "lookups": [],
            "summary": {"malicious": 0, "suspicious": 0, "unknown": 0},
            "service_status": {},
        }
    )

    _emit_progress(progress_callback, 85, "retro_hunt")
    if enable_retrohunt:
        retro_hunt = RetroHuntOrchestrator().run(
            iocs,
            context={"file_path": file_path, "techniques": technique_ids},
        )
    else:
        retro_hunt = {"status": "disabled", "results": [], "confidence_boost": 0.0, "total_hits": 0}

    _emit_progress(progress_callback, 92, "risk")
    risk = calculate_risk(
        static_data=static_result or {},
        dynamic_data=dynamic_result or {},
        ioc_data=iocs,
        vt_data=ti_enrichment,
        behavioral_patterns=behavioral,
    )
    base_score = float(risk.get("score", 0) or 0)
    confidence_boost = float(retro_hunt.get("confidence_boost", 0.0) or 0.0)
    adjusted_score = min(100.0, round(base_score + confidence_boost * 10, 2))
    risk["adjusted_score"] = adjusted_score
    risk["adjusted_level"] = _risk_level_from_score(adjusted_score)
    risk["confidence_boost"] = confidence_boost

    _emit_progress(progress_callback, 97, "fusion")
    fusion = build_fusion_workspace(
        file_path=file_path,
        static_result=static_result,
        dynamic_result=dynamic_result,
        iocs=iocs,
        behavioral=behavioral,
        mitre=mitre,
        ti_enrichment=ti_enrichment,
        retro_hunt=retro_hunt,
    )
    d3fend["recommendations"] = fusion.get("meta", {}).get("d3fend_recommendations", d3fend["recommendations"])

    ai_status = get_ai_analyst().get_provider_status()
    system_status = {
        "frida": dynamic_result.get("runtime_capabilities", {}),
        "yara": static_result.get("yara_status", {}),
        "threat_intel": ti_enrichment.get("service_status", {}),
        "retrohunt": _retrohunt_connector_status(retro_hunt),
        "aitunnel": ai_status,
    }

    _emit_progress(progress_callback, 100, "completed")
    return {
        "static": static_result,
        "dynamic": dynamic_result,
        "iocs": iocs,
        "behavioral": behavioral,
        "mitre": mitre,
        "d3fend": d3fend,
        "ti_enrichment": ti_enrichment,
        "retro_hunt": retro_hunt,
        "fusion": fusion,
        "risk": risk,
        "system_status": system_status,
    }


__all__ = ["run_canonical_pipeline", "enrich_with_threat_intelligence", "build_fusion_workspace"]
