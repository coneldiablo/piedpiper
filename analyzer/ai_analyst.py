#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI-assisted analyst workflows backed by AITUNNEL.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from analyzer.yara_generator import YARAGenerator
from services.ai_provider import AITunnelProvider, extract_json_payload

logger = logging.getLogger("ai_analyst")


def _score_to_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


class AIAnalyst:
    """LLM-backed analyst helper with explicit fallback mode."""

    def __init__(self) -> None:
        self.provider = AITunnelProvider()
        self.yara_generator = YARAGenerator()

    def get_provider_status(self) -> Dict[str, Any]:
        return self.provider.status()

    def analyze_threat(self, analysis_data: Dict[str, Any], language: str = "ru") -> Dict[str, Any]:
        if not isinstance(analysis_data, dict):
            raise ValueError("analysis_data must be a dict")

        fallback = self._fallback_analysis(analysis_data, language=language)
        if not self.provider.is_configured():
            fallback["provider_status"] = self.provider.status()
            return fallback

        prompt = self._build_analysis_prompt(analysis_data, language)
        try:
            response = self.provider.chat(
                system_prompt=self._analysis_system_prompt(language),
                user_prompt=prompt,
                temperature=0.1,
                response_format={"type": "json_object"},
                max_tokens=1200,
            )
            parsed = extract_json_payload(response)
            if not parsed:
                raise ValueError("LLM response did not contain a JSON object")
            result = {
                "description": str(parsed.get("description") or fallback["description"]),
                "malware_type": str(parsed.get("malware_type") or fallback["malware_type"]),
                "threat_level": str(parsed.get("threat_level") or fallback["threat_level"]),
                "recommendations": self._normalise_string_list(parsed.get("recommendations")),
                "attack_vectors": self._normalise_attack_vectors(parsed.get("attack_vectors")),
                "confidence": self._normalise_confidence(parsed.get("confidence"), fallback["confidence"]),
                "provider_status": self.provider.status(),
                "raw_response": response,
            }
            if not result["recommendations"]:
                result["recommendations"] = fallback["recommendations"]
            if not result["attack_vectors"]:
                result["attack_vectors"] = fallback["attack_vectors"]
            return result
        except Exception as exc:
            logger.warning("AITUNNEL threat analysis failed, using fallback: %s", exc)
            fallback["provider_status"] = {
                **self.provider.status(),
                "last_error": str(exc),
                "mode": "fallback",
            }
            return fallback

    def classify_malware(self, features: Dict[str, Any]) -> Dict[str, float]:
        if not self.provider.is_configured():
            return {}
        prompt = (
            "Return a JSON object mapping malware categories to probabilities in the range 0..1.\n"
            f"Features:\n{json.dumps(features, ensure_ascii=False, indent=2)}"
        )
        try:
            response = self.provider.chat(
                system_prompt="You are a malware analyst. Return valid JSON only.",
                user_prompt=prompt,
                temperature=0.1,
                response_format={"type": "json_object"},
                max_tokens=800,
            )
            parsed = extract_json_payload(response)
            if not parsed:
                return {}
            probabilities: Dict[str, float] = {}
            for key, value in parsed.items():
                try:
                    probabilities[str(key)] = max(0.0, min(1.0, float(value)))
                except Exception:
                    continue
            return probabilities
        except Exception as exc:
            logger.warning("AITUNNEL classification failed: %s", exc)
            return {}

    def generate_yara_rule(self, analysis_data: Dict[str, Any], rule_name: str = "detected_threat") -> str:
        if not isinstance(analysis_data, dict):
            raise ValueError("analysis_data must be a dict")

        if self.provider.is_configured():
            prompt = (
                "Create a syntactically valid YARA rule. Return only the YARA rule body with no markdown.\n"
                f"Rule name: {rule_name}\n"
                f"Analysis data:\n{json.dumps(analysis_data, ensure_ascii=False, indent=2)}"
            )
            try:
                response = self.provider.chat(
                    system_prompt=(
                        "You are a malware detection engineer. "
                        "Return one valid YARA rule. Do not add explanations."
                    ),
                    user_prompt=prompt,
                    temperature=0.1,
                    max_tokens=1000,
                )
                rule = self._extract_yara_rule(response)
                if rule:
                    return rule
            except Exception as exc:
                logger.warning("AITUNNEL YARA generation failed, using fallback: %s", exc)

        return self.yara_generator.generate_rule_ml(analysis_data, rule_name)

    def explain_threat(self, question: str, context: Dict[str, Any]) -> str:
        if self.provider.is_configured():
            try:
                return self.provider.chat(
                    system_prompt="You are a senior incident responder. Answer clearly and directly.",
                    user_prompt=(
                        f"Question:\n{question}\n\n"
                        f"Analysis context:\n{json.dumps(context, ensure_ascii=False, indent=2)}"
                    ),
                    temperature=0.2,
                    max_tokens=900,
                )
            except Exception as exc:
                logger.warning("AITUNNEL explanation failed, using fallback: %s", exc)

        summary = self._fallback_analysis(context, language="ru")
        return (
            f"{summary['description']}\n\n"
            f"Threat level: {summary['threat_level']}\n"
            f"Recommendations: {', '.join(summary['recommendations']) or 'n/a'}"
        )

    def predict_attack_vectors(self, iocs: Dict[str, List[str]], behavior: Dict[str, Any]) -> List[Dict[str, str]]:
        if self.provider.is_configured():
            try:
                response = self.provider.chat(
                    system_prompt="Return a JSON object only.",
                    user_prompt=(
                        "Return an object with key 'attack_vectors' containing a list of "
                        "objects: vector, description, likelihood.\n"
                        f"IoCs:\n{json.dumps(iocs, ensure_ascii=False, indent=2)}\n"
                        f"Behavior:\n{json.dumps(behavior, ensure_ascii=False, indent=2)}"
                    ),
                    temperature=0.1,
                    response_format={"type": "json_object"},
                    max_tokens=700,
                )
                parsed = extract_json_payload(response) or {}
                vectors = parsed.get("attack_vectors")
                normalised = self._normalise_attack_vectors(vectors)
                if normalised:
                    return normalised
            except Exception as exc:
                logger.warning("AITUNNEL vector prediction failed, using fallback: %s", exc)

        heuristic_vectors: List[Dict[str, str]] = []
        if any(iocs.get(key) for key in ("url", "domain", "ip")):
            heuristic_vectors.append(
                {
                    "vector": "Network delivery / C2",
                    "description": "Network indicators suggest staging, delivery, or command-and-control activity.",
                    "likelihood": "high",
                }
            )
        if behavior.get("patterns"):
            heuristic_vectors.append(
                {
                    "vector": "Post-compromise execution",
                    "description": "Observed behavioral patterns indicate active execution after initial compromise.",
                    "likelihood": "medium",
                }
            )
        return heuristic_vectors

    def _analysis_system_prompt(self, language: str) -> str:
        lang = "Russian" if language == "ru" else "English"
        return (
            f"You are a senior malware analyst. Respond in {lang}. "
            "Return a single JSON object with keys: description, malware_type, "
            "threat_level, recommendations, attack_vectors, confidence."
        )

    def _build_analysis_prompt(self, data: Dict[str, Any], language: str) -> str:
        return (
            "Summarise the threat, infer the most plausible malware category, "
            "and provide recommended defensive actions.\n"
            f"Language: {language}\n"
            f"Analysis data:\n{json.dumps(data, ensure_ascii=False, indent=2)}"
        )

    def _fallback_analysis(self, analysis_data: Dict[str, Any], *, language: str) -> Dict[str, Any]:
        risk = analysis_data.get("risk") or {}
        threat_score = float(risk.get("score", 0) or 0)
        threat_level = str(risk.get("level") or _score_to_level(threat_score)).capitalize()
        static = analysis_data.get("static") or {}
        dynamic = analysis_data.get("dynamic") or {}
        file_type = static.get("file_type") or "unknown"
        api_calls = dynamic.get("api_calls") or []
        patterns = dynamic.get("behavioral_patterns") or analysis_data.get("behavioral") or []
        yara_matches = static.get("yara_matches") or []
        description = (
            f"Static analysis identified a {file_type} sample. "
            f"Dynamic analysis captured {len(api_calls)} API calls and {len(patterns)} suspicious patterns. "
            f"YARA matches: {len(yara_matches)}."
        )
        return {
            "description": description,
            "malware_type": str(file_type).upper(),
            "threat_level": threat_level,
            "recommendations": [
                "Isolate the analyzed sample and preserve related artifacts.",
                "Pivot on extracted IoCs across endpoints, proxy, and DNS telemetry.",
                "Review persistence and execution indicators before host restoration.",
            ],
            "attack_vectors": [
                {
                    "vector": "Execution chain",
                    "description": "Observed API activity and artifacts indicate a post-execution malicious chain.",
                    "likelihood": "medium" if threat_score < 60 else "high",
                }
            ],
            "confidence": 0.35,
            "provider_status": self.provider.status(),
        }

    @staticmethod
    def _normalise_confidence(value: Any, default: float) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return default

    @staticmethod
    def _normalise_string_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _normalise_attack_vectors(value: Any) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        if not isinstance(value, list):
            return results
        for item in value:
            if isinstance(item, dict):
                vector = str(item.get("vector") or item.get("name") or "").strip()
                description = str(item.get("description") or "").strip()
                likelihood = str(item.get("likelihood") or "medium").strip()
                if vector:
                    results.append(
                        {
                            "vector": vector,
                            "description": description,
                            "likelihood": likelihood,
                        }
                    )
            elif isinstance(item, str) and item.strip():
                results.append(
                    {
                        "vector": item.strip(),
                        "description": "",
                        "likelihood": "medium",
                    }
                )
        return results

    @staticmethod
    def _extract_yara_rule(response: str) -> Optional[str]:
        if not response:
            return None
        match = re.search(r"rule\s+[A-Za-z0-9_]+\s*\{.*\}", response, re.DOTALL)
        if match:
            return match.group(0).strip()
        stripped = response.strip()
        return stripped if stripped.startswith("rule ") else None


_ai_analyst: Optional[AIAnalyst] = None


def get_ai_analyst() -> AIAnalyst:
    global _ai_analyst
    if _ai_analyst is None:
        _ai_analyst = AIAnalyst()
    return _ai_analyst


def analyze_with_ai(analysis_data: Dict[str, Any], language: str = "ru") -> Dict[str, Any]:
    analyst = get_ai_analyst()
    return analyst.analyze_threat(analysis_data, language)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sample = {
        "static": {"file_type": "docm", "yara_matches": [{"rule": "OfficeMacro"}]},
        "dynamic": {"api_calls": [{"api": "CreateProcessW"}], "behavioral_patterns": [{"pattern": "Execution"}]},
        "risk": {"score": 72, "level": "high"},
    }
    print(json.dumps(analyze_with_ai(sample, language="ru"), ensure_ascii=False, indent=2))
