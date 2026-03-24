#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Standalone machine learning helper for ThreatInquisitor.

The scoring engine loads this module to keep model handling,
feature engineering, and inference decoupled from rule logic.
"""

from __future__ import annotations

import logging
import os
import pickle
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ml_detector")


class MalwareMLDetector:
    """Utility that loads an ML model and produces malware probabilities."""

    FEATURE_VECTOR_SIZE = 100
    SUSPICIOUS_APIS = [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "LoadLibrary",
        "GetProcAddress",
        "IsDebuggerPresent",
    ]

    def __init__(
        self,
        ml_model_path: Optional[str] = None,
        *,
        model: Any = None,
        scaler: Any = None,
    ) -> None:
        self.model_path = ml_model_path
        self.model = model
        self.scaler = scaler
        self._load_error: Optional[str] = None

        if self.model is None and self.model_path:
            self._load_model(self.model_path)

    # --------------------------------------------------------------------- #
    # Public API                                                            #
    # --------------------------------------------------------------------- #
    def has_model(self) -> bool:
        """Return True when the detector has a usable ML model."""
        return self.model is not None

    def get_load_error(self) -> Optional[str]:
        """Expose last load error (useful for diagnostics)."""
        return self._load_error

    def predict_probability(
        self,
        static_data: Dict[str, Any],
        dynamic_data: Dict[str, Any],
        ioc_data: List[Dict[str, Any]],
    ) -> Tuple[Optional[float], Dict[str, Any]]:
        """
        Produce malware probability using the underlying ML model.

        Returns a tuple of (probability, details). Probability is None when
        no model is available or inference fails.
        """
        if not self.has_model():
            probability, details = self._heuristic_probability(static_data, dynamic_data, ioc_data)
            details["reason"] = "model_not_loaded"
            return probability, details

        feature_vector = self.extract_features(static_data, dynamic_data, ioc_data)
        model_input = [feature_vector]

        scaled_input = model_input
        if self.scaler is not None:
            try:
                scaled_input = self.scaler.transform(model_input)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Scaler transform failed: %s", exc)
                scaled_input = model_input

        try:
            malware_prob = self._invoke_model(scaled_input)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("ML prediction failed: %s", exc)
            probability, details = self._heuristic_probability(static_data, dynamic_data, ioc_data)
            details.update({"reason": "prediction_failure", "error": str(exc)})
            return probability, details

        details: Dict[str, Any] = {
            "feature_vector_length": len(feature_vector),
            "scaler_used": bool(self.scaler),
            "mode": "ml",
        }
        if self.model_path:
            details["model_path"] = self.model_path
        return malware_prob, details

    def extract_features(
        self,
        static_data: Dict[str, Any],
        dynamic_data: Dict[str, Any],
        ioc_data: List[Dict[str, Any]],
    ) -> List[float]:
        """
        Build the fixed-length feature vector expected by the ML model.

        The logic mirrors the legacy implementation from scoring.py so
        existing models remain compatible.
        """
        features: List[float] = []
        analysis = static_data.get("analysis", {}) if isinstance(static_data, dict) else {}

        # 1-4. Static attributes and heuristics
        file_size = float(static_data.get("file_size", 0) or 0)
        features.append(min(file_size / (10 * 1024 * 1024), 1.0))  # Normalised to 10 MB
        entropy_score = analysis.get("enhanced_checks", {}).get("entropy_score", 0)
        features.append(float(entropy_score))

        sections = analysis.get("sections", [])
        entropy_values = []
        for section in sections:
            if not isinstance(section, dict) or not section:
                continue
            if "entropy" in section:
                entropy_values.append(section.get("entropy", 0))
                continue
            first_value = section.get(next(iter(section)))
            if isinstance(first_value, dict):
                entropy_values.append(first_value.get("entropy", 0))
        max_entropy = max(entropy_values) if entropy_values else 0.0
        features.append(float(max_entropy))

        features.append(float(len(entropy_values)))

        # 5-10. Suspicious imports
        imports = analysis.get("imports", [])
        for api in self.SUSPICIOUS_APIS:
            has_api = int(any(api in str(entry) for entry in imports))
            features.append(float(has_api))

        # 11-15. API call behaviour
        api_calls = dynamic_data.get("api_calls", []) if isinstance(dynamic_data, dict) else []
        features.append(min(len(api_calls), 1000) / 1000.0)

        dangerous_apis = defaultdict(int)
        for call in api_calls:
            api_name = call.get("api", "") if isinstance(call, dict) else ""
            if "Process" in api_name:
                dangerous_apis["process"] += 1
            if "Thread" in api_name:
                dangerous_apis["thread"] += 1
            if "Memory" in api_name:
                dangerous_apis["memory"] += 1
            if "File" in api_name:
                dangerous_apis["file"] += 1
            if "Registry" in api_name:
                dangerous_apis["registry"] += 1

        for category in ["process", "thread", "memory", "file", "registry"]:
            features.append(min(dangerous_apis.get(category, 0), 100) / 100.0)

        # 21-30. IoC statistics
        ioc_counts = defaultdict(int)
        for ioc in ioc_data:
            if isinstance(ioc, dict):
                ioc_type = ioc.get("type", "")
                ioc_counts[ioc_type] += 1

        for ioc_type in ["ip", "domain", "url", "registry", "hash_md5"]:
            features.append(min(ioc_counts.get(ioc_type, 0), 50) / 50.0)

        # Pad/truncate to expected length
        while len(features) < self.FEATURE_VECTOR_SIZE:
            features.append(0.0)

        return features[: self.FEATURE_VECTOR_SIZE]

    # --------------------------------------------------------------------- #
    # Private helpers                                                       #
    # --------------------------------------------------------------------- #
    def _load_model(self, path: str) -> None:
        """Load model + scaler bundle from pickle file."""
        if not os.path.isfile(path):
            self._load_error = f"Model file does not exist: {path}"
            logger.warning(self._load_error)
            return

        try:
            with open(path, "rb") as handle:
                model_data = pickle.load(handle)
            self.model = model_data.get("model")
            self.scaler = model_data.get("scaler")
            self._load_error = None
            logger.info("ML model loaded from %s", path)
        except Exception as exc:  # pragma: no cover - defensive
            self.model = None
            self.scaler = None
            self._load_error = str(exc)
            logger.warning("Failed to load ML model %s: %s", path, exc)

    def _invoke_model(self, model_input: Any) -> float:
        """Call the underlying model and return malware probability."""
        if not self.has_model():
            raise RuntimeError("Model not loaded")

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(model_input)[0]
            if isinstance(proba, (list, tuple)):
                return float(proba[1] if len(proba) > 1 else proba[0])
            if hasattr(proba, "__len__") and not isinstance(proba, (str, bytes)):
                return float(proba[1] if len(proba) > 1 else proba[0])
            return float(proba)

        if hasattr(self.model, "predict"):
            prediction = self.model.predict(model_input)[0]
            return float(prediction)

        raise AttributeError("Model lacks predict_proba/predict methods")

    def _heuristic_probability(
        self,
        static_data: Dict[str, Any],
        dynamic_data: Dict[str, Any],
        ioc_data: List[Dict[str, Any]],
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Derive a conservative malware probability using rule-based heuristics.

        The goal is to provide a meaningful fallback when an ML model is
        unavailable so that downstream scoring logic still receives a value.
        """
        score = 0.0
        contributions: Dict[str, float] = {}

        def add_contribution(name: str, value: float) -> None:
            nonlocal score
            if value <= 0:
                return
            capped_value = max(0.0, min(value, 0.35))
            score += capped_value
            contributions[name] = round(capped_value, 3)

        analysis = static_data.get("analysis", {}) if isinstance(static_data, dict) else {}
        enhanced = analysis.get("enhanced_checks", {}) if isinstance(analysis, dict) else {}

        # Packed binaries often indicate obfuscation.
        packer_indicators = [
            static_data.get("is_packed"),
            analysis.get("is_packed") if isinstance(analysis, dict) else None,
            analysis.get("packer") if isinstance(analysis, dict) else None,
            static_data.get("packer"),
        ]
        if any(
            indicator
            for indicator in packer_indicators
            if isinstance(indicator, bool) and indicator
            or isinstance(indicator, str) and indicator and indicator.lower() not in {"", "none", "false"}
        ):
            add_contribution("packing", 0.18)

        entropy = None
        if isinstance(enhanced, dict):
            entropy = enhanced.get("entropy_score")
        if entropy is None and isinstance(analysis, dict):
            entropy = analysis.get("entropy")
        try:
            entropy_value = float(entropy)
        except (TypeError, ValueError):
            entropy_value = None
        if entropy_value is not None and entropy_value > 6.5:
            entropy_score = min((entropy_value - 6.5) / 3.5, 1.0)
            add_contribution("entropy", 0.22 * entropy_score)

        # Suspicious imports
        imports_raw = analysis.get("imports") if isinstance(analysis, dict) else None
        if not imports_raw:
            imports_raw = static_data.get("imports")
        import_strings: List[str] = []
        if isinstance(imports_raw, list):
            for item in imports_raw:
                if isinstance(item, dict):
                    import_strings.extend(str(val) for val in item.values())
                else:
                    import_strings.append(str(item))
        elif isinstance(imports_raw, dict):
            import_strings.extend(str(key) for key in imports_raw.keys())
            import_strings.extend(str(val) for val in imports_raw.values())

        suspicious_imports = sum(
            1 for entry in import_strings for api in self.SUSPICIOUS_APIS if api.lower() in entry.lower()
        )
        if suspicious_imports:
            add_contribution("suspicious_imports", min(0.05 * suspicious_imports, 0.25))

        # Suspicious strings such as URLs or shell commands.
        suspicious_terms = ("cmd.exe", "powershell", "http://", "https://", "winexec", "socket", "ftp://")
        strings_source = static_data.get("strings")
        if not strings_source and isinstance(analysis, dict):
            strings_source = analysis.get("strings")
        if not isinstance(strings_source, list):
            strings_source = []
        suspicious_strings = [
            s
            for s in strings_source
            if isinstance(s, str) and any(term in s.lower() for term in suspicious_terms)
        ]
        if suspicious_strings:
            add_contribution("suspicious_strings", min(0.03 * len(suspicious_strings), 0.18))

        # Dynamic API calls
        api_calls = dynamic_data.get("api_calls", []) if isinstance(dynamic_data, dict) else []
        suspicious_api_hits = sum(
            1
            for call in api_calls
            if isinstance(call, dict) and call.get("api") in self.SUSPICIOUS_APIS
        )
        if suspicious_api_hits:
            add_contribution("suspicious_api_calls", min(0.07 * suspicious_api_hits, 0.35))

        # Network anomalies (common C2 ports, repeated connections).
        network_data: List[Dict[str, Any]] = []
        if isinstance(dynamic_data, dict):
            candidate_network = dynamic_data.get("network") or dynamic_data.get("connections") or []
            if isinstance(candidate_network, list):
                network_data = candidate_network
        suspicious_ports = {4444, 5555, 6666, 6667, 8080, 8443, 12345, 31337}
        port_hits = sum(
            1
            for entry in network_data
            if isinstance(entry, dict) and int(entry.get("remote_port", 0) or 0) in suspicious_ports
        )
        if port_hits:
            add_contribution("suspicious_ports", min(0.06 * port_hits, 0.2))

        # IoC density.
        ioc_count = len(ioc_data) if isinstance(ioc_data, list) else 0
        if ioc_count:
            add_contribution("ioc_density", min(0.04 * ioc_count, 0.25))

        # Behavioural patterns detected upstream may be present already.
        behaviors: List[Dict[str, Any]] = []
        if isinstance(dynamic_data, dict):
            candidate_behaviors = dynamic_data.get("behavioral_patterns")
            if isinstance(candidate_behaviors, list):
                behaviors = candidate_behaviors
        if behaviors:
            add_contribution("behavioral_patterns", min(0.05 * len(behaviors), 0.2))

        # Clamp to a sensible probability range.
        probability = min(max(score, 0.0), 0.98)
        if probability == 0.0:
            probability = 0.02  # small baseline to avoid "perfectly safe" classification

        confidence = 0.35 if not contributions else min(0.5 + 0.1 * len(contributions), 0.9)

        details: Dict[str, Any] = {
            "mode": "heuristic_fallback",
            "contributions": contributions,
            "confidence": round(confidence, 3),
        }
        return round(probability, 4), details


__all__ = ["MalwareMLDetector"]
