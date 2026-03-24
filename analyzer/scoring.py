#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/scoring.py

Полноценный модуль вычисления риск-скора (0..100) на основе:
- static_data (file_type, analysis)
- dynamic_data (api_calls и т.д.)
- ioc_data (список IoC)
- behavioral_patterns (паттерны поведения)
- VT-результаты (если есть)
- ML-модель (опционально) для предсказания вероятности малвари

Версия 2.0: добавлена поддержка ML-модели и расширенный scoring
"""

import logging
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Optional

try:  # Local import that also works when executed as a script
    from .ml_detector import MalwareMLDetector
except ImportError:  # pragma: no cover - fallback for direct execution
    from ml_detector import MalwareMLDetector  # type: ignore

try:
    from core.config import config_manager
except Exception:  # pragma: no cover - config may be unavailable in some contexts
    config_manager = None  # type: ignore[assignment]

logger = logging.getLogger("scoring")
logger.setLevel(logging.DEBUG)


class ThreatScoring:
    """
    Класс для интеллектуальной оценки угроз.
    Использует rule-based scoring + опционально ML-модель.

    Формула: R = Σ(wi * xi) * k_confidence
    где k_confidence - коэффициент достоверности (0.7-1.0)
    """

    def __init__(self, ml_model_path: Optional[str] = None):
        """
        Инициализация системы scoring.

        Args:
            ml_model_path: Путь к предобученной ML-модели (pickle файл)
        """
        # Базовые веса признаков на основе статистики от Kaspersky/MITRE ATT&CK
        self.base_weights = {
            # Статический анализ (max 30 баллов)
            'packed_executable': 5,
            'suspicious_imports': 8,
            'suspicious_strings': 7,
            'entropy_high': 5,
            'known_signature': 5,

            # Динамический анализ (max 40 баллов)
            'process_injection': 10,
            'persistence_mechanism': 8,
            'network_c2': 10,
            'file_encryption': 7,
            'credential_theft': 5,

            # IoC (max 30 баллов)
            'malicious_ips': 10,
            'suspicious_domains': 10,
            'registry_autorun': 10,

            # Behavioral patterns (дополнительные баллы)
            'ransomware_behavior': 15,
            'code_injection_pattern': 12,
            'downloader_pattern': 8,
        }
        self.weights = dict(self.base_weights)  # Backwards compatibility for legacy access
        self.weight_history: List[Dict[str, Any]] = []

        if ml_model_path is None and config_manager is not None:
            ml_model_path = config_manager.get("ML_MODEL_PATH")

        base_dir = Path(__file__).resolve().parents[1]
        if ml_model_path is None:
            default_path = base_dir / "models" / "malware_model.pkl"
            if default_path.exists():
                ml_model_path = str(default_path)
        elif ml_model_path:
            candidate = Path(str(ml_model_path)).expanduser()
            if not candidate.is_absolute():
                candidate = (base_dir / candidate).resolve()
            ml_model_path = str(candidate)

        # ML модель (опционально)
        self.ml_detector = MalwareMLDetector(ml_model_path=ml_model_path)

    def _prepare_adaptive_context(
        self,
        static_data: Dict[str, Any],
        dynamic_data: Dict[str, Any],
        ioc_data: List[Dict[str, Any]],
        behavioral_patterns: Optional[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Build dynamic weighting profile based on available evidence and ML output.
        """
        weights = dict(self.base_weights)
        dynamic_multiplier = 1.0
        ioc_multiplier = 1.0
        confidence_factor = 1.0
        notes: Dict[str, Any] = {}

        ml_probability: Optional[float] = None
        ml_meta: Dict[str, Any] = {}

        if self.ml_detector:
            try:
                ml_probability, ml_meta = self.ml_detector.predict_probability(
                    static_data,
                    dynamic_data,
                    ioc_data,
                )
            except Exception as exc:  # pragma: no cover - defensive safeguard
                logger.error("[Adaptive] ML prediction exception: %s", exc)
                ml_meta = {"reason": "prediction_exception", "error": str(exc)}
                ml_probability = None

        if ml_probability is not None:
            risk_amplifier = 0.8 + ml_probability * 0.6  # 0.8 .. 1.4
            for key in ("process_injection", "persistence_mechanism", "network_c2"):
                weights[key] = max(5, int(round(weights.get(key, 10) * risk_amplifier)))
            dynamic_multiplier += ml_probability * 0.4
            ioc_multiplier += ml_probability * 0.25
            confidence_factor *= min(1.0 + ml_probability * 0.35, 1.3)
        elif ml_meta:
            notes["ml_status"] = ml_meta.get("reason", "ml_unknown")

        # Data completeness heuristics
        if not isinstance(dynamic_data, dict) or not dynamic_data.get("api_calls"):
            confidence_factor *= 0.88
            notes.setdefault("data_gaps", []).append("missing_dynamic_calls")

        if not ioc_data:
            confidence_factor *= 0.9
            notes.setdefault("data_gaps", []).append("missing_iocs")

        if isinstance(static_data, dict) and static_data.get("file_size") and static_data.get("file_size") < 32_768:
            confidence_factor *= 0.95

        # Behaviour-driven refinements
        if behavioral_patterns:
            ransomware_detected = any(
                "ransom" in str(pattern.get("pattern", "")).lower()
                for pattern in behavioral_patterns
            )
            if ransomware_detected:
                weights["ransomware_behavior"] = int(round(weights["ransomware_behavior"] * 1.2))
                confidence_factor *= 1.05

        self.weight_history.append(
            {
                "weights": weights.copy(),
                "dynamic_multiplier": dynamic_multiplier,
                "ioc_multiplier": ioc_multiplier,
                "confidence": confidence_factor,
                "ml_probability": ml_probability,
            }
        )
        if len(self.weight_history) > 50:
            self.weight_history.pop(0)

        return {
            "weights": weights,
            "dynamic_multiplier": dynamic_multiplier,
            "ioc_multiplier": ioc_multiplier,
            "confidence": confidence_factor,
            "ml_probability": ml_probability,
            "ml_meta": ml_meta,
            "notes": notes,
        }

    def calculate_score(
        self,
        static_data: Dict[str, Any],
        dynamic_data: Dict[str, Any],
        ioc_data: List[Dict[str, str]],
        vt_data: Optional[Dict[str, Any]] = None,
        behavioral_patterns: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Вычисление риск-скора на основе всех данных анализа.

        Args:
            static_data: результаты статического анализа
            dynamic_data: результаты динамического анализа
            ioc_data: список IoC
            vt_data: данные от VirusTotal (опционально)
            behavioral_patterns: обнаруженные поведенческие паттерны (опционально)

        Returns:
            {"score": int, "level": "Low/Medium/High/Critical", "details": {...},
             "ml_probability": float, "confidence": float, "recommendations": []}
        """
        score_details = {}
        total_score = 0
        confidence = 1.0  # Коэффициент достоверности

        adaptive_ctx = self._prepare_adaptive_context(
            static_data,
            dynamic_data,
            ioc_data,
            behavioral_patterns,
        )
        weights = adaptive_ctx["weights"]
        dynamic_multiplier = adaptive_ctx["dynamic_multiplier"]
        ioc_multiplier = adaptive_ctx["ioc_multiplier"]
        confidence *= adaptive_ctx["confidence"]
        ml_probability = adaptive_ctx.get("ml_probability")
        ml_meta = adaptive_ctx.get("ml_meta", {})
        if adaptive_ctx.get("notes"):
            score_details["adaptive_notes"] = adaptive_ctx["notes"]
        score_details["adaptive_weights"] = weights

        # -- 1. Признаки из статического анализа --
        ftype = static_data.get("file_type", "")
        if ftype == "pe":
            # За PE +2 балла
            total_score += 2
            score_details["PE_type"] = +2
            # Если в analysis -> disassembly есть suspicious calls
            analysis = static_data.get("analysis", {})
            if isinstance(analysis, dict):
                disasm = analysis.get("disassembly", [])
                if isinstance(disasm, list) and len(disasm) > 0:
                    # Если мы видим инструкцию "int 3" — как пример подозрительного
                    # (шутка, в реальном мире много других критериев)
                    suspicious_count = sum(1 for line in disasm if "int 3" in line)
                    add_points = suspicious_count * 5
                    total_score += add_points
                    score_details["DisasmSuspicious"] = add_points

        elif ftype == "elf":
            total_score += 3
            score_details["ELF_type"] = +3

        elif ftype == "pdf":
            total_score += 5
            score_details["PDF_type"] = +5

        elif ftype == "docx":
            total_score += 6
            score_details["DOCX_type"] = +6

        elif ftype == "ole_doc":
            total_score += 8
            score_details["OLE_doc_type"] = +8
            # Если есть macros
            if "has_macros" in static_data.get("analysis", {}):
                if static_data["analysis"]["has_macros"]:
                    total_score += 10
                    score_details["OLE_macros"] = +10

        # -- 2. Признаки из dynamic_data --
        api_calls = dynamic_data.get("api_calls", [])
        if isinstance(api_calls, list):
            # Если видим CreateRemoteThread => +15
            create_remote_count = sum(1 for call in api_calls if call.get("api") == "CreateRemoteThread")
            if create_remote_count > 0:
                pts = int(round(create_remote_count * 15 * dynamic_multiplier))
                total_score += pts
                score_details["CreateRemoteThread_count"] = pts

            # Если есть WriteProcessMemory => +10
            wpm_count = sum(1 for call in api_calls if call.get("api") == "WriteProcessMemory")
            if wpm_count > 0:
                pts = int(round(wpm_count * 10 * dynamic_multiplier))
                total_score += pts
                score_details["WriteProcessMemory_count"] = pts

            # Если URLDownloadToFileW => +5
            url_dl_count = sum(1 for call in api_calls if call.get("api") == "URLDownloadToFileW")
            if url_dl_count > 0:
                pts = int(round(url_dl_count * 5 * dynamic_multiplier))
                total_score += pts
                score_details["URLDownload_count"] = pts

        sandbox_data = dynamic_data.get("sandbox_evasion") if isinstance(dynamic_data, dict) else {}
        if isinstance(sandbox_data, dict):
            evasion_score = sandbox_data.get("score", 0)
            if isinstance(evasion_score, (int, float)) and evasion_score > 0:
                evasion_points = min(int(round(float(evasion_score) * 5)), 15)
                total_score += evasion_points
                score_details["sandbox_evasion"] = evasion_points
                confidence *= 0.95

        # -- 3. IoC (частота опасных типов) --
        # domain, ip, url, registry, email, ...
        if ioc_data and isinstance(ioc_data, list):
            domain_count = sum(1 for ioc in ioc_data if ioc["type"] == "domain")
            ip_count = sum(1 for ioc in ioc_data if ioc["type"] == "ip")
            url_count = sum(1 for ioc in ioc_data if ioc["type"] == "url")
            registry_count = sum(1 for ioc in ioc_data if ioc["type"] == "registry")

            # За каждый domain => +1
            domain_points = int(round(domain_count * ioc_multiplier))
            total_score += domain_points
            score_details["domains"] = domain_points

            # За каждый IP => +1
            ip_points = int(round(ip_count * ioc_multiplier))
            total_score += ip_points
            score_details["ips"] = ip_points

            # За каждый URL => +2
            add_url = int(round(url_count * 2 * ioc_multiplier))
            total_score += add_url
            score_details["urls"] = add_url

            # За registry => +1
            registry_points = int(round(registry_count * ioc_multiplier))
            total_score += registry_points
            score_details["registry"] = registry_points

        # -- 4. Поведенческие паттерны (behavioral patterns) --
        if behavioral_patterns and isinstance(behavioral_patterns, list):
            for pattern in behavioral_patterns:
                pattern_type = pattern.get('pattern', '')
                pattern_type_lower = pattern_type.lower()
                severity = str(pattern.get('severity', '')).upper()
                pattern_confidence = pattern.get('confidence')

                if 'ransomware' in pattern_type_lower or 'encryption' in pattern_type_lower:
                    pts = weights.get('ransomware_behavior', 15)
                    if severity == 'CRITICAL':
                        pts = max(pts, 70)
                    elif severity == 'HIGH':
                        pts = max(pts, 45)
                    else:
                        pts = max(pts, 30)
                    if isinstance(pattern_confidence, (int, float)) and pattern_confidence >= 0.95:
                        pts = max(pts, 72)
                    total_score += pts
                    score_details['ransomware_pattern'] = pts
                    logger.warning(f"[CRITICAL] Ransomware pattern detected!")

                elif 'code injection' in pattern_type_lower or 'injection' in pattern_type_lower:
                    pts = weights.get('code_injection_pattern', 12)
                    total_score += pts
                    score_details['code_injection'] = pts

                elif 'downloader' in pattern_type_lower or 'download' in pattern_type_lower:
                    pts = weights.get('downloader_pattern', 8)
                    total_score += pts
                    score_details['downloader'] = pts

                elif 'persistence' in pattern_type_lower:
                    pts = weights.get('persistence_mechanism', 8)
                    total_score += pts
                    score_details['persistence'] = pts

                elif 'powershell' in pattern_type_lower or 'encoded' in pattern_type_lower:
                    total_score += 7
                    score_details['encoded_powershell'] = 7

        # -- 5. VirusTotal data (если есть) --
        if vt_data and isinstance(vt_data, dict):
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            # За каждое malicious => +3, за suspicious => +1
            vt_points = malicious * 3 + suspicious * 1
            total_score += vt_points
            score_details["vt_malicious"] = vt_points

            # Если много движков сказали malicious, снижаем confidence
            if malicious > 30:
                confidence *= 0.95
            elif malicious > 10:
                confidence *= 0.97

        # -- 6. ML-модель (если загружена) --
        if ml_probability is not None:
            score_details['ml_malware_probability'] = round(ml_probability, 3)
            ml_score = int(round(ml_probability * 20))
            total_score += ml_score
            score_details['ml_contribution'] = ml_score
            logger.info(f"[ML] Malware probability: {ml_probability:.3f}, added {ml_score} points")
            if ml_meta:
                meta_copy = {k: v for k, v in ml_meta.items() if k != "reason"}
                if meta_copy:
                    score_details['ml_meta'] = meta_copy
        else:
            status = ml_meta.get('reason') if isinstance(ml_meta, dict) else None
            if status:
                score_details['ml_status'] = status
            if self.ml_detector:
                load_error = self.ml_detector.get_load_error()
                if load_error:
                    score_details['ml_error'] = load_error
                    logger.warning(f"[ML] Model load issue: {load_error}")
# -- 7. Применяем коэффициент достоверности --
        confidence = max(0.3, min(confidence, 1.0))
        total_score = int(total_score * confidence)

        # -- 8. Ограничим макс. 100 --
        if total_score > 100:
            total_score = 100

        # Выводим уровень угрозы
        level = self.categorize_level(total_score)

        # Генерируем рекомендации
        recommendations = self.generate_recommendations(total_score, score_details)

        result = {
            "score": total_score,
            "level": level,
            "details": score_details,
            "confidence": confidence,
            "ml_probability": ml_probability,
            "recommendations": recommendations
        }
        logger.info(f"[Scoring] total_score={total_score}, level={level}, confidence={confidence}")
        return result

    def _extract_ml_features(self, static_data, dynamic_data, ioc_data) -> List[float]:
        """
        Legacy wrapper that preserves the old API while delegating
        feature construction to the dedicated ML module.
        """
        detector = self.ml_detector or MalwareMLDetector()
        return detector.extract_features(static_data, dynamic_data, ioc_data)

    def categorize_level(self, score: int) -> str:
        """
        Классификация уровня угрозы.
        0-29 => Low
        30-59 => Medium
        60-84 => High
        85-100 => Critical
        """
        if score < 30:
            return "Low"
        elif score < 60:
            return "Medium"
        elif score < 85:
            return "High"
        else:
            return "Critical"

    def generate_recommendations(self, score: int, details: Dict[str, Any]) -> List[str]:
        """
        Генерация рекомендаций по митигации на основе обнаруженных угроз.
        """
        recommendations = []

        if score >= 85:
            recommendations.append("🔴 CRITICAL: Немедленно изолируйте систему от сети")
            recommendations.append("🔴 CRITICAL: Запретите выполнение файла через Group Policy")

        if details.get('ransomware_pattern'):
            recommendations.append("🛡️ Ransomware detected: Отключите сетевые диски, сделайте бэкап")
            recommendations.append("🛡️ Проверьте Shadow Copies и восстановите из бэкапа")

        if details.get('code_injection'):
            recommendations.append("⚠️ Code Injection: Проверьте запущенные процессы (Process Hacker)")
            recommendations.append("⚠️ Используйте EDR для поиска memory injections")

        if details.get('persistence'):
            recommendations.append("🔍 Persistence detected: Проверьте автозагрузку (Autoruns)")
            recommendations.append("🔍 Проверьте Tasks Scheduler и Services")

        if details.get('vt_malicious', 0) > 10:
            recommendations.append("☁️ Multiple AV detections: Считайте файл вредоносным")

        if score >= 60:
            recommendations.append("📋 Создайте инцидент в SIEM/SOC")
            recommendations.append("📋 Сохраните образец для форензик-анализа")

        if score < 30:
            recommendations.append("✅ Low risk: Файл вероятно безопасен, но рекомендуется мониторинг")

        return recommendations


def categorize_level(score: int) -> str:
    """
    Legacy функция для обратной совместимости.
    Использует новую классификацию.
    """
    ts = ThreatScoring()
    return ts.categorize_level(score)


def calculate_risk(
    static_data: dict,
    dynamic_data: dict,
    ioc_data: list,
    vt_data: Optional[dict] = None,
    behavioral_patterns: Optional[list] = None,
    ml_model_path: Optional[str] = None
) -> dict:
    """
    Упрощённая точка входа (для совместимости).
    Создаёт ThreatScoring, вызывает calculate_score.

    Args:
        static_data: Результаты статического анализа
        dynamic_data: Результаты динамического анализа
        ioc_data: Список IoC
        vt_data: Данные VirusTotal (опционально)
        behavioral_patterns: Поведенческие паттерны из dynamic_data (опционально)
        ml_model_path: Путь к ML-модели (опционально)

    Returns:
        dict: {"score": int, "level": str, "details": dict, ...}
    """
    # Если behavioral_patterns не переданы, пытаемся извлечь из dynamic_data
    if behavioral_patterns is None and isinstance(dynamic_data, dict):
        behavioral_patterns = dynamic_data.get('behavioral_patterns', [])

    ts = ThreatScoring(ml_model_path=ml_model_path)
    return ts.calculate_score(
        static_data,
        dynamic_data,
        ioc_data,
        vt_data,
        behavioral_patterns
    )


if __name__ == "__main__":
    import json
    import sys
    import io
    logging.basicConfig(level=logging.DEBUG)

    # Fix Windows console encoding for emoji support
    if sys.platform.startswith('win'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    # Тестируем улучшенный scoring
    fake_static = {
        "file_type": "pe",
        "file_size": 524288,  # 512 KB
        "analysis": {
            "disassembly": [
                "0x401000: push ebp",
                "0x401002: mov ebp, esp",
                "0x401004: int 3",
                "0x401005: pop ebp"
            ],
            "imports": [
                "kernel32.dll!CreateRemoteThread",
                "kernel32.dll!WriteProcessMemory",
                "kernel32.dll!VirtualAllocEx"
            ],
            "sections": [
                {".text": {"entropy": 7.2}},
                {".data": {"entropy": 3.1}}
            ],
            "enhanced_checks": {
                "entropy_score": 7.5
            }
        }
    }

    fake_dynamic = {
        "api_calls": [
            {"api": "OpenProcess", "pid": 1234},
            {"api": "VirtualAllocEx", "pid": 1234},
            {"api": "WriteProcessMemory", "pid": 1234},
            {"api": "CreateRemoteThread", "pid": 1234},
            {"api": "RegCreateKeyExW", "pid": 1234},
            {"api": "URLDownloadToFileW", "pid": 1234}
        ],
        "behavioral_patterns": [
            {
                "pattern": "Code Injection Sequence",
                "details": "Detected Open->Alloc->Write->CreateRemoteThread"
            },
            {
                "pattern": "Persistence via Run Key",
                "details": "Registry autorun modification detected"
            }
        ]
    }

    fake_ioc = [
        {"type": "domain", "value": "evil-c2.com"},
        {"type": "ip", "value": "185.220.101.1"},
        {"type": "url", "value": "http://malware-distrib.xyz/payload.exe"},
        {"type": "registry", "value": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
    ]

    fake_vt = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 10,
                    "malicious": 25,
                    "suspicious": 3,
                    "timeout": 0,
                    "undetected": 15
                }
            }
        }
    }

    print("="*60)
    print("Testing ThreatInquisitor Scoring v2.0")
    print("="*60)

    result = calculate_risk(fake_static, fake_dynamic, fake_ioc, fake_vt)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    print("\n" + "="*60)
    print(f"VERDICT: {result['level']} ({result['score']}/100)")
    print(f"Confidence: {result['confidence']*100}%")
    print("="*60)

    if result.get('recommendations'):
        print("\n📋 RECOMMENDATIONS:")
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"  {i}. {rec}")
