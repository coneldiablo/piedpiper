#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/heuristic_analysis.py

Эвристический анализ для детектирования упаковщиков, обфускации и подозрительных паттернов.
"""

import os
import math
import logging
from typing import Dict, List, Any
from collections import Counter

try:
    import pefile
except ImportError:
    pefile = None

logger = logging.getLogger("heuristic_analysis")


class HeuristicAnalyzer:
    """Эвристический анализатор файлов"""

    # Известные упаковщики по сигнатурам
    PACKER_SIGNATURES = {
        b'UPX': 'UPX',
        b'MPRESS': 'MPRESS',
        b'PECompact': 'PECompact',
        b'ASPack': 'ASPack',
        b'Themida': 'Themida',
        b'VMProtect': 'VMProtect',
        b'Obsidium': 'Obsidium',
        b'Enigma': 'Enigma Protector'
    }

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_data = None
        self.results = {
            "entropy": 0.0,
            "packed": False,
            "packer_detected": None,
            "suspicious_sections": [],
            "obfuscation_indicators": [],
            "anomalies": [],
            "risk_score": 0
        }

    def analyze(self) -> Dict[str, Any]:
        """Полный эвристический анализ"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()

            # 1. Энтропийный анализ
            self.results["entropy"] = self.calculate_entropy(self.file_data)

            # 2. Детект упаковщиков
            self.detect_packers()

            # 3. Анализ PE структуры (если PE файл)
            if self.file_path.lower().endswith(('.exe', '.dll', '.sys')):
                self.analyze_pe_structure()

            # 4. Поиск обфускации
            self.detect_obfuscation()

            # 5. Подсчёт риска
            self.results["risk_score"] = self.calculate_heuristic_risk()

        except Exception as e:
            logger.error(f"Ошибка эвристического анализа: {e}")

        return self.results

    def calculate_entropy(self, data: bytes) -> float:
        """Вычислить энтропию данных (Shannon entropy)"""
        if not data:
            return 0.0

        entropy = 0.0
        counter = Counter(data)
        length = len(data)

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_packers(self):
        """Детектирование упаковщиков"""
        for signature, packer_name in self.PACKER_SIGNATURES.items():
            if signature in self.file_data:
                self.results["packed"] = True
                self.results["packer_detected"] = packer_name
                logger.info(f"Детектирован упаковщик: {packer_name}")
                return

        # Эвристика: высокая энтропия = возможно упаковано
        if self.results["entropy"] > 7.2:
            self.results["packed"] = True
            self.results["packer_detected"] = "Unknown (high entropy)"

    def analyze_pe_structure(self):
        """Анализ PE структуры"""
        if not pefile:
            logger.warning("pefile не установлен, пропускаем PE анализ")
            return

        try:
            pe = pefile.PE(data=self.file_data)

            # Проверяем секции на подозрительную энтропию
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_entropy = self.calculate_entropy(section.get_data())

                if section_entropy > 7.0:
                    self.results["suspicious_sections"].append({
                        "name": section_name,
                        "entropy": section_entropy,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData
                    })

                # Аномалия: виртуальный размер != raw размер
                size_diff = abs(section.Misc_VirtualSize - section.SizeOfRawData)
                if size_diff > section.SizeOfRawData * 0.5:
                    self.results["anomalies"].append(
                        f"Section {section_name}: suspicious size mismatch"
                    )

            # Проверка Entry Point
            ep_section = None
            for section in pe.sections:
                if section.VirtualAddress <= pe.OPTIONAL_HEADER.AddressOfEntryPoint < \
                   section.VirtualAddress + section.Misc_VirtualSize:
                    ep_section = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    break

            if ep_section and ep_section not in ['.text', 'CODE']:
                self.results["anomalies"].append(
                    f"Suspicious entry point in section: {ep_section}"
                )

        except Exception as e:
            logger.error(f"Ошибка PE анализа: {e}")

    def detect_obfuscation(self):
        """Детектирование обфускации"""
        # Ищем подозрительные строки
        suspicious_patterns = [
            b'eval(',
            b'exec(',
            b'base64',
            b'FromBase64String',
            b'Invoke-Expression',
            b'DownloadString',
            b'StartProcess'
        ]

        for pattern in suspicious_patterns:
            if pattern in self.file_data:
                self.results["obfuscation_indicators"].append(
                    f"Found: {pattern.decode('utf-8', errors='ignore')}"
                )

    def calculate_heuristic_risk(self) -> int:
        """Расчёт риска на основе эвристик"""
        risk = 0

        # Высокая энтропия
        if self.results["entropy"] > 7.5:
            risk += 30
        elif self.results["entropy"] > 7.0:
            risk += 20

        # Упаковка
        if self.results["packed"]:
            risk += 25

        # Подозрительные секции
        risk += len(self.results["suspicious_sections"]) * 10

        # Обфускация
        risk += len(self.results["obfuscation_indicators"]) * 5

        # Аномалии
        risk += len(self.results["anomalies"]) * 15

        return min(risk, 100)


def analyze_file_heuristically(file_path: str) -> Dict[str, Any]:
    """Быстрая функция для эвристического анализа"""
    analyzer = HeuristicAnalyzer(file_path)
    return analyzer.analyze()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        result = analyze_file_heuristically(sys.argv[1])
        import json
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python heuristic_analysis.py <file>")
