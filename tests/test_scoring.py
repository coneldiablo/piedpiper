#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for analyzer/scoring.py
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.scoring import ThreatScoring, calculate_risk, categorize_level


class TestThreatScoring(unittest.TestCase):
    """Test cases for ThreatScoring class"""

    def setUp(self):
        """Set up test fixtures"""
        self.scorer = ThreatScoring()

    def test_categorize_level_low(self):
        """Test low risk categorization"""
        self.assertEqual(self.scorer.categorize_level(0), "Low")
        self.assertEqual(self.scorer.categorize_level(15), "Low")
        self.assertEqual(self.scorer.categorize_level(29), "Low")

    def test_categorize_level_medium(self):
        """Test medium risk categorization"""
        self.assertEqual(self.scorer.categorize_level(30), "Medium")
        self.assertEqual(self.scorer.categorize_level(45), "Medium")
        self.assertEqual(self.scorer.categorize_level(59), "Medium")

    def test_categorize_level_high(self):
        """Test high risk categorization"""
        self.assertEqual(self.scorer.categorize_level(60), "High")
        self.assertEqual(self.scorer.categorize_level(75), "High")
        self.assertEqual(self.scorer.categorize_level(84), "High")

    def test_categorize_level_critical(self):
        """Test critical risk categorization"""
        self.assertEqual(self.scorer.categorize_level(85), "Critical")
        self.assertEqual(self.scorer.categorize_level(95), "Critical")
        self.assertEqual(self.scorer.categorize_level(100), "Critical")

    def test_basic_scoring(self):
        """Test basic scoring calculation"""
        static_data = {
            "file_type": "pe",
            "file_size": 524288,
            "analysis": {}
        }
        dynamic_data = {"api_calls": []}
        ioc_data = []

        result = self.scorer.calculate_score(static_data, dynamic_data, ioc_data)

        self.assertIn("score", result)
        self.assertIn("level", result)
        self.assertIn("details", result)
        self.assertIn("confidence", result)
        self.assertIn("recommendations", result)

    def test_suspicious_pe_file(self):
        """Test scoring for suspicious PE file"""
        static_data = {
            "file_type": "pe",
            "file_size": 524288,
            "analysis": {
                "imports": [
                    "kernel32.dll!CreateRemoteThread",
                    "kernel32.dll!WriteProcessMemory"
                ],
                "enhanced_checks": {
                    "entropy_score": 7.5
                }
            }
        }
        dynamic_data = {
            "api_calls": [
                {"api": "CreateRemoteThread"},
                {"api": "WriteProcessMemory"}
            ]
        }
        ioc_data = [
            {"type": "ip", "value": "185.220.101.1"},
            {"type": "domain", "value": "evil.com"}
        ]

        result = self.scorer.calculate_score(static_data, dynamic_data, ioc_data)

        self.assertGreater(result["score"], 20)
        self.assertIn(result["level"], ["Low", "Medium", "High", "Critical"])

    def test_ransomware_pattern_scoring(self):
        """Test scoring with ransomware behavioral pattern"""
        static_data = {"file_type": "pe", "analysis": {}}
        dynamic_data = {"api_calls": []}
        ioc_data = []
        behavioral_patterns = [
            {
                "pattern": "RANSOMWARE FILE ENCRYPTION",
                "severity": "CRITICAL",
                "confidence": 0.99
            }
        ]

        result = self.scorer.calculate_score(
            static_data,
            dynamic_data,
            ioc_data,
            behavioral_patterns=behavioral_patterns
        )

        self.assertGreater(result["score"], 50)
        self.assertIn("ransomware_pattern", result["details"])

    def test_virustotal_integration(self):
        """Test VirusTotal data integration"""
        static_data = {"file_type": "pe", "analysis": {}}
        dynamic_data = {"api_calls": []}
        ioc_data = []
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 30,
                        "suspicious": 5,
                        "harmless": 10
                    }
                }
            }
        }

        result = self.scorer.calculate_score(
            static_data,
            dynamic_data,
            ioc_data,
            vt_data=vt_data
        )

        self.assertGreater(result["score"], 50)
        self.assertIn("vt_malicious", result["details"])

    def test_recommendations_generation(self):
        """Test that recommendations are generated"""
        high_score_details = {
            "ransomware_pattern": 15,
            "code_injection": 12,
            "persistence": 8
        }

        recommendations = self.scorer.generate_recommendations(90, high_score_details)

        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any("CRITICAL" in str(rec) for rec in recommendations))

    def test_ml_features_extraction(self):
        """Test ML feature extraction"""
        static_data = {
            "file_type": "pe",
            "file_size": 524288,
            "analysis": {
                "imports": ["CreateProcess"],
                "sections": [{"name": ".text"}],
                "enhanced_checks": {"entropy_score": 6.5}
            }
        }
        dynamic_data = {
            "api_calls": [
                {"api": "CreateProcess"},
                {"api": "WriteProcessMemory"}
            ]
        }
        ioc_data = [
            {"type": "ip", "value": "1.2.3.4"},
            {"type": "domain", "value": "test.com"}
        ]

        features = self.scorer._extract_ml_features(static_data, dynamic_data, ioc_data)

        self.assertIsInstance(features, list)
        self.assertEqual(len(features), 100)
        self.assertTrue(all(isinstance(f, (int, float)) for f in features))

    def test_calculate_risk_wrapper(self):
        """Test calculate_risk wrapper function"""
        static_data = {"file_type": "pe", "analysis": {}}
        dynamic_data = {"api_calls": []}
        ioc_data = []

        result = calculate_risk(static_data, dynamic_data, ioc_data)

        self.assertIn("score", result)
        self.assertIn("level", result)


class TestLegacyFunctions(unittest.TestCase):
    """Test legacy compatibility functions"""

    def test_categorize_level_function(self):
        """Test standalone categorize_level function"""
        self.assertEqual(categorize_level(25), "Low")
        self.assertEqual(categorize_level(45), "Medium")
        self.assertEqual(categorize_level(75), "High")
        self.assertEqual(categorize_level(95), "Critical")


if __name__ == "__main__":
    unittest.main()
