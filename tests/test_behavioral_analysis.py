#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for analyzer/behavioral_analysis.py
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzer.behavioral_analysis import BehavioralAnalyzer, analyze_behavior


class TestBehavioralAnalyzer(unittest.TestCase):
    """Test cases for BehavioralAnalyzer class"""

    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = BehavioralAnalyzer()

    def test_empty_api_calls(self):
        """Test analysis with empty API calls list"""
        result = self.analyzer.analyze_calls([])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_code_injection_detection(self):
        """Test detection of code injection pattern"""
        api_calls = [
            {"api": "OpenProcess", "pid": 1000,
             "args": {"dwProcessId": 2000, "success": True, "handle": "0x124"}},
            {"api": "VirtualAllocEx", "pid": 1000,
             "args": {"hProcess": "0x124", "success": True}},
            {"api": "WriteProcessMemory", "pid": 1000,
             "args": {"hProcess": "0x124", "success": True}},
            {"api": "CreateRemoteThread", "pid": 1000,
             "args": {"hProcess": "0x124", "success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("Code Injection" in str(p.get("pattern", "")) for p in result))

    def test_persistence_detection(self):
        """Test detection of persistence via Run key"""
        api_calls = [
            {"api": "RegOpenKeyExW", "pid": 1001,
             "args": {"lpSubKey": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      "success": True, "hKey_result": "0xabc"}},
            {"api": "RegSetValueExW", "pid": 1001,
             "args": {"hKey": "0xabc", "success": True,
                      "lpValueName": "Malware", "lpData_str": "C:\\evil.exe"}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("Persistence" in str(p.get("pattern", "")) for p in result))

    def test_downloader_detection(self):
        """Test detection of downloader activity"""
        api_calls = [
            {"api": "recv", "pid": 1002,
             "args": {"bytesReceived": 1024, "success": True}},
            {"api": "WriteFile", "pid": 1002,
             "args": {"hFile": "0xdef", "nBytesToWrite": 1024, "success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("Downloader" in str(p.get("pattern", "")) for p in result))

    def test_encoded_powershell_detection(self):
        """Test detection of encoded PowerShell commands"""
        api_calls = [
            {"api": "CreateProcessW", "pid": 1003,
             "args": {"commandLine": "powershell -ExecutionPolicy Bypass -enc SQBFAFgAKABO...",
                      "success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("PowerShell" in str(p.get("pattern", "")) for p in result))

    def test_ransomware_detection(self):
        """Test detection of ransomware behavior"""
        api_calls = []

        # Shadow Copy deletion
        api_calls.append({
            "api": "CreateProcessW",
            "pid": 2000,
            "args": {"commandLine": "vssadmin delete shadows /all /quiet", "success": True}
        })

        # Mass file encryption
        for i in range(25):
            file_path = f"C:\\Users\\User\\Documents\\file_{i}.docx"
            handle = f"0x{100+i:x}"
            api_calls.extend([
                {"api": "CreateFileW", "pid": 2000,
                 "args": {"lpFileName": file_path, "success": True, "handle": handle}},
                {"api": "ReadFile", "pid": 2000,
                 "args": {"hFile": handle, "lpFileName": file_path, "success": True}},
                {"api": "WriteFile", "pid": 2000,
                 "args": {"hFile": handle, "lpFileName": file_path, "success": True}}
            ])

        # Ransom note
        api_calls.append({
            "api": "CreateFileW",
            "pid": 2000,
            "args": {"lpFileName": "C:\\Users\\User\\Desktop\\DECRYPT_README.txt",
                     "success": True}
        })

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        ransomware_pattern = next((p for p in result if "RANSOMWARE" in str(p.get("pattern", ""))), None)
        self.assertIsNotNone(ransomware_pattern)
        self.assertEqual(ransomware_pattern.get("severity"), "CRITICAL")
        self.assertGreater(ransomware_pattern.get("confidence", 0), 0.95)

    def test_shadow_copy_deletion_only(self):
        """Test detection of Shadow Copy deletion without encryption"""
        api_calls = [
            {"api": "CreateProcessW", "pid": 2000,
             "args": {"commandLine": "vssadmin delete shadows /all", "success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("Shadow Copy" in str(p.get("pattern", "")) for p in result))

    def test_ransom_note_only(self):
        """Test detection of ransom note creation without encryption"""
        api_calls = [
            {"api": "CreateFileW", "pid": 2000,
             "args": {"lpFileName": "C:\\README_DECRYPT.txt", "success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)

        self.assertGreater(len(result), 0)
        self.assertTrue(any("Ransom Note" in str(p.get("pattern", "")) for p in result))

    def test_analyze_behavior_wrapper(self):
        """Test analyze_behavior wrapper function"""
        api_calls = [
            {"api": "CreateProcessW", "pid": 1000,
             "args": {"commandLine": "calc.exe", "success": True}}
        ]

        result = analyze_behavior(api_calls)
        self.assertIsInstance(result, list)


class TestPatternDetectionEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = BehavioralAnalyzer()

    def test_failed_api_calls_ignored(self):
        """Test that failed API calls are properly ignored"""
        api_calls = [
            {"api": "OpenProcess", "pid": 1000,
             "args": {"dwProcessId": 2000, "success": False}},  # Failed
            {"api": "CreateRemoteThread", "pid": 1000,
             "args": {"success": True}}
        ]

        result = self.analyzer.analyze_calls(api_calls)
        # Shouldn't detect injection without successful OpenProcess
        injection_found = any("Code Injection" in str(p.get("pattern", "")) for p in result)
        self.assertFalse(injection_found)

    def test_incomplete_sequence(self):
        """Test that incomplete sequences are not detected"""
        api_calls = [
            {"api": "OpenProcess", "pid": 1000,
             "args": {"dwProcessId": 2000, "success": True, "handle": "0x124"}},
            {"api": "VirtualAllocEx", "pid": 1000,
             "args": {"hProcess": "0x124", "success": True}}
            # Missing WriteProcessMemory and CreateRemoteThread
        ]

        result = self.analyzer.analyze_calls(api_calls)
        # Shouldn't detect full injection sequence
        injection_found = any("Code Injection Sequence" in str(p.get("pattern", "")) for p in result)
        self.assertFalse(injection_found)


if __name__ == "__main__":
    unittest.main()
