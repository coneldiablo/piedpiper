#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/core/threat_intel.py

Интеграция с Threat Intelligence платформами:
- AlienVault OTX
- AbuseIPDB
- URLhaus
- VirusTotal (расширенная интеграция)
"""

import logging
import requests
from typing import Dict, List, Any, Optional
from core.config import config_manager

logger = logging.getLogger("threat_intel")


class ThreatIntelligence:
    """Объединённый класс для работы с Threat Intelligence"""

    def __init__(self):
        self.vt_api_key = config_manager.get("VIRUSTOTAL_API_KEY")
        self.otx_api_key = config_manager.get("OTX_API_KEY", "")  # Optional
        self.abuseipdb_key = config_manager.get("ABUSEIPDB_KEY", "")  # Optional
        self.abusech_auth_key = (
            config_manager.get("ABUSECH_AUTH_KEY", "")
            or config_manager.get("THREATFOX_API_KEY", "")
            or config_manager.get("URLHAUS_API_KEY", "")
            or config_manager.get("MALWAREBAZAAR_API_KEY", "")
            or ""
        )
        self.threatfox_api_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.urlhaus_api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        self.greynoise_api_url = "https://api.greynoise.io/v3/community"
        self.greynoise_key = config_manager.get("GREYNOISE_API_KEY", "")
        self.malwarebazaar_api_url = "https://mb-api.abuse.ch/api/v1/"

    def _abusech_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.abusech_auth_key:
            headers["Auth-Key"] = self.abusech_auth_key
        return headers

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Проверка IP через multiple sources"""
        results = {
            "ip": ip_address,
            "virustotal": {},
            "abuseipdb": {},
            "otx": {},
            "threatfox": {},
            "greynoise": {},
            "verdict": "unknown",
            "threat_score": 0
        }

        # VirusTotal
        if self.vt_api_key:
            results["virustotal"] = self._check_ip_virustotal(ip_address)

        # AbuseIPDB
        if self.abuseipdb_key:
            results["abuseipdb"] = self._check_ip_abuseipdb(ip_address)

        # AlienVault OTX
        if self.otx_api_key:
            results["otx"] = self._check_ip_otx(ip_address)

        threatfox_matches = self._query_threatfox(ip_address)
        if threatfox_matches:
            results["threatfox"] = self._summarize_threatfox(threatfox_matches)

        greynoise = self._check_ip_greynoise(ip_address)
        if greynoise:
            results["greynoise"] = greynoise

        # Общий вердикт
        results["verdict"], results["threat_score"] = self._calculate_verdict(results)

        return results

    def check_url(self, url: str) -> Dict[str, Any]:
        """Проверка URL"""
        results = {
            "url": url,
            "virustotal": {},
            "urlhaus": {},
            "threatfox": {},
            "verdict": "unknown",
            "threat_score": 0
        }

        if self.vt_api_key:
            results["virustotal"] = self._check_url_virustotal(url)

        results["urlhaus"] = self._check_url_urlhaus(url)

        threatfox_matches = self._query_threatfox(url)
        if threatfox_matches:
            results["threatfox"] = self._summarize_threatfox(threatfox_matches)

        results["verdict"], results["threat_score"] = self._calculate_verdict(results)

        return results

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Проверка хеша файла"""
        results = {
            "hash": file_hash,
            "virustotal": {},
            "threatfox": {},
            "malwarebazaar": {},
            "verdict": "unknown",
            "threat_score": 0
        }

        if self.vt_api_key:
            results["virustotal"] = self._check_hash_virustotal(file_hash)

        results["malwarebazaar"] = self._check_hash_malwarebazaar(file_hash)

        threatfox_matches = self._query_threatfox(file_hash)
        if threatfox_matches:
            results["threatfox"] = self._summarize_threatfox(threatfox_matches)

        results["verdict"], results["threat_score"] = self._calculate_verdict(results)

        return results

    def _check_ip_virustotal(self, ip: str) -> Dict[str, Any]:
        """VirusTotal IP check"""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
        except Exception as e:
            logger.error(f"VT IP check error: {e}")

        return {}

    def _check_ip_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """AbuseIPDB check"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False)
                }
        except Exception as e:
            logger.error(f"AbuseIPDB check error: {e}")

        return {}

    def _check_ip_otx(self, ip: str) -> Dict[str, Any]:
        """AlienVault OTX check"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.otx_api_key}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0)
                }
        except Exception as e:
            logger.error(f"OTX check error: {e}")

        return {}

    def _check_url_virustotal(self, url: str) -> Dict[str, Any]:
        """VirusTotal URL check"""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.vt_api_key}

            response = requests.get(api_url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)
                }
        except Exception as e:
            logger.error(f"VT URL check error: {e}")

        return {}

    def _check_url_urlhaus(self, url: str) -> Dict[str, Any]:
        """URLhaus check (public API)"""
        try:
            data = {"url": url}
            response = requests.post(
                self.urlhaus_api_url,
                data=data,
                headers=self._abusech_headers(),
                timeout=10,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    return {
                        "threat": result.get("threat", "unknown"),
                        "tags": result.get("tags", []),
                        "urlhaus_reference": result.get("urlhaus_reference", "")
                    }
        except Exception as e:
            logger.error(f"URLhaus check error: {e}")

        return {}

    def _check_hash_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """VirusTotal hash check"""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0)
                }
        except Exception as e:
            logger.error(f"VT hash check error: {e}")

        return {}

    def _query_threatfox(self, ioc: str) -> List[Dict[str, Any]]:
        payload = {"query": "search_ioc", "search_ioc": ioc}
        try:
            response = requests.post(
                self.threatfox_api_url,
                json=payload,
                headers=self._abusech_headers(),
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("data", []) or []
        except Exception as exc:
            logger.error(f"ThreatFox query failed for {ioc}: {exc}")
        return []

    def _summarize_threatfox(self, matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not matches:
            return {}

        tags = set()
        malware = set()
        max_confidence = 0
        first_seen = None
        last_seen = None

        for entry in matches:
            tags.update(entry.get("tags", []))
            malware_name = entry.get("malware") or entry.get("malware_printable")
            if malware_name:
                malware.add(malware_name)
            confidence = entry.get("confidence_level", 0)
            max_confidence = max(max_confidence, confidence)
            entry_first_seen = entry.get("first_seen")
            entry_last_seen = entry.get("last_seen")
            if entry_first_seen and (first_seen is None or entry_first_seen < first_seen):
                first_seen = entry_first_seen
            if entry_last_seen and (last_seen is None or entry_last_seen > last_seen):
                last_seen = entry_last_seen

        return {
            "detections": len(matches),
            "max_confidence": max_confidence,
            "tags": sorted(tags),
            "malware_families": sorted(malware),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def _check_ip_greynoise(self, ip: str) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.greynoise_key:
            headers["key"] = self.greynoise_key
        try:
            response = requests.get(f"{self.greynoise_api_url}/{ip}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "classification": data.get("classification"),
                    "name": data.get("name"),
                    "last_seen": data.get("last_seen"),
                    "link": data.get("link"),
                }
        except Exception as exc:
            logger.error(f"GreyNoise query failed for {ip}: {exc}")
        return {}

    def _check_hash_malwarebazaar(self, file_hash: str) -> Dict[str, Any]:
        try:
            response = requests.post(
                self.malwarebazaar_api_url,
                data={"query": "get_info", "hash": file_hash},
                headers=self._abusech_headers(),
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    entry = data["data"][0]
                    return {
                        "malware_family": entry.get("malware_family"),
                        "signature": entry.get("signature"),
                        "first_seen": entry.get("first_seen") or entry.get("first_seen_utc"),
                        "tags": entry.get("tags", []),
                    }
        except Exception as exc:
            logger.error(f"MalwareBazaar query failed for {file_hash}: {exc}")
        return {}

    def _calculate_verdict(self, results: Dict[str, Any]) -> tuple:
        """Aggregate per-source intelligence into a single verdict."""
        score = 0

        vt = results.get("virustotal", {}) or {}
        if vt:
            vt_score = vt.get("malicious", 0) * 6 + vt.get("suspicious", 0) * 2
            score += min(vt_score, 40)

        abuse = results.get("abuseipdb", {}) or {}
        if abuse:
            score += min(abuse.get("abuse_confidence_score", 0), 30)

        otx = results.get("otx", {}) or {}
        if otx.get("pulse_count", 0):
            score += min(otx.get("pulse_count", 0) * 5, 20)

        urlhaus = results.get("urlhaus", {}) or {}
        if urlhaus.get("threat"):
            score += 35

        threatfox = results.get("threatfox", {}) or {}
        if threatfox:
            detections = threatfox.get("detections", 0)
            max_conf = threatfox.get("max_confidence", 0)
            score += min(detections * 10, 30)
            score += min(max_conf // 4, 20)

        greynoise = results.get("greynoise", {}) or {}
        classification = greynoise.get("classification")
        if classification == "malicious":
            score += 25
        elif classification == "unknown":
            score += 10

        malwarebazaar = results.get("malwarebazaar", {}) or {}
        if malwarebazaar:
            score += 30

        score = min(score, 100)

        high_confidence_threatfox = threatfox and threatfox.get("detections", 0) >= 2 and threatfox.get("max_confidence", 0) >= 80
        malware_linked = bool(malwarebazaar)

        if score >= 70 or malware_linked or high_confidence_threatfox:
            verdict = "malicious"
        elif score >= 35:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return verdict, score

_threat_intel = None

def get_threat_intel() -> ThreatIntelligence:
    """Получить singleton instance"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    ti = get_threat_intel()

    # Тест IP
    print("=== Checking IP ===")
    result = ti.check_ip("1.2.3.4")
    import json
    print(json.dumps(result, indent=2))
