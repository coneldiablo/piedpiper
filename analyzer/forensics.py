#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/forensics.py

Цифровая форензика и incident response.
Сбор артефактов, timeline reconstruction, persistence detection.
"""

import os
import sys
import logging
import json
import glob
import plistlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

try:  # winreg is only available on Windows
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - non-Windows platforms
    winreg = None  # type: ignore

logger = logging.getLogger("forensics")


class ForensicsAnalyzer:
    """Форензический анализатор"""

    def __init__(self):
        self.artifacts = {
            "prefetch": [],
            "recent_files": [],
            "startup_items": [],
            "scheduled_tasks": [],
            "services": [],
            "browser_history": [],
            "persistence_mechanisms": [],
            "system_logs": []
        }

    def collect_artifacts(self) -> Dict[str, Any]:
        """Сбор всех артефактов"""
        if sys.platform == "win32":
            self._collect_windows_artifacts()
        elif sys.platform == "linux":
            self._collect_linux_artifacts()
        elif sys.platform == "darwin":
            self._collect_macos_artifacts()

        return self.artifacts

    def _collect_windows_artifacts(self):
        """Сбор артефактов Windows"""
        # Prefetch
        try:
            prefetch_path = r"C:\Windows\Prefetch\*.pf"
            for pf_file in glob.glob(prefetch_path):
                self.artifacts["prefetch"].append({
                    "path": pf_file,
                    "name": os.path.basename(pf_file),
                    "modified": datetime.fromtimestamp(os.path.getmtime(pf_file)).isoformat()
                })
        except Exception as e:
            logger.warning(f"Prefetch collection error: {e}")

        # Recent files
        try:
            recent_path = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*")
            for recent_file in glob.glob(recent_path)[:50]:
                self.artifacts["recent_files"].append({
                    "path": recent_file,
                    "name": os.path.basename(recent_file),
                    "accessed": datetime.fromtimestamp(os.path.getatime(recent_file)).isoformat()
                })
        except Exception as e:
            logger.warning(f"Recent files error: {e}")

        # Startup items (Registry)
        self._scan_startup_registry()

        # Services
        self._enumerate_services()

        # Persistence mechanisms
        self._detect_persistence()

    def _scan_startup_registry(self):
        """Сканирование автозапуска в реестре"""
        if winreg is None:
            logger.debug("winreg not available; skipping registry startup scan")
            return

        startup_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hive, key_path in startup_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        self.artifacts["startup_items"].append({
                            "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                            "key": key_path,
                            "name": name,
                            "value": value
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception as e:
                logger.debug(f"Registry key read error: {e}")

    def _enumerate_services(self):
        """Перечисление служб Windows"""
        try:
            import subprocess
            result = subprocess.run(
                ["sc", "query", "state=", "all"],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Парсим вывод sc query
            services = result.stdout.split("\n\n")
            for service_block in services[:20]:  # Первые 20
                if "SERVICE_NAME:" in service_block:
                    lines = service_block.strip().split("\n")
                    service_info = {}
                    for line in lines:
                        if ":" in line:
                            key, value = line.split(":", 1)
                            service_info[key.strip()] = value.strip()
                    if service_info:
                        self.artifacts["services"].append(service_info)
        except Exception as e:
            logger.warning(f"Services enumeration error: {e}")

    def _detect_persistence(self):
        """Детектирование механизмов persistence"""
        # Проверяем известные пути persistence
        persistence_locations = [
            r"C:\Windows\System32\Tasks",  # Scheduled tasks
            os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\\Programs\\Startup"
        ]

        for location in persistence_locations:
            try:
                if os.path.exists(location):
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            full_path = os.path.join(root, file)
                            self.artifacts["persistence_mechanisms"].append({
                                "location": location,
                                "file": file,
                                "path": full_path,
                                "modified": datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
                            })
            except Exception as e:
                logger.debug(f"Persistence check error for {location}: {e}")

    def _collect_linux_artifacts(self):
        """Сбор артефактов Linux"""
        # Cron jobs
        try:
            cron_files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
            for cron_file in cron_files:
                if os.path.exists(cron_file):
                    self.artifacts["scheduled_tasks"].append({
                        "type": "cron",
                        "file": cron_file
                    })
        except:
            logger.debug(f"Skipping cron/systemd artifact")

        # Autostart desktop entries
        autostart_paths = [
            Path.home() / ".config" / "autostart",
            Path("/etc/xdg/autostart")
        ]
        for autostart in autostart_paths:
            try:
                if autostart.exists():
                    for desktop_file in autostart.glob("*.desktop"):
                        self.artifacts["persistence_mechanisms"].append({
                            "type": "autostart",
                            "path": str(desktop_file)
                        })
            except Exception as exc:
                logger.debug(f"Autostart scan error for {autostart}: {exc}")

        # Systemd services
        try:
            systemd_paths = ["/etc/systemd/system/", "/lib/systemd/system/"]
            for path in systemd_paths:
                if os.path.exists(path):
                    for service_file in glob.glob(os.path.join(path, "*.service"))[:20]:
                        self.artifacts["services"].append({
                            "type": "systemd",
                            "file": service_file
                        })
        except:
            logger.debug(f"Skipping cron/systemd artifact")

    def _collect_macos_artifacts(self):
        """Сбор артефактов macOS"""
        launch_paths = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        for launch_path in launch_paths:
            try:
                if launch_path.exists():
                    for plist_file in launch_path.glob("*.plist"):
                        self.artifacts["persistence_mechanisms"].append({
                            "type": "launchd",
                            "path": str(plist_file)
                        })
            except Exception as exc:
                logger.debug(f"launchd scan error for {launch_path}: {exc}")

        # Login items plist
        try:
            login_items_path = Path.home() / "Library" / "Preferences" / "com.apple.loginitems.plist"
            if login_items_path.exists():
                with login_items_path.open("rb") as handle:
                    plist_data = plistlib.load(handle)
                items = plist_data.get("SessionItems", {}).get("CustomListItems", [])
                for item in items:
                    name = item.get("Name") or item.get("Name0")
                    path_hint = item.get("Path") or item.get("Alias") or ""
                    self.artifacts["persistence_mechanisms"].append({
                        "type": "login_item",
                        "name": name,
                        "path": path_hint,
                    })
        except Exception as exc:
            logger.debug(f"Login items parsing error: {exc}")

        # Recent items plist
        try:
            recent_plist = Path.home() / "Library" / "Preferences" / "com.apple.recentitems.plist"
            if recent_plist.exists():
                with recent_plist.open("rb") as handle:
                    plist_data = plistlib.load(handle)
                for category, data in plist_data.items():
                    entries = data.get("CustomListItems", []) if isinstance(data, dict) else []
                    for entry in entries:
                        name = entry.get("Name") or entry.get("Name0")
                        recent_item = entry.get("RecentItem")
                        resource = ""
                        if isinstance(recent_item, dict):
                            resource = recent_item.get("URL", "")
                        self.artifacts["recent_files"].append({
                            "category": category,
                            "name": name,
                            "resource": resource,
                        })
        except Exception as exc:
            logger.debug(f"Recent items parsing error: {exc}")

        # System log reference
        try:
            system_log = Path("/var/log/system.log")
            if system_log.exists():
                self.artifacts["system_logs"].append({
                    "path": str(system_log),
                    "modified": datetime.fromtimestamp(system_log.stat().st_mtime).isoformat(),
                })
        except Exception as exc:
            logger.debug(f"macOS system log check error: {exc}")

    def reconstruct_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Реконструкция timeline атаки"""
        timeline = sorted(events, key=lambda x: x.get("timestamp", ""))
        return timeline

    def detect_lateral_movement(self, network_data: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Детектирование lateral movement"""
        lateral_indicators = []

        # Поиск подозрительных сетевых соединений
        suspicious_ports = [445, 139, 3389, 5985, 5986]  # SMB, RDP, WinRM

        for conn in network_data:
            remote_port = conn.get("remote_port", 0)
            if remote_port in suspicious_ports:
                lateral_indicators.append({
                    "type": "Suspicious network connection",
                    "port": remote_port,
                    "remote_ip": conn.get("remote_ip", ""),
                    "protocol": conn.get("protocol", "")
                })

        return lateral_indicators


def collect_forensic_artifacts() -> Dict[str, Any]:
    """Быстрая функция для сбора артефактов"""
    analyzer = ForensicsAnalyzer()
    return analyzer.collect_artifacts()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=== Forensic Artifacts Collection ===")
    artifacts = collect_forensic_artifacts()

    print(f"\nPrefetch files: {len(artifacts['prefetch'])}")
    print(f"Startup items: {len(artifacts['startup_items'])}")
    print(f"Services: {len(artifacts['services'])}")
    print(f"Persistence mechanisms: {len(artifacts['persistence_mechanisms'])}")

    print("\n=== Startup Items ===")
    for item in artifacts["startup_items"][:5]:
        print(f"  {item['name']}: {item['value']}")
