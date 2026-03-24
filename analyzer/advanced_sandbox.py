#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/advanced_sandbox.py

Продвинутый sandbox для динамического анализа.
Расширенные возможности:
- Memory dumping (дампы памяти процессов)
- API call hooking (перехват системных вызовов)
- Снимки системы до/после запуска
- Мониторинг изменений файловой системы
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("advanced_sandbox")


class AdvancedSandbox:
    """Продвинутый sandbox для анализа малвари"""

    DEFAULT_HOOK_APIS = [
        "CreateFileW", "WriteFile", "ReadFile", "DeleteFile",
        "CreateProcessW", "CreateRemoteThread",
        "VirtualAllocEx", "WriteProcessMemory",
        "RegCreateKeyW", "RegSetValueW", "RegDeleteKeyW",
        "InternetOpenW", "InternetConnectW", "HttpSendRequestW",
        "socket", "connect", "send", "recv"
    ]

    def __init__(self, target_file: str):
        self.target_file = target_file
        self.pid = None
        self.process = None
        self.memory_dumps_dir = None
        self.system_snapshot_before = {}
        self.system_snapshot_after = {}
        self.hooked_apis = list(self.DEFAULT_HOOK_APIS)
        self._use_frida = False
        self._custom_frida_script_path: Optional[str] = None
        self._frida_session = None
        self._frida_device = None
        self._frida_script = None
        self._frida_messages: List[Dict[str, Any]] = []

    def take_system_snapshot(self) -> Dict[str, Any]:
        """
        Создать снимок системы (процессы, файлы, сеть)

        Returns:
            Словарь с данными снимка
        """
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "processes": [],
            "network_connections": [],
            "open_files": [],
            "registry_keys": []  # только для Windows
        }

        try:
            # Снимок процессов
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    snapshot["processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                        "create_time": proc.info['create_time']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue  # Process terminated or access denied

            # Снимок сетевых соединений
            for conn in psutil.net_connections(kind='inet'):
                snapshot["network_connections"].append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })

            # Снимок открытых файлов (по всем процессам)
            for proc in psutil.process_iter(['pid', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for f in proc.info['open_files']:
                            snapshot["open_files"].append({
                                "pid": proc.info['pid'],
                                "path": f.path,
                                "fd": f.fd
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue  # Process terminated or access denied

            logger.info(f"Снимок системы создан: {len(snapshot['processes'])} процессов")

        except Exception as e:
            logger.error(f"Ошибка создания снимка: {e}")

        return snapshot

    def compare_snapshots(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        """
        Сравнить снимки до и после

        Returns:
            Словарь с изменениями
        """
        changes = {
            "new_processes": [],
            "terminated_processes": [],
            "new_connections": [],
            "new_files": []
        }

        # Сравниваем процессы
        pids_before = {p['pid'] for p in before['processes']}
        pids_after = {p['pid'] for p in after['processes']}

        new_pids = pids_after - pids_before
        terminated_pids = pids_before - pids_after

        changes["new_processes"] = [p for p in after['processes'] if p['pid'] in new_pids]
        changes["terminated_processes"] = list(terminated_pids)

        # Сравниваем сетевые соединения
        conns_before = {f"{c.get('laddr', '')}:{c.get('raddr', '')}" for c in before['network_connections']}
        conns_after = {f"{c.get('laddr', '')}:{c.get('raddr', '')}" for c in after['network_connections']}

        new_conns = conns_after - conns_before
        changes["new_connections"] = [c for c in after['network_connections']
                                      if f"{c.get('laddr', '')}:{c.get('raddr', '')}" in new_conns]

        # Сравниваем файлы
        files_before = {f['path'] for f in before['open_files']}
        files_after = {f['path'] for f in after['open_files']}

        new_files = files_after - files_before
        changes["new_files"] = [f for f in after['open_files'] if f['path'] in new_files]

        logger.info(f"Изменения: {len(changes['new_processes'])} новых процессов, "
                   f"{len(changes['new_connections'])} новых соединений")

        return changes

    def dump_process_memory(self, pid: int, output_dir: str = None) -> List[str]:
        """
        Дамп памяти процесса

        Args:
            pid: ID процесса
            output_dir: Директория для сохранения дампов

        Returns:
            Список путей к файлам дампов
        """
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix=f"memory_dumps_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        self.memory_dumps_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        dump_files = []

        try:
            proc = psutil.Process(pid)

            # Для Windows используем procdump (если доступен)
            if sys.platform == "win32":
                dump_file = os.path.join(output_dir, f"memory_dump_{pid}.dmp")
                try:
                    # Попытка использовать procdump
                    subprocess.run(
                        ["procdump", "-ma", str(pid), dump_file],
                        check=True,
                        capture_output=True,
                        timeout=30
                    )
                    dump_files.append(dump_file)
                    logger.info(f"Memory dump создан (procdump): {dump_file}")
                except (FileNotFoundError, subprocess.CalledProcessError) as e:
                    logger.warning(f"procdump недоступен, используем альтернативный метод: {e}")
                    # Альтернативный метод для Windows
                    dump_file = self._dump_memory_windows_alternative(pid, output_dir)
                    if dump_file:
                        dump_files.append(dump_file)

            # Для Linux используем gcore
            elif sys.platform == "linux":
                dump_file = os.path.join(output_dir, f"core.{pid}")
                try:
                    subprocess.run(
                        ["gcore", "-o", os.path.join(output_dir, "core"), str(pid)],
                        check=True,
                        capture_output=True,
                        timeout=30
                    )
                    dump_files.append(dump_file)
                    logger.info(f"Memory dump создан (gcore): {dump_file}")
                except (FileNotFoundError, subprocess.CalledProcessError) as e:
                    logger.error(f"Ошибка gcore: {e}")

            # Memory regions dump (кроссплатформенный метод через psutil)
            regions_dump = self._dump_memory_regions(proc, output_dir)
            dump_files.extend(regions_dump)

        except psutil.NoSuchProcess:
            logger.error(f"Процесс {pid} не найден")
        except psutil.AccessDenied:
            logger.error(f"Доступ запрещён к процессу {pid}")
        except Exception as e:
            logger.error(f"Ошибка дампа памяти: {e}")

        return dump_files

    def _dump_memory_windows_alternative(self, pid: int, output_dir: str) -> Optional[str]:
        """Альтернативный метод дампа памяти для Windows через psutil"""
        try:
            proc = psutil.Process(pid)
            dump_file = os.path.join(output_dir, f"memory_info_{pid}.json")

            memory_info = {
                "pid": pid,
                "name": proc.name(),
                "memory_info": proc.memory_info()._asdict(),
                "memory_percent": proc.memory_percent(),
                "memory_maps": []
            }

            # Получаем карту памяти
            try:
                for mmap in proc.memory_maps(grouped=False):
                    memory_info["memory_maps"].append({
                        "path": mmap.path,
                        "rss": mmap.rss,
                        "size": mmap.size if hasattr(mmap, 'size') else 0,
                        "pss": mmap.pss if hasattr(mmap, 'pss') else 0
                    })
            except (psutil.AccessDenied, AttributeError) as exc:
                logger.debug("Skipping detailed memory map for PID %s: %s", pid, exc)

            with open(dump_file, 'w', encoding='utf-8') as f:
                json.dump(memory_info, f, indent=2)

            logger.info(f"Memory info сохранён: {dump_file}")
            return dump_file

        except Exception as e:
            logger.error(f"Ошибка альтернативного дампа: {e}")
            return None

    def _dump_memory_regions(self, proc: psutil.Process, output_dir: str) -> List[str]:
        """Дамп отдельных регионов памяти"""
        dump_files = []

        try:
            regions_file = os.path.join(output_dir, f"memory_regions_{proc.pid}.json")
            regions_data = {
                "pid": proc.pid,
                "name": proc.name(),
                "regions": []
            }

            # Получаем информацию о регионах памяти
            for mmap in proc.memory_maps(grouped=False):
                regions_data["regions"].append({
                    "path": mmap.path,
                    "rss": mmap.rss,
                    "size": mmap.size if hasattr(mmap, 'size') else 0,
                    "pss": mmap.pss if hasattr(mmap, 'pss') else 0,
                    "shared_clean": mmap.shared_clean if hasattr(mmap, 'shared_clean') else 0,
                    "shared_dirty": mmap.shared_dirty if hasattr(mmap, 'shared_dirty') else 0
                })

            with open(regions_file, 'w', encoding='utf-8') as f:
                json.dump(regions_data, f, indent=2)

            dump_files.append(regions_file)
            logger.info(f"Memory regions дамп: {regions_file}")

        except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
            logger.warning(f"Не удалось получить memory regions: {e}")
        except Exception as e:
            logger.error(f"Ошибка дампа regions: {e}")

        return dump_files

    def setup_api_hooking(
        self,
        apis_to_hook: Optional[List[str]] = None,
        *,
        enable_frida: bool = False,
        frida_script_path: Optional[str] = None
    ) -> bool:
        """Configure API interception rules and optional Frida instrumentation."""
        if apis_to_hook is None:
            apis_to_hook = list(self.DEFAULT_HOOK_APIS)
        else:
            apis_to_hook = list(apis_to_hook)

        self.hooked_apis = apis_to_hook
        self._use_frida = enable_frida
        self._custom_frida_script_path = frida_script_path

        logger.info(
            "API hooking prepared for %d functions (Frida %s)",
            len(self.hooked_apis),
            "enabled" if self._use_frida else "disabled"
        )
        return True

    def _launch_target_process(self, args: Optional[List[str]] = None) -> Dict[str, Any]:
        args = args or []
        if self._use_frida:
            return self._launch_with_frida(args)
        return self._launch_with_subprocess(args)

    def _launch_with_subprocess(self, args: List[str]) -> Dict[str, Any]:
        target_path = Path(self.target_file)
        if not target_path.is_file():
            raise FileNotFoundError(f"Target executable not found: {self.target_file}")

        creationflags = 0
        if sys.platform.startswith("win"):
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        try:
            self.process = subprocess.Popen(
                [self.target_file, *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to launch {self.target_file}: {exc}") from exc

        self.pid = self.process.pid
        logger.info("Started %s via subprocess (PID %s)", self.target_file, self.pid)
        return {"mode": "subprocess", "pid": self.pid}

    def _launch_with_frida(self, args: List[str]) -> Dict[str, Any]:
        try:
            import frida  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Frida integration requested, but the 'frida' module is not installed.") from exc

        script_source = self._load_frida_script()
        device = frida.get_local_device()
        spawn_args = [self.target_file, *args]
        try:
            pid = device.spawn(spawn_args)
            session = device.attach(pid)
        except Exception as exc:
            raise RuntimeError(f"Frida failed to attach to {spawn_args}: {exc}") from exc

        self._frida_messages.clear()
        script = session.create_script(script_source)
        script.on("message", self._handle_frida_message)
        script.load()

        device.resume(pid)

        self.pid = pid
        self._frida_session = session
        self._frida_device = device
        self._frida_script = script

        logger.info("Started %s under Frida supervision (PID %s)", self.target_file, pid)
        return {"mode": "frida", "pid": pid}

    def _handle_frida_message(self, message: Dict[str, Any], data: Any) -> None:
        entry: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": f"pid:{self.pid}" if self.pid else "frida",
        }

        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            payload = message["payload"]
            entry.update(payload)
            entry.setdefault("operation", payload.get("event", "api-call"))
            entry.setdefault("target", payload.get("api", "unknown"))
        else:
            entry.update({
                "operation": "frida-message",
                "target": "frida",
                "details": message
            })

        self._frida_messages.append(entry)
        api_name = entry.get("api")
        if api_name and api_name not in self.hooked_apis:
            self.hooked_apis.append(api_name)

    def _load_frida_script(self) -> str:
        if self._custom_frida_script_path:
            script_path = Path(self._custom_frida_script_path)
            if not script_path.is_file():
                raise FileNotFoundError(f"Frida script not found: {script_path}")
            return script_path.read_text(encoding="utf-8")
        return self._build_default_frida_script()

    def _build_default_frida_script(self) -> str:
        apis_json = json.dumps(self.hooked_apis)
        return f"""
var trackedApis = {apis_json};
trackedApis.forEach(function(apiName) {{
    try {{
        var address = Module.findExportByName(null, apiName);
        if (!address) {{
            send({{event: 'missing-api', api: apiName}});
            return;
        }}
        Interceptor.attach(address, {{
            onEnter: function(args) {{
                send({{
                    event: 'api-call',
                    api: apiName,
                    thread_id: this.threadId,
                    timestamp: Date.now()
                }});
            }}
        }});
        send({{event: 'hook-installed', api: apiName}});
    }} catch (err) {{
        send({{event: 'hook-error', api: apiName, error: err.toString()}});
    }}
}});
"""

    def _terminate_process(self, force: bool = False) -> None:
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if force:
                    self.process.kill()
                    self.process.wait(timeout=5)
            except Exception as exc:
                logger.warning("Failed to terminate monitored subprocess: %s", exc)
        self.process = None

        if self._frida_session:
            try:
                self._frida_session.detach()
            except Exception as exc:
                logger.debug("Error detaching Frida session: %s", exc)
            self._frida_session = None

        if self._frida_device and self.pid:
            try:
                self._frida_device.kill(self.pid)
            except Exception as exc:
                logger.debug("Error terminating Frida spawned process: %s", exc)
        self._frida_device = None
        self._frida_script = None
        self.pid = None

    def run_with_monitoring(self, timeout: int = 30) -> Dict[str, Any]:
        """Run target under observation and return a sandbox report."""
        report = {
            "target_file": self.target_file,
            "start_time": datetime.now().isoformat(),
            "system_snapshot_before": {},
            "system_snapshot_after": {},
            "system_changes": {},
            "memory_dumps": [],
            "hooked_apis": self.hooked_apis,
            "process_tree": [],
            "timeline": []
        }

        self._frida_messages.clear()

        try:
            logger.info("Capturing pre-execution system snapshot...")
            report["system_snapshot_before"] = self.take_system_snapshot()

            logger.info("Launching target %s", self.target_file)
            launch_info = self._launch_target_process()
            report["timeline"].append({
                "timestamp": datetime.now().isoformat(),
                "event": "process_start",
                "details": {
                    "target": self.target_file,
                    "mode": launch_info.get("mode"),
                    "pid": launch_info.get("pid")
                }
            })

            start_monotonic = time.monotonic()
            deadline = start_monotonic + timeout
            process_reference = self.process
            exit_code = None

            while time.monotonic() < deadline:
                if process_reference and process_reference.poll() is not None:
                    exit_code = process_reference.poll()
                    break
                time.sleep(0.5)

            if process_reference:
                exit_code = process_reference.poll()

            if exit_code is None and time.monotonic() >= deadline:
                logger.warning("Timeout %.2fs reached, terminating monitored process", timeout)
                report["timeline"].append({
                    "timestamp": datetime.now().isoformat(),
                    "event": "timeout_reached",
                    "details": {"timeout_seconds": timeout}
                })
                self._terminate_process(force=True)
                if process_reference:
                    exit_code = process_reference.poll()
            else:
                self._terminate_process(force=False)
                if process_reference:
                    exit_code = process_reference.poll()

            report["timeline"].append({
                "timestamp": datetime.now().isoformat(),
                "event": "process_exit",
                "details": {
                    "pid": launch_info.get("pid"),
                    "exit_code": exit_code
                }
            })

            logger.info("Capturing post-execution system snapshot...")
            report["system_snapshot_after"] = self.take_system_snapshot()

            logger.info("Calculating environment changes...")
            report["system_changes"] = self.compare_snapshots(
                report["system_snapshot_before"],
                report["system_snapshot_after"]
            )

            if report["system_changes"].get("new_processes"):
                for proc in report["system_changes"]["new_processes"][:3]:
                    try:
                        dumps = self.dump_process_memory(proc['pid'])
                        report["memory_dumps"].extend(dumps)
                    except Exception as exc:
                        logger.warning("Failed to dump memory for PID %s: %s", proc['pid'], exc)

            if self._frida_messages:
                report["timeline"].extend(self._frida_messages)

            report["end_time"] = datetime.now().isoformat()
            report["status"] = "completed"

        except Exception as exc:
            logger.error("Sandbox execution error: %s", exc)
            report["status"] = "error"
            report["error"] = str(exc)
            self._terminate_process(force=True)

        return report

    def analyze_memory_dump(self, dump_file: str) -> Dict[str, Any]:
        """
        Анализ дампа памяти на предмет подозрительных паттернов

        Returns:
            Результаты анализа
        """
        analysis = {
            "file": dump_file,
            "size": 0,
            "strings": [],
            "suspicious_patterns": [],
            "entropy": 0.0
        }

        try:
            if not os.path.exists(dump_file):
                logger.warning(f"Файл дампа не найден: {dump_file}")
                return analysis

            analysis["size"] = os.path.getsize(dump_file)

            # Извлекаем строки (упрощённо)
            if dump_file.endswith('.json'):
                with open(dump_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    analysis["memory_info"] = data
            else:
                # Для бинарных дампов - извлекаем строки
                with open(dump_file, 'rb') as f:
                    content = f.read(1024 * 1024)  # Читаем первый MB
                    # Поиск ASCII строк
                    import re
                    strings = re.findall(b'[ -~]{4,}', content)
                    analysis["strings"] = [s.decode('ascii', errors='ignore') for s in strings[:100]]

                    # Подозрительные паттерны
                    suspicious = [
                        b'http://', b'https://', b'cmd.exe', b'powershell',
                        b'CreateRemoteThread', b'VirtualAlloc', b'LoadLibrary'
                    ]
                    for pattern in suspicious:
                        if pattern in content:
                            analysis["suspicious_patterns"].append(pattern.decode('ascii'))

        except Exception as e:
            logger.error(f"Ошибка анализа дампа: {e}")

        return analysis


def run_advanced_analysis(target_file: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Быстрая функция для запуска продвинутого анализа

    Args:
        target_file: Путь к файлу
        timeout: Таймаут

    Returns:
        Полный отчёт
    """
    sandbox = AdvancedSandbox(target_file)
    sandbox.setup_api_hooking()
    return sandbox.run_with_monitoring(timeout=timeout)


if __name__ == "__main__":
    # Тестирование
    logging.basicConfig(level=logging.INFO)

    print("=== Тест Advanced Sandbox ===")

    # Создаём тестовый файл
    test_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    test_file.write(b"MZ fake exe content")
    test_file.close()

    try:
        sandbox = AdvancedSandbox(test_file.name)

        print("\n=== Снимок системы ===")
        snapshot = sandbox.take_system_snapshot()
        print(f"Процессов: {len(snapshot['processes'])}")
        print(f"Соединений: {len(snapshot['network_connections'])}")

        print("\n=== Полный анализ ===")
        report = sandbox.run_with_monitoring(timeout=5)
        print(json.dumps({
            "status": report["status"],
            "new_processes": len(report["system_changes"].get("new_processes", [])),
            "new_connections": len(report["system_changes"].get("new_connections", [])),
            "memory_dumps": len(report["memory_dumps"])
        }, indent=2))

    finally:
        os.unlink(test_file.name)
