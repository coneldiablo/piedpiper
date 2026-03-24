#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/behavioral_analysis.py

Модуль для обнаружения подозрительных поведенческих паттернов
на основе последовательности вызовов API, полученных из динамического анализа.
"""

import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger("behavioral_analysis")
logger.setLevel(logging.DEBUG)

class BehavioralAnalyzer:
    """
    Анализирует список вызовов API для выявления известных подозрительных
    поведенческих паттернов.
    """

    def __init__(self, thresholds: Optional[Dict[str, int]] = None, enabled_patterns: Optional[List[str]] = None):
        """Configure detection thresholds and optional pattern allow-list."""
        default_thresholds = {
            'code_injection': 1,
            'run_key_persistence': 1,
            'simple_downloader': 1,
            'encoded_powershell': 1,
            'ransomware_behavior': 1,
        }
        if thresholds:
            default_thresholds.update(thresholds)
        self.thresholds = default_thresholds
        self.enabled_patterns = set(enabled_patterns) if enabled_patterns else None

    def analyze_calls(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Анализирует предоставленный список вызовов API.

        :param api_calls: Список словарей, каждый из которых представляет вызов API
                          (как возвращается из dynamic_analysis). Ожидается, что
                          каждый словарь содержит как минимум ключи 'api', 'pid', 'args'.
        :return: Список словарей, описывающих обнаруженные подозрительные паттерны.
                 Пример: [{'pattern': 'Code Injection', 'details': '...', 'involved_calls': [...]}]
        """
        detected_patterns = []
        if not api_calls:
            return detected_patterns

        logger.info(f"Starting behavioral analysis on {len(api_calls)} API calls.")

        # Здесь будем вызывать приватные методы для поиска конкретных паттернов
        detected_patterns.extend(self._detect_code_injection(api_calls))
        detected_patterns.extend(self._detect_run_key_persistence(api_calls))
        detected_patterns.extend(self._detect_simple_downloader(api_calls))
        detected_patterns.extend(self._detect_encoded_powershell(api_calls))
        detected_patterns.extend(self._detect_ransomware_behavior(api_calls))
        # Добавить вызовы других детекторов...

        if detected_patterns:
            logger.info(f"Detected {len(detected_patterns)} suspicious behavioral patterns.")
        else:
            logger.info("No specific suspicious behavioral patterns detected.")
            
        return detected_patterns

    # ---------------- Приватные методы для обнаружения паттернов ----------------

    def _detect_code_injection(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обнаруживает паттерн: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
        """
        patterns = []
        # Простой поиск последовательности, может быть неэффективным на больших логах
        # Нужен более умный подход, учитывающий хендлы и PID
        # Улучшенная логика сопоставления hProcess и PID:
        # Отслеживаем хендлы через словарь handle_to_pid для точного матчинга
        
        open_proc_calls = {} # pid -> list of OpenProcess calls
        alloc_calls = {} # pid -> list of VirtualAllocEx calls
        write_calls = {} # pid -> list of WriteProcessMemory calls
        
        for i, call in enumerate(api_calls):
            pid = call.get("pid")
            api = call.get("api")
            args = call.get("args", {})

            if api == "OpenProcess":
                 # Запоминаем успешные вызовы OpenProcess
                 if args.get("success"):
                    target_pid = args.get("dwProcessId")
                    handle = args.get("handle")
                    if target_pid and handle:
                         if pid not in open_proc_calls: open_proc_calls[pid] = []
                         open_proc_calls[pid].append({'index': i, 'call': call, 'target_pid': target_pid, 'handle': handle})

            elif api == "VirtualAllocEx":
                 if args.get("success"):
                     hProcess = args.get("hProcess")
                     if hProcess:
                         if pid not in alloc_calls: alloc_calls[pid] = []
                         alloc_calls[pid].append({'index': i, 'call': call, 'hProcess': hProcess})
                         
            elif api == "WriteProcessMemory":
                 if args.get("success"):
                     hProcess = args.get("hProcess")
                     if hProcess:
                          if pid not in write_calls: write_calls[pid] = []
                          write_calls[pid].append({'index': i, 'call': call, 'hProcess': hProcess})

            elif api == "CreateRemoteThread":
                 if args.get("success"):
                    hProcess = args.get("hProcess")
                    # Проверяем, были ли предыдущие шаги для этого hProcess от этого PID
                    # Эта логика очень упрощена!
                    if pid in write_calls:
                         for wc in write_calls[pid]:
                             if wc['hProcess'] == hProcess:
                                 # Нашли Write к этому процессу, ищем Alloc
                                 if pid in alloc_calls:
                                     for ac in alloc_calls[pid]:
                                         if ac['hProcess'] == hProcess and ac['index'] < wc['index']:
                                             # Нашли Alloc, ищем Open (или текущий процесс)
                                             opened = False
                                             if pid in open_proc_calls:
                                                  for oc in open_proc_calls[pid]:
                                                       # Сопоставление hProcess с handle из OpenProcess:
                                                       # Проверяем что handle совпадает или указывает на тот же PID
                                                       # Сейчас просто проверяем, что открывали этот PID раньше
                                                       if oc['handle'] == hProcess and oc['index'] < ac['index']:
                                                            opened = True
                                                            break
                                             # Если не нашли OpenProcess, возможно инъекция в себя? (hProcess == self_handle)
                                             # Или hProcess был получен другим способом.

                                             # Если нашли все шаги (упрощенно)
                                             if opened or hProcess == "0xffffffffffffffff": # Приблизительно NtCurrentProcess
                                                  pattern_info = {
                                                      'pattern': 'Code Injection Sequence',
                                                      'details': f"Detected Open->Alloc->Write->CreateRemoteThread targeting process handle {hProcess} by PID {pid}.",
                                                      'involved_calls_indices': [oc['index'] if opened else -1, ac['index'], wc['index'], i],
                                                      'target_process_handle': hProcess
                                                  }
                                                  patterns.append(pattern_info)
                                                  # Можно добавить break, если достаточно одного совпадения на поток
                                                  break # Alloc loop
                                     if patterns and patterns[-1]['involved_calls_indices'][3] == i: break # Write loop
                         # if patterns and patterns[-1]['involved_calls_indices'][3] == i: break # Outer loops?

        return patterns

    def _detect_run_key_persistence(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обнаруживает паттерн: RegCreateKeyExW/RegOpenKeyExW (Run key) -> RegSetValueExW
        """
        patterns = []
        opened_run_keys = {} # pid -> {hKey_result -> subkey_path}
        run_key_marker = "currentversion\\run"

        for i, call in enumerate(api_calls):
            pid = call.get("pid")
            api = call.get("api")
            args = call.get("args", {})

            if api in ["RegCreateKeyExW", "RegOpenKeyExW"] and args.get("success"):
                sub_key = args.get("lpSubKey", "").lower()
                if run_key_marker in sub_key:
                    hKey_result = args.get("hKey_result")
                    if hKey_result:
                        if pid not in opened_run_keys: opened_run_keys[pid] = {}
                        opened_run_keys[pid][hKey_result] = sub_key
                        logger.debug(f"PID {pid} opened/created Run key: {sub_key} (handle: {hKey_result})")

            elif api == "RegSetValueExW" and args.get("success"):
                hKey = args.get("hKey")
                if pid in opened_run_keys and hKey in opened_run_keys[pid]:
                    value_name = args.get("lpValueName")
                    data_str = args.get("lpData_str")
                    pattern_info = {
                        'pattern': 'Persistence via Run Key',
                        'details': f"PID {pid} wrote value '{value_name}' = '{data_str}' to Run key '{opened_run_keys[pid][hKey]}' (handle {hKey}).",
                        'involved_call_index': i,
                        'key_path': opened_run_keys[pid][hKey],
                        'value_name': value_name,
                        'value_data': data_str
                    }
                    patterns.append(pattern_info)
                    # Можно удалить ключ из opened_run_keys, если не ожидаем повторной записи?

        return patterns

    def _detect_simple_downloader(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обнаруживает паттерн: Network Read (InternetReadFile/recv) -> File Write (WriteFile)
        """
        patterns = []
        network_reads = {} # pid -> list of {'index': i, 'call': call}
        file_writes = {}   # pid -> list of {'index': i, 'call': call}

        for i, call in enumerate(api_calls):
            pid = call.get("pid")
            api = call.get("api")
            args = call.get("args", {})

            # Шаг 1: Сетевое чтение
            if api in ["InternetReadFile", "recv"] and args.get("success") and args.get("bytesReceived", 0) > 0:
                 if pid not in network_reads: network_reads[pid] = []
                 network_reads[pid].append({'index': i, 'call': call})

            # Шаг 2: Запись в файл
            elif api == "WriteFile" and args.get("success") and args.get("nBytesToWrite", 0) > 0:
                if pid not in file_writes: file_writes[pid] = []
                file_writes[pid].append({'index': i, 'call': call})

        # Шаг 3: Сопоставление (упрощенное: любая запись после любого чтения в том же PID)
        for pid, writes in file_writes.items():
            if pid in network_reads:
                for write_info in writes:
                    for read_info in network_reads[pid]:
                        # Проверяем, что чтение было *до* записи
                        if read_info['index'] < write_info['index']:
                             # Простая эвристика: если между чтением и записью прошло мало времени/вызовов?
                             # Или если размеры совпадают? (сложно)
                             # Пока просто фиксируем факт
                            pattern_info = {
                                'pattern': 'Potential Downloader Activity',
                                'details': f"PID {pid} performed network read (e.g., {read_info['call']['api']} at index {read_info['index']}) followed by file write (WriteFile to handle {write_info['call']['args'].get('hFile')} at index {write_info['index']}).",
                                'read_call_index': read_info['index'],
                                'write_call_index': write_info['index'],
                                'pid': pid
                             }
                            # Чтобы не дублировать для одной записи файла, найденной после чтения
                            if pattern_info not in patterns:
                                 patterns.append(pattern_info)
                             # break # Достаточно одного чтения перед этой записью

        return patterns

    def _detect_encoded_powershell(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обнаруживает запуск PowerShell с закодированной командой (-enc).
        """
        patterns = []
        encoded_flag_re = re.compile(r"(?:^|\s)-(?:enc|encodedcommand)\b", re.IGNORECASE)
        base64_like_re = re.compile(r"(?:^|\s)-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
        for i, call in enumerate(api_calls):
            pid = call.get("pid")
            api = call.get("api")
            args = call.get("args", {})
            command_line = None

            if api == "CreateProcessW":
                command_line = args.get("commandLine", "")
            elif api == "ShellExecuteW":
                 # ShellExecute может запускать через 'cmd /c powershell ...' или напрямую
                 file = args.get("lpFile", "").lower()
                 params = args.get("lpParameters", "")
                 if "powershell.exe" in file:
                      command_line = file + " " + params
                 elif "cmd.exe" in file and "powershell" in params.lower():
                      command_line = params # Интересует команда для PowerShell

            if command_line and "powershell" in command_line.lower():
                 # Используем re для поиска '-enc' или '-encodedcommand' (регистронезависимо)
                 # и последующего Base64-подобного блока
                 if encoded_flag_re.search(command_line) and (
                     base64_like_re.search(command_line) or "..." in command_line
                 ):
                    pattern_info = {
                        'pattern': 'Encoded PowerShell Command Execution',
                        'details': f"PID {pid} executed PowerShell with encoded command via {api}. Command line: {command_line}",
                        'involved_call_index': i,
                        'command_line': command_line,
                        'pid': pid
                    }
                    patterns.append(pattern_info)
        return patterns

    def _detect_ransomware_behavior(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Детекция ransomware по паттернам:
        - Массовое открытие файлов (CreateFileW)
        - Чтение -> Шифрование/Запись -> Переименование/Удаление
        - Создание ransom note (.txt файлов с требованиями)
        - Удаление Shadow Copies (vssadmin delete shadows)
        """
        from collections import defaultdict

        patterns = []
        file_operations = defaultdict(list)
        shadow_copy_deletion = False
        ransom_note_created = False

        # Собираем все файловые операции по файлам
        for i, call in enumerate(api_calls):
            pid = call.get("pid")
            api = call.get("api")
            args = call.get("args", {})

            # Операции с файлами
            if api in ['CreateFileW', 'DeleteFileW', 'MoveFileW']:
                filename = args.get('lpFileName') or args.get('lpExistingFileName', '')
                if filename:
                    file_operations[filename].append({
                        'index': i,
                        'api': api,
                        'pid': pid,
                        'args': args
                    })
            elif api in ['ReadFile', 'WriteFile']:
                # Для ReadFile/WriteFile используем lpFileName если есть, иначе hFile
                filename = args.get('lpFileName') or args.get('hFile', '')
                if filename:
                    file_operations[filename].append({
                        'index': i,
                        'api': api,
                        'pid': pid,
                        'args': args
                    })

            # Поиск создания ransom note
            if api == 'CreateFileW' and args.get('success'):
                filename = args.get('lpFileName', '').lower()
                ransom_keywords = ['readme', 'decrypt', 'ransom', 'how_to_decrypt',
                                   'recover', 'encrypted', 'locked', 'restore']
                if any(keyword in filename for keyword in ransom_keywords) and filename.endswith('.txt'):
                    ransom_note_created = True
                    logger.warning(f"Potential ransom note detected: {filename}")

            # Поиск удаления Shadow Copies
            if api in ['CreateProcessW', 'ShellExecuteW']:
                cmdline = args.get('commandLine', '') or args.get('lpParameters', '')
                if cmdline:
                    # vssadmin delete shadows, wmic shadowcopy delete, bcdedit /set {default} recoveryenabled No
                    if any(cmd in cmdline.lower() for cmd in ['vssadmin delete shadows',
                                                                'wmic shadowcopy delete',
                                                                'bcdedit', 'wbadmin delete']):
                        shadow_copy_deletion = True
                        logger.warning(f"Shadow Copy deletion command detected: {cmdline}")

        # Анализ массовой обработки файлов
        encryption_candidates = []
        for filename, ops in file_operations.items():
            # Ищем паттерн: ReadFile -> WriteFile (может быть без CreateFile если файл уже открыт)
            op_sequence = [op['api'] for op in ops]

            # Ransomware обычно: читает, шифрует (пишет обратно)
            # Упрощенная проверка: если есть и Read, и Write
            if 'ReadFile' in op_sequence and 'WriteFile' in op_sequence:
                read_indices = [i for i, op in enumerate(ops) if op['api'] == 'ReadFile']
                write_indices = [i for i, op in enumerate(ops) if op['api'] == 'WriteFile']

                # Проверяем, что хотя бы один Read идет перед Write
                if read_indices and write_indices:
                    if any(r < w for r in read_indices for w in write_indices):
                        encryption_candidates.append(filename)

        # Если обнаружено массовое шифрование файлов
        if len(encryption_candidates) > 20:  # Порог: более 20 файлов
            severity = 'CRITICAL'
            confidence = 0.95

            # Увеличиваем confidence если есть дополнительные индикаторы
            if shadow_copy_deletion:
                confidence = 0.98
            if ransom_note_created:
                confidence = 0.99

            pattern_info = {
                'pattern': 'RANSOMWARE FILE ENCRYPTION',
                'severity': severity,
                'confidence': confidence,
                'details': f'Detected mass file encryption pattern: {len(encryption_candidates)} files '
                          f'processed with Read->Write sequence. Shadow Copy deletion: {shadow_copy_deletion}. '
                          f'Ransom note created: {ransom_note_created}.',
                'affected_files_count': len(encryption_candidates),
                'affected_files_sample': encryption_candidates[:10],  # Первые 10 файлов
                'shadow_copy_deleted': shadow_copy_deletion,
                'ransom_note_detected': ransom_note_created
            }
            patterns.append(pattern_info)
            logger.critical(f"[RANSOMWARE] Detected! {len(encryption_candidates)} files affected")

        # Если только удаление Shadow Copies без массового шифрования
        elif shadow_copy_deletion:
            patterns.append({
                'pattern': 'Shadow Copy Deletion',
                'severity': 'HIGH',
                'confidence': 0.85,
                'details': 'Detected Shadow Copy deletion command. Common ransomware preparation step.',
                'shadow_copy_deleted': True
            })

        # Если только ransom note без других индикаторов
        elif ransom_note_created:
            patterns.append({
                'pattern': 'Potential Ransom Note Creation',
                'severity': 'MEDIUM',
                'confidence': 0.70,
                'details': 'Detected creation of file with ransom-like name, but no mass encryption observed.',
                'ransom_note_detected': True
            })

        return patterns

# --- Точка входа модуля (для CLI или импорта) ---
def analyze_behavior(api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Функция-обертка для создания экземпляра BehavioralAnalyzer и запуска анализа.
    """
    analyzer = BehavioralAnalyzer()
    return analyzer.analyze_calls(api_calls)

# --------------------- Локальный тест ----------------------
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.DEBUG)

    # Примерные данные вызовов API
    test_calls = [
        {"api": "OpenProcess", "pid": 1000, "args": {"dwProcessId": 2000, "success": True, "handle": "0x124"}},
        {"api": "VirtualAllocEx", "pid": 1000, "args": {"hProcess": "0x124", "success": True, "allocatedBaseAddress": "0x500000", "allocatedRegionSize": 4096}},
        {"api": "WriteProcessMemory", "pid": 1000, "args": {"hProcess": "0x124", "success": True, "lpBaseAddress": "0x500000", "nSize": 100}},
        {"api": "CreateRemoteThread", "pid": 1000, "args": {"hProcess": "0x124", "success": True, "lpStartAddress": "0x500100"}},

        {"api": "RegOpenKeyExW", "pid": 1001, "args": {"lpSubKey": r"Software\Microsoft\Windows\CurrentVersion\Run", "success": True, "hKey_result": "0xabc"}},
        {"api": "RegSetValueExW", "pid": 1001, "args": {"hKey": "0xabc", "success": True, "lpValueName": "MyApp", "lpData_str": "C:\\path\\to\\evil.exe"}},

        {"api": "connect", "pid": 1002, "args": {"targetIP": "1.2.3.4", "targetPort": 80, "success": True}},
        {"api": "recv", "pid": 1002, "args": {"bytesReceived": 1024, "success": True}},
        {"api": "CreateFileW", "pid": 1002, "args": {"lpFileName": "C:\\temp\\downloaded.tmp", "success": True, "handle": "0xdef"}},
        {"api": "WriteFile", "pid": 1002, "args": {"hFile": "0xdef", "nBytesToWrite": 1024, "success": True}},

        {"api": "CreateProcessW", "pid": 1003, "args": {"commandLine": "powershell -ExecutionPolicy Bypass -enc SQBFAFgAKABO...", "success": True, "dwProcessId": 3000}},
    ]

    print("--- Analyzing test API calls ---")
    detected = analyze_behavior(test_calls)
    print(json.dumps(detected, indent=2))

    print("\n--- Analyzing empty list ---")
    detected_empty = analyze_behavior([])
    print(json.dumps(detected_empty, indent=2))

    print("\n--- Testing RANSOMWARE Detection ---")
    # Симулируем ransomware активность
    ransomware_calls = []

    # Удаление Shadow Copies
    ransomware_calls.append({
        "api": "CreateProcessW",
        "pid": 2000,
        "args": {
            "commandLine": "vssadmin delete shadows /all /quiet",
            "success": True
        }
    })

    # Массовое чтение и перезапись файлов (симуляция шифрования)
    for i in range(30):
        file_path = f"C:\\\\Users\\\\User\\\\Documents\\\\file_{i}.docx"
        handle_val = f"0x{100+i:x}"
        # CreateFile
        ransomware_calls.append({
            "api": "CreateFileW",
            "pid": 2000,
            "args": {"lpFileName": file_path, "success": True, "handle": handle_val}
        })
        # ReadFile - использует lpFileName для связи с файлом
        ransomware_calls.append({
            "api": "ReadFile",
            "pid": 2000,
            "args": {"hFile": handle_val, "lpFileName": file_path, "nBytesToRead": 4096, "success": True}
        })
        # WriteFile (зашифрованные данные) - также нужен lpFileName
        ransomware_calls.append({
            "api": "WriteFile",
            "pid": 2000,
            "args": {"hFile": handle_val, "lpFileName": file_path, "nBytesToWrite": 4096, "success": True}
        })

    # Создание ransom note
    ransomware_calls.append({
        "api": "CreateFileW",
        "pid": 2000,
        "args": {
            "lpFileName": "C:\\Users\\User\\Desktop\\HOW_TO_DECRYPT.txt",
            "success": True,
            "handle": "0xaaa"
        }
    })

    detected_ransomware = analyze_behavior(ransomware_calls)
    print(json.dumps(detected_ransomware, indent=2, ensure_ascii=False))
