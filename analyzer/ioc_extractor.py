#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/ioc_extractor.py

Модуль для извлечения IoC (Indicators of Compromise) с использованием
объектно-ориентированного подхода для лучшей структурированности.

    Улучшения v4 (Рефакторинг):
- Введен класс IocExtractor для инкапсуляции логики.
- Regex и константы перенесены в класс.
- Основной метод разбит на _process_static_data и _process_dynamic_data.
- Вспомогательные функции стали методами класса.
- Сохранена вся функциональность предыдущей версии (типы IoC, source, фильтрация).
"""

import re
import logging
import ipaddress
from typing import List, Dict, Any, Set, Tuple, Optional
import argparse
import os
import binascii # Для декодирования hex из дампов/буферов

logger = logging.getLogger("ioc_extractor")
logger.setLevel(logging.DEBUG)

# Помощник для сбора строк (оставим вне класса, т.к. он stateless)
def collect_strings_from_structure(data: Any) -> List[str]:
    """
    Рекурсивно обходим (dict,list,str...) и возвращаем все подстроки.
    """
    results = []
    if isinstance(data, str):
        if len(data.strip()) >= 3:
            results.append(data.strip())
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and len(k.strip()) >= 3:
                results.append(k.strip())
            results.extend(collect_strings_from_structure(v))
    elif isinstance(data, list):
        for item in data:
            results.extend(collect_strings_from_structure(item))
    return results

class IocExtractor:
    """
    Класс для извлечения IoC из статических и динамических данных анализа.
    Предоставляет настройки фильтрации.
    """

    # --------------------- Регулярные выражения ----------------------
    IP_REGEX = re.compile(
        r"\b((?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])\.)"
        r"{3}"
        r"(?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])" # 1-255
        r"\b"
    )
    DOMAIN_REGEX = re.compile(
        r"\b(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"([a-zA-Z]{2,15})"
        r"\b"
    )
    URL_REGEX = re.compile(
        r"""\b
           (?:(?:https?|ftp|sftp|file)://)
           (?:[\w\-._~:/?#[\]@!$&\'\(\)\*\+,;=]|%[0-9a-fA-F]{2})+
        """,
        re.IGNORECASE | re.VERBOSE
    )
    EMAIL_REGEX = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        re.IGNORECASE
    )
    REGISTRY_REGEX = re.compile(
        r"\b(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\\\[\\w\\\\\\-\\{\\}\\(\\)]+)\b",
        re.IGNORECASE
    )
    FILEPATH_REGEX = re.compile(
        r"""
        (?:
            [a-zA-Z]:\\
            (?:(?:[^\\/:*?"<>|\r\n]+\\)*)
            [^\\/:*?"<>|\r\n]*
        |
            (?:/|\./|\.\./)
            (?:(?:[^/\\:\s]+)/)*
            [^/\\:\s]*
        )
        """,
        re.VERBOSE
    )
    MD5_REGEX = re.compile(r"\b([a-fA-F0-9]{32})\b")
    SHA1_REGEX = re.compile(r"\b([a-fA-F0-9]{40})\b")
    SHA256_REGEX = re.compile(r"\b([a-fA-F0-9]{64})\b")
    CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
    MUTEX_REGEX = re.compile(
        r"\b(?:Global|Local)\\\\[\\{\\(]?[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}[\\}\\)]?\b",
        re.IGNORECASE
    )
    BITCOIN_REGEX = re.compile(
        r"\b(?:bc1[ac-hj-np-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
    )

    # --------------------- Константы и Паттерны ----------------------
    SUSPICIOUS_CMD_PATTERNS = [
        re.compile(r"powershell.+-(?:enc|encoded)", re.IGNORECASE),
        re.compile(r"rundll32", re.IGNORECASE),
        re.compile(r"mshta\.exe", re.IGNORECASE),
        re.compile(r"certutil", re.IGNORECASE),
        re.compile(r"bitsadmin", re.IGNORECASE),
        re.compile(r"schtasks", re.IGNORECASE),
        re.compile(r"wmic", re.IGNORECASE),
    ]
    COMMON_SYSTEM_PATHS_PREFIXES = {
        "c:\\windows", "c:\\program files", "c:\\program files (x86)",
        "c:\\programdata", "c:\\users\\public",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib",
        "/etc", "/var/log", "/dev", "/proc", "/sys",
    }
    # Максимальный размер данных для декодирования из hex (чтобы избежать перегрузки)
    MAX_HEX_DECODE_SIZE = 1024 

    def __init__(self, filter_private_ips: bool = True, filter_common_paths: bool = True):
        self.filter_private_ips = filter_private_ips
        self.filter_common_paths = filter_common_paths
        self.found_iocs: List[Dict[str, str]] = []
        self.unique_set: Set[Tuple[str, str, str]] = set()

    def _is_private_ip(self, ip_str: str) -> bool:
        """ Проверяет, является ли IP-адрес частным или localhost. """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified
        except ValueError:
            return False

    def _is_common_system_path(self, path_str: str) -> bool:
        """ Проверяет, начинается ли путь с одного из общих системных префиксов. """
        if not path_str:
            return False
        path_lower = path_str.lower().replace("/", "\\")
        for prefix in self.COMMON_SYSTEM_PATHS_PREFIXES:
            if path_lower.startswith(prefix):
                return True
        return False

    def _add_ioc(self, ioc_type: str, value: str, source: str):
        """ Добавляет IoC с проверкой уникальности и фильтрацией. """
        if not value or not isinstance(value, str) or len(value) < 3:
            return
        value = value.strip()

        if ioc_type == "ip" and self.filter_private_ips and self._is_private_ip(value):
            return
        if ioc_type == "filepath" and self.filter_common_paths and self._is_common_system_path(value):
            return

        key = (ioc_type, value, source)
        if key not in self.unique_set:
            self.found_iocs.append({"type": ioc_type, "value": value, "source": source})
            self.unique_set.add(key)

    def _find_iocs_in_strings(self, strings: List[str], source_tag: str):
        """ Применяет набор regex к списку строк и добавляет найденные IoC. """
        if not strings:
            return

        for s in strings:
            if not isinstance(s, str) or len(s) < 3:
                continue
            s = s.strip() # Убираем пробелы по краям
            if not s: continue

            # IP
            for match in self.IP_REGEX.finditer(s):
                ip = match.group(0)
                # Доп. проверка, чтобы не захватывать версии типа 1.2.3.4.5
                if self._is_valid_ip_format(ip): 
                    self._add_ioc("ip", ip, source_tag)
            # URL
            for match in self.URL_REGEX.finditer(s):
                self._add_ioc("url", match.group(0), source_tag)
            # Email
            for match in self.EMAIL_REGEX.finditer(s):
                self._add_ioc("email", match.group(0), source_tag)
            # Domain (добавляем, только если это не IP адрес)
            for match in self.DOMAIN_REGEX.finditer(s):
                domain = match.group(0)
                # Проверяем, не является ли найденный домен просто IP-адресом
                if not self.IP_REGEX.fullmatch(domain): 
                    self._add_ioc("domain", domain, source_tag)
            # Registry
            for match in self.REGISTRY_REGEX.finditer(s):
                self._add_ioc("registry", match.group(0), source_tag)
            # Filepath
            for match in self.FILEPATH_REGEX.finditer(s):
                fp = match.group(0)
                # Игнорируем очень короткие или относительные пути без имени файла
                if len(fp) > 2 and fp not in (".", "..", "./", "../"): 
                    self._add_ioc("filepath", fp, source_tag)
            # Hashes
            for match in self.MD5_REGEX.finditer(s): self._add_ioc("hash_md5", match.group(1).lower(), source_tag)
            for match in self.SHA1_REGEX.finditer(s): self._add_ioc("hash_sha1", match.group(1).lower(), source_tag)
            for match in self.SHA256_REGEX.finditer(s): self._add_ioc("hash_sha256", match.group(1).lower(), source_tag)
            # CVE
            for match in self.CVE_REGEX.finditer(s): self._add_ioc("cve", match.group(1).upper(), source_tag)
            # Mutex
            for match in self.MUTEX_REGEX.finditer(s): self._add_ioc("mutex", match.group(0), source_tag)
            # Bitcoin wallet addresses
            for match in self.BITCOIN_REGEX.finditer(s):
                self._add_ioc("btc_address", match.group(0), source_tag)

    def _is_valid_ip_format(self, candidate: str) -> bool:
        """ Проверяет только формат IPv4 (4 октета 0-255). """
        parts = candidate.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _process_static_data(self, static_data: Optional[Dict[str, Any]]):
        """ Обрабатывает данные статического анализа. """
        if not static_data or not isinstance(static_data, dict):
            return

        # Собираем строки из основной структуры анализа
        analysis = static_data.get("analysis", {})
        all_static_strings = collect_strings_from_structure(analysis)

        # Обрабатываем строки из enhanced_checks
        enhanced = analysis.get("enhanced_checks", {})
        if isinstance(enhanced, dict):
            # Из strings_ioc
            string_iocs = enhanced.get("strings_ioc", {})
            if isinstance(string_iocs, dict):
                for ip in string_iocs.get("ips", []): self._add_ioc("ip", ip, "static:enhanced:strings_ioc:ips")
                for url in string_iocs.get("urls", []): self._add_ioc("url", url, "static:enhanced:strings_ioc:urls")
                all_static_strings.extend(string_iocs.get("keywords", [])) # Добавляем ключевые слова для общего сканирования

            # Из decoded_strings
            decoded_strings = enhanced.get("decoded_strings", [])
            if decoded_strings:
                self._find_iocs_in_strings(decoded_strings, "static:enhanced:decoded_strings")

            # Из suspicious_patterns (это обычно строки с контекстом)
            suspicious_patterns = enhanced.get("suspicious_patterns", [])
            if suspicious_patterns:
                self._find_iocs_in_strings(suspicious_patterns, "static:enhanced:suspicious_patterns")

            # Из suspicious_imports (описание может содержать что-то? маловероятно, но проверим)
            suspicious_imports = enhanced.get("suspicious_imports", [])
            if suspicious_imports:
                import_strings = collect_strings_from_structure(suspicious_imports)
                self._find_iocs_in_strings(import_strings, "static:enhanced:suspicious_imports")

        # Обрабатываем строки из Yara matches
        yara_matches = static_data.get("yara_matches", [])
        if isinstance(yara_matches, list):
            yara_strings = []
            for match in yara_matches:
                # Добавляем строки из метаданных правила
                yara_strings.extend(collect_strings_from_structure(match.get("meta", {})))
                # Добавляем найденные строки из самого совпадения
                strings_in_match = match.get("strings_in_match", []) # Это поле добавляется в static_analysis
                if isinstance(strings_in_match, list):
                    for s_id, offset, data in strings_in_match:
                        # Данные могут быть байтами, декодируем с игнорированием ошибок
                        try:
                            if isinstance(data, bytes):
                                yara_strings.append(data.decode(errors='ignore'))
                            elif isinstance(data, str):
                                yara_strings.append(data)
                        except Exception as exc:
                            logger.debug('Failed to normalise YARA match data: %s', exc)
            if yara_strings:
                self._find_iocs_in_strings(yara_strings, "static:yara_matches")

        # Запускаем поиск IoC во всех собранных строках
        self._find_iocs_in_strings(all_static_strings, "static:general")

        # Обрабатываем хеши файла
        hashes = static_data.get("hashes", {})
        if hashes.get("md5"): self._add_ioc("hash_md5", hashes["md5"].lower(), "static:file_hash")
        if hashes.get("sha1"): self._add_ioc("hash_sha1", hashes.get("sha1", "").lower(), "static:file_hash") # sha1 может отсутствовать
        if hashes.get("sha256"): self._add_ioc("hash_sha256", hashes["sha256"].lower(), "static:file_hash")

    def _process_dynamic_data(self, dynamic_data: Optional[Dict[str, Any]]):
        """ Обрабатывает данные динамического анализа. """
        if not dynamic_data or not isinstance(dynamic_data, dict):
            return

        # Обрабатываем вызовы API
        calls = dynamic_data.get("api_calls", [])
        for call in calls:
            self._process_api_call(call)

        # Обрабатываем строки из анализа дампов памяти
        dump_analysis = dynamic_data.get("memory_dump_analysis", {})
        if isinstance(dump_analysis, dict):
            for dump_filepath, scan_result in dump_analysis.items():
                dump_basename = os.path.basename(dump_filepath) if dump_filepath else "unknown_dump"
                if isinstance(scan_result, dict):
                    # Строки из дампа
                    dump_strings = scan_result.get("strings", [])
                    if dump_strings:
                        self._find_iocs_in_strings(dump_strings, f"dynamic:memory_dump:{dump_basename}:strings")

                    # Строки из Yara-совпадений в дампе
                    yara_matches = scan_result.get("yara_matches", [])
                    if yara_matches:
                        yara_dump_strings = []
                        for match in yara_matches:
                            # Из метаданных правила
                            yara_dump_strings.extend(collect_strings_from_structure(match.get("meta", {})))
                            # Из строк, найденных Yara в дампе
                            strings_in_match = match.get("strings_in_match", [])
                            if isinstance(strings_in_match, list):
                                for s_id, offset, data in strings_in_match:
                                    try:
                                        # data может быть str или bytes
                                        s_data = data
                                        if isinstance(data, bytes):
                                            s_data = data.decode(errors='ignore')
                                        # Берем только первые N символов для анализа
                                        yara_dump_strings.append(s_data[:256]) 
                                    except Exception as e:
                                        logger.debug(f"Error extracting URL: {e}")
                        if yara_dump_strings:
                            self._find_iocs_in_strings(yara_dump_strings, f"dynamic:memory_dump:{dump_basename}:yara")

    def _decode_hex_buffer(self, hex_str: Optional[str], source: str):
        """Decode HEX buffers and feed discovered strings back into IoC detection."""
        if not hex_str or not isinstance(hex_str, str):
            return

        try:
            if len(hex_str) > self.MAX_HEX_DECODE_SIZE * 2:
                logger.debug("Truncating hex buffer from %s due to size (%d bytes)", source, len(hex_str) // 2)
                hex_str = hex_str[: self.MAX_HEX_DECODE_SIZE * 2]

            decoded_bytes = binascii.unhexlify(hex_str)

            try:
                decoded_text = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                logger.debug("Failed to decode HEX buffer from %s as UTF-8: %s", source, exc)
                decoded_text = ""

            if decoded_text:
                printable_strings = re.findall(r"[\w\s\.:/\-_=]{4,}", decoded_text)
                if printable_strings:
                    self._find_iocs_in_strings(printable_strings, f"{source}:decoded_utf8")

            ascii_strings = re.findall(rb"[ -~]{4,}", decoded_bytes)
            if ascii_strings:
                ascii_decoded: List[str] = []
                for raw in ascii_strings:
                    try:
                        ascii_decoded.append(raw.decode("ascii"))
                    except UnicodeDecodeError as exc:
                        logger.debug("ASCII decode problem for %s: %s", source, exc)
                if ascii_decoded:
                    self._find_iocs_in_strings(ascii_decoded, f"{source}:decoded_ascii")

        except (binascii.Error, ValueError) as exc:
            logger.debug("Invalid HEX buffer from %s: %s", source, exc)
        except Exception as exc:
            logger.warning(f"Error decoding/scanning hex buffer from {source}: {exc}")

    def _process_api_call(self, call: Dict[str, Any]):
        """ Обрабатывает один вызов API из динамического анализа. """
        pid = call.get("pid", "?") # Получаем PID
        api_name = call.get("api", "UnknownAPI")
        args_obj = call.get("args", {})
        if not isinstance(args_obj, dict):
            return

        source_prefix = f"dynamic:pid{pid}:{api_name}"

        # --- Обработка специфичных аргументов для разных API ---

        # Процессы
        if api_name == "CreateProcessW":
            app_name = args_obj.get("applicationName")
            cmd_line = args_obj.get("commandLine")
            if app_name: self._add_ioc("filepath", app_name, f"{source_prefix}:applicationName")
            if cmd_line:
                self._add_ioc("command", cmd_line, f"{source_prefix}:commandLine")
                # Проверка на подозрительные паттерны в команде
                for pattern in self.SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(cmd_line):
                        self._add_ioc("suspicious_command", cmd_line, f"{source_prefix}:commandLine:suspicious")
                        break # Достаточно одного совпадения
                # Сканируем саму командную строку на IoC
                self._find_iocs_in_strings([cmd_line], f"{source_prefix}:commandLine_scan")

        elif api_name == "ShellExecuteW":
            file_arg = args_obj.get("lpFile")
            params_arg = args_obj.get("lpParameters")
            if file_arg:
                # Если это URL, добавляем как URL
                if self.URL_REGEX.match(file_arg):
                    self._add_ioc("url", file_arg, f"{source_prefix}:lpFile_url")
                else: # Иначе считаем путем к файлу
                    self._add_ioc("filepath", file_arg, f"{source_prefix}:lpFile")
            if params_arg:
                self._add_ioc("command_args", params_arg, f"{source_prefix}:lpParameters")
                # Также ищем IoC внутри параметров
                self._find_iocs_in_strings([params_arg], f"{source_prefix}:lpParameters_scan")
        elif api_name in {"CreateMutexA", "CreateMutexW", "CreateMutexExA", "CreateMutexExW", "OpenMutexA", "OpenMutexW", "NtCreateMutant", "NtCreateMutex"}:
            mutex_name = (
                args_obj.get("lpName")
                or args_obj.get("lpMutexName")
                or args_obj.get("name")
                or args_obj.get("ObjectName")
            )
            if mutex_name and isinstance(mutex_name, str):
                self._add_ioc("mutex", mutex_name, f"{source_prefix}:mutexName")
                self._find_iocs_in_strings([mutex_name], f"{source_prefix}:mutexName_scan")

        # Файловая система
        elif api_name == "CreateFileW":
            filename = args_obj.get("lpFileName")
            if filename: self._add_ioc("filepath", filename, f"{source_prefix}:lpFileName")

        elif api_name == "DeleteFileW":
            filename = args_obj.get("lpFileName")
            if filename: self._add_ioc("filepath_deleted", filename, f"{source_prefix}:lpFileName")

        elif api_name == "MoveFileW":
            old_filename = args_obj.get("lpExistingFileName")
            new_filename = args_obj.get("lpNewFileName")
            if old_filename: self._add_ioc("filepath_moved_from", old_filename, f"{source_prefix}:lpExistingFileName")
            if new_filename: self._add_ioc("filepath_moved_to", new_filename, f"{source_prefix}:lpNewFileName")

        elif api_name == "WriteFile":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        elif api_name == "ReadFile":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        # Сеть (WinInet)
        elif api_name == "InternetOpenUrlW":
            url_arg = args_obj.get("lpszUrl")
            if url_arg: self._add_ioc("url", url_arg, f"{source_prefix}:lpszUrl")
            headers = args_obj.get("lpszHeaders")
            if headers: self._find_iocs_in_strings([headers], f"{source_prefix}:lpszHeaders")

        elif api_name == "HttpSendRequestW":
            headers = args_obj.get("lpszHeaders")
            optional_data_hex = args_obj.get("optionalDataHex")
            if headers: self._find_iocs_in_strings([headers], f"{source_prefix}:lpszHeaders")
            self._decode_hex_buffer(optional_data_hex, f"{source_prefix}:optionalData")

        elif api_name == "InternetReadFile":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        elif api_name == "InternetWriteFile":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        # Сеть (Sockets)
        elif api_name == "connect":
            ip = args_obj.get("targetIP")
            port = args_obj.get("targetPort")
            if ip and not ip.startswith("["): # Игнорируем плейсхолдеры типа [IPv6 Addr]
                 self._add_ioc("ip", ip, f"{source_prefix}:targetIP")
                 if port: self._add_ioc("port", str(port), f"{source_prefix}:targetPort") # Порт как строка

        elif api_name == "send":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        elif api_name == "recv":
            buffer_hex = args_obj.get("buffer_hex")
            self._decode_hex_buffer(buffer_hex, f"{source_prefix}:buffer")

        elif api_name == "DnsQuery_W":
            name = args_obj.get("lpstrName")
            if name: self._add_ioc("domain_queried", name, f"{source_prefix}:lpstrName")

        # Реестр
        elif api_name == "RegOpenKeyExW" or api_name == "RegCreateKeyExW":
            sub_key = args_obj.get("lpSubKey")
            if sub_key:
                self._add_ioc("registry", sub_key, f"{source_prefix}:lpSubKey")
                if "currentversion\\run" in sub_key.lower():
                     self._add_ioc("autostart_key", sub_key, f"{source_prefix}:lpSubKey:autostart")

        elif api_name == "RegSetValueExW":
             # Ключ был обработан в RegOpen/Create, здесь смотрим значение
             value_name = args_obj.get("lpValueName")
             data_str = args_obj.get("lpData_str") # Уже частично разобрано в Frida
             if value_name: self._add_ioc("registry_value", value_name, f"{source_prefix}:lpValueName")
             if data_str and isinstance(data_str, str):
                 # Если данные - путь к файлу, добавим как путь
                 if self.FILEPATH_REGEX.fullmatch(data_str):
                     self._add_ioc("filepath", data_str, f"{source_prefix}:lpData_filepath")
                 # И всегда ищем IoC внутри строки данных
                 self._find_iocs_in_strings([data_str], f"{source_prefix}:lpData_scan")

        elif api_name == "RegDeleteKeyW":
            sub_key = args_obj.get("lpSubKey")
            if sub_key: self._add_ioc("registry_deleted", sub_key, f"{source_prefix}:lpSubKey")

        elif api_name == "RegDeleteValueW":
            value_name = args_obj.get("lpValueName")
            if value_name: self._add_ioc("registry_value_deleted", value_name, f"{source_prefix}:lpValueName")

        # --- Общий поиск IoC во всех строковых аргументах ---
        # Собираем строки из всех значений в args_obj
        all_arg_strings = collect_strings_from_structure(args_obj)
        # Удаляем строки, которые мы уже обработали специфично (например, hex буферы)
        processed_hex_keys = {"buffer_hex", "optionalDataHex"}
        strings_to_scan = [s for k, s in args_obj.items() if isinstance(s, str) and k not in processed_hex_keys]
        strings_to_scan.extend([s for s in all_arg_strings if isinstance(s, str)]) # Добавляем остальные собранные строки
        
        # Убираем дубликаты и сканируем
        unique_strings_to_scan = list(set(strings_to_scan))
        if unique_strings_to_scan:
             self._find_iocs_in_strings(unique_strings_to_scan, f"{source_prefix}:args_scan")

    def extract(self, static_data: Optional[Dict[str, Any]] = None,
                dynamic_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        """
        Основной метод для запуска извлечения IoC.
        Принимает словари статических и/или динамических данных.
        Возвращает список найденных уникальных IoC.
        """
        self.found_iocs = []
        self.unique_set = set()

        logger.info("Processing static data...")
        self._process_static_data(static_data)
        logger.info("Processing dynamic data...")
        self._process_dynamic_data(dynamic_data)

        logger.info(f"IocExtractor: found {len(self.found_iocs)} total IoCs (unique) after filtering.")
        return self.found_iocs

# --- Точка входа модуля (для совместимости или прямого вызова) ---
def extract_iocs(static_data: Optional[Dict[str, Any]] = None,
                 dynamic_data: Optional[Dict[str, Any]] = None,
                 filter_private_ips: bool = True,
                 filter_common_paths: bool = True
                 ) -> List[Dict[str, str]]:
    """
    Функция-обертка для создания экземпляра IocExtractor и запуска извлечения.
    """
    extractor = IocExtractor(filter_private_ips=filter_private_ips,
                             filter_common_paths=filter_common_paths)
    return extractor.extract(static_data, dynamic_data)

# --------------------- Локальный тест (обновлен для argparse) ----------------------
if __name__ == "__main__":
    import json
    import argparse # Добавлено
    import os       # Добавлено
    logging.basicConfig(level=logging.INFO) # Уровень INFO для CLI

    parser = argparse.ArgumentParser(description="Extract IoCs from static and/or dynamic analysis JSON files.")
    parser.add_argument("--static-json", help="Path to static analysis JSON file (optional).", default=None)
    parser.add_argument("--dynamic-json", help="Path to dynamic analysis JSON file (optional).", default=None)
    parser.add_argument("--no-filter-private-ips", action="store_true", help="Disable filtering of private/local IPs.")
    parser.add_argument("--no-filter-common-paths", action="store_true", help="Disable filtering of common system paths.")
    parser.add_argument("-o", "--output", help="Output file for extracted IoCs (JSON).", default=None)

    args = parser.parse_args()

    if not args.static_json and not args.dynamic_json:
        parser.error("At least one of --static-json or --dynamic-json must be provided.")

    # Загрузка данных
    def load_json_data(filepath: Optional[str]) -> Optional[dict]:
        if not filepath or not os.path.isfile(filepath):
            # Если путь не указан, это не ошибка
            if filepath: 
                logger.warning(f"JSON file not found: {filepath}. Skipping.")
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Если данные обернуты в ключ 'result'
                if isinstance(data, dict) and 'result' in data and isinstance(data['result'], dict):
                    return data['result']
                elif isinstance(data, dict): # Если это уже словарь с данными
                    return data
                else:
                    logger.error(f"Unexpected JSON structure in {filepath}. Expected a dictionary.")
                    return None
        except Exception as e:
            logger.error(f"Error loading JSON from {filepath}: {e}")
            return None

    static_data_loaded = load_json_data(args.static_json)
    dynamic_data_loaded = load_json_data(args.dynamic_json)

    # Настройки фильтрации
    filter_ips = not args.no_filter_private_ips
    filter_paths = not args.no_filter_common_paths

    print(f"--- Extracting IoCs (Filter Private IPs: {filter_ips}, Filter Common Paths: {filter_paths}) ---")
    
    # Используем функцию-обертку
    extracted_iocs = extract_iocs(
        static_data=static_data_loaded, 
        dynamic_data=dynamic_data_loaded, 
        filter_private_ips=filter_ips,
        filter_common_paths=filter_paths
    )

    # Вывод результата
    output_json = json.dumps(extracted_iocs, indent=2, ensure_ascii=False)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_json)
            print(f"Results saved to: {args.output}")
        except Exception as e:
            print(f"Error saving results to {args.output}: {e}")
            print("\nResults:\n" + output_json) # Выводим в консоль при ошибке записи
    else:
        # Если файл вывода не указан, печатаем в консоль
        print(output_json)
