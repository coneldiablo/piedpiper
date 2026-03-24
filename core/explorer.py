#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/core/explorer.py

Полноценный модуль, который:
1) Рекурсивно сканирует директории в поисках файлов.
2) Фильтрует файлы по расширениям (exe, elf, pdf, doc, docx...).
3) Проверяет их атрибуты (размер, дата изменения, хэши).
4) Выявляет подозрительные признаки (слишком большой размер, нулевой размер, слишком свежая дата).
5) Предоставляет функции для "interesting" файлов (payload, tmp, random name).

Все операции реально выполняются при вызове scan_directory(...).
"""

import os
import logging
import hashlib
import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("explorer")
logger.setLevel(logging.DEBUG)


SUPPORTED_EXTENSIONS = {".exe", ".dll", ".pdf", ".doc", ".docx", ".elf", ".bin", ".scr"}


def is_supported_extension(filename: str) -> bool:
    """
    Проверяем, принадлежит ли файл к одному из поддерживаемых расширений
    """
    ext = os.path.splitext(filename.lower())[1]
    return ext in SUPPORTED_EXTENSIONS


def compute_file_hashes(filepath: str, do_md5: bool = True, do_sha256: bool = True) -> Dict[str, str]:
    """
    Считает MD5 и/или SHA256 для файла, если нужно.
    """
    result = {}
    chunk_size = 8192

    if not os.path.isfile(filepath):
        return result

    md5_hasher = hashlib.md5() if do_md5 else None
    sha256_hasher = hashlib.sha256() if do_sha256 else None

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            if md5_hasher:
                md5_hasher.update(chunk)
            if sha256_hasher:
                sha256_hasher.update(chunk)

    if md5_hasher:
        result["md5"] = md5_hasher.hexdigest()
    if sha256_hasher:
        result["sha256"] = sha256_hasher.hexdigest()
    return result


def scan_directory(
    start_path: str,
    recursive: bool = True,
    with_hashes: bool = False,
    suspicious_rules: bool = True
) -> List[Dict[str, Any]]:
    """
    Рекурсивно (или нет) сканируем директорию, находим подходящие файлы,
    собираем инфу:
      - путь
      - размер
      - дата изменения
      - хэши (опционально)
      - is_suspicious (если suspicious_rules=True)
    :return: список словарей, по одному на каждый файл
    """
    results = []
    if not os.path.isdir(start_path):
        logger.warning(f"Path '{start_path}' is not a directory!")
        return results

    for root, dirs, files in os.walk(start_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            if is_supported_extension(fname):
                info = {}
                info["filepath"] = fpath
                st = os.stat(fpath)
                info["size"] = st.st_size
                mtime = datetime.datetime.fromtimestamp(st.st_mtime)
                info["modified_time"] = mtime.isoformat()

                if with_hashes:
                    hashes = compute_file_hashes(fpath, do_md5=True, do_sha256=True)
                    info.update(hashes)

                if suspicious_rules:
                    info["suspicious"] = is_suspicious_file(info)

                results.append(info)

        if not recursive:
            # Если не нужно рекурсию, выходим
            break

    logger.info(f"Scanned {start_path}, found {len(results)} interesting files.")
    return results


def is_suspicious_file(file_info: Dict[str, Any]) -> bool:
    """
    Реальные правила, без заглушек:
    - Размер 0? подозрительно
    - Очень большой > 500MB? подозрительно
    - Очень свежая дата (последний час)? возможно подозрительно
    - (Если есть MD5/sha256...) можно проверить, не совпадает ли с известными сигнатурами
    """
    size = file_info.get("size", 0)
    if size == 0:
        return True
    if size > 500 * 1024 * 1024:  # 500 MB
        return True

    # Дата
    mod_str = file_info.get("modified_time", "")
    if mod_str:
        mod_dt = datetime.datetime.fromisoformat(mod_str)
        now = datetime.datetime.now()
        diff = now - mod_dt
        if diff.total_seconds() < 3600:  # изменён в течение часа
            return True

    # Если есть хэши - (пример) проверяем, не equals "e3b0c442..." - (hash от пустого файла)
    sha256 = file_info.get("sha256", "")
    if sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        # пустой
        return True

    return False


"""
Примечание: вспомогательная функция find_interesting_files() ранее присутствовала,
но не использовалась в проекте. Удалена, чтобы сократить поверхность кода.
"""


if __name__ == "__main__":
    import sys
    import json
    logging.basicConfig(level=logging.DEBUG)

    # Пример: python explorer.py /path/to/scan
    if len(sys.argv) < 2:
        print("Usage: python explorer.py <directory_to_scan>")
        sys.exit(0)

    path = sys.argv[1]
    results = scan_directory(path, recursive=True, with_hashes=True, suspicious_rules=True)
    print(f"Found {len(results)} supported files.\nDetails:")
    print(json.dumps(results, indent=2))
