#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/core/vt_integration.py

Полноценный модуль для взаимодействия с VirusTotal API (v3):
1) Класс VirusTotalClient, инициализируется api_key.
2) Методы:
   - check_file_hash(hash_value): возвращает словарь с информацией о детектах.
   - check_url(url_value): отправляем/получаем отчёт о URL.
   - submit_file(file_path): (по желанию) загружаем файл на VT.
3) Простейшее кэширование результатов (в памяти или JSON),
   чтобы не превышать лимитов, если анализируем повторяющиеся объекты.
4) Никаких заглушек — реальные HTTP-запросы к https://www.virustotal.com/api/v3/...
   Если api_key не задан, вернёт ошибку.

Пример использования:
    from core.config import config_manager
    vt = VirusTotalClient(api_key=config_manager.get("VIRUSTOTAL_API_KEY", ""))
    info = vt.check_file_hash("abcd1234...")
    print(info)
"""

import os
import time
import json
import logging
from typing import Optional, Dict, Any
import requests

logger = logging.getLogger("vt_integration")
logger.setLevel(logging.DEBUG)

# Для удобства укажем URL VirusTotal
VT_API_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalClient:
    """
    Класс для интеграции с VirusTotal API (v3).
    """

    def __init__(self, api_key: str, use_cache: bool = True, cache_file: Optional[str] = None):
        """
        :param api_key: Ваш API-ключ от VirusTotal
        :param use_cache: Включить ли кэширование результатов
        :param cache_file: Путь к JSON-файлу, где хранить кэш. Если None, хранится в памяти.
        """
        self.api_key = api_key
        self.use_cache = use_cache
        self.cache_file = cache_file
        self._cache_data = {}

        if self.use_cache and self.cache_file:
            self._load_cache()

    def _load_cache(self):
        if os.path.isfile(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._cache_data = json.load(f)
            except Exception as e:
                logger.warning(f"Не удалось загрузить кэш из {self.cache_file}: {e}")
                self._cache_data = {}

    def _save_cache(self):
        if not self.use_cache or not self.cache_file:
            return
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache_data, f, indent=2)
        except Exception as e:
            logger.warning(f"Не удалось сохранить кэш в {self.cache_file}: {e}")

    def _get_headers(self) -> dict:
        if not self.api_key or self.api_key == "YOUR_API_KEY":
            # Можно выбросить исключение
            raise ValueError("VirusTotal API key is not set.")
        return {
            "x-apikey": self.api_key
        }

    def check_file_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Проверяет информацию о файле по его хэшу (MD5/SHA1/SHA256).
        Реально вызывает GET /api/v3/files/{hash}.
        Возвращает словарь с результатами (атрибутами).
        """
        if self.use_cache:
            cache_key = f"file:{hash_value}"
            if cache_key in self._cache_data:
                logger.debug(f"[VT] Using cached result for hash={hash_value}")
                return self._cache_data[cache_key]

        url = f"{VT_API_BASE}/files/{hash_value}"
        headers = self._get_headers()
        logger.debug(f"[VT] GET {url}")
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # Сохраним в кэш
            if self.use_cache:
                self._cache_data[cache_key] = data
                self._save_cache()
            return data
        else:
            logger.warning(f"[VT] Error {resp.status_code} for hash={hash_value}")
            return {"error": resp.status_code, "text": resp.text}

    def check_url(self, url_str: str) -> Dict[str, Any]:
        """
        Анализируем URL.
        Шаг 1: нужно преобразовать URL в формат, который используется VT (base64 encoding).
        Или же отправить POST /urls для анализа, получить id, потом GET /urls/id.
        """
        # Для упрощения: делаем POST /urls, чтобы отправить URL на анализ, возвращаем ID, потом GET /urls/{id}
        # (Подробности: https://developers.virustotal.com/reference/url-scan )
        if self.use_cache:
            cache_key = f"url:{url_str}"
            if cache_key in self._cache_data:
                logger.debug(f"[VT] Using cached result for url={url_str}")
                return self._cache_data[cache_key]

        # 1) Отправляем URL
        submit_url = f"{VT_API_BASE}/urls"
        headers = self._get_headers()
        data = {"url": url_str}
        logger.debug(f"[VT] POST {submit_url}")
        r_sub = requests.post(submit_url, headers=headers, data=data)
        if r_sub.status_code != 200 and r_sub.status_code != 201:
            logger.warning(f"[VT] URL submit error {r_sub.status_code} for {url_str}")
            return {"error": r_sub.status_code, "text": r_sub.text}

        sub_json = r_sub.json()
        # В sub_json["data"]["id"] лежит идентификатор
        url_id = sub_json.get("data", {}).get("id")
        if not url_id:
            return {"error": "No url_id returned", "text": sub_json}

        # 2) GET /urls/{id}
        get_url = f"{VT_API_BASE}/urls/{url_id}"
        logger.debug(f"[VT] GET {get_url}")
        time.sleep(1)  # Подождём секунду, пока VT обрабатывает
        resp_get = requests.get(get_url, headers=headers)
        if resp_get.status_code == 200:
            data_result = resp_get.json()
            if self.use_cache:
                self._cache_data[cache_key] = data_result
                self._save_cache()
            return data_result
        else:
            return {"error": resp_get.status_code, "text": resp_get.text}

    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Отправляем реальный файл на анализ (POST /files).
        (https://developers.virustotal.com/reference/file-scan)
        """
        if not os.path.isfile(file_path):
            return {"error": f"File {file_path} not found"}

        url = f"{VT_API_BASE}/files"
        headers = self._get_headers()
        files = {
            "file": open(file_path, "rb")
        }
        logger.debug(f"[VT] Uploading file {file_path}")
        resp = requests.post(url, headers=headers, files=files)
        if resp.status_code == 200 or resp.status_code == 201:
            return resp.json()
        else:
            return {"error": resp.status_code, "text": resp.text}


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)

    # Пример запуска: python vt_integration.py <API_KEY> <command> <argument>
    #    e.g. python vt_integration.py 123abc filehash abcd1234
    #    e.g. python vt_integration.py 123abc url https://google.com
    #    e.g. python vt_integration.py 123abc upload test.exe

    if len(sys.argv) < 4:
        print("Usage:\n  python vt_integration.py <API_KEY> <command> <argument>\n"
              "Commands:\n"
              "  filehash <hash>\n"
              "  url <url>\n"
              "  upload <file_path>\n")
        sys.exit(0)

    api_key = sys.argv[1]
    command = sys.argv[2]
    argument = sys.argv[3]

    vt = VirusTotalClient(api_key=api_key, use_cache=True, cache_file="vt_cache.json")

    if command == "filehash":
        info = vt.check_file_hash(argument)
        print(info)
    elif command == "url":
        info = vt.check_url(argument)
        print(info)
    elif command == "upload":
        info = vt.submit_file(argument)
        print(info)
    else:
        print("[Error] Unknown command:", command)
