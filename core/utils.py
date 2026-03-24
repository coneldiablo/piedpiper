#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/core/utils.py

Полноценный набор вспомогательных утилит:
1) color_log(msg, level) - цветной вывод в консоль,
2) TimerContext(name) - контекст-менеджер для замера производительности,
3) run_command(cmd) - безопасное выполнение системной команды (subprocess), с логированием,
4) approx_match(str1, str2) - приблизительное сравнение строк (Levenshtein distance).

Никаких "заглушек" — все функции действительно работают.
"""

import os
import sys
import time
import logging
import subprocess
from contextlib import contextmanager

logger = logging.getLogger("utils")
logger.setLevel(logging.DEBUG)

# Для цветного вывода (если хотим)
COLOR_CODES = {
    "DEBUG": "\033[94m",     # Синий
    "INFO": "\033[92m",      # Зелёный
    "WARNING": "\033[93m",   # Желтый
    "ERROR": "\033[91m",     # Красный
    "RESET": "\033[0m"
}


def color_log(message: str, level: str = "INFO"):
    """
    Реальный цветной вывод в консоль, 
    с учётом того, что в некоторых консолях (Windows) надо включать color support.
    """
    # Если консоль не поддерживает ANSI:
    # можно проверить os.name == 'nt' и т.д. Но для упрощения считаем, что поддерживает.
    color_code = COLOR_CODES.get(level.upper(), "")
    reset_code = COLOR_CODES["RESET"]
    print(f"{color_code}[{level}] {message}{reset_code}")


@contextmanager
def TimerContext(name: str):
    """
    Контекст-менеджер для замера времени выполнения блока кода.
    Пример:
        with TimerContext("Heavy Operation"):
            do_something()
    """
    t0 = time.time()
    try:
        yield
    finally:
        dt = time.time() - t0
        logger.info(f"[TimerContext] {name} took {dt:.3f} sec")


def run_command(cmd, cwd=None, timeout=60, shell=False) -> dict:
    """
    Безопасное выполнение системной команды.
    :param cmd: список аргументов (рекомендуется) или строка.
    :param cwd: рабочая директория.
    :param timeout: время ожидания.
    :param shell: использовать ли shell=True (рискованно).
    :return: словарь: {"returncode": int, "stdout": "...", "stderr": "...", "error": ...}
    """
    logger.debug(f"[run_command] Executing: {cmd}, timeout={timeout}, shell={shell}")
    try:
        if isinstance(cmd, str) and not shell:
            # Если cmd - строка, но shell=False, надо преобразовать cmd в список (split)
            cmd = cmd.strip().split()

        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        rc = proc.returncode
        return {
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr
        }
    except subprocess.TimeoutExpired as e:
        logger.error(f"[run_command] TimeoutExpired: {e}")
        return {"error": f"Timeout after {timeout}s", "returncode": -1, "stdout": "", "stderr": ""}
    except Exception as e:
        logger.error(f"[run_command] Exception: {e}")
        return {"error": str(e), "returncode": -1, "stdout": "", "stderr": ""}


def approx_match(str1: str, str2: str) -> float:
    """
    Реальное вычисление похожести строк (Levenshtein-based).
    Возвращает "сходство" от 0.0 до 1.0, где 1.0 = полное совпадение.
    """
    dist = levenshtein_distance(str1, str2)
    max_len = max(len(str1), len(str2))
    if max_len == 0:
        return 1.0  # обе пустые
    similarity = 1.0 - (dist / max_len)
    return similarity


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Классический алгоритм Левенштейна (динамическое программирование),
    возвращает кол-во операций (вставка/удаление/замена),
    необходимых для превращения s1 в s2.
    """
    if s1 == s2:
        return 0
    len_s1 = len(s1)
    len_s2 = len(s2)

    # создаём матрицу (len_s1+1) x (len_s2+1)
    dp = [[0] * (len_s2 + 1) for _ in range(len_s1 + 1)]

    for i in range(len_s1 + 1):
        dp[i][0] = i
    for j in range(len_s2 + 1):
        dp[0][j] = j

    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,      # удаление
                dp[i][j-1] + 1,      # вставка
                dp[i-1][j-1] + cost  # замена (cost=0 если совпадают)
            )
    return dp[len_s1][len_s2]


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)

    color_log("Test message in color", "INFO")

    # Тест TimerContext
    with TimerContext("Sleep test"):
        time.sleep(1.2)

    # run_command test
    res = run_command(["echo", "Hello from subprocess"])
    print("run_command result:", res)

    # approx_match test
    sim = approx_match("malware", "m4lwarez")
    print(f"Approx match for 'malware' vs 'm4lwarez': {sim:.3f}")
