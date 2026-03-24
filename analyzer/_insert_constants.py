#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Maintenance helper that ensures the static-analysis constants block exists.

It is not used by the runtime application, but it remains in the repository as
an idempotent helper for manual maintenance of `analyzer/static_analysis.py`.
"""

from __future__ import annotations

from pathlib import Path


TARGET = Path(__file__).with_name("static_analysis.py")
ANCHOR = "URL_REGEX_SCRIPT = re.compile"
CONSTANT_MARKER = "SUSPICIOUS_IMPORT_NAMES ="
CONSTANT_BLOCK = """
# === Enhanced heuristics constants ===
SUSPICIOUS_IMPORT_NAMES = {'VirtualAllocEx', 'CreateRemoteThread', 'WriteProcessMemory', 'VirtualProtect'}
SUSPICIOUS_DLL_NAMES = {'kernel32.dll', 'advapi32.dll', 'ntdll.dll'}
PACKER_SECTION_NAMES = {'.upx', 'UPX0', 'UPX1'}
SUSPICIOUS_KEYWORDS = ['psexec', 'mimikatz', 'powershell', 'reverse shell']
HIGH_ENTROPY_THRESHOLD = 7.2
PACKER_SECTION_NAMES_LOWER = {name.lower() for name in PACKER_SECTION_NAMES}
""".strip()


def ensure_constants_block() -> bool:
    text = TARGET.read_text(encoding="utf-8")
    if CONSTANT_MARKER in text:
        return False

    lines = text.splitlines()
    updated_lines = []
    inserted = False
    for line in lines:
        updated_lines.append(line)
        if not inserted and line.startswith(ANCHOR):
            updated_lines.append(CONSTANT_BLOCK)
            inserted = True

    if not inserted:
        raise RuntimeError(f"Anchor not found in {TARGET}")

    TARGET.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    return True


def main() -> int:
    changed = ensure_constants_block()
    print("constants inserted" if changed else "constants already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
