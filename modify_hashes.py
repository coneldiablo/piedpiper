#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility script for recalculating file hashes.

This script is intentionally standalone and is kept in the repository as a
maintenance helper for quick verification of samples outside the main GUI/API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict


def calculate_hashes(path: Path) -> Dict[str, str]:
    md5h = hashlib.md5()
    sha1h = hashlib.sha1()
    sha256h = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            md5h.update(chunk)
            sha1h.update(chunk)
            sha256h.update(chunk)

    return {
        "path": str(path.resolve()),
        "md5": md5h.hexdigest(),
        "sha1": sha1h.hexdigest(),
        "sha256": sha256h.hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recalculate hashes for one file.")
    parser.add_argument("file", help="Path to the target file")
    args = parser.parse_args()

    target = Path(args.file)
    if not target.is_file():
        raise SystemExit(f"File not found: {target}")

    print(json.dumps(calculate_hashes(target), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
