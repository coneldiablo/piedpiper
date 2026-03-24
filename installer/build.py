#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper script to produce a standalone ThreatInquisitor binary with PyInstaller.

Usage:
    python installer/build.py --onefile
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run_pyinstaller(onefile: bool = False) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    spec_path = repo_root / "installer" / "build.spec"

    cmd = [sys.executable, "-m", "PyInstaller", str(spec_path)]
    if onefile:
        cmd.append("--onefile")

    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ThreatInquisitor installer with PyInstaller")
    parser.add_argument("--onefile", action="store_true", help="Produce a single-file executable")
    args = parser.parse_args()
    run_pyinstaller(onefile=args.onefile)


if __name__ == "__main__":  # pragma: no cover
    main()

