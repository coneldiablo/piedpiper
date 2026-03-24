# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent

block_cipher = None

datas = [
    (str(project_root / "config.json"), "config.json"),
    (str(project_root / "reports"), "reports"),
]

hidden_imports = [
    "api.server",
    "services.retro_hunt",
    "services.threat_simulation",
    "services.intel_fusion",
    "analyzer.ml_detector",
    "flask_socketio",
]

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="ThreatInquisitor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
