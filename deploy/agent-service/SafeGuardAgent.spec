# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_dynamic_libs

block_cipher = None

REPO_ROOT = Path(SPECPATH).resolve().parents[1]
ENV_ROOT = Path(sys.executable).resolve().parent
LIB_BIN = ENV_ROOT / "Library" / "bin"
DLLS_DIR = ENV_ROOT / "DLLs"


def _append_unique(items, item):
    if item not in items:
        items.append(item)


def _binary_candidates():
    filenames = [
        "python312.dll",
        "expat.dll",
        "libexpat.dll",
        "ffi-8.dll",
        "ffi-7.dll",
        "ffi.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "vcruntime140_threads.dll",
        "ucrtbase.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140_2.dll",
        "msvcp140_atomic_wait.dll",
        "msvcp140_codecvt_ids.dll",
    ]
    search_roots = [ENV_ROOT, LIB_BIN]
    found = []
    for name in filenames:
        for root in search_roots:
            candidate = root / name
            if candidate.exists():
                _append_unique(found, (str(candidate), "."))
                break
    pyexpat = DLLS_DIR / "pyexpat.pyd"
    if pyexpat.exists():
        _append_unique(found, (str(pyexpat), "."))
    for binary in collect_dynamic_libs("pywin32"):
        _append_unique(found, binary)
    return found

a = Analysis(
    [str(REPO_ROOT / "agent.py")],
    pathex=[str(REPO_ROOT)],
    binaries=_binary_candidates(),
    datas=[],
    hiddenimports=[
        "pkg_resources",
        "plistlib",
        "pyexpat",
        "xml",
        "xml.parsers",
        "xml.parsers.expat",
        "win32timezone",
    ],
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
    name="SafeGuardAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)
