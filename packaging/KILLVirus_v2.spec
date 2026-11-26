# -*- mode: python ; coding: utf-8 -*-
import os

from PyInstaller.utils.hooks import collect_all

# Las rutas del spec se resuelven relativas a packaging/, no al cwd. Se ancla
# todo a la raíz del proyecto para que el build funcione desde cualquier sitio.
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

# Solo assets: el código de core/ y ui/ ya se compila dentro del PYZ.
# Empaquetarlo como "datas" exponía el código fuente y, con él, herramientas de
# administración que no deben salir del entorno de desarrollo.
datas = [(os.path.join(ROOT, "assets"), "assets")]
binaries = []
hiddenimports = [
    # Importados de forma diferida dentro de app.pyw (modo servicio/CLI).
    'core.agent',
    'core.winservice',
    'core.service_control',
    'core.autoprotect',
    'services.scan_service',
    # watchdog carga el observer de Windows dinamicamente.
    'watchdog.observers.read_directory_changes',
    'watchdog.observers.winapi',
]
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    [os.path.join(ROOT, "app.pyw")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='KILLVirus_v2',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=os.path.join(ROOT, 'packaging', 'version_info.txt'),
    icon=[os.path.join(ROOT, 'assets', 'icon.ico')],
)
