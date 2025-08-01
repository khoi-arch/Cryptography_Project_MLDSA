# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['docx_verifier.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt5.QtCore',
        'PyQt5.QtWidgets',
        'PyQt5.QtGui',
        'requests',
        'json',
        'base64',
        'hashlib',
        'datetime',
        'os',
        'sys',
        'io',
        'tempfile',
        'logging',
        'qrcode',
        'docx',
        'docx.shared',
        'docx.enum.text',
        'Crypto.Cipher.AES',
        'Crypto.Random',
        'Crypto.Protocol.KDF',
        'dilithium_py.ml_dsa',
        'reportlab.pdfgen',
        'reportlab.lib.pagesizes'
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
    name='MLDSA_Document_System',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
) 