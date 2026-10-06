"""Offline x64 console executable; no configuration, secrets or reports bundled."""

from pathlib import Path

root = Path(SPECPATH)
checks = [f"agent.checks.w{number:02d}" for number in range(1, 65)]

a = Analysis(
    [str(root / "packaging" / "local_runner_entry.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[],
    hiddenimports=checks,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

# Fail the build if a dynamic CHECK was omitted. No whole-project data copying.
bundled_modules = {entry[0] for entry in a.pure}
if not set(checks).issubset(bundled_modules):
    raise RuntimeError("One or more Windows CHECK modules were not bundled")

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="os-guard-local-check",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    # Keep non-administrator runs possible; never elevate automatically.
    uac_admin=False,
    uac_uiaccess=False,
)
