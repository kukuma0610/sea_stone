"""Unsigned development GUI installer, explicit UAC; no commercial approval claim."""
from pathlib import Path
root = Path(SPECPATH)
a = Analysis([str(root / "packaging/setup_entry.py")], pathex=[str(root)], binaries=[],
             datas=[(str(root / "build/service-payload.zip"), ".")],
             hiddenimports=[f"agent.checks.w{i:02d}" for i in range(1, 65)], hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="os-guard-agent-dev-setup", console=False,
          upx=False, uac_admin=True, uac_uiaccess=False)
coll = COLLECT(exe, a.binaries, a.datas, name="os-guard-agent-dev-setup", upx=False)
