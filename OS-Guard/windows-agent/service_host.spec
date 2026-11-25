"""Development onedir SCM service; no secret/config/state included."""
from pathlib import Path
root = Path(SPECPATH)
a = Analysis([str(root / "packaging/service_entry.py")], pathex=[str(root)], binaries=[],
             datas=[(str(root / "agent/central/manifest-windows-64-2026-v1.json"), "agent/central")],
             hiddenimports=[f"agent.checks.w{i:02d}" for i in range(1, 65)], hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="os-guard-agent-service", console=False, upx=False, uac_admin=False)
coll = COLLECT(exe, a.binaries, a.datas, name="os-guard-agent-service", upx=False)
