"""Build artifact generator: allowlisted onedir output only, never copy project state/secrets."""
import hashlib
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
source = root / "dist/os-guard-agent-service"
target = root / "build/service-payload.zip"
files = sorted(path for path in source.rglob("*") if path.is_file())
if not (source / "os-guard-agent-service.exe").is_file(): raise SystemExit("Service build missing")
for path in files:
    if path.is_symlink() or path.suffix.lower() in {".env", ".dpapi", ".log", ".key", ".pem"}:
        raise SystemExit("Unexpected payload file")
index = {"development_unsigned": True, "files": {
    path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}}
target.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in files: archive.write(path, path.relative_to(source).as_posix())
    archive.writestr("payload-manifest.json", json.dumps(index, sort_keys=True))
print("Development service payload built; no signing/approval implied")
