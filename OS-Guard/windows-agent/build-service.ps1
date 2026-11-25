[CmdletBinding()]
param([string]$Python = "$PSScriptRoot\build\.venv\Scripts\python.exe")
$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    & $Python -c "import struct, sys; sys.exit(0 if struct.calcsize('P') == 8 else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Use Windows x64 Python for the development build." }
    & $Python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0) { throw "Use an existing approved build environment with PyInstaller; no packages are installed by this script." }
    & $Python -m PyInstaller --noconfirm --workpath build\service-host --distpath dist service_host.spec
    if ($LASTEXITCODE -ne 0) { throw "Service build failed" }
    & $Python packaging\make_service_payload.py
    if ($LASTEXITCODE -ne 0) { throw "Payload build failed" }
    & $Python -m PyInstaller --noconfirm --workpath build\service-setup --distpath dist service_setup.spec
    if ($LASTEXITCODE -ne 0) { throw "Installer build failed" }
    Compress-Archive -Path dist\os-guard-agent-dev-setup -DestinationPath dist\os-guard-agent-dev-setup.zip -Force
    Write-Output "Built unsigned development installer: dist\os-guard-agent-dev-setup\os-guard-agent-dev-setup.exe (keep complete folder)"
    Write-Output "No installation, service registration, CA trust, Enrollment or OS policy change was performed."
}
finally { Pop-Location }
