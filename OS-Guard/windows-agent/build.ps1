<#
Build on Windows x64. Only build/.venv receives PyInstaller and its dependencies.
Run from a writable directory on Server 2022 (Python is not required):
  .\dist\os-guard-local-check.exe --output .\results\windows-check.json
The output path is relative to the current directory, not the extraction folder.
Source execution remains: python -m agent.local_runner --output results/windows-check.json

The executable uses the caller's privileges. Protected policy exports/reads need
administrator rights; insufficient rights keep the existing UNABLE behavior.
PyInstaller warns against elevating onefile executables because of temporary
DLL tampering risk. Review executable/extraction-directory ACLs before privileged
deployment; use a controlled VM for validation. This script changes no ACLs/UAC.
Windows PowerShell, secedit and native Windows DLLs remain OS prerequisites.
No Server roles or PowerShell modules are installed by this build or executable.
#>
[CmdletBinding()]
param([string]$Python = "python")

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Build on Windows x64." }

Push-Location $PSScriptRoot
try {
    & $Python -c "import struct, sys; sys.exit(0 if struct.calcsize('P') == 8 else 1)"
    if ($LASTEXITCODE -ne 0) { throw "A 64-bit Python installation is required." }
    $buildPython = Join-Path $PSScriptRoot "build\.venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $buildPython)) {
        & $Python -m venv (Join-Path $PSScriptRoot "build\.venv")
        if ($LASTEXITCODE -ne 0) { throw "Build virtual environment creation failed." }
    }
    & $buildPython -m pip install --disable-pip-version-check "PyInstaller==6.22.3"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller installation failed." }
    & $buildPython -m PyInstaller --noconfirm --workpath build\pyinstaller --distpath dist local_runner.spec
    if ($LASTEXITCODE -ne 0) { throw "Executable build failed." }
    Write-Output "Built: $PSScriptRoot\dist\os-guard-local-check.exe"
}
finally {
    Pop-Location
}
