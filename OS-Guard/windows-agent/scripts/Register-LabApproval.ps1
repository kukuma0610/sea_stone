[CmdletBinding()]
param(
    [ValidateSet('W-04','W-05','W-07','W-08','W-09','W-10','W-12','W-13','W-15','W-28','W-36','W-48','W-49','W-50','W-52','W-53','W-55','W-59')]
    [string]$Code = 'W-07',
    [Parameter(Mandatory=$true)][string]$SnapshotId
)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    & python scripts/lab_approval_registration.py --code $Code --snapshot-id $SnapshotId
    exit $LASTEXITCODE
}
finally { Pop-Location }
