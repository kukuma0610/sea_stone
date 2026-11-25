[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^OSGuardLabApproval-[0-9a-f]{32}$')][string]$PipeName,
    [string]$UserName,
    [switch]$AsOwner
)
$ErrorActionPreference = 'Stop'
try {
    if (-not $AsOwner) {
        $credential = Get-Credential -UserName $UserName -Message 'TEST_OWNER Windows login. Do not use the administrator account.'
        if ($null -eq $credential) { exit 1 }
        $exe = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell1.0powershell.exe'
        $arguments = @('-NoLogo', '-NoProfile', '-File', ('"' + $PSCommandPath + '"'), '-AsOwner', '-PipeName', $PipeName)
        # 승인자가 직접 보는 로그인/동의 창이다. 암호를 argv, 파일, 로그로 전달하지 않는다.
        $child = Start-Process -FilePath $exe -Credential $credential -LoadUserProfile -ArgumentList $arguments -WindowStyle Normal -PassThru -Wait
        exit $child.ExitCode
    }
    $pipe = New-Object IO.Pipes.NamedPipeClientStream -ArgumentList '.', $PipeName, ([IO.Pipes.PipeDirection]::InOut), ([IO.Pipes.PipeOptions]::None), ([Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        $pipe.Connect(30000)
        $reader = New-Object IO.StreamReader -ArgumentList $pipe, ([Text.UTF8Encoding]::new($false)), $false, 1024, $true
        $writer = New-Object IO.StreamWriter -ArgumentList $pipe, ([Text.UTF8Encoding]::new($false)), 1024, $true
        $writer.AutoFlush = $true
        $request = $reader.ReadLine() | ConvertFrom-Json
        if ($request.protocol -cne 'LAB-APPROVAL-1' -or $request.risk -cne 'POLICY_OVERDUE_MEANING_UNVERIFIED') { throw 'PROTOCOL' }
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $request.owner_sid) { throw 'ACCOUNT' }
        Write-Host 'TEST_OWNER: authenticated Windows account; approval registration only.'
        Write-Host ('VM: ' + $request.vm_uuid)
        Write-Host ('Commit: ' + $request.commit)
        Write-Host ('Item: ' + $request.code + ' Snapshot: ' + $request.snapshot_id)
        Write-Host 'PolicyOverdue=0 meaning remains UNVERIFIED. Accept only isolated VM testing with recovery.'
        Write-Host 'Confirm no operating network, work data or production credentials; the VMware recovery snapshot must exist.'
        Write-Host 'No hardening will run from this window.'
        $accepted = (Read-Host ('Type ACCEPT ' + $request.code + ' to accept this specific risk')) -ceq ('ACCEPT ' + $request.code)
        $reply = @{approval_id=$request.approval_id; nonce=$request.nonce; accepted=[bool]$accepted}
        $writer.WriteLine(($reply | ConvertTo-Json -Compress))
        $ack = $reader.ReadLine() | ConvertFrom-Json
        if (-not $accepted -or $ack.received -ne $true) { throw 'DECLINED' }
        Write-Host 'Consent received. No system policy was changed.'
    }
    finally { $pipe.Dispose() }
    exit 0
}
catch {
    Write-Host 'Owner logon/consent failed or was declined. No approval issued.'
    exit 1
}
