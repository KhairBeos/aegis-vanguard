[CmdletBinding()]
param(
    [switch]$RunDefenderScan,

    # Opt-in: runs a benign encoded PowerShell command so the deployed detection rule
    # T1059.001 has something to match. Kept behind a switch because plain ingestion
    # verification should not manufacture alerts.
    [switch]$TriggerEncodedCommandRule
)

$ErrorActionPreference = 'Stop'

$markerDirectory = 'C:\AEGIS\markers'
$startUtc = [DateTime]::UtcNow
$markerId = 'AEGIS-{0}-{1}' -f $startUtc.ToString('yyyyMMddTHHmmssfffZ'), [Guid]::NewGuid().ToString('N').Substring(0, 8)

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($RunDefenderScan -and -not (Test-Administrator)) {
    Write-Error 'Run PowerShell as Administrator when using -RunDefenderScan.'
    exit 1
}

try {
    $null = New-Item -ItemType Directory -Path $markerDirectory -Force

    $scriptBlock = [ScriptBlock]::Create("Write-Output '$markerId' | Out-Null")
    & $scriptBlock
    Write-Host 'PASS: PowerShell marker script block executed.' -ForegroundColor Green

    & $env:ComSpec /d /c "echo $markerId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cmd.exe marker returned exit code $LASTEXITCODE."
    }
    Write-Host 'PASS: cmd.exe marker executed.' -ForegroundColor Green

    $markerFile = Join-Path $markerDirectory "$markerId.ps1"
    Set-Content -LiteralPath $markerFile -Encoding UTF8 -Value "Write-Output '$markerId'"
    Write-Host "PASS: Marker file created at $markerFile." -ForegroundColor Green

    try {
        Resolve-DnsName -Name 'example.com' -Type A -ErrorAction Stop | Out-Null
        Write-Host 'PASS: Benign DNS lookup completed.' -ForegroundColor Green
    }
    catch {
        Write-Warning "DNS lookup was attempted but did not resolve: $($_.Exception.Message)"
    }

    if ($TriggerEncodedCommandRule) {
        # The payload only echoes the marker id. -EncodedCommand expects UTF-16LE base64.
        $ruleProbeCommand = "Write-Output '$markerId'"
        $ruleProbeEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ruleProbeCommand))

        & powershell.exe -NoProfile -EncodedCommand $ruleProbeEncoded | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Encoded-command rule probe returned exit code $LASTEXITCODE."
        }

        Write-Host 'PASS: Benign encoded-command probe executed (expect one detection alert).' -ForegroundColor Green
    }

    if ($RunDefenderScan) {
        $defenderCommand = Get-Command -Name Start-MpScan -ErrorAction SilentlyContinue
        if ($null -eq $defenderCommand) {
            throw 'Start-MpScan is unavailable; Defender custom scan was not started.'
        }

        Start-MpScan -ScanType CustomScan -ScanPath $markerDirectory
        Write-Host "PASS: Defender custom scan requested for $markerDirectory." -ForegroundColor Green
    }

    $endUtc = [DateTime]::UtcNow
    Write-Host ''
    Write-Host "MarkerId: $markerId"
    Write-Host "StartUtc: $($startUtc.ToString('o'))"
    Write-Host "EndUtc: $($endUtc.ToString('o'))"
    if ($TriggerEncodedCommandRule) {
        Write-Host ''
        Write-Host 'Collect the result from the host with:' -ForegroundColor Cyan
        Write-Host "  .\scripts\collect-evidence.ps1 -ScenarioId <id> -ExecutionStartUtc '$($startUtc.ToString('o'))' -ExecutionEndUtc '$($endUtc.ToString('o'))' -MarkerId $markerId"
    }
    exit 0
}
catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
