[CmdletBinding()]
param(
    [ValidateRange(5, 600)]
    [int]$DurationSeconds = 60,

    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = 'C:\AEGIS\capture',

    # Generates a little benign traffic so a short capture is not empty.
    [switch]$GenerateTraffic
)

# Captures network traffic inside victim-win-01 using pktmon, which ships with Windows, and
# converts it to pcapng for offline Suricata analysis on the host.
#
# REQUIRES AN ELEVATED SESSION. pktmon talks to a kernel driver and returns
# "Failed to communicate with the PktMon driver: Access is denied" otherwise. VBoxManage
# guestcontrol cannot obtain an elevated token on this VM, so this script is the one step
# in the network telemetry path that a human has to start.

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host 'FAIL: run this from an Administrator PowerShell session.' -ForegroundColor Red
    Write-Host '      pktmon requires elevation to attach to its kernel driver.' -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$etlPath = Join-Path $OutputDirectory "aegis-$stamp.etl"
$pcapPath = Join-Path $OutputDirectory "aegis-$stamp.pcapng"

$startUtc = [DateTime]::UtcNow

try {
    & pktmon start --capture --pkt-size 0 -f $etlPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon start exited $LASTEXITCODE" }
    Write-Host "PASS: capture started -> $etlPath" -ForegroundColor Green

    if ($GenerateTraffic) {
        # Benign and local: a DNS lookup that will not resolve on the host-only network, and
        # an HTTP request to Elasticsearch which is already a normal destination for this host.
        try { Resolve-DnsName -Name 'aegis-lab-probe.example' -Type A -ErrorAction Stop | Out-Null } catch { }
        try { Invoke-WebRequest -Uri 'http://192.168.56.1:9200' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch { }
        Write-Host 'PASS: benign probe traffic generated.' -ForegroundColor Green
    }

    Write-Host "capturing for $DurationSeconds second(s)..."
    Start-Sleep -Seconds $DurationSeconds
}
finally {
    & pktmon stop | Out-Null
    Write-Host 'PASS: capture stopped.' -ForegroundColor Green
}

$endUtc = [DateTime]::UtcNow

& pktmon etl2pcap $etlPath -o $pcapPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcapPath)) {
    Write-Host "FAIL: etl2pcap did not produce $pcapPath" -ForegroundColor Red
    exit 1
}

$sizeBytes = (Get-Item -LiteralPath $pcapPath).Length
Write-Host "PASS: converted to $pcapPath ($sizeBytes bytes)" -ForegroundColor Green
Write-Host ''
Write-Host "StartUtc : $($startUtc.ToString('o'))"
Write-Host "EndUtc   : $($endUtc.ToString('o'))"
Write-Host "Pcap     : $pcapPath"
Write-Host ''
Write-Host 'Copy it to the host, then analyse and ingest it there:' -ForegroundColor Cyan
Write-Host '  VBoxManage guestcontrol victim-win-01 copyfrom --target-directory <host-dir> ' -NoNewline
Write-Host "$pcapPath"
Write-Host '  .\scripts\analyze-network-telemetry.ps1 -PcapPath <host-dir>\' -NoNewline
Write-Host "$(Split-Path -Leaf $pcapPath) -UpdateRules"

exit 0
