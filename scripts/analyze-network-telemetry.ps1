[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PcapPath,

    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [ValidateNotNullOrEmpty()]
    [string]$DataStream = 'logs-suricata.eve-aegis_lab',

    [ValidateNotNullOrEmpty()]
    [string]$SuricataImage = 'jasonish/suricata:latest',

    # Rule updates reach out to the internet, so they are opt-in and never happen implicitly.
    [switch]$UpdateRules,

    # A self-authored local ruleset (e.g. infra/suricata/local.rules). Loaded in addition to
    # ET Open when supplied. A detection from a local rule is Runtime verified, not Live verified.
    [string]$LocalRulesPath,

    [switch]$KeepWorkingDirectory
)

# Runs Suricata over a packet capture and ships the resulting EVE JSON into Elasticsearch.
#
# Suricata reads a file here rather than sniffing an interface. Live capture is not possible
# from this host: Docker Desktop containers sit behind the WSL2 network namespace and cannot
# see the VirtualBox host-only adapter. Capture happens inside the victim VM instead, with
# scripts/windows/capture-network-telemetry.ps1, and the resulting pcap is analysed here.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

if (-not (Test-Path -LiteralPath $PcapPath)) {
    Write-Host "FAIL: capture not found: $PcapPath" -ForegroundColor Red
    exit 1
}

$resolvedPcap = (Resolve-Path -LiteralPath $PcapPath).ProviderPath
$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("aegis-suricata-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Copy-Item -LiteralPath $resolvedPcap -Destination (Join-Path $workRoot 'input.pcap') -Force

$authHeader = Get-AegisElasticAuthHeader
$baseUrl = $ElasticsearchUrl.TrimEnd('/')
$rulesArgument = @()

try {
    if ($UpdateRules) {
        Write-Host 'Fetching the ET Open ruleset (requires internet)...'
        & docker run --rm -v "${workRoot}:/data" $SuricataImage suricata-update --no-test --data-dir /data/su --local /data 2>&1 |
            Select-String -Pattern 'Writing rules to' | ForEach-Object { "  $($_.Line)" }
    }

    $rulesPath = Join-Path $workRoot 'su\rules\suricata.rules'
    if (Test-Path -LiteralPath $rulesPath) {
        $rulesArgument += @('-S', '/data/su/rules/suricata.rules')
        Write-Host "PASS: using ET Open ruleset at $rulesPath" -ForegroundColor Green
    }

    if ($LocalRulesPath) {
        if (-not (Test-Path -LiteralPath $LocalRulesPath)) {
            Write-Host "FAIL: local rules not found: $LocalRulesPath" -ForegroundColor Red
            exit 1
        }
        Copy-Item -LiteralPath (Resolve-Path -LiteralPath $LocalRulesPath).ProviderPath -Destination (Join-Path $workRoot 'local.rules') -Force
        $rulesArgument += @('-S', '/data/local.rules')
        Write-Host "PASS: using local ruleset $LocalRulesPath" -ForegroundColor Green
    }

    if ($rulesArgument.Count -eq 0) {
        Write-Host 'WARN: no ruleset present; protocol records will be produced but no alerts.' -ForegroundColor Yellow
        Write-Host '      Re-run with -UpdateRules to fetch ET Open, or -LocalRulesPath for lab rules.' -ForegroundColor Yellow
    }

    & docker run --rm -v "${workRoot}:/data" $SuricataImage suricata -r /data/input.pcap -l /data @rulesArgument 2>&1 |
        Select-String -Pattern 'read 1 file|error' | ForEach-Object { "  $($_.Line)" }

    $evePath = Join-Path $workRoot 'eve.json'
    if (-not (Test-Path -LiteralPath $evePath)) {
        Write-Host 'FAIL: Suricata produced no eve.json' -ForegroundColor Red
        exit 1
    }

    # stats records describe the Suricata process, not the network, so they are dropped.
    $records = @(
        Get-Content -LiteralPath $evePath |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.event_type -ne 'stats' }
    )

    if ($records.Count -eq 0) {
        Write-Host 'FAIL: no network records to ingest' -ForegroundColor Red
        exit 1
    }

    $byType = $records | Group-Object event_type
    Write-Host "`nPASS: $($records.Count) record(s) parsed" -ForegroundColor Green
    $byType | ForEach-Object { "  {0,-10} {1}" -f $_.Name, $_.Count }

    # Suricata writes its own `timestamp`; Elasticsearch data streams require @timestamp.
    $bulk = [Text.StringBuilder]::new()
    foreach ($record in $records) {
        $record | Add-Member -NotePropertyName '@timestamp' -NotePropertyValue $record.timestamp -Force
        $record | Add-Member -NotePropertyName 'observer' -NotePropertyValue ([pscustomobject]@{ type = 'ids'; vendor = 'Suricata' }) -Force
        [void]$bulk.AppendLine('{"create":{}}')
        [void]$bulk.AppendLine(($record | ConvertTo-Json -Depth 30 -Compress))
    }

    try {
        $response = Invoke-RestMethod `
            -Method POST `
            -Uri "$baseUrl/$DataStream/_bulk?refresh=true" `
            -Headers $authHeader `
            -ContentType 'application/x-ndjson' `
            -Body $bulk.ToString() `
            -ErrorAction Stop
    }
    catch {
        Write-Host "FAIL: bulk ingest failed - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $failed = @($response.items | Where-Object { $_.create.error })
    if ($failed.Count -gt 0) {
        Write-Host "FAIL: $($failed.Count) document(s) rejected" -ForegroundColor Red
        $failed | Select-Object -First 3 | ForEach-Object { "  $($_.create.error.reason)" }
        exit 1
    }

    Write-Host "PASS: ingested $($records.Count) record(s) into $DataStream" -ForegroundColor Green
    Write-Host ''
    Write-Host 'This is offline analysis of a capture, not a live IDS deployment.' -ForegroundColor Yellow
    Write-Host 'Nothing here is evidence of network detection unless the capture came from the VM.' -ForegroundColor Yellow
    exit 0
}
finally {
    if ($KeepWorkingDirectory) {
        Write-Host "working directory kept: $workRoot"
    }
    else {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
