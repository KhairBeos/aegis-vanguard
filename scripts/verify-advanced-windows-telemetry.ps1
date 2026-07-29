[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedHostName,

    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 30,

    [ValidatePattern('^AEGIS-\d{8}T\d{9}Z-[0-9a-fA-F]{8}$')]
    [string]$MarkerId
)

$ErrorActionPreference = 'Stop'

$namespace = 'aegis_lab'
$normalizedExpectedHostName = $ExpectedHostName.Trim().ToLowerInvariant()
$failures = [System.Collections.Generic.List[string]]::new()

$sources = @(
    [pscustomobject]@{
        Name             = 'Sysmon'
        Channel          = 'Microsoft-Windows-Sysmon/Operational'
        Dataset          = 'windows.sysmon'
        PreferredEventId = $null
    }
    [pscustomobject]@{
        Name             = 'PowerShell'
        Channel          = 'Microsoft-Windows-PowerShell/Operational'
        Dataset          = 'windows.powershell'
        PreferredEventId = '4104'
    }
    [pscustomobject]@{
        Name             = 'Defender'
        Channel          = 'Microsoft-Windows-Windows Defender/Operational'
        Dataset          = 'windows.defender'
        PreferredEventId = $null
    }
)

function Write-Pass {
    param([string]$Message)
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Write-Warn {
    param([string]$Message)
    Write-Host "WARN: $Message" -ForegroundColor Yellow
}

function Invoke-ElasticsearchJson {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [object]$Body
    )

    $baseUrl = $ElasticsearchUrl.TrimEnd('/')
    $uri = if ($Path.StartsWith('/')) { "$baseUrl$Path" } else { "$baseUrl/$Path" }
    $requestParameters = @{
        Method      = $Method
        Uri         = $uri
        ErrorAction = 'Stop'
    }

    if ($null -ne $Body) {
        $requestParameters.ContentType = 'application/json'
        $requestParameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    Invoke-RestMethod @requestParameters
}

function Get-ErrorSummary {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = $null
    if ($null -ne $ErrorRecord.Exception.Response -and
        $null -ne $ErrorRecord.Exception.Response.StatusCode) {
        $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
    }

    if ($null -ne $statusCode) {
        return "HTTP $statusCode - $($ErrorRecord.Exception.Message)"
    }

    $ErrorRecord.Exception.Message
}

function New-RecentQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Channel,

        [switch]$IncludeExpectedHost,

        [ValidateRange(1, 20)]
        [int]$Size = 1
    )

    $filters = @(
        @{
            term = @{
                'winlog.channel' = $Channel
            }
        }
        @{
            range = @{
                '@timestamp' = @{
                    gte = "now-$($LookbackMinutes)m"
                }
            }
        }
    )

    if ($IncludeExpectedHost) {
        $filters += @{
            term = @{
                'host.name' = $normalizedExpectedHostName
            }
        }
    }

    @{
        size             = $Size
        track_total_hits = $false
        sort             = @(
            @{
                '@timestamp' = @{
                    order = 'desc'
                }
            }
        )
        _source          = @(
            '@timestamp'
            'host.name'
            'winlog.channel'
            'winlog.event_id'
            'event.code'
        )
        query            = @{
            bool = @{
                filter = $filters
            }
        }
    }
}

function Get-SafeEventId {
    param([Parameter(Mandatory = $true)][psobject]$Hit)

    $eventCode = $Hit._source.event.code
    if (-not [string]::IsNullOrWhiteSpace([string]$eventCode)) {
        return [string]$eventCode
    }

    $winlogEventId = $Hit._source.winlog.event_id
    if (-not [string]::IsNullOrWhiteSpace([string]$winlogEventId)) {
        return [string]$winlogEventId
    }

    'unknown'
}

try {
    $rootResponse = Invoke-ElasticsearchJson -Method GET -Path '/'
    $version = $rootResponse.version.number
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw 'Elasticsearch responded without a version number.'
    }
    Write-Pass "Elasticsearch is reachable at $ElasticsearchUrl (version $version)."
}
catch {
    $summary = Get-ErrorSummary -ErrorRecord $_
    Write-Fail "Elasticsearch HTTP error: $summary"
    foreach ($source in $sources) {
        Write-Fail "$($source.Name) source was not checked because Elasticsearch is unavailable."
    }
    Write-Host ''
    Write-Host "Advanced Windows telemetry verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

try {
    $dataStreamResponse = Invoke-ElasticsearchJson `
        -Method GET `
        -Path "/_data_stream/logs-windows.*-${namespace}?expand_wildcards=all"
    $dataStreamNames = @($dataStreamResponse.data_streams | ForEach-Object { $_.name })
}
catch {
    $summary = Get-ErrorSummary -ErrorRecord $_
    Write-Fail "Advanced data-stream discovery HTTP error: $summary"
    foreach ($source in $sources) {
        Write-Fail "$($source.Name) source was not checked because data-stream discovery failed."
    }
    Write-Host ''
    Write-Host "Advanced Windows telemetry verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

foreach ($source in $sources) {
    $dataStream = "logs-$($source.Dataset)-$namespace"

    if ($dataStream -notin $dataStreamNames) {
        Write-Fail "$($source.Name) data stream does not exist: $dataStream"
        continue
    }
    Write-Pass "$($source.Name) data stream exists: $dataStream"

    try {
        $channelResponse = Invoke-ElasticsearchJson `
            -Method POST `
            -Path "/${dataStream}/_search" `
            -Body (New-RecentQuery -Channel $source.Channel)
    }
    catch {
        Write-Fail "$($source.Name) Elasticsearch HTTP error: $(Get-ErrorSummary -ErrorRecord $_)"
        continue
    }

    $channelHit = @($channelResponse.hits.hits) | Select-Object -First 1
    if ($null -eq $channelHit) {
        Write-Fail "$($source.Name) channel has no recent event within $LookbackMinutes minute(s): $($source.Channel)"
        continue
    }

    try {
        $hostResponse = Invoke-ElasticsearchJson `
            -Method POST `
            -Path "/${dataStream}/_search" `
            -Body (New-RecentQuery -Channel $source.Channel -IncludeExpectedHost -Size 10)
    }
    catch {
        Write-Fail "$($source.Name) Elasticsearch HTTP error: $(Get-ErrorSummary -ErrorRecord $_)"
        continue
    }

    $hostHits = @($hostResponse.hits.hits)
    if ($hostHits.Count -eq 0) {
        Write-Fail "$($source.Name) hostname mismatch: recent channel data exists, but none matches '$normalizedExpectedHostName'."
        continue
    }

    $selectedHit = $hostHits | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace($source.PreferredEventId)) {
        $preferredQuery = New-RecentQuery -Channel $source.Channel -IncludeExpectedHost
        $preferredQuery.query.bool.filter += @{
            bool = @{
                should = @(
                    @{
                        term = @{
                            'event.code' = $source.PreferredEventId
                        }
                    }
                    @{
                        term = @{
                            'winlog.event_id' = $source.PreferredEventId
                        }
                    }
                )
                minimum_should_match = 1
            }
        }

        try {
            $preferredResponse = Invoke-ElasticsearchJson `
                -Method POST `
                -Path "/${dataStream}/_search" `
                -Body $preferredQuery
            $preferredHit = @($preferredResponse.hits.hits) | Select-Object -First 1
            if ($null -ne $preferredHit) {
                $selectedHit = $preferredHit
            }
        }
        catch {
            Write-Warn "$($source.Name) preferred event search HTTP error: $(Get-ErrorSummary -ErrorRecord $_)"
        }
    }

    $timestamp = $selectedHit._source.'@timestamp'
    $eventId = Get-SafeEventId -Hit $selectedHit
    if ($source.Name -eq 'Sysmon') {
        Write-Pass "Sysmon recent event found; latest selected event ID: $eventId; timestamp: $timestamp"
    }
    elseif ($source.Name -eq 'PowerShell') {
        $preference = if ($eventId -eq '4104') { 'preferred 4104 event' } else { 'latest available event' }
        Write-Pass "PowerShell recent event found; $preference ID: $eventId; timestamp: $timestamp"
    }
    else {
        Write-Pass "Defender recent Operational event found; event ID: $eventId; timestamp: $timestamp"
    }

    if (-not [string]::IsNullOrWhiteSpace($MarkerId)) {
        $markerQuery = New-RecentQuery -Channel $source.Channel -IncludeExpectedHost
        $markerQuery.query.bool.must = @(
            @{
                multi_match = @{
                    query  = $MarkerId
                    type   = 'phrase'
                    lenient = $true
                    fields = @(
                        'message'
                        'event.original'
                        'powershell.file.script_block_text'
                        'process.command_line'
                        'file.path'
                        'winlog.event_data.*'
                    )
                }
            }
        )

        try {
            $markerResponse = Invoke-ElasticsearchJson `
                -Method POST `
                -Path "/${dataStream}/_search" `
                -Body $markerQuery
            $markerHit = @($markerResponse.hits.hits) | Select-Object -First 1
            if ($null -ne $markerHit) {
                Write-Pass "$($source.Name) marker found: $MarkerId"
            }
            else {
                Write-Warn "$($source.Name) has recent data, but marker was not found: $MarkerId"
            }
        }
        catch {
            Write-Warn "$($source.Name) marker search HTTP error: $(Get-ErrorSummary -ErrorRecord $_)"
        }
    }
}

Write-Host ''

if ($failures.Count -gt 0) {
    Write-Host "Advanced Windows telemetry verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host 'Advanced Windows telemetry verification passed.' -ForegroundColor Green
exit 0
