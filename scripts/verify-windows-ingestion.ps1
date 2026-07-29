[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedHostName,

    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 15
)

$ErrorActionPreference = 'Stop'
$baseUrl = $ElasticsearchUrl.TrimEnd('/')
$namespace = 'aegis_lab'
$failures = [System.Collections.Generic.List[string]]::new()
$channels = @(
    [pscustomobject]@{ Name = 'Application'; Dataset = 'system.application' }
    [pscustomobject]@{ Name = 'System'; Dataset = 'system.system' }
    [pscustomobject]@{ Name = 'Security'; Dataset = 'system.security' }
)

function Write-Pass {
    param([string]$Message)
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    $failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Invoke-ElasticsearchRequest {
    param(
        [ValidateSet('Get', 'Post')]
        [string]$Method,
        [string]$Path,
        [hashtable]$Body
    )

    $request = @{
        Uri        = "$baseUrl$Path"
        Method     = $Method
        TimeoutSec = 15
    }

    if ($Body) {
        $request.ContentType = 'application/json'
        $request.Body = $Body | ConvertTo-Json -Depth 10
    }

    Invoke-RestMethod @request
}

try {
    $root = Invoke-ElasticsearchRequest -Method Get -Path '/'
    Write-Pass "Elasticsearch is reachable at $baseUrl (version $($root.version.number))"
}
catch {
    Write-Fail "Elasticsearch is not reachable at $baseUrl - $($_.Exception.Message)"
    foreach ($channel in $channels) {
        Write-Fail "$($channel.Name) channel was not checked because Elasticsearch is unavailable"
    }
    exit 1
}

try {
    $dataStreams = Invoke-ElasticsearchRequest -Method Get -Path "/_data_stream/logs-system.*-$namespace?expand_wildcards=all"
    $dataStreamNames = @($dataStreams.data_streams | ForEach-Object { $_.name })
    if ($dataStreamNames.Count -eq 0) {
        Write-Fail "No Windows log data streams exist in namespace '$namespace'"
    }
    else {
        Write-Pass "Windows log data streams: $($dataStreamNames -join ', ')"
    }
}
catch {
    Write-Fail "Windows log data streams are unavailable - $($_.Exception.Message)"
}

foreach ($channel in $channels) {
    $dataStream = "logs-$($channel.Dataset)-$namespace"
    $query = @{
        size             = 1
        track_total_hits = $false
        sort             = @(
            @{ '@timestamp' = @{ order = 'desc' } }
        )
        '_source'        = @('@timestamp')
        query            = @{
            bool = @{
                filter = @(
                    @{ term = @{ 'host.name' = $ExpectedHostName } }
                    @{ term = @{ 'winlog.channel' = $channel.Name } }
                    @{ range = @{ '@timestamp' = @{ gte = "now-$($LookbackMinutes)m" } } }
                )
            }
        }
    }

    try {
        $result = Invoke-ElasticsearchRequest -Method Post -Path "/$dataStream/_search" -Body $query
        $hits = @($result.hits.hits)
        if ($hits.Count -eq 0) {
            Write-Fail "No recent $($channel.Name) document for host '$ExpectedHostName' within $LookbackMinutes minute(s)"
            continue
        }

        $latestTimestamp = $hits[0]._source.'@timestamp'
        Write-Pass "$($channel.Name) channel latest timestamp: $latestTimestamp"
    }
    catch {
        Write-Fail "$($channel.Name) channel query failed - $($_.Exception.Message)"
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`nWindows ingestion verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host "`nWindows ingestion verification passed for all three channels." -ForegroundColor Green
exit 0
