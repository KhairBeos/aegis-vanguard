[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedHostName,

    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 15
)

$ErrorActionPreference = 'Stop'

$namespace = 'aegis_lab'
$normalizedExpectedHostName = $ExpectedHostName.Trim().ToLowerInvariant()

$failures = [System.Collections.Generic.List[string]]::new()

$channels = @(
    [pscustomobject]@{
        Name    = 'Application'
        Dataset = 'system.application'
    }
    [pscustomobject]@{
        Name    = 'System'
        Dataset = 'system.system'
    }
    [pscustomobject]@{
        Name    = 'Security'
        Dataset = 'system.security'
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

    if ($Path.StartsWith('/')) {
        $uri = "$baseUrl$Path"
    }
    else {
        $uri = "$baseUrl/$Path"
    }

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

# 1. Elasticsearch connectivity
try {
    $rootResponse = Invoke-ElasticsearchJson -Method GET -Path '/'

    $version = $rootResponse.version.number

    if ([string]::IsNullOrWhiteSpace($version)) {
        Write-Fail "Elasticsearch responded but did not return a version"
    }
    else {
        Write-Pass "Elasticsearch is reachable at $ElasticsearchUrl (version $version)"
    }
}
catch {
    Write-Fail "Elasticsearch is not reachable: $($_.Exception.Message)"
}

# 2. Required Windows data streams
try {
    $dataStreamResponse = Invoke-ElasticsearchJson `
        -Method GET `
        -Path "/_data_stream/logs-system.*-$namespace?expand_wildcards=all"

    $dataStreamNames = @(
        $dataStreamResponse.data_streams |
            ForEach-Object { $_.name }
    )

    $expectedDataStreamNames = @(
        $channels |
            ForEach-Object {
                "logs-$($_.Dataset)-$namespace"
            }
    )

    $missingDataStreamNames = @(
        $expectedDataStreamNames |
            Where-Object {
                $_ -notin $dataStreamNames
            }
    )

    if ($missingDataStreamNames.Count -gt 0) {
        Write-Fail "Missing Windows log data streams: $($missingDataStreamNames -join ', ')"
    }
    else {
        Write-Pass "Windows log data streams: $($dataStreamNames -join ', ')"
    }
}
catch {
    Write-Fail "Failed to query Windows log data streams: $($_.Exception.Message)"
}

# 3. Recent document for each Windows channel
foreach ($channel in $channels) {
    $dataStream = "logs-$($channel.Dataset)-$namespace"

    $query = @{
        size             = 1
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
            'winlog.provider_name'
            'event.code'
        )
        query            = @{
            bool = @{
                filter = @(
                    @{
                        term = @{
                            'host.name' = $normalizedExpectedHostName
                        }
                    }
                    @{
                        term = @{
                            'winlog.channel' = $channel.Name
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
            }
        }
    }

    try {
        $searchResponse = Invoke-ElasticsearchJson `
            -Method POST `
            -Path "/$dataStream/_search" `
            -Body $query

        $latestHit = @($searchResponse.hits.hits) |
            Select-Object -First 1

        if ($null -eq $latestHit) {
            Write-Fail "No recent $($channel.Name) document for host '$normalizedExpectedHostName' within $LookbackMinutes minute(s)"
            continue
        }

        $latestTimestamp = $latestHit._source.'@timestamp'

        if ([string]::IsNullOrWhiteSpace($latestTimestamp)) {
            Write-Fail "$($channel.Name) document exists but has no @timestamp"
            continue
        }

        Write-Pass "$($channel.Name) channel latest timestamp: $latestTimestamp"
    }
    catch {
        Write-Fail "Failed to query $($channel.Name) channel: $($_.Exception.Message)"
    }
}

Write-Host ''

if ($failures.Count -gt 0) {
    Write-Host "Windows ingestion verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host "Windows ingestion verification passed." -ForegroundColor Green
exit 0