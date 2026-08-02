[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [ValidateNotNullOrEmpty()]
    [string]$Topic = 'aegis.alerts',

    [ValidateNotNullOrEmpty()]
    [string]$Container = 'aegis-kafka',

    [ValidateRange(1, 500)]
    [int]$MaxAlerts = 50
)

# Answers the one question PROJECT_PLAN.md asks of Phase 7: can an event path that already
# has evidence behind it cross Kafka without losing records?
#
# Real detection alerts are read from Elasticsearch, produced to a topic, consumed back, and
# compared by content hash. Anything weaker - synthetic messages, or comparing counts only -
# would not answer the question, because a broker that silently reorders or truncates
# payloads would still pass a count check.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$authHeader = Get-AegisElasticAuthHeader
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Pass { param([string]$Message) Write-Host "PASS: $Message" -ForegroundColor Green }
function Write-Fail {
    param([string]$Message)
    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Get-Sha256 {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $sha.Dispose() }
}

# 1. Source records ----------------------------------------------------------------------
try {
    $query = @{
        size    = $MaxAlerts
        sort    = @(@{ '@timestamp' = @{ order = 'asc' } })
        _source = @('@timestamp', 'kibana.alert.uuid', 'kibana.alert.rule.rule_id', 'kibana.alert.original_time')
        query   = @{ match_all = @{} }
    } | ConvertTo-Json -Depth 20 -Compress

    $response = Invoke-RestMethod `
        -Method POST `
        -Uri "$($ElasticsearchUrl.TrimEnd('/'))/.alerts-security.alerts-default/_search" `
        -Headers $authHeader `
        -ContentType 'application/json' `
        -Body $query `
        -ErrorAction Stop
}
catch {
    Write-Fail "could not read alerts from Elasticsearch - $($_.Exception.Message)"
    exit 1
}

$sourceMessages = @(
    $response.hits.hits | ForEach-Object {
        [pscustomobject]@{
            alert_uuid  = $_._source.'kibana.alert.uuid'
            rule_id     = $_._source.'kibana.alert.rule.rule_id'
            alert_time  = $_._source.'@timestamp'
            source_time = $_._source.'kibana.alert.original_time'
        } | ConvertTo-Json -Depth 10 -Compress
    }
)

if ($sourceMessages.Count -eq 0) {
    Write-Fail 'no alerts exist to transport; run a detection scenario first'
    exit 1
}
Write-Pass "read $($sourceMessages.Count) real alert(s) from Elasticsearch"

# 2. Produce ------------------------------------------------------------------------------
$topicArgs = @('--bootstrap-server', 'localhost:9092', '--topic', $Topic)
& docker exec $Container /opt/kafka/bin/kafka-topics.sh --create --if-not-exists @topicArgs --partitions 1 --replication-factor 1 2>&1 | Out-Null

$sourceMessages -join "`n" | & docker exec -i $Container /opt/kafka/bin/kafka-console-producer.sh @topicArgs 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Fail "producer exited $LASTEXITCODE"
    exit 1
}
Write-Pass "produced $($sourceMessages.Count) message(s) to topic '$Topic'"

# 3. Consume ------------------------------------------------------------------------------
# The consumer writes its progress line ("Processed a total of N messages") to stderr.
# Windows PowerShell 5.1 wraps native stderr in an ErrorRecord, which under
# $ErrorActionPreference = 'Stop' aborts the script on a perfectly successful run.
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $consumed = @(
        & docker exec $Container /opt/kafka/bin/kafka-console-consumer.sh @topicArgs `
            --from-beginning --max-messages $sourceMessages.Count --timeout-ms 20000
    ) | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) }
}
finally {
    $ErrorActionPreference = $previousPreference
}

Write-Pass "consumed $($consumed.Count) message(s) back"

# 4. Compare -------------------------------------------------------------------------------
if ($consumed.Count -ne $sourceMessages.Count) {
    Write-Fail "count mismatch: produced $($sourceMessages.Count), consumed $($consumed.Count)"
}
else {
    Write-Pass "count matches: $($sourceMessages.Count) in, $($consumed.Count) out"
}

$producedHashes = @($sourceMessages | ForEach-Object { Get-Sha256 $_.Trim() } | Sort-Object)
$consumedHashes = @($consumed | ForEach-Object { Get-Sha256 $_.Trim() } | Sort-Object)
$missing = @(Compare-Object -ReferenceObject $producedHashes -DifferenceObject $consumedHashes)

if ($missing.Count -eq 0) {
    Write-Pass 'every message came back byte-identical (SHA-256 per record)'
}
else {
    Write-Fail "$($missing.Count) message(s) differ between produced and consumed"
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "Kafka transport verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host 'Kafka transport verification passed.' -ForegroundColor Green
Write-Host 'This shows records survive the broker. It does not make Kafka useful here:' -ForegroundColor Yellow
Write-Host 'at this volume the broker earns nothing operationally and is an architecture' -ForegroundColor Yellow
Write-Host 'demonstration only.' -ForegroundColor Yellow
exit 0
