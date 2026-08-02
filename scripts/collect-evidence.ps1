[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ScenarioId,

    # Strings, not [datetime]. A [datetime] passed through -File loses its Kind, gets
    # re-parsed as local time, and is then shifted again by ToUniversalTime(), which
    # silently corrupts every timestamp in the bundle. Parsed explicitly below instead.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExecutionStartUtc,

    [string]$ExecutionEndUtc,

    [string]$RuleId = '1131fb39-a497-4a09-b051-4e4c89066f5f',

    [string]$MitreTechniqueId = 'T1059.001',

    [string]$AtomicTestNumber = 'not applicable - benign marker run',

    [string]$MarkerId,

    [string]$LabSessionId,

    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [ValidateNotNullOrEmpty()]
    [string]$KibanaUrl = 'http://192.168.56.1:5601',

    # Alerts arrive after the rule's next scheduled run, so look past the execution window.
    [ValidateRange(1, 1440)]
    [int]$AlertGraceMinutes = 30,

    [string]$OutputDirectory
)

# Builds one scenario evidence bundle for the MVP checkpoint in PROJECT_PLAN.md.
# It reports what it finds. It never invents an alert timestamp, and it records
# `missed` honestly when no alert exists.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

function ConvertTo-Utc {
    <#
        Parses a timestamp into UTC with no ambiguity:
        - '2026-08-02T04:41:51Z'      -> 04:41:51 UTC (offset honoured)
        - '2026-08-02T11:41:51+07:00' -> 04:41:51 UTC (offset honoured)
        - '2026-08-02T04:41:51'       -> 04:41:51 UTC (no offset means UTC, never local)
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$ParameterName
    )

    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor
              [Globalization.DateTimeStyles]::AssumeUniversal

    if (-not [datetime]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "$ParameterName is not a valid timestamp: '$Value'. Use ISO 8601, for example 2026-08-02T04:41:51Z."
    }

    $parsed
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repositoryRoot 'evidence' }
if (-not $LabSessionId) { $LabSessionId = 'AEGIS-LAB-{0}' -f (ConvertTo-Utc -Value $ExecutionStartUtc -ParameterName 'ExecutionStartUtc').ToString('yyyyMMdd') }

$authHeader = Get-AegisElasticAuthHeader
$kibanaHeader = Get-AegisElasticAuthHeader
$kibanaHeader['kbn-xsrf'] = 'true'

$esBase = $ElasticsearchUrl.TrimEnd('/')
$startUtc = ConvertTo-Utc -Value $ExecutionStartUtc -ParameterName 'ExecutionStartUtc'
$endUtc = if ([string]::IsNullOrWhiteSpace($ExecutionEndUtc)) {
    [datetime]::UtcNow
}
else {
    ConvertTo-Utc -Value $ExecutionEndUtc -ParameterName 'ExecutionEndUtc'
}

if ($endUtc -lt $startUtc) {
    throw "ExecutionEndUtc ($($endUtc.ToString('o'))) is before ExecutionStartUtc ($($startUtc.ToString('o')))."
}

$alertWindowEndUtc = $endUtc.AddMinutes($AlertGraceMinutes)

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# 1. Rule identity and execution context -------------------------------------------------
try {
    $rule = Invoke-RestMethod `
        -Uri "$($KibanaUrl.TrimEnd('/'))/api/detection_engine/rules?rule_id=$RuleId" `
        -Headers $kibanaHeader `
        -ErrorAction Stop
}
catch {
    Write-Host "FAIL: rule $RuleId is not deployed - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$lastExecution = $rule.execution_summary.last_execution
$ruleExecutionResult = if ($lastExecution) {
    "$($lastExecution.status) at $($lastExecution.date): $($lastExecution.message)"
}
else {
    'no execution recorded yet'
}

# 2. Alerts ------------------------------------------------------------------------------
# Attribution must use the SOURCE event time, not the alert time. One rule execution
# emits every alert at the same @timestamp, so filtering on @timestamp would pull in
# alerts about activity that happened before this scenario and credit them to it.
# kibana.alert.original_time is the time of the event that actually triggered the alert.
$alertQuery = @{
    size             = 50
    track_total_hits = $true
    sort             = @(@{ '@timestamp' = @{ order = 'asc' } })
    query            = @{
        bool = @{
            filter = @(
                @{ term  = @{ 'kibana.alert.rule.rule_id' = $RuleId } }
                @{ range = @{ 'kibana.alert.original_time' = @{
                    gte = $startUtc.ToString('o')
                    lte = $endUtc.ToString('o')
                } } }
                # Bounds the search to alerts this scenario could plausibly have caused.
                @{ range = @{ '@timestamp' = @{
                    gte = $startUtc.ToString('o')
                    lte = $alertWindowEndUtc.ToString('o')
                } } }
            )
        }
    }
} | ConvertTo-Json -Depth 20 -Compress

$alerts = @()
try {
    $alertResponse = Invoke-RestMethod `
        -Method POST `
        -Uri "$esBase/.alerts-security.alerts-default/_search" `
        -Headers $authHeader `
        -ContentType 'application/json' `
        -Body $alertQuery `
        -ErrorAction Stop
    $alerts = @($alertResponse.hits.hits)
}
catch {
    Write-Host "WARN: alerts index unavailable, treating as zero alerts - $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Source documents referenced by the alerts -------------------------------------------
$sourceDocuments = [System.Collections.Generic.List[object]]::new()

foreach ($alert in $alerts) {
    foreach ($ancestor in @($alert._source.'kibana.alert.ancestors')) {
        if (-not $ancestor.id -or -not $ancestor.index) { continue }

        try {
            $sourceHit = Invoke-RestMethod `
                -Method POST `
                -Uri "$esBase/$($ancestor.index)/_search" `
                -Headers $authHeader `
                -ContentType 'application/json' `
                -Body (@{
                    size  = 1
                    query = @{ ids = @{ values = @($ancestor.id) } }
                } | ConvertTo-Json -Depth 10 -Compress) `
                -ErrorAction Stop

            foreach ($hit in @($sourceHit.hits.hits)) {
                $sourceDocuments.Add([pscustomobject]@{
                    document_id = $hit._id
                    index       = $hit._index
                    source      = $hit._source
                }) | Out-Null
            }
        }
        catch {
            Write-Host "WARN: could not fetch source document $($ancestor.id) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# 4. Result ------------------------------------------------------------------------------
$detectionResult = if ($alerts.Count -gt 0) { 'detected' } else { 'missed' }

$firstAlertTimestamp = 'not applicable'
$meanTimeToDetectSeconds = 'not applicable'

if ($alerts.Count -gt 0) {
    $firstAlertTimestamp = $alerts[0]._source.'@timestamp'
    $meanTimeToDetectSeconds = [math]::Round(
        ((ConvertTo-Utc -Value $firstAlertTimestamp -ParameterName 'alert @timestamp') - $startUtc).TotalSeconds, 1)
}

# 5. Raw export and hash -----------------------------------------------------------------
$rawPath = Join-Path $OutputDirectory "$ScenarioId-raw.json"
[pscustomobject]@{
    scenario_id      = $ScenarioId
    lab_session_id   = $LabSessionId
    collected_utc    = [datetime]::UtcNow.ToString('o')
    # Machine-readable summary so scripts/build-coverage.ps1 can derive the MITRE
    # coverage matrix from evidence instead of from a hand-maintained list.
    technique_id     = $MitreTechniqueId
    atomic_test      = $AtomicTestNumber
    marker_id        = $MarkerId
    detection_result = $detectionResult
    alert_count      = $alerts.Count
    source_doc_count = $sourceDocuments.Count
    time_to_detect_s = $meanTimeToDetectSeconds
    execution_start  = $startUtc.ToString('o')
    execution_end    = $endUtc.ToString('o')
    alert_timestamp  = $firstAlertTimestamp
    rule             = [pscustomobject]@{
        rule_id  = $rule.rule_id
        uuid     = $rule.id
        name     = $rule.name
        version  = $rule.version
        interval = $rule.interval
        from     = $rule.from
        to       = $rule.to
        index    = $rule.index
        query    = $rule.query
    }
    alerts           = $alerts
    source_documents = $sourceDocuments
} | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $rawPath -Encoding utf8

$rawHash = (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash

# 6. Report ------------------------------------------------------------------------------
# Analyst prose is the one part of a bundle a machine cannot regenerate, so any existing
# triage note and gap category are carried forward instead of being overwritten.
$reportPath = Join-Path $OutputDirectory "$ScenarioId.md"

function Get-ExistingSection {
    param([string]$Path, [string]$Heading, [string]$NextHeading)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $content = Get-Content -LiteralPath $Path -Raw
    $startIndex = $content.IndexOf("## $Heading")
    if ($startIndex -lt 0) { return $null }

    $bodyStart = $content.IndexOf("`n", $startIndex)
    if ($bodyStart -lt 0) { return $null }

    $endIndex = if ($NextHeading) { $content.IndexOf("## $NextHeading", $bodyStart) } else { -1 }
    $body = if ($endIndex -lt 0) { $content.Substring($bodyStart) } else { $content.Substring($bodyStart, $endIndex - $bodyStart) }

    $body = $body.Trim()
    # An untouched template is not worth preserving.
    if ($body.Length -eq 0 -or $body -replace '(?s)<!--.*?-->', '' -replace '\s', '' -eq 'TODO') { return $null }

    return $body
}

$existingTriage = Get-ExistingSection -Path $reportPath -Heading 'Analyst triage note' -NextHeading 'Gap category'
$existingGap = Get-ExistingSection -Path $reportPath -Heading 'Gap category' -NextHeading 'Why this is recorded as missed'

$reportLines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$Text = '') $reportLines.Add($Text) | Out-Null }

Add-Line "# Scenario evidence bundle: $ScenarioId"
Add-Line
Add-Line '> REDACTION REVIEW REQUIRED before committing. Command lines, script blocks, user'
Add-Line '> names, and host names can carry credentials or personal data. Check the fields'
Add-Line "> listed under Source events and the raw export at ``$([IO.Path]::GetFileName($rawPath))``."
Add-Line
Add-Line '## MVP checkpoint fields'
Add-Line
Add-Line '| Field | Value |'
Add-Line '| --- | --- |'
Add-Line "| Scenario ID | ``$ScenarioId`` |"
Add-Line "| Lab session ID | ``$LabSessionId`` |"
Add-Line "| MITRE technique ID | ``$MitreTechniqueId`` |"
Add-Line "| Atomic test number | $AtomicTestNumber |"
Add-Line "| Rule identity | ``$($rule.rule_id)`` version ``$($rule.version)`` |"
Add-Line "| Rule name | $($rule.name) |"
Add-Line "| Attack execution start (UTC) | ``$($startUtc.ToString('o'))`` |"
Add-Line "| Attack execution end (UTC) | ``$($endUtc.ToString('o'))`` |"
Add-Line "| Alert timestamp (UTC) | ``$firstAlertTimestamp`` |"
Add-Line "| Time to detect (seconds) | $meanTimeToDetectSeconds |"
Add-Line "| Rule execution result | $ruleExecutionResult |"
Add-Line "| Query time window | ``$($rule.from)`` to ``$($rule.to)``, every ``$($rule.interval)`` |"
Add-Line "| Alert deduplication | Detection engine derives a deterministic alert id from the source document and rule identity |"
Add-Line "| Alert count | $($alerts.Count) |"
Add-Line "| Source document count | $($sourceDocuments.Count) |"
Add-Line "| Evidence artifact path | ``evidence/$([IO.Path]::GetFileName($rawPath))`` |"
Add-Line "| Evidence hash (SHA-256) | ``$rawHash`` |"
Add-Line "| Detection result | **$detectionResult** |"
if ($MarkerId) { Add-Line "| Marker ID | ``$MarkerId`` |" }
Add-Line

if ($alerts.Count -gt 0) {
    Add-Line '## Alerts'
    Add-Line
    Add-Line '| Alert UUID | Alert @timestamp | Original event time |'
    Add-Line '| --- | --- | --- |'
    foreach ($alert in $alerts) {
        Add-Line ('| `{0}` | `{1}` | `{2}` |' -f `
            $alert._source.'kibana.alert.uuid', `
            $alert._source.'@timestamp', `
            $alert._source.'kibana.alert.original_time')
    }
    Add-Line
}

if ($sourceDocuments.Count -gt 0) {
    Add-Line '## Source events'
    Add-Line
    foreach ($document in $sourceDocuments) {
        Add-Line "- ``$($document.index)`` / ``$($document.document_id)``"
    }
    Add-Line
}

Add-Line '## Analyst triage note'
Add-Line
if ($existingTriage) {
    Add-Line $existingTriage
}
else {
    Add-Line '<!-- Written by a human. Describe what happened, what the alert showed, which'
    Add-Line '     events you pivoted to, and whether this is a true or false positive. -->'
    Add-Line
    Add-Line 'TODO'
}
Add-Line
Add-Line '## Gap category'
Add-Line
if ($existingGap) {
    Add-Line $existingGap
}
else {
    Add-Line '<!-- One of: telemetry gap, normalization gap, rule logic gap, scenario limitation.'
    Add-Line '     Leave as not applicable only when the result is detected and nothing was missed. -->'
    Add-Line
    Add-Line 'TODO'
}
Add-Line

if ($detectionResult -eq 'missed') {
    Add-Line '## Why this is recorded as missed'
    Add-Line
    Add-Line "No alert existed for rule ``$RuleId`` between ``$($startUtc.ToString('o'))`` and"
    Add-Line "``$($alertWindowEndUtc.ToString('o'))``. The alert timestamp is recorded as"
    Add-Line '`not applicable` rather than as a placeholder value. Confirm the rule ran at least'
    Add-Line 'once inside that window before concluding the rule logic is at fault.'
    Add-Line
}

Set-Content -LiteralPath $reportPath -Value $reportLines -Encoding utf8

# 7. Summary -----------------------------------------------------------------------------
$resultColour = if ($detectionResult -eq 'detected') { 'Green' } else { 'Yellow' }
Write-Host "Detection result: $detectionResult" -ForegroundColor $resultColour
Write-Host "  alerts            : $($alerts.Count)"
Write-Host "  source documents  : $($sourceDocuments.Count)"
Write-Host "  rule execution    : $ruleExecutionResult"
Write-Host "  report            : $reportPath"
Write-Host "  raw export        : $rawPath"
Write-Host "  raw SHA-256       : $rawHash"
Write-Host ''
Write-Host 'REDACT before committing, then fill in the triage note and gap category.' -ForegroundColor Yellow

exit 0
