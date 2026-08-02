[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$KibanaUrl = 'http://192.168.56.1:5601',

    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [string]$NdjsonPath,

    [ValidateRange(1, 10080)]
    [int]$LookbackMinutes = 60
)

# Verifies that every deployed Sigma-derived rule exists in Elastic Security, is
# enabled, and executed without error. Alert counts are reported, not asserted:
# no alert is the correct result until matching telemetry exists.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
if (-not $NdjsonPath) {
    $NdjsonPath = Join-Path $repositoryRoot 'rules\generated\aegis-detection-rules.ndjson'
}

$failures = [System.Collections.Generic.List[string]]::new()

function Write-Pass { param([string]$Message) Write-Host "PASS: $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "WARN: $Message" -ForegroundColor Yellow }
function Write-Fail {
    param([string]$Message)
    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

if (-not (Test-Path -LiteralPath $NdjsonPath)) {
    Write-Fail "No converted rules at $NdjsonPath; run scripts\convert-sigma.ps1 first."
    exit 1
}

$headers = Get-AegisElasticAuthHeader
$headers['kbn-xsrf'] = 'true'

$expectedRules = @(
    Get-Content -LiteralPath $NdjsonPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)

Write-Pass "Found $($expectedRules.Count) converted rule(s) to verify."

foreach ($expectedRule in $expectedRules) {
    $ruleId = $expectedRule.rule_id

    try {
        $deployedRule = Invoke-RestMethod `
            -Uri "$($KibanaUrl.TrimEnd('/'))/api/detection_engine/rules?rule_id=$ruleId" `
            -Headers $headers `
            -ErrorAction Stop
    }
    catch {
        Write-Fail "$ruleId is not deployed in Elastic Security - $($_.Exception.Message)"
        continue
    }

    Write-Pass "$($deployedRule.name) is deployed (rule_id $ruleId)."

    if ($deployedRule.enabled) {
        Write-Pass "$ruleId is enabled."
    }
    else {
        Write-Fail "$ruleId is deployed but DISABLED; it will never produce an alert."
    }

    $lastExecution = $deployedRule.execution_summary.last_execution
    if (-not $lastExecution) {
        Write-Fail "$ruleId has no execution history yet; wait for one interval ($($deployedRule.interval))."
    }
    elseif ($lastExecution.status -eq 'succeeded') {
        Write-Pass "$ruleId last execution succeeded at $($lastExecution.date)."
    }
    else {
        Write-Fail "$ruleId last execution status is '$($lastExecution.status)': $($lastExecution.message)"
    }

    # Alerts are counted for visibility. Zero alerts is expected until the victim VM
    # produces matching telemetry, so this never fails the run.
    $alertQuery = @{
        size             = 0
        track_total_hits = $true
        query            = @{
            bool = @{
                filter = @(
                    @{ term  = @{ 'kibana.alert.rule.rule_id' = $ruleId } }
                    @{ range = @{ '@timestamp' = @{ gte = "now-$($LookbackMinutes)m" } } }
                )
            }
        }
    }

    try {
        $alertResponse = Invoke-RestMethod `
            -Method POST `
            -Uri "$($ElasticsearchUrl.TrimEnd('/'))/.alerts-security.alerts-default/_search" `
            -Headers (Get-AegisElasticAuthHeader) `
            -ContentType 'application/json' `
            -Body ($alertQuery | ConvertTo-Json -Depth 20 -Compress) `
            -ErrorAction Stop

        $alertCount = $alertResponse.hits.total.value
        if ($alertCount -gt 0) {
            Write-Pass "$ruleId produced $alertCount alert(s) in the last $LookbackMinutes minute(s)."
        }
        else {
            Write-Warn "$ruleId produced no alerts in the last $LookbackMinutes minute(s); expected until matching telemetry exists."
        }
    }
    catch {
        Write-Warn "$ruleId alert count unavailable (the alerts index may not exist until the first alert): $($_.Exception.Message)"
    }
}

Write-Host ''

if ($failures.Count -gt 0) {
    Write-Host "Detection rule verification failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host 'Detection rule verification passed.' -ForegroundColor Green
Write-Host 'Deployment and execution are verified. An alert count above zero shows the rule' -ForegroundColor Yellow
Write-Host 'matches real telemetry, but no rule-scenario pair is Live verified until an' -ForegroundColor Yellow
Write-Host 'approved Atomic Red Team run produces a complete evidence bundle.' -ForegroundColor Yellow
exit 0
