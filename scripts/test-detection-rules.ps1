[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [string]$NdjsonPath,

    [string]$CasesPath
)

# Detection rule query validation.
#
# WHAT THIS PROVES: that each converted rule query matches the documents it should and
# rejects the ones it should not, given the lab's field mapping.
#
# WHAT THIS DOES NOT PROVE: that any rule detects real activity. Every document here is
# a synthetic fixture. Per README.md, a fixture result is `Unit tested` and must NEVER be
# cited as detection evidence, coverage, or a MITRE claim.
#
# Fixtures are written to a throwaway namespace and deleted afterwards. No document is
# ever written into the aegis_lab namespace.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
if (-not $NdjsonPath) { $NdjsonPath = Join-Path $repositoryRoot 'rules\generated\aegis-detection-rules.ndjson' }
if (-not $CasesPath)  { $CasesPath  = Join-Path $repositoryRoot 'rules\tests\cases.json' }

$authHeader = Get-AegisElasticAuthHeader
$baseUrl = $ElasticsearchUrl.TrimEnd('/')
$testNamespace = 'aegisruletest'
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Pass { param([string]$Message) Write-Host "PASS: $Message" -ForegroundColor Green }
function Write-Fail {
    param([string]$Message)
    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

foreach ($requiredPath in @($NdjsonPath, $CasesPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        Write-Host "FAIL: required file missing: $requiredPath" -ForegroundColor Red
        Write-Host '      Run scripts\convert-sigma.ps1 first.' -ForegroundColor Yellow
        exit 1
    }
}

$convertedRules = @(
    Get-Content -LiteralPath $NdjsonPath |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
# Windows PowerShell 5.1 emits a parsed JSON array as ONE pipeline item, so wrapping it
# in @() produces a single-element array containing the array. Normalise explicitly so
# both a multi-suite array and a lone suite object iterate correctly.
$parsedSuites = Get-Content -LiteralPath $CasesPath -Raw | ConvertFrom-Json
$ruleSuites = if ($parsedSuites -is [System.Array]) { $parsedSuites } else { @($parsedSuites) }

$createdDataStreams = [System.Collections.Generic.List[string]]::new()
$suiteIndex = 0

try {
    foreach ($suite in $ruleSuites) {
        $suiteIndex++
        $rule = $convertedRules | Where-Object { $_.rule_id -eq $suite.rule_id } | Select-Object -First 1

        if (-not $rule) {
            Write-Fail "No converted rule found for rule_id $($suite.rule_id)"
            continue
        }

        Write-Host "`n--- $($suite.rule_name) ($($suite.rule_id)) ---"

        # A dedicated throwaway data stream per suite, so one rule's fixtures can never
        # satisfy another rule's query and document ids cannot collide between suites.
        $dataStream = "logs-windows.sysmon-$testNamespace$suiteIndex"
        $createdDataStreams.Add($dataStream) | Out-Null

        $caseIndex = 0
        $expectedMatchIds = [System.Collections.Generic.List[string]]::new()

        foreach ($case in $suite.cases) {
            $caseIndex++
            $documentId = "case-$caseIndex"

            $document = $case.document | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $document | Add-Member -NotePropertyName '@timestamp' -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force

            Invoke-RestMethod `
                -Method PUT `
                -Uri "$baseUrl/$dataStream/_bulk?refresh=true" `
                -Headers $authHeader `
                -ContentType 'application/x-ndjson' `
                -Body ("{`"create`":{`"_id`":`"$documentId`"}}`n" + ($document | ConvertTo-Json -Depth 20 -Compress) + "`n") `
                -ErrorAction Stop | Out-Null

            if ($case.should_match) { $expectedMatchIds.Add($documentId) | Out-Null }
        }

        $searchBody = @{
            size             = 100
            track_total_hits = $true
            _source          = $false
            query            = @{ query_string = @{ query = $rule.query } }
        } | ConvertTo-Json -Depth 20 -Compress

        $searchResponse = Invoke-RestMethod `
            -Method POST `
            -Uri "$baseUrl/$dataStream/_search" `
            -Headers $authHeader `
            -ContentType 'application/json' `
            -Body $searchBody `
            -ErrorAction Stop

        $actualMatchIds = @($searchResponse.hits.hits | ForEach-Object { $_._id })

        $caseIndex = 0
        foreach ($case in $suite.cases) {
            $caseIndex++
            $documentId = "case-$caseIndex"
            $matched = $actualMatchIds -contains $documentId

            if ($matched -eq [bool]$case.should_match) {
                Write-Pass "$($case.name) (should_match=$($case.should_match))"
            }
            else {
                Write-Fail "$($case.name) - expected should_match=$($case.should_match) but got $matched"
            }
        }
    }
}
finally {
    foreach ($dataStream in ($createdDataStreams | Select-Object -Unique)) {
        try {
            Invoke-RestMethod -Method DELETE -Uri "$baseUrl/_data_stream/$dataStream" -Headers $authHeader -ErrorAction Stop | Out-Null
            Write-Host "`nCleaned up fixture data stream $dataStream."
        }
        catch {
            Write-Host "`nWARN: could not delete fixture data stream $dataStream - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "Detection rule query validation failed with $($failures.Count) error(s)." -ForegroundColor Red
    Write-Host 'If the case-evasion cases failed, the lowercase normalizer is missing:' -ForegroundColor Yellow
    Write-Host '  .\scripts\apply-index-templates.ps1' -ForegroundColor Yellow
    exit 1
}

Write-Host 'Detection rule query validation passed.' -ForegroundColor Green
Write-Host 'This is a fixture-based logic check only. It is NOT detection evidence.' -ForegroundColor Yellow
exit 0
