[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    # Mapping changes only affect new backing indices. Existing data streams keep the
    # old mapping until they roll over, so opt in explicitly.
    [switch]$RolloverExistingDataStreams
)

# Applies the AEGIS component templates. Run this BEFORE the victim VM starts writing
# advanced telemetry, so the Sysmon data streams are created with the right mapping.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$templateDirectory = Join-Path $repositoryRoot 'infra\elastic\component-templates'
$authHeader = Get-AegisElasticAuthHeader
$baseUrl = $ElasticsearchUrl.TrimEnd('/')
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Pass { param([string]$Message) Write-Host "PASS: $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "WARN: $Message" -ForegroundColor Yellow }
function Write-Fail {
    param([string]$Message)
    $script:failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

# Ingest pipelines must exist before a component template references one as
# final_pipeline, otherwise index creation fails with a missing-pipeline error.
$pipelineDirectory = Join-Path $repositoryRoot 'infra\elastic\ingest-pipelines'
foreach ($pipelineFile in @(Get-ChildItem -LiteralPath $pipelineDirectory -Filter '*.json' -ErrorAction SilentlyContinue)) {
    $pipelineName = [IO.Path]::GetFileNameWithoutExtension($pipelineFile.Name)

    try {
        Invoke-RestMethod `
            -Method PUT `
            -Uri "$baseUrl/_ingest/pipeline/$pipelineName" `
            -Headers $authHeader `
            -ContentType 'application/json' `
            -Body (Get-Content -LiteralPath $pipelineFile.FullName -Raw) `
            -ErrorAction Stop | Out-Null

        Write-Pass "Applied ingest pipeline '$pipelineName'."
    }
    catch {
        Write-Fail "Could not apply ingest pipeline '$pipelineName' - $($_.Exception.Message)"
    }
}

$templateFiles = @(Get-ChildItem -LiteralPath $templateDirectory -Filter '*.json' -ErrorAction SilentlyContinue)
if ($templateFiles.Count -eq 0) {
    Write-Fail "No component templates found in $templateDirectory"
    exit 1
}

foreach ($templateFile in $templateFiles) {
    $templateName = [IO.Path]::GetFileNameWithoutExtension($templateFile.Name)

    try {
        Invoke-RestMethod `
            -Method PUT `
            -Uri "$baseUrl/_component_template/$templateName" `
            -Headers $authHeader `
            -ContentType 'application/json' `
            -Body (Get-Content -LiteralPath $templateFile.FullName -Raw) `
            -ErrorAction Stop | Out-Null

        Write-Pass "Applied component template '$templateName'."
    }
    catch {
        Write-Fail "Could not apply '$templateName' - $($_.Exception.Message)"
    }
}

if ($RolloverExistingDataStreams) {
    try {
        $dataStreams = @((Invoke-RestMethod -Uri "$baseUrl/_data_stream/logs-*-aegis_lab" -Headers $authHeader).data_streams)
    }
    catch {
        Write-Fail "Could not list data streams - $($_.Exception.Message)"
        $dataStreams = @()
    }

    foreach ($dataStream in $dataStreams) {
        try {
            Invoke-RestMethod -Method POST -Uri "$baseUrl/$($dataStream.name)/_rollover" -Headers $authHeader -ErrorAction Stop | Out-Null
            Write-Pass "Rolled over $($dataStream.name); new documents use the updated mapping."
        }
        catch {
            Write-Fail "Could not roll over $($dataStream.name) - $($_.Exception.Message)"
        }
    }
}
else {
    Write-Warn 'Existing data streams were NOT rolled over; their already-indexed documents keep the old mapping.'
    Write-Warn 'Re-run with -RolloverExistingDataStreams to apply it to new documents in existing streams.'
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "Template application failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host 'Component templates applied.' -ForegroundColor Green
exit 0
