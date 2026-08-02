[CmdletBinding()]
param(
    [string]$RulesPath,

    [string]$OutputPath,

    # Every generated rule already filters on winlog.channel, so listing all lab
    # data streams keeps the conversion rule-agnostic without widening matches.
    [string[]]$IndexNames = @(
        'logs-windows.sysmon-aegis_lab'
        'logs-windows.powershell-aegis_lab'
        'logs-windows.defender-aegis_lab'
        'logs-system.security-aegis_lab'
    ),

    [ValidateRange(1, 1440)]
    [int]$ScheduleIntervalMinutes = 5
)

# Converts the Sigma rules in rules/ into Elastic Security detection rules (NDJSON).
# Nothing here talks to Elasticsearch; deploy with scripts/deploy-detection-rules.ps1.

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath

if (-not $RulesPath) { $RulesPath = Join-Path $repositoryRoot 'rules\windows' }
if (-not $OutputPath) { $OutputPath = Join-Path $repositoryRoot 'rules\generated\aegis-detection-rules.ndjson' }

$sigmaExecutable = Join-Path $repositoryRoot '.venv\Scripts\sigma.exe'
$pipelinePath = Join-Path $repositoryRoot 'sigma\pipelines\aegis-lab.yml'

if (-not (Test-Path -LiteralPath $sigmaExecutable)) {
    Write-Host "FAIL: sigma-cli not found at $sigmaExecutable" -ForegroundColor Red
    Write-Host '      Create the environment first:' -ForegroundColor Yellow
    Write-Host '        py -m venv .venv'
    Write-Host '        .\.venv\Scripts\python.exe -m pip install -r requirements.txt'
    exit 1
}

foreach ($requiredPath in @($RulesPath, $pipelinePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        Write-Host "FAIL: required path does not exist: $requiredPath" -ForegroundColor Red
        exit 1
    }
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# ecs_windows resolves the Windows log source and ECS names; aegis-lab.yml then
# widens the process fields so raw winlog documents also match.
$arguments = @(
    'convert'
    '--target', 'lucene'
    '--pipeline', 'ecs_windows'
    '--pipeline', $pipelinePath
    '--format', 'siem_rule_ndjson'
    '--output', $OutputPath
)

foreach ($indexName in $IndexNames) {
    $arguments += @('--backend-option', "index_names=$indexName")
}

$arguments += @('--backend-option', "schedule_interval=$ScheduleIntervalMinutes")
$arguments += @('--backend-option', 'schedule_interval_unit=m')
$arguments += $RulesPath

& $sigmaExecutable @arguments

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: sigma convert exited with code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

# sigma-cli emits index_names as a bare string when only one value is supplied,
# but the Elastic rule import API requires an array. Normalise before deploying.
$normalizedLines = [System.Collections.Generic.List[string]]::new()
$ruleCount = 0

foreach ($line in Get-Content -LiteralPath $OutputPath) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    $rule = $line | ConvertFrom-Json

    if ($rule.index -is [string]) {
        $rule.index = @($rule.index)
    }

    $normalizedLines.Add(($rule | ConvertTo-Json -Depth 20 -Compress))
    $ruleCount++
}

if ($ruleCount -eq 0) {
    Write-Host "FAIL: conversion produced no rules from $RulesPath" -ForegroundColor Red
    exit 1
}

Set-Content -LiteralPath $OutputPath -Value $normalizedLines -Encoding utf8

Write-Host "PASS: converted $ruleCount rule(s) to $OutputPath" -ForegroundColor Green
Write-Host "      index patterns: $($IndexNames -join ', ')"
Write-Host "      schedule: every $ScheduleIntervalMinutes minute(s), query window now-$($ScheduleIntervalMinutes)m to now"
exit 0
