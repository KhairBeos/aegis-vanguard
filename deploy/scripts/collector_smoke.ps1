param(
  [string]$EnvFile = "deploy/env/.env",
  [string]$CollectorConfig = "config/dev/collector.yaml",
  [string]$EngineExe = "build/debug-engine/engine/src/aegis_engine.exe",
  [string]$CollectorExe = "build/debug-collector/collector/src/aegis_collector_agent.exe",
  [switch]$AutoStart,
  [switch]$BuildCollector,
  [switch]$BuildEngine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-True {
  param(
    [bool]$Condition,
    [string]$Message
  )

  if (-not $Condition) {
    throw $Message
  }
}

function Get-EnvMap {
  param([string]$Path)

  $map = @{}
  foreach ($line in Get-Content -Path $Path) {
    $trim = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trim) -or $trim.StartsWith("#")) {
      continue
    }

    $idx = $trim.IndexOf("=")
    if ($idx -lt 1) {
      continue
    }

    $key = $trim.Substring(0, $idx).Trim()
    $value = $trim.Substring($idx + 1).Trim()
    $map[$key] = $value
  }

  return $map
}

function Invoke-ClickHouseScalar {
  param(
    [hashtable]$EnvMap,
    [string]$Query
  )

  $db = if ($EnvMap.ContainsKey("CLICKHOUSE_DB")) { $EnvMap["CLICKHOUSE_DB"] } else { "aegis" }
  $user = if ($EnvMap.ContainsKey("CLICKHOUSE_USER")) { $EnvMap["CLICKHOUSE_USER"] } else { "default" }
  $password = if ($EnvMap.ContainsKey("CLICKHOUSE_PASSWORD")) { $EnvMap["CLICKHOUSE_PASSWORD"] } else { "" }

  $dockerArgs = @("exec", "aegis-clickhouse", "clickhouse-client", "--user", $user)
  if (-not [string]::IsNullOrWhiteSpace($password)) {
    $dockerArgs += @("--password", $password)
  }
  $dockerArgs += @("--query", $Query.Replace("{db}", $db))

  $result = & docker @dockerArgs
  if ($LASTEXITCODE -ne 0) {
    throw "ClickHouse query failed: $Query"
  }

  return ($result | Out-String).Trim()
}

function Wait-Until {
  param(
    [scriptblock]$Action,
    [int]$MaxAttempts = 20,
    [int]$DelaySeconds = 1
  )

  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    $result = & $Action
    if ($result) {
      return $true
    }

    if ($attempt -lt $MaxAttempts) {
      Start-Sleep -Seconds $DelaySeconds
    }
  }

  return $false
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Join-Path $scriptDir "..\.."
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)
Set-Location $repoRoot

$envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path $repoRoot $EnvFile }
$collectorConfigPath = if ([System.IO.Path]::IsPathRooted($CollectorConfig)) { $CollectorConfig } else { Join-Path $repoRoot $CollectorConfig }
$engineExePath = if ([System.IO.Path]::IsPathRooted($EngineExe)) { $EngineExe } else { Join-Path $repoRoot $EngineExe }
$collectorExePath = if ([System.IO.Path]::IsPathRooted($CollectorExe)) { $CollectorExe } else { Join-Path $repoRoot $CollectorExe }

Assert-True (Test-Path $envPath) "Env file not found: $envPath"
Assert-True (Test-Path $collectorConfigPath) "Collector config not found: $collectorConfigPath"
Assert-True ([bool](Get-Command docker -ErrorAction SilentlyContinue)) "Docker CLI is not installed or not in PATH"

$envMap = Get-EnvMap -Path $envPath

if ($AutoStart) {
  Write-Output "[COLLECTOR_SMOKE] Ensuring infrastructure is healthy..."
  powershell -ExecutionPolicy Bypass -File (Join-Path $repoRoot "deploy/scripts/smoke_test.ps1") -EnvFile $envPath -AutoStart
}

if ($BuildEngine) {
  Write-Output "[COLLECTOR_SMOKE] Building engine preset..."
  cmake --build --preset build-debug-engine --target aegis_engine
  Assert-True ($LASTEXITCODE -eq 0) "Engine build failed"
}

if ($BuildCollector) {
  Write-Output "[COLLECTOR_SMOKE] Building collector preset..."
  cmake --build --preset build-debug-collector --target aegis_collector_agent
  Assert-True ($LASTEXITCODE -eq 0) "Collector build failed"
}

Assert-True (Test-Path $engineExePath) "Engine executable not found: $engineExePath"
Assert-True (Test-Path $collectorExePath) "Collector executable not found: $collectorExePath"

$beforeRaw = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.raw_events WHERE source = 'collector.app'")
$beforeAlerts = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.alerts WHERE host = 'localhost'")

Write-Output "[COLLECTOR_SMOKE] raw_events before=$beforeRaw alerts before=$beforeAlerts"

foreach ($entry in $envMap.GetEnumerator()) {
  [System.Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
}

$engineStdoutLog = Join-Path $env:TEMP "aegis-collector-smoke-engine.stdout.log"
$engineStderrLog = Join-Path $env:TEMP "aegis-collector-smoke-engine.stderr.log"
if (Test-Path $engineStdoutLog) {
  Remove-Item $engineStdoutLog -Force
}
if (Test-Path $engineStderrLog) {
  Remove-Item $engineStderrLog -Force
}

$engineProcess = Start-Process -FilePath $engineExePath -WorkingDirectory $repoRoot -RedirectStandardOutput $engineStdoutLog -RedirectStandardError $engineStderrLog -PassThru

try {
  Start-Sleep -Seconds 3

  Write-Output "[COLLECTOR_SMOKE] Running collector..."
  & $collectorExePath $collectorConfigPath
  Assert-True ($LASTEXITCODE -eq 0) "Collector execution failed"

  $ready = Wait-Until -Action {
    try {
      $rawNow = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.raw_events WHERE source = 'collector.app'")
      $alertsNow = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.alerts WHERE host = 'localhost'")
      return ($rawNow -ge ($beforeRaw + 5) -and $alertsNow -ge ($beforeAlerts + 1))
    } catch {
      return $false
    }
  } -MaxAttempts 20 -DelaySeconds 1

  Assert-True $ready "Collector smoke verification timed out"

  $afterRaw = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.raw_events WHERE source = 'collector.app'")
  $afterAlerts = [int](Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT count() FROM {db}.alerts WHERE host = 'localhost'")
  $topAlerts = Invoke-ClickHouseScalar -EnvMap $envMap -Query "SELECT rule_id, summary FROM {db}.alerts WHERE host = 'localhost' ORDER BY ts DESC LIMIT 4 FORMAT TSV"

  Write-Output "[COLLECTOR_SMOKE] raw_events after=$afterRaw alerts after=$afterAlerts"
  Write-Output "[COLLECTOR_SMOKE] Recent alerts:"
  Write-Output $topAlerts
  Write-Output "[COLLECTOR_SMOKE] Smoke passed."
}
finally {
  if (-not $engineProcess.HasExited) {
    Stop-Process -Id $engineProcess.Id -Force
  }
}