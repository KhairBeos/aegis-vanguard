param(
  [string]$EnvFile = "deploy/env/.env",
  [string]$ComposeFile = "deploy/docker-compose.yml",
  [switch]$AutoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvMap {
  param([string]$Path)

  $map = @{}
  foreach ($line in Get-Content -Path $Path) {
    $trim = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trim)) { continue }
    if ($trim.StartsWith("#")) { continue }

    $idx = $trim.IndexOf("=")
    if ($idx -lt 1) { continue }

    $key = $trim.Substring(0, $idx).Trim()
    $value = $trim.Substring($idx + 1).Trim()
    $map[$key] = $value
  }
  return $map
}

function Assert-True {
  param(
    [bool]$Condition,
    [string]$Message
  )

  if (-not $Condition) {
    throw $Message
  }
}

function Get-ContainerState {
  param([string]$Name)

  $state = docker inspect -f "{{.State.Status}}" $Name 2>$null
  if ($LASTEXITCODE -ne 0) {
    return "missing"
  }
  return $state.Trim()
}

function Get-ContainerHealth {
  param([string]$Name)

  $health = docker inspect -f "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" $Name 2>$null
  if ($LASTEXITCODE -ne 0) {
    return "missing"
  }
  return $health.Trim()
}

function Wait-CommandSuccess {
  param(
    [scriptblock]$Action,
    [int]$MaxAttempts = 15,
    [int]$DelaySeconds = 2
  )

  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    $result = & $Action
    if ($LASTEXITCODE -eq 0) {
      return $result
    }

    if ($attempt -lt $MaxAttempts) {
      Start-Sleep -Seconds $DelaySeconds
    }
  }

  return $null
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Join-Path $scriptDir "..\.."
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)
Set-Location $repoRoot

$envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path $repoRoot $EnvFile }
$composePath = if ([System.IO.Path]::IsPathRooted($ComposeFile)) { $ComposeFile } else { Join-Path $repoRoot $ComposeFile }

Assert-True (Test-Path $envPath) "Env file not found: $envPath"
Assert-True (Test-Path $composePath) "Compose file not found: $composePath"
Assert-True ([bool](Get-Command docker -ErrorAction SilentlyContinue)) "Docker CLI is not installed or not in PATH"

$envMap = Get-EnvMap -Path $envPath
$topicEvents = if ($envMap.ContainsKey("KAFKA_TOPIC_EVENTS")) { $envMap["KAFKA_TOPIC_EVENTS"] } else { "siem.events" }
$topicAlerts = if ($envMap.ContainsKey("KAFKA_TOPIC_ALERTS")) { $envMap["KAFKA_TOPIC_ALERTS"] } else { "siem.alerts" }
$topicDlq = if ($envMap.ContainsKey("KAFKA_TOPIC_EVENTS_DLQ")) { $envMap["KAFKA_TOPIC_EVENTS_DLQ"] } else { "siem.events.dlq" }
$clickhouseDb = if ($envMap.ContainsKey("CLICKHOUSE_DB")) { $envMap["CLICKHOUSE_DB"] } else { "aegis" }

Write-Output "[SMOKE] Validating compose configuration..."
docker compose --env-file $envPath -f $composePath config > $null
Assert-True ($LASTEXITCODE -eq 0) "docker compose config failed"

if ($AutoStart) {
  Write-Output "[SMOKE] AutoStart enabled, ensuring stack is up..."
  docker compose --env-file $envPath -f $composePath up -d > $null
  Assert-True ($LASTEXITCODE -eq 0) "docker compose up failed"
}

$requiredRunning = @(
  "aegis-clickhouse",
  "aegis-zookeeper",
  "aegis-kafka",
  "aegis-grafana"
)

foreach ($name in $requiredRunning) {
  $state = Get-ContainerState -Name $name
  Assert-True ($state -eq "running") "Container '$name' is not running (state: $state)"
  Write-Output "[SMOKE] ${name}: running"
}

$healthCritical = @("aegis-clickhouse", "aegis-kafka")
foreach ($name in $healthCritical) {
  $health = Get-ContainerHealth -Name $name
  Assert-True ($health -eq "healthy") "Container '$name' is not healthy (health: $health)"
  Write-Output "[SMOKE] ${name}: healthy"
}

Write-Output "[SMOKE] Checking Kafka topics..."
$topics = docker exec aegis-kafka kafka-topics --bootstrap-server kafka:29092 --list
Assert-True ($LASTEXITCODE -eq 0) "Failed to list Kafka topics"
Assert-True (($topics -contains $topicEvents)) "Missing Kafka topic: $topicEvents"
Assert-True (($topics -contains $topicAlerts)) "Missing Kafka topic: $topicAlerts"
Assert-True (($topics -contains $topicDlq)) "Missing Kafka topic: $topicDlq"
Write-Output "[SMOKE] Kafka topics: OK"

Write-Output "[SMOKE] Checking ClickHouse tables..."
$tables = docker exec aegis-clickhouse clickhouse-client --query "SHOW TABLES FROM $clickhouseDb"
Assert-True ($LASTEXITCODE -eq 0) "Failed to list ClickHouse tables in DB '$clickhouseDb'"
Assert-True (($tables -contains "raw_events")) "Missing ClickHouse table: ${clickhouseDb}.raw_events"
Assert-True (($tables -contains "alerts")) "Missing ClickHouse table: ${clickhouseDb}.alerts"
Write-Output "[SMOKE] ClickHouse tables: OK"

Write-Output "[SMOKE] Checking Grafana health endpoint..."
$grafanaHealth = Wait-CommandSuccess -Action { docker exec aegis-grafana sh -c "wget -q -O - http://localhost:3000/api/health" }
Assert-True ($null -ne $grafanaHealth) "Failed to call Grafana health endpoint"
$grafanaHealthText = ($grafanaHealth | Out-String).Trim()
Assert-True ([bool]($grafanaHealthText -match '"database"\s*:\s*"ok"')) "Grafana health response does not contain database=ok"
Write-Output "[SMOKE] Grafana health: OK"

Write-Output "[SMOKE] All checks passed."
