param(
  [string]$EnvFile = "deploy/env/.env",
  [string]$ComposeFile = "deploy/docker-compose.yml",
  [string]$EngineExe = "build/debug-engine/engine/src/aegis_engine.exe",
  [int]$TimeoutSec = 45,
  [string]$KafkaContainer = "aegis-kafka",
  [string]$ClickHouseContainer = "aegis-clickhouse",
  [string]$BootstrapServer = "kafka:29092"
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
    [string]$Container,
    [string]$Query
  )

  $result = docker exec $Container clickhouse-client --query $Query
  Assert-True ($LASTEXITCODE -eq 0) "ClickHouse query failed: $Query"
  return ($result | Out-String).Trim()
}

function Send-KafkaBatch {
  param(
    [string]$Container,
    [string]$Bootstrap,
    [string]$Topic,
    [string[]]$Messages
  )

  Assert-True ($Messages.Count -gt 0) "Failed to send Kafka batch: no messages were provided"

  $producerCmd = "kafka-console-producer --bootstrap-server $Bootstrap --topic $Topic > /dev/null"
  $payload = ($Messages -join "`n")
  $payload | docker exec -i $Container bash -lc $producerCmd
  Assert-True ($LASTEXITCODE -eq 0) "Failed to send Kafka messages to topic '$Topic'"
}

function Get-ProcessOutput {
  param([string]$Path)

  if (-not (Test-Path $Path)) {
    return ""
  }

  return (Get-Content -Path $Path -Raw)
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Join-Path $scriptDir "..\.."
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)
Set-Location $repoRoot

$envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path $repoRoot $EnvFile }
$composePath = if ([System.IO.Path]::IsPathRooted($ComposeFile)) { $ComposeFile } else { Join-Path $repoRoot $ComposeFile }
$enginePath = if ([System.IO.Path]::IsPathRooted($EngineExe)) { $EngineExe } else { Join-Path $repoRoot $EngineExe }

Assert-True (Test-Path $envPath) "Env file not found: $envPath"
Assert-True (Test-Path $composePath) "Compose file not found: $composePath"
Assert-True (Test-Path $enginePath) "Engine executable not found: $enginePath"
Assert-True ([bool](Get-Command docker -ErrorAction SilentlyContinue)) "Docker CLI is not installed or not in PATH"

$smokeScript = Join-Path $scriptDir "smoke_test.ps1"
& $smokeScript -EnvFile $envPath -ComposeFile $composePath -AutoStart

$envMap = Get-EnvMap -Path $envPath
$topicEvents = if ($envMap.ContainsKey("KAFKA_TOPIC_EVENTS")) { $envMap["KAFKA_TOPIC_EVENTS"] } else { "siem.events" }
$clickhouseDb = if ($envMap.ContainsKey("CLICKHOUSE_DB")) { $envMap["CLICKHOUSE_DB"] } else { "aegis" }

$hostName = "e2e-host-" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
$sourceName = "engine.e2e"
$traceId = [guid]::NewGuid().ToString()
$stdoutPath = Join-Path $repoRoot "build/debug-engine/engine-e2e.stdout.log"
$stderrPath = Join-Path $repoRoot "build/debug-engine/engine-e2e.stderr.log"

$savedEnv = @{}
$envKeys = @(
  "KAFKA_BROKERS",
  "KAFKA_GROUP_ID",
  "KAFKA_TOPIC_EVENTS",
  "KAFKA_TOPIC_ALERTS",
  "KAFKA_TOPIC_EVENTS_DLQ",
  "KAFKA_POLL_TIMEOUT_MS",
  "CLICKHOUSE_HOST",
  "CLICKHOUSE_PORT",
  "CLICKHOUSE_DB",
  "CLICKHOUSE_USER",
  "CLICKHOUSE_PASSWORD",
  "ENGINE_LOG_LEVEL",
  "ENGINE_RETRY_MAX_ATTEMPTS",
  "ENGINE_RETRY_BASE_DELAY_MS",
  "ENGINE_METRICS_INTERVAL_SEC"
)

$engineProcess = $null

try {
  foreach ($key in $envKeys) {
    $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
  }

  [Environment]::SetEnvironmentVariable("KAFKA_BROKERS", "localhost:9092", "Process")
  [Environment]::SetEnvironmentVariable("CLICKHOUSE_HOST", "localhost", "Process")
  [Environment]::SetEnvironmentVariable("CLICKHOUSE_PORT", "8123", "Process")
  [Environment]::SetEnvironmentVariable("CLICKHOUSE_DB", $clickhouseDb, "Process")
  [Environment]::SetEnvironmentVariable("ENGINE_LOG_LEVEL", "info", "Process")
  [Environment]::SetEnvironmentVariable("ENGINE_METRICS_INTERVAL_SEC", "5", "Process")

  foreach ($entry in $envMap.GetEnumerator()) {
    if ($envKeys -contains $entry.Key -and $entry.Key -notin @("KAFKA_BROKERS", "CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DB", "ENGINE_LOG_LEVEL", "ENGINE_METRICS_INTERVAL_SEC")) {
      [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
    }
  }

  Remove-Item -Path $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
  $engineDir = Split-Path -Parent $enginePath
  $engineProcess = Start-Process -FilePath $enginePath -WorkingDirectory $engineDir -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
  Start-Sleep -Seconds 5

  if ($engineProcess.HasExited) {
    $stderr = Get-ProcessOutput -Path $stderrPath
    $stdout = Get-ProcessOutput -Path $stdoutPath
    throw "Engine exited before ingesting events.`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
  }

  Write-Output "[E2E] Engine started with PID $($engineProcess.Id)"
  Write-Output "[E2E] Sending brute-force simulation for host '$hostName'"

  $messages = @()
  for ($index = 0; $index -lt 5; $index++) {
    $eventObject = [ordered]@{
      schema_version = "v1.1"
      event_id = [guid]::NewGuid().ToString("N")
      ts = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
      host = $hostName
      agent_id = "collector-e2e"
      source = $sourceName
      event_type = "auth_failure"
      severity = "medium"
      tenant_id = "default"
      trace_id = $traceId
      event = [ordered]@{
        auth = [ordered]@{
          user_name = "root"
          method = "ssh"
          src_ip = "198.51.100.77"
          reason = "invalid_password"
        }
      }
    }

    $messages += ($eventObject | ConvertTo-Json -Depth 10 -Compress)
  }

  Send-KafkaBatch -Container $KafkaContainer -Bootstrap $BootstrapServer -Topic $topicEvents -Messages $messages
  Write-Output "[E2E] Sent $($messages.Count) auth_failure events"

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $rawCount = 0
  $bruteforceAlertCount = 0
  $externalAlertCount = 0
  $externalAlertSummary = ""

  do {
    Start-Sleep -Seconds 2
    $rawQuery = "SELECT count() FROM $clickhouseDb.raw_events WHERE host = '$hostName' AND source = '$sourceName' AND event_type = 'auth_failure'"
    $bruteforceAlertQuery = "SELECT count() FROM $clickhouseDb.alerts WHERE host = '$hostName' AND rule_id = 'auth-brute-force'"
    $externalAlertQuery = "SELECT count() FROM $clickhouseDb.alerts WHERE host = '$hostName' AND rule_id = 'ext-auth-admin-failure'"
    $externalSummaryQuery = "SELECT summary FROM $clickhouseDb.alerts WHERE host = '$hostName' AND rule_id = 'ext-auth-admin-failure' ORDER BY ts DESC LIMIT 1"
    $rawCount = [int](Invoke-ClickHouseScalar -Container $ClickHouseContainer -Query $rawQuery)
    $bruteforceAlertCount = [int](Invoke-ClickHouseScalar -Container $ClickHouseContainer -Query $bruteforceAlertQuery)
    $externalAlertCount = [int](Invoke-ClickHouseScalar -Container $ClickHouseContainer -Query $externalAlertQuery)
    if ($externalAlertCount -gt 0) {
      $externalAlertSummary = Invoke-ClickHouseScalar -Container $ClickHouseContainer -Query $externalSummaryQuery
    }
    Write-Output "[E2E] raw_events=$rawCount brute_force_alerts=$bruteforceAlertCount external_alerts=$externalAlertCount"
  } while ((Get-Date) -lt $deadline -and ($rawCount -lt 5 -or $bruteforceAlertCount -lt 1 -or $externalAlertCount -lt 1))

  Assert-True ($rawCount -ge 5) "E2E failed: expected 5 raw auth_failure events, got $rawCount"
  Assert-True ($bruteforceAlertCount -ge 1) "E2E failed: expected auth-brute-force alert, got $bruteforceAlertCount"
  Assert-True ($externalAlertCount -ge 1) "E2E failed: expected ext-auth-admin-failure alert, got $externalAlertCount"
  Assert-True ($externalAlertSummary.Contains($hostName)) "E2E failed: external alert summary missing host"
  Assert-True ($externalAlertSummary.Contains("root")) "E2E failed: external alert summary missing user_name"
  Assert-True ($externalAlertSummary.Contains("198.51.100.77")) "E2E failed: external alert summary missing src_ip"
  Assert-True ($externalAlertSummary.Contains("(5/5)")) "E2E failed: external alert summary missing hit counter"

  Start-Sleep -Milliseconds 500
  $stdout = Get-ProcessOutput -Path $stdoutPath
  Assert-True (-not $stdout.Contains("Validation failed")) "E2E failed: unexpected validation failure detected in engine log"
  Assert-True (-not $stdout.Contains("DlqHandler:")) "E2E failed: unexpected DLQ publication detected in engine log"

  Write-Output "[E2E] End-to-end validation passed."
}
finally {
  if ($engineProcess -and -not $engineProcess.HasExited) {
    Stop-Process -Id $engineProcess.Id -Force
    Wait-Process -Id $engineProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
  }

  foreach ($key in $envKeys) {
    [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], "Process")
  }
}