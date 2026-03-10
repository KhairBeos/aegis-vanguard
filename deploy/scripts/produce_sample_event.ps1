param(
  [string]$EnvFile = "deploy/env/.env",
  [string]$KafkaContainer = "aegis-kafka",
  [string]$BootstrapServer = "kafka:29092",
  [switch]$VerifyConsumer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Get-Sha256Hex {
  param([string]$InputText)

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $hash = $sha.ComputeHash($bytes)
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
  }
  finally {
    $sha.Dispose()
  }
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Join-Path $scriptDir "..\.."
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)
Set-Location $repoRoot

$envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path $repoRoot $EnvFile }
if (-not (Test-Path $envPath)) {
  throw "Env file not found: $envPath"
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker CLI is not available in PATH"
}

$containerState = docker inspect -f "{{.State.Status}}" $KafkaContainer 2>$null
if ($LASTEXITCODE -ne 0 -or $containerState.Trim() -ne "running") {
  throw "Kafka container '$KafkaContainer' is not running"
}

$envMap = Get-EnvMap -Path $envPath
$topicEvents = if ($envMap.ContainsKey("KAFKA_TOPIC_EVENTS")) { $envMap["KAFKA_TOPIC_EVENTS"] } else { "siem.events" }

$nowUtc = [DateTime]::UtcNow
$ts = $nowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
$hostName = "workstation-01"
$procId = Get-Random -Minimum 1000 -Maximum 9000
$processStartTime = $ts
$processGuid = Get-Sha256Hex -InputText ("{0}{1}{2}" -f $hostName, $procId, $processStartTime)

$eventObject = [ordered]@{
  schema_version = "v1.1"
  event_id = [guid]::NewGuid().ToString("N")
  ts = $ts
  host = $hostName
  agent_id = "collector-dev-01"
  source = "collector.sim"
  event_type = "process_start"
  severity = "info"
  tenant_id = "default"
  trace_id = [guid]::NewGuid().ToString()
  process_guid = $processGuid
  event = [ordered]@{
    process = [ordered]@{
      pid = $procId
      ppid = 1
      uid = 1000
      user_name = "alice"
      name = "bash"
      exe = "/usr/bin/bash"
      cmdline = "bash -c whoami"
      process_start_time = $processStartTime
    }
  }
}

$eventJson = $eventObject | ConvertTo-Json -Depth 10 -Compress

Write-Output "[PRODUCE] Topic: $topicEvents"
Write-Output "[PRODUCE] Event ID: $($eventObject.event_id)"
Write-Output "[PRODUCE] Process GUID: $processGuid"

$producerCmd = "kafka-console-producer --bootstrap-server $BootstrapServer --topic $topicEvents > /dev/null"
$eventJson | docker exec -i $KafkaContainer bash -lc $producerCmd
if ($LASTEXITCODE -ne 0) {
  throw "Failed to produce sample event"
}

Write-Output "[PRODUCE] Sample event sent successfully."

if ($VerifyConsumer) {
  Write-Output "[VERIFY] Reading 1 message from topic '$topicEvents'..."
  $consumeCmd = "kafka-console-consumer --bootstrap-server $BootstrapServer --topic $topicEvents --from-beginning --max-messages 1 --timeout-ms 10000"
  $msg = docker exec $KafkaContainer bash -lc $consumeCmd
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to verify topic read"
  }

  $text = ($msg | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($text)) {
    throw "Verification failed: no message returned"
  }

  Write-Output "[VERIFY] Consumer returned at least one message."
}
