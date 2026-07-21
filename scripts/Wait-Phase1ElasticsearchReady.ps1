#requires -Version 5.1

[CmdletBinding()]
param(
  [string]$ComposeFile = (Join-Path $PSScriptRoot '..\deploy\compose.yaml'),
  [string]$EnvironmentFile = (Join-Path $PSScriptRoot '..\deploy\env\.env.example'),
  [string]$CaCertificate = (Join-Path $PSScriptRoot '..\deploy\tls\generated\ca\ca.crt'),
  [ValidateRange(30, 1800)]
  [int]$TimeoutSeconds = 300,
  [ValidateRange(1, 30)]
  [int]$PollSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($requiredPath in @($ComposeFile, $EnvironmentFile, $CaCertificate)) {
  if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
    throw "Required runtime file is missing: $requiredPath"
  }
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker CLI is unavailable.'
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  throw 'curl.exe is unavailable.'
}

$deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
$listenerUri = 'https://192.168.15.1:9200/'
$listenerReady = $false

while ([datetime]::UtcNow -lt $deadline) {
  $httpCode = (& curl.exe --silent --output NUL --write-out '%{http_code}' `
    --cacert $CaCertificate --connect-timeout 3 --max-time 8 $listenerUri 2>$null | Out-String).Trim()
  $curlExitCode = $LASTEXITCODE

  if ($curlExitCode -eq 0 -and $httpCode -eq '401') {
    $listenerReady = $true
    Write-Host 'PASS: CA-verified HTTPS listener returned 401 (listener-only readiness).'
    break
  }
  if ($curlExitCode -eq 0 -and $httpCode -match '^[45]\d\d$' -and $httpCode -ne '503') {
    throw "Unexpected Elasticsearch listener status: $httpCode"
  }

  Start-Sleep -Seconds $PollSeconds
}

if (-not $listenerReady) {
  throw "Timed out waiting for the CA-verified listener-only 401 response after $TimeoutSeconds seconds."
}

$containerId = (& docker compose --env-file $EnvironmentFile -f $ComposeFile --profile elastic ps -q elasticsearch 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
  throw 'Unable to resolve the running Elasticsearch container.'
}

while ([datetime]::UtcNow -lt $deadline) {
  $healthState = (& docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' $containerId 2>$null | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw 'Unable to inspect Elasticsearch authenticated health.'
  }

  switch ($healthState) {
    'healthy' {
      Write-Host 'PASS: Elasticsearch authenticated cluster health is healthy.'
      return
    }
    'unhealthy' {
      throw 'Elasticsearch authenticated cluster health is unhealthy.'
    }
    'missing' {
      throw 'Elasticsearch has no configured Docker health check.'
    }
    'starting' {
      Start-Sleep -Seconds $PollSeconds
    }
    default {
      throw "Unexpected Elasticsearch health state: $healthState"
    }
  }
}

throw "Timed out waiting for authenticated Elasticsearch health after $TimeoutSeconds seconds."
