param(
  [string]$EnvFile = "deploy/env/.env"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-RandomSecret {
  param([int]$Length = 28)

  $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
  return -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $repoRoot ("..\" + $EnvFile)
$envPath = [System.IO.Path]::GetFullPath($envPath)
$examplePath = Join-Path (Split-Path $envPath -Parent) ".env.example"

if (-not (Test-Path $examplePath)) {
  throw "Template not found: $examplePath"
}

if (-not (Test-Path $envPath)) {
  Copy-Item $examplePath $envPath
}

$content = Get-Content -Path $envPath -Raw

$clickhouseSecret = New-RandomSecret
$grafanaSecret = New-RandomSecret

$content = $content -replace "(?m)^CLICKHOUSE_PASSWORD=.*$", "CLICKHOUSE_PASSWORD=$clickhouseSecret"
$content = $content -replace "(?m)^GRAFANA_ADMIN_PASSWORD=.*$", "GRAFANA_ADMIN_PASSWORD=$grafanaSecret"

Set-Content -Path $envPath -Value $content -NoNewline

Write-Output "Updated secrets in: $envPath"
Write-Output "NOTE: Keep this file local and never commit it."
