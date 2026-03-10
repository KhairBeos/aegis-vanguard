param(
  [string]$VolumeName = "",
  [string]$OutputDir = "deploy/backups/clickhouse"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Join-Path $repoRoot ".."
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot)

if ([string]::IsNullOrWhiteSpace($VolumeName)) {
  $envPath = Join-Path $repoRoot "deploy/env/.env"
  if (Test-Path $envPath) {
    $line = Select-String -Path $envPath -Pattern '^CLICKHOUSE_VOLUME_NAME=' | Select-Object -First 1
    if ($line) {
      $VolumeName = ($line.Line -replace '^CLICKHOUSE_VOLUME_NAME=', '').Trim()
    }
  }

  if ([string]::IsNullOrWhiteSpace($VolumeName)) {
    $VolumeName = "deploy_clickhouse_data"
  }
}

$outDirPath = Join-Path $repoRoot $OutputDir
New-Item -ItemType Directory -Path $outDirPath -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupFile = "clickhouse-backup-$timestamp.tar.gz"

Write-Output "Checking volume: $VolumeName"
docker volume inspect $VolumeName *> $null
if ($LASTEXITCODE -ne 0) {
  throw "Docker volume not found: $VolumeName"
}

Write-Output "Creating backup: $backupFile"
docker run --rm -v "${VolumeName}:/data:ro" -v "${outDirPath}:/backup" alpine sh -c "tar -czf /backup/$backupFile -C /data ."
if ($LASTEXITCODE -ne 0) {
  throw "Backup failed"
}

Write-Output "Backup created at: $(Join-Path $outDirPath $backupFile)"
