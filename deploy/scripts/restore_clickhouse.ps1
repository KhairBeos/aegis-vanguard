param(
  [Parameter(Mandatory = $true)]
  [string]$BackupFile,
  [string]$VolumeName = ""
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

$resolvedBackup = if ([System.IO.Path]::IsPathRooted($BackupFile)) {
  $BackupFile
} else {
  Join-Path $repoRoot $BackupFile
}

$resolvedBackup = [System.IO.Path]::GetFullPath($resolvedBackup)
if (-not (Test-Path $resolvedBackup)) {
  throw "Backup file not found: $resolvedBackup"
}

docker volume inspect $VolumeName *> $null
if ($LASTEXITCODE -ne 0) {
  throw "Docker volume not found: $VolumeName"
}

$backupDir = Split-Path -Parent $resolvedBackup
$backupName = Split-Path -Leaf $resolvedBackup

Write-Warning "This will replace all data in volume '$VolumeName'."
Write-Warning "Ensure containers using ClickHouse are stopped before restore."
$confirm = Read-Host "Type 'RESTORE' to continue"
if ($confirm -ne "RESTORE") {
  throw "Restore cancelled"
}

docker run --rm -v "${VolumeName}:/data" -v "${backupDir}:/backup" alpine sh -c "rm -rf /data/* && tar -xzf /backup/$backupName -C /data"
if ($LASTEXITCODE -ne 0) {
  throw "Restore failed"
}

Write-Output "Restore completed from: $resolvedBackup"
