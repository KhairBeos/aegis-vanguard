#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [switch]$Approve
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-RestrictedAcl {
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Directory
  )

  $operator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  $grant = if ($Directory) {
    "${operator}:(OI)(CI)(F)"
  }
  else {
    "${operator}:(F)"
  }

  & icacls.exe $Path /inheritance:r /grant:r $grant 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) {
    throw "ACL restriction failed for path: $Path"
  }
}

function Assert-RestrictedAcl {
  param([Parameter(Mandatory)][string]$Path)

  try {
    $operator = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules(
      $true,
      $true,
      [System.Security.Principal.NTAccount]
    ))
    $validRules = @($rules | Where-Object {
      -not $_.IsInherited -and
      $_.IdentityReference.Value -eq $operator -and
      $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl)
    })

    if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or $validRules.Count -ne 1) {
      throw 'ACL contract mismatch.'
    }
  }
  catch {
    throw "Restricted ACL verification failed for path: $Path"
  }
}

function Remove-ExactTree {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$FailurePrefix
  )

  if (Test-Path -LiteralPath $Path) {
    try {
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    catch {
      throw "$FailurePrefix $Path"
    }
  }
  if (Test-Path -LiteralPath $Path) {
    throw "$FailurePrefix $Path"
  }
}

function Assert-ExpectedMaterial {
  param([Parameter(Mandatory)][string]$Root)

  $expectedRelativePaths = @(
    'ca\ca.crt',
    'ca\ca.key',
    'elasticsearch\elasticsearch.crt',
    'elasticsearch\elasticsearch.key'
  )
  foreach ($relativePath in $expectedRelativePaths) {
    $expectedPath = Join-Path $Root $relativePath
    if (
      -not (Test-Path -LiteralPath $expectedPath -PathType Leaf) -or
      (Get-Item -LiteralPath $expectedPath).Length -le 0
    ) {
      throw "Expected generated file is missing or empty: $expectedPath"
    }
  }

  $allowedPrivateKeys = @(
    'ca\ca.key',
    'elasticsearch\elasticsearch.key'
  )
  foreach ($file in @(Get-ChildItem -LiteralPath $Root -Recurse -File)) {
    $relativePath = $file.FullName.Substring($Root.Length).TrimStart([char[]]@('\', '/'))
    $isSensitiveExtension = $file.Extension.ToLowerInvariant() -in @('.key', '.pem', '.p12', '.pfx', '.zip')
    if ($isSensitiveExtension -and $allowedPrivateKeys -notcontains $relativePath) {
      throw "Unexpected private-key or archive content: $($file.FullName)"
    }
  }
}

$image = 'docker.elastic.co/elasticsearch/elasticsearch:9.4.3'
$tlsRoot = (Resolve-Path $PSScriptRoot).Path
$instancesPath = Join-Path $tlsRoot 'instances.yml'
$generatedRoot = Join-Path $tlsRoot 'generated'
$stagingRoot = Join-Path $tlsRoot '.runtime-staging'
$runId = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $stagingRoot $runId
$archiveRoot = Join-Path $runRoot 'archives'
$materialRoot = Join-Path $runRoot 'material'
$caArchive = Join-Path $archiveRoot 'ca.zip'
$certificateArchive = Join-Path $archiveRoot 'elasticsearch.zip'
$runRelativePath = ".runtime-staging/$runId"
$caContainerArchivePath = "/work/$runRelativePath/archives/ca.zip"
$certificateContainerArchivePath = "/work/$runRelativePath/archives/elasticsearch.zip"
$createdStagingRoot = $false
$promotionStarted = $false

if (-not $Approve -and -not $WhatIfPreference) {
  throw 'Certificate generation requires -Approve and an explicit ShouldProcess confirmation.'
}
if (-not (Test-Path -LiteralPath $instancesPath -PathType Leaf)) {
  throw "Missing certificate definition: $instancesPath"
}
if (Test-Path -LiteralPath $generatedRoot) {
  throw "Refusing to overwrite existing generated material: $generatedRoot"
}
if (Test-Path -LiteralPath $stagingRoot) {
  $staleStagingItems = @(Get-ChildItem -LiteralPath $stagingRoot -Force)
  if ($staleStagingItems.Count -ne 0) {
    throw "Refusing to use non-empty staging root: $stagingRoot"
  }
}
if (-not (Get-Command docker -ErrorAction Ignore)) {
  throw 'Docker CLI is unavailable.'
}
if ($tlsRoot.Contains(',')) {
  throw 'The TLS path contains a comma and cannot be passed safely to Docker --mount.'
}
if (-not $PSCmdlet.ShouldProcess($generatedRoot, 'Generate one local CA and one Elasticsearch HTTP certificate with the pinned 9.4.3 image')) {
  return
}

$mountArgument = "type=bind,source=$tlsRoot,target=/work"

try {
  if (-not (Test-Path -LiteralPath $stagingRoot)) {
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    $createdStagingRoot = $true
  }
  New-Item -ItemType Directory -Path $runRoot | Out-Null
  Set-RestrictedAcl -Path $runRoot -Directory
  Assert-RestrictedAcl -Path $runRoot
  New-Item -ItemType Directory -Path $archiveRoot, $materialRoot | Out-Null

  & docker run --rm --pull never --network none --mount $mountArgument `
    --entrypoint /usr/share/elasticsearch/bin/elasticsearch-certutil `
    $image ca --silent --pem --out $caContainerArchivePath 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) {
    throw 'CA generation failed. The pinned image must already exist locally; this script never pulls it.'
  }
  Expand-Archive -LiteralPath $caArchive -DestinationPath $materialRoot

  & docker run --rm --pull never --network none --mount $mountArgument `
    --entrypoint /usr/share/elasticsearch/bin/elasticsearch-certutil `
    $image cert --silent --pem `
    --in /work/instances.yml `
    --ca-cert "/work/$runRelativePath/material/ca/ca.crt" `
    --ca-key "/work/$runRelativePath/material/ca/ca.key" `
    --out $certificateContainerArchivePath 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) {
    throw 'Elasticsearch HTTP certificate generation failed.'
  }
  Expand-Archive -LiteralPath $certificateArchive -DestinationPath $materialRoot

  Assert-ExpectedMaterial -Root $materialRoot
  $archiveFiles = @(Get-ChildItem -LiteralPath $archiveRoot -File)
  if (
    $archiveFiles.Count -ne 2 -or
    @($archiveFiles.FullName | Where-Object { $_ -notin @($caArchive, $certificateArchive) }).Count -ne 0
  ) {
    throw "Unexpected private-key or archive content: $archiveRoot"
  }

  $stagedPrivateKeys = @(
    (Join-Path $materialRoot 'ca\ca.key'),
    (Join-Path $materialRoot 'elasticsearch\elasticsearch.key')
  )
  foreach ($stagedPrivateKey in $stagedPrivateKeys) {
    Set-RestrictedAcl -Path $stagedPrivateKey
    Assert-RestrictedAcl -Path $stagedPrivateKey
  }

  Remove-Item -LiteralPath $caArchive, $certificateArchive -Force -ErrorAction Stop
  if (
    (Test-Path -LiteralPath $caArchive) -or
    (Test-Path -LiteralPath $certificateArchive) -or
    @(Get-ChildItem -LiteralPath $runRoot -Recurse -File -Filter '*.zip').Count -ne 0
  ) {
    throw "Archive deletion verification failed: $archiveRoot"
  }

  $promotionStarted = $true
  Move-Item -LiteralPath $materialRoot -Destination $generatedRoot -ErrorAction Stop

  Assert-ExpectedMaterial -Root $generatedRoot
  $finalPrivateKeys = @(
    (Join-Path $generatedRoot 'ca\ca.key'),
    (Join-Path $generatedRoot 'elasticsearch\elasticsearch.key')
  )
  foreach ($finalPrivateKey in $finalPrivateKeys) {
    Assert-RestrictedAcl -Path $finalPrivateKey
  }

  Write-Host 'Generated Phase 1 certificate material. Certificate and private values were not printed.'
}
catch {
  if ($promotionStarted -and (Test-Path -LiteralPath $generatedRoot)) {
    Remove-ExactTree -Path $generatedRoot -FailurePrefix 'Rollback failed for path:'
  }
  throw 'Certificate generation failed; generated material was not retained.'
}
finally {
  Remove-ExactTree -Path $runRoot -FailurePrefix 'Cleanup failed for path:'
  if ($createdStagingRoot -and (Test-Path -LiteralPath $stagingRoot)) {
    if (@(Get-ChildItem -LiteralPath $stagingRoot -Force).Count -ne 0) {
      throw "Cleanup failed for path: $stagingRoot"
    }
    Remove-ExactTree -Path $stagingRoot -FailurePrefix 'Cleanup failed for path:'
  }
}
