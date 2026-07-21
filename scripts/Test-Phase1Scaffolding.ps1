#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$failures = New-Object 'System.Collections.Generic.List[string]'
$assertionCount = 0
$passedAssertionCount = 0
$negativeFixtureCount = 0
$rejectedNegativeFixtureCount = 0
$temporaryCleanupSucceeded = $false
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aegis-phase1-validation-{0}" -f [guid]::NewGuid().ToString('N'))

function Add-ValidationFailure {
  param([Parameter(Mandatory)][string]$Message)

  $script:failures.Add($Message)
}

function Assert-Validation {
  param(
    [Parameter(Mandatory)][bool]$Condition,
    [Parameter(Mandatory)][string]$Message
  )

  $script:assertionCount++
  if ($Condition) {
    $script:passedAssertionCount++
    Write-Host ("PASS {0}: condition held; failure condition: {1}" -f $script:assertionCount, $Message)
  }
  else {
    Write-Host ("FAIL {0}: {1}" -f $script:assertionCount, $Message)
    Add-ValidationFailure -Message $Message
  }
}

function Write-Utf8NoBomFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Value
  )

  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Invoke-CapturedCommand {
  param(
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][string[]]$Arguments
  )

  $captureId = [guid]::NewGuid().ToString('N')
  $standardOutputPath = Join-Path $temporaryRoot ("native-{0}.stdout" -f $captureId)
  $standardErrorPath = Join-Path $temporaryRoot ("native-{0}.stderr" -f $captureId)
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    & $Command @Arguments 1> $standardOutputPath 2> $standardErrorPath
    $exitCode = $LASTEXITCODE
    $output = if (Test-Path -LiteralPath $standardOutputPath) {
      Get-Content -Raw -LiteralPath $standardOutputPath
    }
    else {
      ''
    }
    $errorOutput = if (Test-Path -LiteralPath $standardErrorPath) {
      Get-Content -Raw -LiteralPath $standardErrorPath
    }
    else {
      ''
    }
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
    Remove-Item -LiteralPath $standardOutputPath, $standardErrorPath -Force -ErrorAction SilentlyContinue
  }

  [pscustomobject]@{
    ExitCode = $exitCode
    Output = [System.Convert]::ToString($output).Trim()
    ErrorOutput = [System.Convert]::ToString($errorOutput).Trim()
  }
}

function ConvertTo-YamlSingleQuotedPath {
  param([Parameter(Mandatory)][string]$Path)

  "'{0}'" -f ($Path.Replace('\', '/').Replace("'", "''"))
}

function Get-ObjectPropertyValue {
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Name,
    $DefaultValue
  )

  $property = @($Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
  if ($property.Count -eq 0) {
    return $DefaultValue
  }
  return $property[0].Value
}

function Test-ExactPortPublication {
  param(
    [Parameter(Mandatory)]$Service,
    [Parameter(Mandatory)][string]$HostIp,
    [Parameter(Mandatory)][int]$Port
  )

  $ports = @($Service.ports)
  if ($ports.Count -ne 1) {
    return $false
  }

  $publication = $ports[0]
  return (
    [string]$publication.host_ip -eq $HostIp -and
    [int]$publication.published -eq $Port -and
    [int]$publication.target -eq $Port -and
    [string]$publication.protocol -eq 'tcp'
  )
}

function Test-GitIgnoreState {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][bool]$ShouldBeIgnored
  )

  & git -C $repoRoot check-ignore -q -- $Path
  $isIgnored = $LASTEXITCODE -eq 0
  Assert-Validation -Condition ($isIgnored -eq $ShouldBeIgnored) -Message (
    "Ignore state for '{0}' was {1}; expected ignored={2}." -f $Path, $isIgnored, $ShouldBeIgnored
  )
}

function Test-MarkdownLinks {
  param([Parameter(Mandatory)][string]$MarkdownPath)

  if (-not (Test-Path -LiteralPath $MarkdownPath -PathType Leaf)) {
    return
  }

  $baseDirectory = Split-Path -Parent $MarkdownPath
  $content = Get-Content -Raw -LiteralPath $MarkdownPath
  foreach ($match in [regex]::Matches($content, '\[[^\]]+\]\(([^)]+)\)')) {
    $target = $match.Groups[1].Value.Trim().Trim('<', '>')
    if ($target -match '^(?:https?://|mailto:|#)' -or $target -match '^<.*>$') {
      continue
    }

    $pathOnly = ($target -split '#', 2)[0]
    if ([string]::IsNullOrWhiteSpace($pathOnly)) {
      continue
    }

    $resolvedTarget = Join-Path $baseDirectory $pathOnly
    Assert-Validation -Condition (Test-Path -LiteralPath $resolvedTarget) -Message (
      "Markdown link target is missing: {0} -> {1}" -f $MarkdownPath, $target
    )
  }
}

function Add-ContractViolation {
  param(
    [Parameter(Mandatory)]$Violations,
    [Parameter(Mandatory)][string]$Rule
  )

  if (-not $Violations.Contains($Rule)) {
    [void]$Violations.Add($Rule)
  }
}

function Get-TlsIgnoreContractViolations {
  param(
    [Parameter(Mandatory)][string]$GitIgnoreContent,
    [Parameter(Mandatory)][string]$TlsContent
  )

  $violations = New-Object 'System.Collections.Generic.List[string]'
  if ($GitIgnoreContent -notmatch '(?m)^deploy/tls/\.runtime-staging/\s*$') {
    Add-ContractViolation -Violations $violations -Rule 'tls-runtime-staging-ignore'
  }
  if ($GitIgnoreContent -notmatch '(?m)^deploy/tls/generated/\s*$') {
    Add-ContractViolation -Violations $violations -Rule 'tls-generated-ignore'
  }
  if (($GitIgnoreContent + "`n" + $TlsContent) -match '\.phase1-certificate-staging') {
    Add-ContractViolation -Violations $violations -Rule 'tls-legacy-staging-absent'
  }

  return @($violations)
}

function Get-TlsTransactionContractViolations {
  param([Parameter(Mandatory)][string]$Content)

  $violations = New-Object 'System.Collections.Generic.List[string]'
  $parseTokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $Content,
    [ref]$parseTokens,
    [ref]$parseErrors
  )
  if (@($parseErrors).Count -ne 0) {
    Add-ContractViolation -Violations $violations -Rule 'tls-powershell-parse'
    return @($violations)
  }

  $commandAsts = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst]
  }, $true))
  $dockerCommands = @($commandAsts | Where-Object { $_.GetCommandName() -eq 'docker' })
  $moveCommands = @($commandAsts | Where-Object { $_.GetCommandName() -eq 'Move-Item' })
  $promotionCommands = @($moveCommands | Where-Object {
    $_.Extent.Text -match '\$materialRoot' -and $_.Extent.Text -match '\$generatedRoot'
  })
  $promotionOffset = if ($promotionCommands.Count -eq 1) {
    $promotionCommands[0].Extent.StartOffset
  }
  else {
    [int]::MaxValue
  }
  $firstDockerOffset = if ($dockerCommands.Count -gt 0) {
    ($dockerCommands | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1).Extent.StartOffset
  }
  else {
    [int]::MaxValue
  }

  if ($Content -notmatch 'Join-Path \$tlsRoot ''\.runtime-staging''' -or $Content -notmatch '\[guid\]::NewGuid\(\)') {
    Add-ContractViolation -Violations $violations -Rule 'tls-run-guid-staging'
  }
  if ($Content -notmatch 'Join-Path \$runRoot ''archives''' -or $Content -notmatch 'Join-Path \$runRoot ''material''') {
    Add-ContractViolation -Violations $violations -Rule 'tls-separate-archive-material'
  }
  if (
    $Content -notmatch '/work/\$runRelativePath/archives/ca\.zip' -or
    $Content -notmatch '/work/\$runRelativePath/archives/elasticsearch\.zip' -or
    $dockerCommands.Count -ne 2 -or
    @($dockerCommands | Where-Object { $_.Extent.Text -notmatch '--out\s+\$(?:ca|certificate)ContainerArchivePath' }).Count -ne 0
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-certutil-archives-beneath-run'
  }
  if (
    $Content -notmatch 'Expected generated file is missing or empty' -or
    $Content -notmatch 'Unexpected private-key or archive content'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-material-validation'
  }
  if (
    $Content -notmatch 'Remove-Item -LiteralPath \$caArchive, \$certificateArchive' -or
    $Content -notmatch 'Archive deletion verification failed' -or
    $Content -notmatch 'Get-ChildItem -LiteralPath \$runRoot -Recurse -File -Filter [''"]\*\.zip[''"]'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-archive-deletion-before-promotion'
  }

  $runAclCommands = @($commandAsts | Where-Object {
    $_.GetCommandName() -in @('Set-RestrictedAcl', 'Assert-RestrictedAcl') -and
    $_.Extent.Text -match '\$runRoot'
  })
  if (
    $runAclCommands.Count -lt 2 -or
    @($runAclCommands | Where-Object { $_.Extent.StartOffset -ge $firstDockerOffset }).Count -ne 0
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-run-acl-before-generation'
  }

  $stagedAclCommands = @($commandAsts | Where-Object {
    $_.GetCommandName() -in @('Set-RestrictedAcl', 'Assert-RestrictedAcl') -and
    $_.Extent.Text -match '\$stagedPrivateKey'
  })
  if (
    $promotionCommands.Count -ne 1 -or
    @($stagedAclCommands | Where-Object { $_.GetCommandName() -eq 'Set-RestrictedAcl' }).Count -lt 1 -or
    @($stagedAclCommands | Where-Object { $_.GetCommandName() -eq 'Assert-RestrictedAcl' }).Count -lt 1 -or
    @($stagedAclCommands | Where-Object { $_.Extent.StartOffset -ge $promotionOffset }).Count -ne 0
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-acl-before-promotion'
  }

  $finalAclCommands = @($commandAsts | Where-Object {
    $_.GetCommandName() -eq 'Assert-RestrictedAcl' -and
    $_.Extent.Text -match '\$finalPrivateKey'
  })
  if (
    $finalAclCommands.Count -lt 1 -or
    @($finalAclCommands | Where-Object { $_.Extent.StartOffset -le $promotionOffset }).Count -ne 0
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-post-promotion-revalidation'
  }

  $catchText = (@($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CatchClauseAst]
  }, $true)) | ForEach-Object { $_.Extent.Text }) -join "`n"
  if (
    $catchText -notmatch '\$promotionStarted' -or
    $catchText -notmatch 'Remove-ExactTree -Path \$generatedRoot'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-exact-promotion-rollback'
  }

  if ($Content -notmatch '(?s)finally\s*\{.*Remove-ExactTree -Path \$runRoot') {
    Add-ContractViolation -Violations $violations -Rule 'tls-finally-run-cleanup'
  }
  if (
    $Content -match 'SilentlyContinue' -or
    $Content -notmatch 'Cleanup failed for path:' -or
    $Content -notmatch 'Rollback failed for path:' -or
    $Content -notmatch 'Remove-Item -LiteralPath \$Path -Recurse -Force -ErrorAction Stop' -or
    $Content -notmatch 'if \(Test-Path -LiteralPath \$Path\)'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-cleanup-failure-surfaced'
  }
  if (
    $Content -notmatch 'Get-ChildItem -LiteralPath \$stagingRoot -Force' -or
    $Content -notmatch 'Refusing to use non-empty staging root'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'tls-stale-staging-rejected'
  }

  return @($violations)
}

function Get-KibanaTelemetryContractViolations {
  param([Parameter(Mandatory)][string]$Content)

  $violations = New-Object 'System.Collections.Generic.List[string]'
  $telemetryLines = @($Content -split "`r?`n" | Where-Object {
    $_ -match '^\s*telemetry\.[A-Za-z0-9_.-]+\s*:' -and $_ -notmatch '^\s*#'
  })
  if ($Content -match '(?m)^\s*telemetry\.enabled\s*:') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-telemetry-enabled-absent'
  }
  if ($telemetryLines.Count -ne 1) {
    Add-ContractViolation -Violations $violations -Rule 'kibana-telemetry-single-setting'
  }
  if ($telemetryLines.Count -ne 1 -or $telemetryLines[0].Trim() -ne 'telemetry.optIn: false') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-telemetry-optin-only'
  }
  if (@($telemetryLines | Where-Object { $_.Trim() -notmatch '^telemetry\.optIn:\s*false$' }).Count -ne 0) {
    Add-ContractViolation -Violations $violations -Rule 'kibana-telemetry-unsupported-key'
  }

  return @($violations)
}

function Get-KibanaHealthHelperContractViolations {
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

  $violations = New-Object 'System.Collections.Generic.List[string]'
  if ($Content -notmatch 'require\([''"]http[''"]\)' -or $Content -match 'require\([''"](?!http[''"])[^''"]+[''"]\)') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-builtins-only'
  }
  if ($Content -notmatch 'http://127\.0\.0\.1:5601/api/status') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-endpoint'
  }
  if ($Content -notmatch 'REQUEST_TIMEOUT_MS\s*=\s*5000' -or $Content -notmatch 'setTimeout\(REQUEST_TIMEOUT_MS') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-timeout'
  }
  if ($Content -notmatch 'MAX_RESPONSE_BYTES\s*=\s*64\s*\*\s*1024' -or $Content -notmatch 'bodyBytes\s*>\s*MAX_RESPONSE_BYTES') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-body-limit'
  }
  if ($Content -notmatch 'response\.statusCode\s*!==\s*200') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-http-200'
  }
  if ($Content -notmatch 'JSON\.parse\(') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-json'
  }
  if ($Content -notmatch 'payload\.status\.overall\.level\s*!==\s*[''"]available[''"]') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-available'
  }
  if ($Content -notmatch 'process\.exitCode\s*=\s*1') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-nonzero-failure'
  }
  if ($Content -match '(?i)authorization|credential|token|console\.|process\.(?:stdout|stderr)|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-health-sensitive-or-insecure'
  }

  return @($violations)
}

function Get-KibanaComposeSourceContractViolations {
  param([Parameter(Mandatory)][string]$Content)

  $violations = New-Object 'System.Collections.Generic.List[string]'
  if (
    $Content -notmatch '(?s)source:\s*\./kibana/bin/kibana-healthcheck\.js\s+target:\s*/usr/local/bin/kibana-healthcheck\.js\s+read_only:\s*true\s+bind:\s*\r?\n\s+create_host_path:\s*false'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'kibana-compose-helper-mount'
  }
  if ($Content -notmatch '(?s)healthcheck:\s*\r?\n\s+test:\s*\r?\n\s+- CMD\s*\r?\n\s+- /usr/share/kibana/node/bin/node\s*\r?\n\s+- /usr/local/bin/kibana-healthcheck\.js') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-compose-health-command'
  }
  if (
    $Content -notmatch '(?s)healthcheck:.*interval:\s*10s.*timeout:\s*8s.*retries:\s*30.*start_period:\s*60s'
  ) {
    Add-ContractViolation -Violations $violations -Rule 'kibana-compose-health-timing'
  }
  if ($Content -notmatch '(?s)name:\s*kibana-http.*host_ip:\s*127\.0\.0\.1') {
    Add-ContractViolation -Violations $violations -Rule 'kibana-compose-loopback-publication'
  }

  return @($violations)
}

function Test-EditorConfigPattern {
  param(
    [Parameter(Mandatory)][string]$Pattern,
    [Parameter(Mandatory)][string]$RelativePath
  )

  $normalizedPath = $RelativePath.Replace('\', '/')
  $target = if ($Pattern.Contains('/')) {
    $normalizedPath
  }
  else {
    [System.IO.Path]::GetFileName($normalizedPath)
  }

  if ($Pattern -match '^(.*)\{([^}]+)\}(.*)$') {
    $prefix = $matches[1]
    $suffix = $matches[3]
    foreach ($option in $matches[2].Split(',')) {
      if ($target -like ($prefix + $option + $suffix)) {
        return $true
      }
    }
    return $false
  }

  return $target -like $Pattern
}

function Get-EditorConfigSettings {
  param(
    [Parameter(Mandatory)][string]$Content,
    [Parameter(Mandatory)][string]$RelativePath
  )

  $settings = @{}
  $sectionApplies = $false
  foreach ($line in ($Content -split "`r?`n")) {
    $trimmed = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) {
      continue
    }
    if ($trimmed -match '^\[(.+)\]$') {
      $sectionApplies = Test-EditorConfigPattern -Pattern $matches[1] -RelativePath $RelativePath
      continue
    }
    if ($sectionApplies -and $trimmed -match '^([^=]+?)\s*=\s*(.+)$') {
      $settings[$matches[1].Trim().ToLowerInvariant()] = $matches[2].Trim().ToLowerInvariant()
    }
  }

  return $settings
}

function Get-TextQualityViolations {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$RelativePath,
    [Parameter(Mandatory)][string]$EditorConfigContent
  )

  $violations = New-Object 'System.Collections.Generic.List[object]'
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
  try {
    $content = $strictUtf8.GetString($bytes)
  }
  catch {
    [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = 1; Rule = 'strict-utf8' })
    return @($violations | ForEach-Object { $_ })
  }

  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = 1; Rule = 'utf8-no-bom' })
  }

  $settings = Get-EditorConfigSettings -Content $EditorConfigContent -RelativePath $RelativePath
  $requiresFinalNewline = if ($settings.ContainsKey('insert_final_newline')) {
    $settings['insert_final_newline'] -eq 'true'
  }
  else {
    $true
  }
  $expectedEndOfLine = if ($settings.ContainsKey('end_of_line')) {
    $settings['end_of_line']
  }
  elseif ([System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant() -in @('.sh', '.js')) {
    'lf'
  }
  else {
    $null
  }
  $trimTrailingWhitespace = $settings.ContainsKey('trim_trailing_whitespace') -and $settings['trim_trailing_whitespace'] -eq 'true'
  $spaceIndentation = $settings.ContainsKey('indent_style') -and $settings['indent_style'] -eq 'space'

  $lines = [regex]::Split($content, "`r`n|`n|`r")
  if ($requiresFinalNewline -and ($bytes.Length -eq 0 -or $bytes[$bytes.Length - 1] -ne 10)) {
    [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = [Math]::Max(1, $lines.Count); Rule = 'final-newline' })
  }
  if ($expectedEndOfLine -eq 'lf') {
    $carriageReturnIndex = $content.IndexOf("`r")
    if ($carriageReturnIndex -ge 0) {
      $lineNumber = ([regex]::Matches($content.Substring(0, $carriageReturnIndex), "`n")).Count + 1
      [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = $lineNumber; Rule = 'lf-line-ending' })
    }
  }

  for ($index = 0; $index -lt $lines.Count; $index++) {
    if ($trimTrailingWhitespace -and $lines[$index] -match '[ \t]+$') {
      [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = $index + 1; Rule = 'trailing-whitespace' })
    }
    if ($spaceIndentation -and $lines[$index] -match '^ *\t') {
      [void]$violations.Add([pscustomobject]@{ Path = $RelativePath; Line = $index + 1; Rule = 'space-indentation' })
    }
  }

  return @($violations | ForEach-Object { $_ })
}

function Assert-NegativeFixtureRejected {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Violations,
    [Parameter(Mandatory)][string]$ExpectedRule
  )

  $script:negativeFixtureCount++
  $rejected = @($Violations | ForEach-Object {
    if ($_ -is [string]) { $_ } else { [string]$_.Rule }
  }) -contains $ExpectedRule
  if ($rejected) {
    $script:rejectedNegativeFixtureCount++
  }
  Assert-Validation -Condition $rejected -Message ("Negative fixture was accepted: {0} ({1})." -f $Name, $ExpectedRule)
}

Push-Location $repoRoot
try {
  $requiredFiles = @(
    '.gitignore',
    'deploy/compose.yaml',
    'deploy/elasticsearch/config/elasticsearch.yml',
    'deploy/elasticsearch/bin/elasticsearch-healthcheck.sh',
    'deploy/kibana/config/kibana.yml',
    'deploy/kibana/bin/kibana-healthcheck.js',
    'deploy/elastic-agent/README.md',
    'deploy/tls/instances.yml',
    'deploy/tls/New-Phase1Certificates.ps1',
    'deploy/env/.env.example',
    'deploy/secrets/README.md',
    'scripts/Test-Phase1Scaffolding.ps1',
    'scripts/Wait-Phase1ElasticsearchReady.ps1',
    'scripts/New-Phase1HostFirewallRule.ps1',
    'scripts/Remove-Phase1HostFirewallRule.ps1',
    'normalization/ecs_mapping.md',
    'docs/phase-1-implementation.md',
    'docs/phase-1-verification.md',
    'PROJECT_PLAN.md',
    'docs/phase-0-environment.md',
    'CONTEXT.md'
  )

  $approvedScaffoldTextPaths = @(
    '.gitignore',
    'CONTEXT.md',
    'PROJECT_PLAN.md',
    'deploy/compose.yaml',
    'deploy/elastic-agent/README.md',
    'deploy/elasticsearch/bin/elasticsearch-healthcheck.sh',
    'deploy/elasticsearch/config/elasticsearch.yml',
    'deploy/env/.env.example',
    'deploy/kibana/bin/kibana-healthcheck.js',
    'deploy/kibana/config/kibana.yml',
    'deploy/secrets/README.md',
    'deploy/tls/New-Phase1Certificates.ps1',
    'deploy/tls/instances.yml',
    'docs/phase-0-environment.md',
    'docs/phase-1-implementation.md',
    'docs/phase-1-verification.md',
    'normalization/ecs_mapping.md',
    'scripts/New-Phase1HostFirewallRule.ps1',
    'scripts/Remove-Phase1HostFirewallRule.ps1',
    'scripts/Test-Phase1Scaffolding.ps1',
    'scripts/Wait-Phase1ElasticsearchReady.ps1'
  )
  $editorConfigContent = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.editorconfig')

  foreach ($relativePath in $requiredFiles) {
    Assert-Validation -Condition (Test-Path -LiteralPath (Join-Path $repoRoot $relativePath) -PathType Leaf) -Message (
      "Required scaffold file is missing: {0}" -f $relativePath
    )
  }

  foreach ($powerShellRelativePath in @(
    'deploy/tls/New-Phase1Certificates.ps1',
    'scripts/Test-Phase1Scaffolding.ps1',
    'scripts/Wait-Phase1ElasticsearchReady.ps1',
    'scripts/New-Phase1HostFirewallRule.ps1',
    'scripts/Remove-Phase1HostFirewallRule.ps1'
  )) {
    $powerShellPath = Join-Path $repoRoot $powerShellRelativePath
    if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
      continue
    }

    $parseTokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
      $powerShellPath,
      [ref]$parseTokens,
      [ref]$parseErrors
    ) | Out-Null
    Assert-Validation -Condition (@($parseErrors).Count -eq 0) -Message (
      "PowerShell 5.1 syntax validation failed: {0}" -f $powerShellRelativePath
    )
  }

  New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
  $temporaryCaDirectory = New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'ca')
  $temporaryElasticsearchDirectory = New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'elasticsearch')
  $temporaryPassword = Join-Path $temporaryRoot 'validation-password.txt'
  $temporaryKeystore = Join-Path $temporaryRoot 'kibana.keystore'
  $temporaryOverride = Join-Path $temporaryRoot 'compose.validation.yaml'

  Write-Utf8NoBomFile -Path (Join-Path $temporaryCaDirectory.FullName 'ca.crt') -Value 'VALIDATION-ONLY INVALID CA PLACEHOLDER'
  Write-Utf8NoBomFile -Path (Join-Path $temporaryCaDirectory.FullName 'ca.key') -Value 'VALIDATION-ONLY INVALID KEY PLACEHOLDER'
  Write-Utf8NoBomFile -Path (Join-Path $temporaryElasticsearchDirectory.FullName 'elasticsearch.crt') -Value 'VALIDATION-ONLY INVALID CERTIFICATE PLACEHOLDER'
  Write-Utf8NoBomFile -Path (Join-Path $temporaryElasticsearchDirectory.FullName 'elasticsearch.key') -Value 'VALIDATION-ONLY INVALID KEY PLACEHOLDER'
  Write-Utf8NoBomFile -Path $temporaryPassword -Value 'VALIDATION-ONLY-NOT-A-REAL-PASSWORD'
  Write-Utf8NoBomFile -Path $temporaryKeystore -Value 'VALIDATION-ONLY INVALID KEYSTORE PLACEHOLDER'

  $caSource = ConvertTo-YamlSingleQuotedPath -Path $temporaryCaDirectory.FullName
  $elasticsearchSource = ConvertTo-YamlSingleQuotedPath -Path $temporaryElasticsearchDirectory.FullName
  $keystoreSource = ConvertTo-YamlSingleQuotedPath -Path $temporaryKeystore
  $passwordSource = ConvertTo-YamlSingleQuotedPath -Path $temporaryPassword
  $overrideContent = @"
services:
  elasticsearch:
    volumes:
      - type: bind
        source: $caSource
        target: /usr/share/elasticsearch/config/certs/ca
        read_only: true
      - type: bind
        source: $elasticsearchSource
        target: /usr/share/elasticsearch/config/certs/elasticsearch
        read_only: true
  kibana:
    volumes:
      - type: bind
        source: $caSource
        target: /usr/share/kibana/config/certs/ca
        read_only: true
      - type: bind
        source: $keystoreSource
        target: /usr/share/kibana/config/kibana.keystore
        read_only: true
secrets:
  elasticsearch-bootstrap-password:
    file: $passwordSource
"@
  Write-Utf8NoBomFile -Path $temporaryOverride -Value $overrideContent

  $composePath = Join-Path $repoRoot 'deploy/compose.yaml'
  $envPath = Join-Path $repoRoot 'deploy/env/.env.example'
  if (
    (Test-Path -LiteralPath $composePath -PathType Leaf) -and
    (Test-Path -LiteralPath $envPath -PathType Leaf) -and
    (Get-Command docker -ErrorAction SilentlyContinue)
  ) {
    $composeArguments = @(
      'compose',
      '--env-file', $envPath,
      '-f', $composePath,
      '-f', $temporaryOverride,
      '--profile', 'elastic',
      'config'
    )

    $quietResult = Invoke-CapturedCommand -Command 'docker' -Arguments ($composeArguments + '--quiet')
    Assert-Validation -Condition ($quietResult.ExitCode -eq 0) -Message (
      "docker compose config --quiet failed: {0}" -f $quietResult.ErrorOutput
    )

    $jsonResult = Invoke-CapturedCommand -Command 'docker' -Arguments ($composeArguments + @('--format', 'json'))
    Assert-Validation -Condition ($jsonResult.ExitCode -eq 0) -Message 'docker compose config --format json failed.'

    if ($jsonResult.ExitCode -eq 0) {
      try {
        $model = $jsonResult.Output | ConvertFrom-Json
        $serviceNames = @($model.services.psobject.Properties.Name | Sort-Object)
        Assert-Validation -Condition (($serviceNames -join ',') -eq 'elasticsearch,kibana') -Message 'Compose services must be exactly elasticsearch and kibana.'

        $elasticsearch = $model.services.elasticsearch
        $kibana = $model.services.kibana
        Assert-Validation -Condition ([string]$elasticsearch.image -eq 'docker.elastic.co/elasticsearch/elasticsearch:9.4.3') -Message 'Elasticsearch image must be pinned exactly to 9.4.3.'
        Assert-Validation -Condition ([string]$kibana.image -eq 'docker.elastic.co/kibana/kibana:9.4.3') -Message 'Kibana image must be pinned exactly to 9.4.3.'
        Assert-Validation -Condition ((@($elasticsearch.profiles) -join ',') -eq 'elastic') -Message 'Elasticsearch profile must be exactly elastic.'
        Assert-Validation -Condition ((@($kibana.profiles) -join ',') -eq 'elastic') -Message 'Kibana profile must be exactly elastic.'
        Assert-Validation -Condition ([string]$elasticsearch.restart -eq 'no') -Message 'Elasticsearch restart policy must be no.'
        Assert-Validation -Condition ([string]$kibana.restart -eq 'no') -Message 'Kibana restart policy must be no.'
        Assert-Validation -Condition (Test-ExactPortPublication -Service $elasticsearch -HostIp '192.168.15.1' -Port 9200) -Message 'Elasticsearch must publish only 192.168.15.1:9200.'
        Assert-Validation -Condition (Test-ExactPortPublication -Service $kibana -HostIp '127.0.0.1' -Port 5601) -Message 'Kibana must publish only 127.0.0.1:5601.'

        $renderedPublications = @($elasticsearch.ports) + @($kibana.ports)
        Assert-Validation -Condition (-not ($renderedPublications | Where-Object { [string]$_.host_ip -eq '0.0.0.0' })) -Message 'A host publication uses 0.0.0.0.'
        Assert-Validation -Condition (-not ($renderedPublications | Where-Object { [int]$_.published -in @(9300, 8220) })) -Message 'A forbidden host port (9300 or 8220) is published.'

        $volumeNames = @($model.volumes.psobject.Properties.Name | Sort-Object)
        Assert-Validation -Condition (($volumeNames -join ',') -eq 'elasticsearch-data,kibana-data') -Message 'Compose must define exactly the two approved named data volumes.'
        $networkNames = @($model.networks.psobject.Properties.Name)
        Assert-Validation -Condition (($networkNames -join ',') -eq 'phase1') -Message 'Compose must define exactly one phase1 network.'
        $phase1Network = $model.networks.phase1
        Assert-Validation -Condition ([string]$phase1Network.driver -eq 'bridge') -Message 'The phase1 network must use the bridge driver.'
        $networkInternal = Get-ObjectPropertyValue -Object $phase1Network -Name 'internal' -DefaultValue $false
        $networkExternal = Get-ObjectPropertyValue -Object $phase1Network -Name 'external' -DefaultValue $false
        Assert-Validation -Condition (-not [bool]$networkInternal) -Message 'The phase1 bridge must remain outbound-capable (internal=false).'
        Assert-Validation -Condition (-not [bool]$networkExternal) -Message 'The phase1 bridge must be project-private (external=false).'

        $elasticsearchNetworks = @($elasticsearch.networks.PSObject.Properties.Name)
        $kibanaNetworks = @($kibana.networks.PSObject.Properties.Name)
        Assert-Validation -Condition (($elasticsearchNetworks -join ',') -eq 'phase1') -Message 'Elasticsearch must attach only to the phase1 network.'
        Assert-Validation -Condition (($kibanaNetworks -join ',') -eq 'phase1') -Message 'Kibana must attach only to the phase1 network.'

        $secretNames = @($model.secrets.PSObject.Properties.Name)
        Assert-Validation -Condition (($secretNames -join ',') -eq 'elasticsearch-bootstrap-password') -Message 'Compose must define exactly the file-backed Elasticsearch password secret.'
        $elasticsearchSecretSources = @($elasticsearch.secrets | ForEach-Object { [string]$_.source })
        Assert-Validation -Condition (($elasticsearchSecretSources -join ',') -eq 'elasticsearch-bootstrap-password') -Message 'Elasticsearch must mount exactly the approved password secret.'
        $kibanaSecrets = @(Get-ObjectPropertyValue -Object $kibana -Name 'secrets' -DefaultValue @())
        Assert-Validation -Condition ($kibanaSecrets.Count -eq 0) -Message 'Kibana must not receive a Compose secret or environment credential.'
        Assert-Validation -Condition ([string]$elasticsearch.environment.ELASTIC_PASSWORD_FILE -eq '/run/secrets/elasticsearch-bootstrap-password') -Message 'Elasticsearch must use ELASTIC_PASSWORD_FILE with the mounted secret path.'
        Assert-Validation -Condition ($jsonResult.Output -notmatch '(?i)elasticsearch\.serviceAccountToken|Authorization\s*:\s*ApiKey') -Message 'The rendered Compose model contains a service token or Agent API key.'

        $dependency = $kibana.depends_on.elasticsearch
        Assert-Validation -Condition ([string]$dependency.condition -eq 'service_healthy') -Message 'Kibana must depend on Elasticsearch service_healthy.'
        Assert-Validation -Condition ([bool]$dependency.restart) -Message 'Kibana dependency must restart after an explicitly restarted Elasticsearch dependency.'
        $healthCommand = @($elasticsearch.healthcheck.test) -join ' '
        Assert-Validation -Condition ($healthCommand -eq 'CMD /bin/sh /usr/local/bin/elasticsearch-healthcheck.sh') -Message 'Elasticsearch health must invoke the mounted helper through /bin/sh.'
        Assert-Validation -Condition ([string]$elasticsearch.healthcheck.start_period -eq '30s') -Message 'Elasticsearch health start_period must be 30s.'
        Assert-Validation -Condition ([string]$elasticsearch.healthcheck.interval -eq '10s') -Message 'Elasticsearch health interval must be 10s.'
        Assert-Validation -Condition ([string]$elasticsearch.healthcheck.timeout -eq '10s') -Message 'Elasticsearch health timeout must be 10s.'
        Assert-Validation -Condition ([int]$elasticsearch.healthcheck.retries -eq 30) -Message 'Elasticsearch health retries must be 30.'

        $kibanaHelperMounts = @($kibana.volumes | Where-Object {
          [string]$_.target -eq '/usr/local/bin/kibana-healthcheck.js'
        })
        Assert-Validation -Condition ($kibanaHelperMounts.Count -eq 1) -Message 'Kibana must mount exactly one health helper at /usr/local/bin/kibana-healthcheck.js.'
        if ($kibanaHelperMounts.Count -eq 1) {
          $kibanaHelperMount = $kibanaHelperMounts[0]
          $normalizedHelperSource = ([string]$kibanaHelperMount.source).Replace('\', '/')
          Assert-Validation -Condition ([string]$kibanaHelperMount.type -eq 'bind') -Message 'Kibana health helper must use a bind mount.'
          Assert-Validation -Condition ($normalizedHelperSource.EndsWith('/deploy/kibana/bin/kibana-healthcheck.js')) -Message 'Kibana health helper source must be the exact committed helper.'
          Assert-Validation -Condition ([bool]$kibanaHelperMount.read_only) -Message 'Kibana health helper mount must be read-only.'
          $helperBind = Get-ObjectPropertyValue -Object $kibanaHelperMount -Name 'bind' -DefaultValue $null
          $createHostPath = if ($null -eq $helperBind) {
            $true
          }
          else {
            [bool](Get-ObjectPropertyValue -Object $helperBind -Name 'create_host_path' -DefaultValue $true)
          }
          Assert-Validation -Condition (-not $createHostPath) -Message 'Kibana health helper bind.create_host_path must be false.'
        }

        $kibanaHealth = Get-ObjectPropertyValue -Object $kibana -Name 'healthcheck' -DefaultValue $null
        $kibanaHealthTest = if ($null -eq $kibanaHealth) {
          @()
        }
        else {
          @(Get-ObjectPropertyValue -Object $kibanaHealth -Name 'test' -DefaultValue @())
        }
        $kibanaHealthCommand = $kibanaHealthTest -join ' '
        Assert-Validation -Condition ($kibanaHealthCommand -eq 'CMD /usr/share/kibana/node/bin/node /usr/local/bin/kibana-healthcheck.js') -Message 'Kibana health must invoke the exact bundled Node command.'
        $renderedKibanaStartPeriod = if ($null -eq $kibanaHealth) {
          ''
        }
        else {
          [string](Get-ObjectPropertyValue -Object $kibanaHealth -Name 'start_period' -DefaultValue '')
        }
        Assert-Validation -Condition ($renderedKibanaStartPeriod -in @('60s', '1m0s')) -Message 'Kibana health start_period must render as the approved 60 seconds.'
        Assert-Validation -Condition ($null -ne $kibanaHealth -and [string](Get-ObjectPropertyValue -Object $kibanaHealth -Name 'interval' -DefaultValue '') -eq '10s') -Message 'Kibana health interval must be 10s.'
        Assert-Validation -Condition ($null -ne $kibanaHealth -and [string](Get-ObjectPropertyValue -Object $kibanaHealth -Name 'timeout' -DefaultValue '') -eq '8s') -Message 'Kibana health timeout must be 8s.'
        Assert-Validation -Condition ($null -ne $kibanaHealth -and [int](Get-ObjectPropertyValue -Object $kibanaHealth -Name 'retries' -DefaultValue 0) -eq 30) -Message 'Kibana health retries must be 30.'
      }
      catch {
        Add-ValidationFailure -Message ("Rendered Compose model inspection failed: {0}" -f $_.Exception.Message)
      }
    }
  }
  elseif (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Add-ValidationFailure -Message 'docker is unavailable; Compose static validation could not run.'
  }

  $healthPath = Join-Path $repoRoot 'deploy/elasticsearch/bin/elasticsearch-healthcheck.sh'
  if (Test-Path -LiteralPath $healthPath -PathType Leaf) {
    $healthContent = Get-Content -Raw -LiteralPath $healthPath
    Assert-Validation -Condition ($healthContent -match '/run/secrets/elasticsearch-bootstrap-password') -Message 'Health helper does not read the mounted password secret.'
    Assert-Validation -Condition ($healthContent -match '/usr/share/elasticsearch/config/certs/ca/ca\.crt') -Message 'Health helper does not use the mounted CA.'
    Assert-Validation -Condition ($healthContent -match '/_cluster/health\?wait_for_status=yellow&timeout=5s&filter_path=status,timed_out') -Message 'Health helper does not use the approved cluster-health query.'
    Assert-Validation -Condition ($healthContent -match 'curl --config -') -Message 'Health helper must pass curl credentials through stdin configuration.'
    Assert-Validation -Condition ($healthContent -match 'max-time = "8"') -Message 'Health helper lacks the approved curl timeout.'
    Assert-Validation -Condition ($healthContent -match 'timed_out') -Message 'Health helper does not reject cluster-health timeouts.'
    Assert-Validation -Condition ($healthContent -match 'yellow\|green|yellow.*green') -Message 'Health helper does not restrict success to yellow or green.'
    Assert-Validation -Condition ($healthContent -notmatch '(?m)^\s*exit\s+2\s*$') -Message 'Health helper must never use reserved exit code 2.'
    Assert-Validation -Condition ($healthContent -notmatch '(?m)^\s*(?:echo|printf).*\$password') -Message 'Health helper may print the password.'
    Assert-Validation -Condition ($healthContent -notmatch '(?m)^\s*(?:export|env)\s+.*password') -Message 'Health helper may export the password through the environment.'
    Assert-Validation -Condition ($healthContent -notmatch '(?m)^\s*curl\s+.*(?:--user|-u\s)') -Message 'Health helper may expose the password through curl arguments.'
    $healthBytes = [System.IO.File]::ReadAllBytes($healthPath)
    Assert-Validation -Condition (-not ($healthBytes -contains 13)) -Message 'Health helper must use LF rather than CRLF line endings.'
  }

  $gitIgnoreContent = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.gitignore')
  $tlsScriptPath = Join-Path $repoRoot 'deploy/tls/New-Phase1Certificates.ps1'
  $tlsScriptContent = if (Test-Path -LiteralPath $tlsScriptPath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $tlsScriptPath
  }
  else {
    ''
  }
  $tlsIgnoreViolations = @(Get-TlsIgnoreContractViolations -GitIgnoreContent $gitIgnoreContent -TlsContent $tlsScriptContent)
  foreach ($rule in @(
    'tls-runtime-staging-ignore',
    'tls-generated-ignore',
    'tls-legacy-staging-absent'
  )) {
    Assert-Validation -Condition ($tlsIgnoreViolations -notcontains $rule) -Message ("TLS ignore contract failed: {0}." -f $rule)
  }

  $tlsTransactionViolations = @(Get-TlsTransactionContractViolations -Content $tlsScriptContent)
  foreach ($rule in @(
    'tls-powershell-parse',
    'tls-run-guid-staging',
    'tls-separate-archive-material',
    'tls-certutil-archives-beneath-run',
    'tls-material-validation',
    'tls-archive-deletion-before-promotion',
    'tls-run-acl-before-generation',
    'tls-acl-before-promotion',
    'tls-post-promotion-revalidation',
    'tls-exact-promotion-rollback',
    'tls-finally-run-cleanup',
    'tls-cleanup-failure-surfaced',
    'tls-stale-staging-rejected'
  )) {
    Assert-Validation -Condition ($tlsTransactionViolations -notcontains $rule) -Message ("TLS transaction contract failed: {0}." -f $rule)
  }

  $composeSourceContent = Get-Content -Raw -LiteralPath $composePath
  $composeSourceViolations = @(Get-KibanaComposeSourceContractViolations -Content $composeSourceContent)
  foreach ($rule in @(
    'kibana-compose-helper-mount',
    'kibana-compose-health-command',
    'kibana-compose-health-timing',
    'kibana-compose-loopback-publication'
  )) {
    Assert-Validation -Condition ($composeSourceViolations -notcontains $rule) -Message ("Kibana Compose source contract failed: {0}." -f $rule)
  }

  $kibanaHealthHelperPath = Join-Path $repoRoot 'deploy/kibana/bin/kibana-healthcheck.js'
  $kibanaHealthHelperContent = if (Test-Path -LiteralPath $kibanaHealthHelperPath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $kibanaHealthHelperPath
  }
  else {
    ''
  }
  $kibanaHealthViolations = @(Get-KibanaHealthHelperContractViolations -Content $kibanaHealthHelperContent)
  foreach ($rule in @(
    'kibana-health-builtins-only',
    'kibana-health-endpoint',
    'kibana-health-timeout',
    'kibana-health-body-limit',
    'kibana-health-http-200',
    'kibana-health-json',
    'kibana-health-available',
    'kibana-health-nonzero-failure',
    'kibana-health-sensitive-or-insecure'
  )) {
    Assert-Validation -Condition ($kibanaHealthViolations -notcontains $rule) -Message ("Kibana health-helper contract failed: {0}." -f $rule)
  }

  $instancesPath = Join-Path $repoRoot 'deploy/tls/instances.yml'
  if (Test-Path -LiteralPath $instancesPath -PathType Leaf) {
    $instancesContent = (Get-Content -Raw -LiteralPath $instancesPath).Replace("`r`n", "`n").Trim()
    $expectedInstances = @'
instances:
  - name: elasticsearch
    dns:
      - elasticsearch
    ip:
      - 192.168.15.1
'@.Trim()
    Assert-Validation -Condition ($instancesContent -eq $expectedInstances) -Message 'TLS instances.yml must define only Elasticsearch with the approved DNS and IP SANs.'
  }

  $elasticsearchConfigPath = Join-Path $repoRoot 'deploy/elasticsearch/config/elasticsearch.yml'
  if (Test-Path -LiteralPath $elasticsearchConfigPath -PathType Leaf) {
    $elasticsearchConfig = Get-Content -Raw -LiteralPath $elasticsearchConfigPath
    Assert-Validation -Condition ($elasticsearchConfig -match '(?m)^discovery\.type:\s*single-node\s*$') -Message 'Elasticsearch must remain single-node.'
    Assert-Validation -Condition ($elasticsearchConfig -match '(?m)^xpack\.security\.enabled:\s*true\s*$') -Message 'Elasticsearch security must be enabled.'
    Assert-Validation -Condition ($elasticsearchConfig -match '(?m)^xpack\.security\.http\.ssl\.enabled:\s*true\s*$') -Message 'Elasticsearch HTTP TLS must be enabled.'
    Assert-Validation -Condition ($elasticsearchConfig -match '/certs/ca/ca\.crt' -and $elasticsearchConfig -match '/certs/elasticsearch/elasticsearch\.crt' -and $elasticsearchConfig -match '/certs/elasticsearch/elasticsearch\.key') -Message 'Elasticsearch must use the generated CA, HTTP certificate, and key paths.'
  }

  $kibanaConfigPath = Join-Path $repoRoot 'deploy/kibana/config/kibana.yml'
  if (Test-Path -LiteralPath $kibanaConfigPath -PathType Leaf) {
    $kibanaConfig = Get-Content -Raw -LiteralPath $kibanaConfigPath
    Assert-Validation -Condition ($kibanaConfig -match 'https://elasticsearch:9200') -Message 'Kibana must use the internal Elasticsearch HTTPS endpoint.'
    Assert-Validation -Condition ($kibanaConfig -match '(?m)^elasticsearch\.ssl\.verificationMode:\s*full\s*$') -Message 'Kibana must use full Elasticsearch certificate verification.'
    Assert-Validation -Condition ($kibanaConfig -match '/certs/ca/ca\.crt') -Message 'Kibana must trust the mounted local CA.'
    Assert-Validation -Condition ($kibanaConfig -notmatch '(?i)username\s*:|password\s*:|serviceAccountToken\s*:') -Message 'Kibana configuration contains an inline Elasticsearch credential.'
    $telemetryViolations = @(Get-KibanaTelemetryContractViolations -Content $kibanaConfig)
    foreach ($rule in @(
      'kibana-telemetry-enabled-absent',
      'kibana-telemetry-single-setting',
      'kibana-telemetry-optin-only',
      'kibana-telemetry-unsupported-key'
    )) {
      Assert-Validation -Condition ($telemetryViolations -notcontains $rule) -Message ("Kibana telemetry contract failed: {0}." -f $rule)
    }
  }

  $waitPath = Join-Path $repoRoot 'scripts/Wait-Phase1ElasticsearchReady.ps1'
  if (Test-Path -LiteralPath $waitPath -PathType Leaf) {
    $waitContent = Get-Content -Raw -LiteralPath $waitPath
    Assert-Validation -Condition ($waitContent -match "'401'") -Message 'Listener readiness script must require HTTP 401.'
    Assert-Validation -Condition ($waitContent -match 'listener-only') -Message 'The 401 result must be labeled listener-only.'
    Assert-Validation -Condition ($waitContent -match 'State\.Health') -Message 'Readiness script must wait for authenticated Docker health.'
    $waitUnsafeTlsPattern = '(?i)--' + 'insecure|skipcertificate|verificationmode\s*[:=]\s*none'
    Assert-Validation -Condition ($waitContent -notmatch $waitUnsafeTlsPattern) -Message 'Readiness script weakens TLS verification.'
  }

  $firewallCreatePath = Join-Path $repoRoot 'scripts/New-Phase1HostFirewallRule.ps1'
  $firewallRemovePath = Join-Path $repoRoot 'scripts/Remove-Phase1HostFirewallRule.ps1'
  foreach ($firewallPath in @($firewallCreatePath, $firewallRemovePath)) {
    if (Test-Path -LiteralPath $firewallPath -PathType Leaf) {
      $firewallContent = Get-Content -Raw -LiteralPath $firewallPath
      Assert-Validation -Condition ($firewallContent -match 'SupportsShouldProcess') -Message "Firewall script lacks SupportsShouldProcess: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match '192\.168\.15\.1') -Message "Firewall script lacks the exact local address: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match '192\.168\.15\.6') -Message "Firewall script lacks the exact remote address: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match '9200') -Message "Firewall script lacks TCP 9200: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match 'VirtualBox.*Host') -Message "Firewall script does not constrain discovery to VirtualBox host-only: $firewallPath"
      Assert-Validation -Condition ($firewallContent -notmatch '(?i)Set-NetFirewallProfile|Disable-NetFirewall|RemoteAddress\s*=\s*[''\"]?192\.168\.15\.0/24|LocalPort\s*=\s*[''\"]?(?:5601|8220|9300)') -Message "Firewall script contains a broad or forbidden operation: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match '#requires -RunAsAdministrator') -Message "Firewall script must require administrator rights: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match '\[switch\]\$Approve' -and $firewallContent -match 'WhatIfPreference') -Message "Firewall script must require explicit approval while preserving WhatIf: $firewallPath"
      Assert-Validation -Condition ($firewallContent -match "@\('Domain', 'Private', 'Public'\)") -Message "Firewall script must restrict the applicable profile to Domain, Private, or Public: $firewallPath"
    }
  }

  if (Test-Path -LiteralPath $firewallCreatePath -PathType Leaf) {
    $firewallCreateContent = Get-Content -Raw -LiteralPath $firewallCreatePath
    Assert-Validation -Condition ($firewallCreateContent -match 'New-NetFirewallRule' -and $firewallCreateContent -match '-Direction Inbound' -and $firewallCreateContent -match '-Action Allow' -and $firewallCreateContent -match '-Protocol TCP') -Message 'Firewall creation script must create only the approved inbound Allow TCP rule.'
    Assert-Validation -Condition ($firewallCreateContent -match 'same-name firewall rule differs' -and $firewallCreateContent -match 'already exists; no change') -Message 'Firewall creation script must be idempotent and fail closed on same-name drift.'
  }
  if (Test-Path -LiteralPath $firewallRemovePath -PathType Leaf) {
    $firewallRemoveContent = Get-Content -Raw -LiteralPath $firewallRemovePath
    Assert-Validation -Condition ($firewallRemoveContent -match 'Test-ExactPhase1Rule' -and $firewallRemoveContent -match 'Remove-NetFirewallRule') -Message 'Firewall removal script must verify and remove only the exact approved rule.'
    Assert-Validation -Condition ($firewallRemoveContent -notmatch 'New-NetFirewallRule') -Message 'Firewall removal script must not create a firewall rule.'
  }

  Test-GitIgnoreState -Path 'deploy/env/.env' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/secrets/elasticsearch-bootstrap-password.txt' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/kibana/config/kibana.keystore' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/tls/.runtime-staging/00000000000000000000000000000000/material/ca/ca.key' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/tls/.runtime-staging/00000000000000000000000000000000/material/elasticsearch/elasticsearch.key' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/tls/generated/ca/ca.key' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/tls/generated/elasticsearch/elasticsearch.key' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/elastic-agent/runtime/elastic-agent.yml' -ShouldBeIgnored $true
  Test-GitIgnoreState -Path 'deploy/env/.env.example' -ShouldBeIgnored $false
  Test-GitIgnoreState -Path 'deploy/elastic-agent/README.md' -ShouldBeIgnored $false
  Test-GitIgnoreState -Path 'deploy/elastic-agent/elastic-agent.yml.example' -ShouldBeIgnored $false
  Test-GitIgnoreState -Path 'deploy/tls/instances.yml' -ShouldBeIgnored $false

  Assert-Validation -Condition (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'deploy/elastic-agent/runtime/elastic-agent.yml'))) -Message 'The unsanitized runtime Agent policy must not exist during scaffolding.'
  Assert-Validation -Condition (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'deploy/elastic-agent/elastic-agent.yml.example'))) -Message 'The sanitized Agent example is deferred and must not exist during initial scaffolding.'

  $candidatePaths = @(& git -c core.quotepath=false -C $repoRoot ls-files --cached --others --exclude-standard)
  $candidateExitCode = $LASTEXITCODE
  if ($candidateExitCode -eq 0) {
    $textExtensions = @('.md', '.yml', '.yaml', '.ps1', '.sh', '.js', '.txt', '.json', '.env', '.example', '.gitignore')
    foreach ($relativePath in @($candidatePaths | Where-Object { $_ })) {
      $absolutePath = Join-Path $repoRoot $relativePath
      if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        continue
      }

      $extension = [System.IO.Path]::GetExtension($absolutePath).ToLowerInvariant()
      if ($relativePath -ne '.gitignore' -and $textExtensions -notcontains $extension) {
        continue
      }

      $content = Get-Content -Raw -LiteralPath $absolutePath -ErrorAction SilentlyContinue
      if ($null -eq $content) {
        continue
      }

      if ($content -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') {
        Add-ValidationFailure -Message "Private-key material detected in: $relativePath"
      }
      if ($content -match '(?i)(?:authorization\s*:\s*ApiKey|elasticsearch\.serviceAccountToken\s*[:=])\s*[A-Za-z0-9+/=_-]{16,}') {
        Add-ValidationFailure -Message "Populated credential pattern detected in: $relativePath"
      }
      $unsafeTlsPattern = '(?i)(?:--' + 'insecure|verification' + 'Mode\s*:\s*none|ssl\.verification_' + 'mode\s*:\s*none)'
      $isPhase1OperationalFile = $relativePath -match '^(?:deploy|scripts)/.*\.(?:ya?ml|ps1|sh)$'
      if ($isPhase1OperationalFile -and $content -match $unsafeTlsPattern) {
        Add-ValidationFailure -Message "Unsafe TLS pattern detected in: $relativePath"
      }

      if ($approvedScaffoldTextPaths -contains $relativePath) {
        $textQualityViolations = @(Get-TextQualityViolations -Path $absolutePath -RelativePath $relativePath -EditorConfigContent $editorConfigContent)
        if ($textQualityViolations.Count -eq 0) {
          Assert-Validation -Condition $true -Message ("{0}:0:text-quality" -f $relativePath)
        }
        else {
          foreach ($violation in $textQualityViolations) {
            Assert-Validation -Condition $false -Message ("{0}:{1}:{2}" -f $violation.Path, $violation.Line, $violation.Rule)
          }
        }
      }
    }
  }
  else {
    Add-ValidationFailure -Message 'Unable to enumerate tracked and candidate files for secret scanning.'
  }

  $negativeFixtureRoot = New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'negative-fixtures')

  $oldStagingIgnoreFixture = ($gitIgnoreContent.Replace("`r`n", "`n") -replace '(?m)^deploy/tls/\.runtime-staging/\n?', '') + "`ndeploy/tls/.phase1-certificate-staging/`n"
  $oldStagingIgnorePath = Join-Path $negativeFixtureRoot.FullName '.gitignore.old-staging'
  Write-Utf8NoBomFile -Path $oldStagingIgnorePath -Value $oldStagingIgnoreFixture
  Assert-NegativeFixtureRejected -Name 'old unignored TLS staging' -Violations @(
    Get-TlsIgnoreContractViolations -GitIgnoreContent (Get-Content -Raw -LiteralPath $oldStagingIgnorePath) -TlsContent $tlsScriptContent
  ) -ExpectedRule 'tls-runtime-staging-ignore'

  $aclAfterPromotionContent = $tlsScriptContent.Replace(
    'Set-RestrictedAcl -Path $stagedPrivateKey',
    'Set-RestrictedAclAfterPromotion -Path $stagedPrivateKey'
  ).Replace(
    'Assert-RestrictedAcl -Path $stagedPrivateKey',
    'Assert-RestrictedAclAfterPromotion -Path $stagedPrivateKey'
  ) + "`nSet-RestrictedAcl -Path `$stagedPrivateKey`nAssert-RestrictedAcl -Path `$stagedPrivateKey`n"
  $aclAfterPromotionPath = Join-Path $negativeFixtureRoot.FullName 'New-Phase1Certificates.acl-after-promotion.ps1'
  Write-Utf8NoBomFile -Path $aclAfterPromotionPath -Value $aclAfterPromotionContent
  Assert-NegativeFixtureRejected -Name 'ACL hardening after promotion' -Violations @(
    Get-TlsTransactionContractViolations -Content (Get-Content -Raw -LiteralPath $aclAfterPromotionPath)
  ) -ExpectedRule 'tls-acl-before-promotion'

  $missingRollbackContent = $tlsScriptContent.Replace(
    'Remove-ExactTree -Path $generatedRoot -FailurePrefix ''Rollback failed for path:''',
    'Write-Output ''rollback omitted'''
  )
  $missingRollbackPath = Join-Path $negativeFixtureRoot.FullName 'New-Phase1Certificates.missing-rollback.ps1'
  Write-Utf8NoBomFile -Path $missingRollbackPath -Value $missingRollbackContent
  Assert-NegativeFixtureRejected -Name 'missing rollback' -Violations @(
    Get-TlsTransactionContractViolations -Content (Get-Content -Raw -LiteralPath $missingRollbackPath)
  ) -ExpectedRule 'tls-exact-promotion-rollback'

  $silentCleanupContent = $tlsScriptContent.Replace(
    'Remove-ExactTree -Path $runRoot -FailurePrefix ''Cleanup failed for path:''',
    'Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue'
  )
  $silentCleanupPath = Join-Path $negativeFixtureRoot.FullName 'New-Phase1Certificates.silent-cleanup.ps1'
  Write-Utf8NoBomFile -Path $silentCleanupPath -Value $silentCleanupContent
  Assert-NegativeFixtureRejected -Name 'silent cleanup' -Violations @(
    Get-TlsTransactionContractViolations -Content (Get-Content -Raw -LiteralPath $silentCleanupPath)
  ) -ExpectedRule 'tls-cleanup-failure-surfaced'

  $telemetryEnabledPath = Join-Path $negativeFixtureRoot.FullName 'kibana.telemetry-enabled.yml'
  Write-Utf8NoBomFile -Path $telemetryEnabledPath -Value ($kibanaConfig + "`ntelemetry.enabled: false`n")
  Assert-NegativeFixtureRejected -Name 'telemetry.enabled' -Violations @(
    Get-KibanaTelemetryContractViolations -Content (Get-Content -Raw -LiteralPath $telemetryEnabledPath)
  ) -ExpectedRule 'kibana-telemetry-enabled-absent'

  $unsupportedTelemetryPath = Join-Path $negativeFixtureRoot.FullName 'kibana.unsupported-telemetry.yml'
  Write-Utf8NoBomFile -Path $unsupportedTelemetryPath -Value ($kibanaConfig + "`ntelemetry.sendUsageFrom: server`n")
  Assert-NegativeFixtureRejected -Name 'unsupported telemetry key' -Violations @(
    Get-KibanaTelemetryContractViolations -Content (Get-Content -Raw -LiteralPath $unsupportedTelemetryPath)
  ) -ExpectedRule 'kibana-telemetry-unsupported-key'

  $missingHealthComposeContent = [regex]::Replace(
    $composeSourceContent,
    '(?ms)^    healthcheck:\r?\n      test:\r?\n        - CMD\r?\n        - /usr/share/kibana/node/bin/node\r?\n        - /usr/local/bin/kibana-healthcheck\.js\r?\n      interval: 10s\r?\n      timeout: 8s\r?\n      retries: 30\r?\n      start_period: 60s\r?\n',
    ''
  )
  $missingHealthComposePath = Join-Path $negativeFixtureRoot.FullName 'compose.missing-kibana-health.yaml'
  Write-Utf8NoBomFile -Path $missingHealthComposePath -Value $missingHealthComposeContent
  Assert-NegativeFixtureRejected -Name 'missing Kibana health check' -Violations @(
    Get-KibanaComposeSourceContractViolations -Content (Get-Content -Raw -LiteralPath $missingHealthComposePath)
  ) -ExpectedRule 'kibana-compose-health-command'

  $non200HelperContent = $kibanaHealthHelperContent.Replace('response.statusCode !== 200', 'response.statusCode < 200')
  $non200HelperPath = Join-Path $negativeFixtureRoot.FullName 'kibana-healthcheck.accepts-non-200.js'
  Write-Utf8NoBomFile -Path $non200HelperPath -Value $non200HelperContent
  Assert-NegativeFixtureRejected -Name 'helper accepts non-200' -Violations @(
    Get-KibanaHealthHelperContractViolations -Content (Get-Content -Raw -LiteralPath $non200HelperPath)
  ) -ExpectedRule 'kibana-health-http-200'

  $unavailableHelperContent = $kibanaHealthHelperContent.Replace(
    "payload.status.overall.level !== 'available'",
    "payload.status.overall.level !== 'unavailable'"
  )
  $unavailableHelperPath = Join-Path $negativeFixtureRoot.FullName 'kibana-healthcheck.no-available.js'
  Write-Utf8NoBomFile -Path $unavailableHelperPath -Value $unavailableHelperContent
  Assert-NegativeFixtureRejected -Name 'helper does not require available' -Violations @(
    Get-KibanaHealthHelperContractViolations -Content (Get-Content -Raw -LiteralPath $unavailableHelperPath)
  ) -ExpectedRule 'kibana-health-available'

  $crlfShellPath = Join-Path $negativeFixtureRoot.FullName 'crlf.sh'
  Write-Utf8NoBomFile -Path $crlfShellPath -Value "#!/bin/sh`r`nexit 0`r`n"
  Assert-NegativeFixtureRejected -Name 'CRLF shell script' -Violations @(
    Get-TextQualityViolations -Path $crlfShellPath -RelativePath 'negative-fixtures/crlf.sh' -EditorConfigContent $editorConfigContent
  ) -ExpectedRule 'lf-line-ending'

  $missingFinalNewlinePath = Join-Path $negativeFixtureRoot.FullName 'missing-final-newline.ps1'
  Write-Utf8NoBomFile -Path $missingFinalNewlinePath -Value 'Write-Output ''fixture'''
  Assert-NegativeFixtureRejected -Name 'missing final newline' -Violations @(
    Get-TextQualityViolations -Path $missingFinalNewlinePath -RelativePath 'negative-fixtures/missing-final-newline.ps1' -EditorConfigContent $editorConfigContent
  ) -ExpectedRule 'final-newline'

  $trailingWhitespacePath = Join-Path $negativeFixtureRoot.FullName 'trailing-whitespace.ps1'
  Write-Utf8NoBomFile -Path $trailingWhitespacePath -Value "Write-Output 'fixture'  `n"
  Assert-NegativeFixtureRejected -Name 'prohibited trailing whitespace' -Violations @(
    Get-TextQualityViolations -Path $trailingWhitespacePath -RelativePath 'negative-fixtures/trailing-whitespace.ps1' -EditorConfigContent $editorConfigContent
  ) -ExpectedRule 'trailing-whitespace'

  $tabIndentationPath = Join-Path $negativeFixtureRoot.FullName 'tab-indentation.ps1'
  Write-Utf8NoBomFile -Path $tabIndentationPath -Value "if (`$true) {`n`tWrite-Output 'fixture'`n}`n"
  Assert-NegativeFixtureRejected -Name 'prohibited tab indentation' -Violations @(
    Get-TextQualityViolations -Path $tabIndentationPath -RelativePath 'negative-fixtures/tab-indentation.ps1' -EditorConfigContent $editorConfigContent
  ) -ExpectedRule 'space-indentation'

  foreach ($markdownPath in @(
    'deploy/elastic-agent/README.md',
    'deploy/secrets/README.md',
    'normalization/ecs_mapping.md',
    'docs/phase-1-implementation.md',
    'docs/phase-1-verification.md'
  )) {
    Test-MarkdownLinks -MarkdownPath (Join-Path $repoRoot $markdownPath)
  }

  $verificationPath = Join-Path $repoRoot 'docs/phase-1-verification.md'
  if (Test-Path -LiteralPath $verificationPath -PathType Leaf) {
    $verificationContent = Get-Content -Raw -LiteralPath $verificationPath
    Assert-Validation -Condition ($verificationContent -notmatch '(?m)^\s*- \[x\]') -Message 'Phase 1 verification must remain unchecked.'
    Assert-Validation -Condition ($verificationContent -match 'Unverified') -Message 'Phase 1 verification must be explicitly labeled Unverified.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] TLS generation completes as one validated transaction before promotion\.$') -Message 'Phase 1 verification lacks the future TLS transaction-safety check.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] Generated private keys retain restrictive non-inherited ACLs after promotion\.$') -Message 'Phase 1 verification lacks the future private-key ACL check.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] No run-specific TLS staging material remains after success or failure\.$') -Message 'Phase 1 verification lacks the future staging-cleanup check.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] Kibana `/api/status` returns HTTP `200`\.$') -Message 'Phase 1 verification lacks the future Kibana HTTP 200 check.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] Kibana `status\.overall\.level` equals `available`\.$') -Message 'Phase 1 verification lacks the future Kibana available-level check.'
    Assert-Validation -Condition ($verificationContent -match '(?m)^- \[ \] Kibana health runs successfully through the bundled Node path `/usr/share/kibana/node/bin/node`\.$') -Message 'Phase 1 verification lacks the future bundled-Node runtime check.'
  }

  $mappingPath = Join-Path $repoRoot 'normalization/ecs_mapping.md'
  if (Test-Path -LiteralPath $mappingPath -PathType Leaf) {
    $mappingContent = Get-Content -Raw -LiteralPath $mappingPath
    Assert-Validation -Condition ($mappingContent -match 'Application' -and $mappingContent -match 'Security' -and $mappingContent -match 'System') -Message 'ECS mapping template must contain all three approved Windows channels.'
    Assert-Validation -Condition ($mappingContent -notmatch '`Live verified`|\|\s*Live verified\s*\|') -Message 'ECS mapping template contains a Live verified claim.'
  }

  $agentReadmePath = Join-Path $repoRoot 'deploy/elastic-agent/README.md'
  if (Test-Path -LiteralPath $agentReadmePath -PathType Leaf) {
    $agentReadmeContent = Get-Content -Raw -LiteralPath $agentReadmePath
    Assert-Validation -Condition ($agentReadmeContent -match 'deploy/elastic-agent/runtime/elastic-agent\.yml') -Message 'Agent README must specify the exact ignored runtime policy path.'
    Assert-Validation -Condition ($agentReadmeContent -match 'deploy/elastic-agent/elastic-agent\.yml\.example') -Message 'Agent README must specify the deferred sanitized example path.'
    Assert-Validation -Condition ($agentReadmeContent -match 'Application' -and $agentReadmeContent -match 'Security' -and $agentReadmeContent -match 'System') -Message 'Agent README must limit policy generation to Application, Security, and System.'
    Assert-Validation -Condition ($agentReadmeContent -match 'epr\.elastic\.co:443' -and $agentReadmeContent -match 'Stop on drift') -Message 'Agent README must document the EPR boundary and package-version drift stop.'
    Assert-Validation -Condition ($agentReadmeContent -match 'no Fleet Server' -and $agentReadmeContent -match 'no enrollment') -Message 'Agent README must preserve standalone mode without Fleet Server or enrollment.'
  }

  $implementationPath = Join-Path $repoRoot 'docs/phase-1-implementation.md'
  if (Test-Path -LiteralPath $implementationPath -PathType Leaf) {
    $implementationContent = Get-Content -Raw -LiteralPath $implementationPath
    Assert-Validation -Condition ($implementationContent -match 'Windows PowerShell 5\.1' -and $implementationContent -match 'powershell\.exe -NoProfile -ExecutionPolicy Bypass -File \.\\scripts\\Test-Phase1Scaffolding\.ps1') -Message 'Implementation guide must record the approved Windows PowerShell 5.1 validation command.'
    Assert-Validation -Condition ($implementationContent -match 'epr\.elastic\.co:443' -and $implementationContent -match 'stop on drift') -Message 'Implementation guide must document controlled EPR access and drift handling.'
    Assert-Validation -Condition ($implementationContent -match '(?s)1\. Reverify RAM.*20\. Install the Agent') -Message 'Implementation guide must preserve the exact 20-step first-start sequence.'
    Assert-Validation -Condition ($implementationContent -match [regex]::Escape('deploy/tls/.runtime-staging/<guid>/') -and $implementationContent -match 'ACL.*before.*promotion') -Message 'Implementation guide must document ignored per-run TLS staging and ACL-before-promotion.'
    Assert-Validation -Condition ($implementationContent -match 'rollback' -and $implementationContent -match 'finally') -Message 'Implementation guide must document TLS rollback and cleanup behavior.'
    Assert-Validation -Condition ($implementationContent -match 'HTTP `200`' -and $implementationContent -match 'status\.overall\.level.*available') -Message 'Implementation guide must document the Kibana health contract.'
    Assert-Validation -Condition ($implementationContent -match 'bundled Node path.*runtime-pending') -Message 'Implementation guide must label the bundled Node path as runtime-pending.'
    Assert-Validation -Condition ($implementationContent -match 'negative fixtures' -and $implementationContent -match 'tracked and untracked') -Message 'Implementation guide must document expanded static validation coverage.'
  }

  $projectPlanContent = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'PROJECT_PLAN.md')
  Assert-Validation -Condition ($projectPlanContent -match 'resource gates block image acquisition.*live ingestion' -and $projectPlanContent -match 'do not block separately approved repository authoring') -Message 'PROJECT_PLAN.md must distinguish runtime gates from approved repository authoring.'

  $phase0Content = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/phase-0-environment.md')
  Assert-Validation -Condition ($phase0Content -notmatch 'Future Elastic/Kibana/Fleet containers|Elastic/Kibana/Fleet container plan|Requires live Sysmon/Elastic Agent evidence|Fleet image/tag or integration version') -Message 'Phase 0 documentation still contains a stale Fleet/Sysmon-first phrase.'

  $contextContent = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'CONTEXT.md')
  Assert-Validation -Condition ($contextContent -match '## 2026-07-14 - Phase 1 Secure Repository Scaffolding Implemented') -Message 'CONTEXT.md lacks the dated Phase 1 scaffolding implementation entry.'
  Assert-Validation -Condition ($contextContent -match 'PowerShell 5\.1 fallback') -Message 'CONTEXT.md does not record the approved Windows PowerShell 5.1 fallback.'
  Assert-Validation -Condition ($contextContent -match [regex]::Escape('Phase 1 secure repository scaffolding implemented and statically validated with Windows PowerShell 5.1; runtime startup and live ingestion remain pending resource provisioning and runtime approval.')) -Message 'CONTEXT.md lacks the exact successful current-status statement.'
  Assert-Validation -Condition ($contextContent -match [regex]::Escape('Review the Phase 1 scaffolding diff, then prepare the separately approved runtime resource and Docker-storage remediation plan.')) -Message 'CONTEXT.md lacks the exact next suggested step.'
  Assert-Validation -Condition ($contextContent -match '## 2026-07-14 - Phase 1 Scaffold Remediation Implemented') -Message 'CONTEXT.md lacks the dated Phase 1 remediation entry.'
  Assert-Validation -Condition ($contextContent -match [regex]::Escape('Phase 1 scaffold remediation implemented and statically validated; runtime validation and live ingestion remain deferred.')) -Message 'CONTEXT.md lacks the exact remediation current-status statement.'
  Assert-Validation -Condition ($contextContent -match [regex]::Escape('Perform a new independent read-only Phase 1 scaffold audit before Phase 2 planning.')) -Message 'CONTEXT.md lacks the exact remediation next-step statement.'

  $approvedChangedPaths = @(
    '.gitignore',
    'CONTEXT.md',
    'PROJECT_PLAN.md',
    'deploy/compose.yaml',
    'deploy/elastic-agent/README.md',
    'deploy/elasticsearch/bin/elasticsearch-healthcheck.sh',
    'deploy/elasticsearch/config/elasticsearch.yml',
    'deploy/env/.env.example',
    'deploy/kibana/bin/kibana-healthcheck.js',
    'deploy/kibana/config/kibana.yml',
    'deploy/secrets/README.md',
    'deploy/tls/New-Phase1Certificates.ps1',
    'deploy/tls/instances.yml',
    'docs/phase-0-environment.md',
    'docs/phase-1-implementation.md',
    'docs/phase-1-verification.md',
    'normalization/ecs_mapping.md',
    'scripts/New-Phase1HostFirewallRule.ps1',
    'scripts/Remove-Phase1HostFirewallRule.ps1',
    'scripts/Test-Phase1Scaffolding.ps1',
    'scripts/Wait-Phase1ElasticsearchReady.ps1'
  )
  $statusLines = @(& git -c core.quotepath=false -C $repoRoot status --porcelain=v1 --untracked-files=all)
  $unexpectedChangedPaths = @()
  foreach ($statusLine in $statusLines) {
    if ([string]::IsNullOrWhiteSpace($statusLine) -or $statusLine.Length -lt 4) {
      continue
    }
    $statusPath = $statusLine.Substring(3)
    if ($statusPath -match ' -> ') {
      $statusPath = ($statusPath -split ' -> ')[-1]
    }
    if ($approvedChangedPaths -notcontains $statusPath) {
      $unexpectedChangedPaths += $statusPath
    }
  }
  Assert-Validation -Condition ($unexpectedChangedPaths.Count -eq 0) -Message ("Changed path is outside the approved scaffold: {0}" -f ($unexpectedChangedPaths -join ', '))
  Assert-Validation -Condition (-not ($statusLines | Where-Object { $_ -match 'README\.md$' -and $_ -notmatch 'deploy/elastic-agent/README\.md$' -and $_ -notmatch 'deploy/secrets/README\.md$' })) -Message 'Root README.md or an unapproved README was modified.'
  Assert-Validation -Condition (-not ($statusLines | Where-Object { $_ -match 'evidence/' })) -Message 'Historical evidence was modified.'

  $diffCheck = Invoke-CapturedCommand -Command 'git' -Arguments @('-C', $repoRoot, 'diff', '--check')
  Assert-Validation -Condition ($diffCheck.ExitCode -eq 0) -Message ("git diff --check failed: {0}" -f $diffCheck.Output)
}
catch {
  Add-ValidationFailure -Message (
    "Validator error at script line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message
  )
}
finally {
  if (Test-Path -LiteralPath $temporaryRoot) {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $temporaryRoot) {
    Add-ValidationFailure -Message 'Temporary validation material was not removed.'
  }
  $temporaryCleanupSucceeded = -not (Test-Path -LiteralPath $temporaryRoot)
  Pop-Location
}

Write-Host 'Phase 1 scaffolding path status:'
& git -C $repoRoot status --short --untracked-files=all
Write-Host ("Negative fixture summary: {0} rejected; {1} accepted; {2} total." -f $rejectedNegativeFixtureCount, ($negativeFixtureCount - $rejectedNegativeFixtureCount), $negativeFixtureCount)
Write-Host ("Temporary cleanup result: {0}." -f $(if ($temporaryCleanupSucceeded) { 'passed' } else { 'failed' }))
Write-Host ("Assertion summary: {0} passed; {1} failed; {2} total." -f $passedAssertionCount, ($assertionCount - $passedAssertionCount), $assertionCount)

if ($failures.Count -gt 0) {
  Write-Host ("Phase 1 static validation failed ({0} issue(s)):" -f $failures.Count)
  foreach ($failure in $failures) {
    Write-Host ("- {0}" -f $failure)
  }
  exit 1
}

Write-Host 'Phase 1 static validation passed.'
exit 0
