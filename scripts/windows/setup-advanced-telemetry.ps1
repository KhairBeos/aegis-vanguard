[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SysmonBinaryPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SysmonConfigPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ElasticAgentConfigPath
)

$ErrorActionPreference = 'Stop'

$requiredSysmonVersion = [Version]'15.21'
$stateDirectory = 'C:\AEGIS\telemetry-state'
$statePath = Join-Path $stateDirectory 'state.json'
$auditBackupPath = Join-Path $stateDirectory 'audit-policy.csv'
$agentConfigBackupPath = Join-Path $stateDirectory 'elastic-agent.yml.backup'
$installedAgentConfigPath = 'C:\Program Files\Elastic\Agent\elastic-agent.yml'
$scriptBlockLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$scriptBlockLoggingName = 'EnableScriptBlockLogging'
$processCommandLinePath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$processCommandLineName = 'ProcessCreationIncludeCmdLine_Enabled'
$processCreationSubcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'

function Write-Pass {
    param([string]$Message)
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from a PowerShell session started as Administrator.'
    }
}

function Get-RegistryValueState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            KeyExists   = $false
            ValueExists = $false
            Value       = $null
            Kind        = $null
        }
    }

    $key = Get-Item -LiteralPath $Path
    if ($Name -notin $key.GetValueNames()) {
        return [pscustomobject]@{
            KeyExists   = $true
            ValueExists = $false
            Value       = $null
            Kind        = $null
        }
    }

    [pscustomobject]@{
        KeyExists   = $true
        ValueExists = $true
        Value       = $key.GetValue(
            $Name,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        Kind        = $key.GetValueKind($Name).ToString()
    }
}

function Get-SysmonService {
    Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Get-ServiceExecutablePath {
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $escapedName = $ServiceName.Replace("'", "''")
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'"
    if ($null -eq $service -or [string]::IsNullOrWhiteSpace($service.PathName)) {
        throw "Cannot resolve executable path for service '$ServiceName'."
    }

    $pathName = $service.PathName.Trim()
    if ($pathName -match '^"([^"]+)"') {
        return $Matches[1]
    }

    if ($pathName -match '^(.+?\.exe)(?:\s|$)') {
        return $Matches[1]
    }

    throw "Cannot parse executable path for service '$ServiceName'."
}

function Assert-SysmonVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description does not exist: $Path"
    }

    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $actualVersion = [Version]::new($versionInfo.FileMajorPart, $versionInfo.FileMinorPart)
    if ($actualVersion -ne $requiredSysmonVersion) {
        throw "$Description version is $actualVersion; expected exactly $requiredSysmonVersion."
    }

    Write-Pass "$Description version is $actualVersion."
}

function Invoke-CheckedNativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }

    Write-Pass $Description
}

try {
    Assert-Administrator
    Write-Pass 'Administrator privilege confirmed.'

    foreach ($inputPath in @($SysmonBinaryPath, $SysmonConfigPath, $ElasticAgentConfigPath)) {
        if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
            throw "Required input file does not exist: $inputPath"
        }
    }

    $resolvedSysmonBinaryPath = (Resolve-Path -LiteralPath $SysmonBinaryPath).ProviderPath
    $resolvedSysmonConfigPath = (Resolve-Path -LiteralPath $SysmonConfigPath).ProviderPath
    $resolvedAgentConfigPath = (Resolve-Path -LiteralPath $ElasticAgentConfigPath).ProviderPath
    Write-Pass 'All three input files exist.'

    try {
        [xml]$sysmonConfig = Get-Content -Raw -LiteralPath $resolvedSysmonConfigPath
    }
    catch {
        throw "Sysmon configuration is not valid XML: $($_.Exception.Message)"
    }
    if ($sysmonConfig.DocumentElement.Name -ne 'Sysmon') {
        throw 'Sysmon configuration root element must be Sysmon.'
    }
    Write-Pass 'Sysmon configuration is well-formed XML.'

    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedSysmonBinaryPath
    if ($signature.Status -ne 'Valid') {
        throw "Sysmon Authenticode signature status is '$($signature.Status)', not 'Valid'."
    }

    $signerSubject = $signature.SignerCertificate.Subject
    if ([string]::IsNullOrWhiteSpace($signerSubject) -or
        $signerSubject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
        throw 'Sysmon Authenticode signer is not Microsoft Corporation.'
    }
    Write-Pass 'Sysmon Authenticode signature is valid and signed by Microsoft Corporation.'

    Assert-SysmonVersion -Path $resolvedSysmonBinaryPath -Description 'Provided Sysmon binary'

    if (-not (Test-Path -LiteralPath $installedAgentConfigPath -PathType Leaf)) {
        throw "Installed Elastic Agent config is missing: $installedAgentConfigPath"
    }

    $existingSysmonService = Get-SysmonService
    if ($null -ne $existingSysmonService) {
        $installedSysmonPath = Get-ServiceExecutablePath -ServiceName $existingSysmonService.Name
        Assert-SysmonVersion -Path $installedSysmonPath -Description 'Installed Sysmon service binary'
    }

    $null = New-Item -ItemType Directory -Path $stateDirectory -Force

    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        if ((Test-Path -LiteralPath $agentConfigBackupPath) -or
            (Test-Path -LiteralPath $auditBackupPath)) {
            throw 'Incomplete telemetry-state artifacts exist; refusing to overwrite the original backup.'
        }

        Copy-Item -LiteralPath $installedAgentConfigPath -Destination $agentConfigBackupPath

        Invoke-CheckedNativeCommand `
            -FilePath 'auditpol.exe' `
            -Arguments @('/backup', "/file:$auditBackupPath") `
            -Description 'Audit policy backup'

        $auditRow = Import-Csv -LiteralPath $auditBackupPath |
            Where-Object {
                $values = @($_.PSObject.Properties | ForEach-Object { $_.Value })
                $values.Count -ge 7 -and $values[3] -ieq $processCreationSubcategory
            } |
            Select-Object -First 1

        if ($null -eq $auditRow) {
            throw 'Process Creation audit state was not found in the audit policy backup.'
        }

        $auditValues = @($auditRow.PSObject.Properties | ForEach-Object { $_.Value })
        $auditSetting = [int]$auditValues[6]
        if ($auditSetting -lt 0 -or $auditSetting -gt 3) {
            throw "Unexpected Process Creation audit setting value: $auditSetting"
        }

        $state = [ordered]@{
            SchemaVersion               = 1
            CreatedUtc                  = [DateTime]::UtcNow.ToString('o')
            InstalledAgentConfigPath    = $installedAgentConfigPath
            AgentConfigBackupPath       = $agentConfigBackupPath
            AuditProcessCreationSetting = $auditSetting
            Registry                    = [ordered]@{
                ScriptBlockLogging = Get-RegistryValueState `
                    -Path $scriptBlockLoggingPath `
                    -Name $scriptBlockLoggingName
                ProcessCommandLine = Get-RegistryValueState `
                    -Path $processCommandLinePath `
                    -Name $processCommandLineName
            }
        }

        $state |
            ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $statePath -Encoding UTF8
        Write-Pass "Original telemetry state backed up under $stateDirectory."
    }
    else {
        $existingState = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
        if ($existingState.SchemaVersion -ne 1 -or
            -not (Test-Path -LiteralPath $existingState.AgentConfigBackupPath -PathType Leaf)) {
            throw 'Existing telemetry state is invalid or incomplete; refusing to overwrite it.'
        }
        Write-Pass 'Existing original-state backup preserved for idempotent setup.'
    }

    $null = New-Item -Path $scriptBlockLoggingPath -Force
    $null = New-ItemProperty `
        -Path $scriptBlockLoggingPath `
        -Name $scriptBlockLoggingName `
        -PropertyType DWord `
        -Value 1 `
        -Force
    Write-Pass 'PowerShell Script Block Logging enabled.'

    $null = New-Item -Path $processCommandLinePath -Force
    $null = New-ItemProperty `
        -Path $processCommandLinePath `
        -Name $processCommandLineName `
        -PropertyType DWord `
        -Value 1 `
        -Force
    Write-Pass 'Command-line inclusion for Security event 4688 enabled.'

    Invoke-CheckedNativeCommand `
        -FilePath 'auditpol.exe' `
        -Arguments @('/set', "/subcategory:$processCreationSubcategory", '/success:enable') `
        -Description 'Process Creation success auditing enabled'

    if ($null -eq $existingSysmonService) {
        Invoke-CheckedNativeCommand `
            -FilePath $resolvedSysmonBinaryPath `
            -Arguments @('-accepteula', '-i', $resolvedSysmonConfigPath) `
            -Description 'Sysmon 15.21 installed with the AEGIS configuration'
    }
    else {
        Invoke-CheckedNativeCommand `
            -FilePath $resolvedSysmonBinaryPath `
            -Arguments @('-c', $resolvedSysmonConfigPath) `
            -Description 'Existing Sysmon 15.21 configuration updated'
    }

    Copy-Item -LiteralPath $resolvedAgentConfigPath -Destination $installedAgentConfigPath -Force
    Write-Pass 'Updated standalone Elastic Agent config copied into the installed path.'

    Restart-Service -Name 'Elastic Agent' -ErrorAction Stop
    Write-Pass 'Elastic Agent service restarted.'

    $sysmonService = Get-SysmonService
    if ($null -eq $sysmonService -or $sysmonService.Status -ne 'Running') {
        throw 'Sysmon service is not running.'
    }
    Write-Pass "Sysmon service '$($sysmonService.Name)' is running."

    $agentService = Get-Service -Name 'Elastic Agent' -ErrorAction Stop
    if ($agentService.Status -ne 'Running') {
        throw 'Elastic Agent service is not running.'
    }
    Write-Pass 'Elastic Agent service is running.'

    foreach ($channel in @(
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
    )) {
        $null = Get-WinEvent -ListLog $channel -ErrorAction Stop
        Write-Pass "Windows event channel exists: $channel"
    }

    Write-Host ''
    Write-Host 'Advanced Windows telemetry setup completed.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Fail $_.Exception.Message
    Write-Host 'Advanced Windows telemetry setup did not complete.' -ForegroundColor Red
    exit 1
}
