[CmdletBinding()]
param(
    [switch]$RemoveSysmon
)

$ErrorActionPreference = 'Stop'

$stateDirectory = 'C:\AEGIS\telemetry-state'
$statePath = Join-Path $stateDirectory 'state.json'
$processCreationSubcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$scriptBlockLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$scriptBlockLoggingName = 'EnableScriptBlockLogging'
$processCommandLinePath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$processCommandLineName = 'ProcessCreationIncludeCmdLine_Enabled'

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

function Restore-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [psobject]$State
    )

    if ($State.ValueExists) {
        $null = New-Item -Path $Path -Force
        $null = New-ItemProperty `
            -Path $Path `
            -Name $Name `
            -PropertyType $State.Kind `
            -Value $State.Value `
            -Force
        return
    }

    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($Name -in $key.GetValueNames()) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
        }

        if (-not $State.KeyExists) {
            $key = Get-Item -LiteralPath $Path
            if ($key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0) {
                Remove-Item -LiteralPath $Path -Force
            }
        }
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

    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "Telemetry state backup is missing: $statePath"
    }

    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.SchemaVersion -ne 1) {
        throw "Unsupported telemetry state schema: $($state.SchemaVersion)"
    }

    if (-not (Test-Path -LiteralPath $state.AgentConfigBackupPath -PathType Leaf)) {
        throw "Elastic Agent config backup is missing: $($state.AgentConfigBackupPath)"
    }

    $auditSetting = [int]$state.AuditProcessCreationSetting
    if ($auditSetting -lt 0 -or $auditSetting -gt 3) {
        throw "Invalid saved Process Creation audit setting: $auditSetting"
    }

    Restore-RegistryValue `
        -Path $scriptBlockLoggingPath `
        -Name $scriptBlockLoggingName `
        -State $state.Registry.ScriptBlockLogging
    Write-Pass 'PowerShell Script Block Logging registry state restored.'

    Restore-RegistryValue `
        -Path $processCommandLinePath `
        -Name $processCommandLineName `
        -State $state.Registry.ProcessCommandLine
    Write-Pass 'Process command-line audit registry state restored.'

    $successState = if (($auditSetting -band 1) -ne 0) { 'enable' } else { 'disable' }
    $failureState = if (($auditSetting -band 2) -ne 0) { 'enable' } else { 'disable' }
    Invoke-CheckedNativeCommand `
        -FilePath 'auditpol.exe' `
        -Arguments @(
            '/set',
            "/subcategory:$processCreationSubcategory",
            "/success:$successState",
            "/failure:$failureState"
        ) `
        -Description 'Original Process Creation audit state restored'

    Copy-Item `
        -LiteralPath $state.AgentConfigBackupPath `
        -Destination $state.InstalledAgentConfigPath `
        -Force
    Write-Pass 'Previous Elastic Agent config restored.'

    Restart-Service -Name 'Elastic Agent' -ErrorAction Stop
    $agentService = Get-Service -Name 'Elastic Agent' -ErrorAction Stop
    if ($agentService.Status -ne 'Running') {
        throw 'Elastic Agent service is not running after rollback.'
    }
    Write-Pass 'Elastic Agent service restarted and running.'

    if ($RemoveSysmon) {
        $sysmonService = Get-SysmonService
        if ($null -eq $sysmonService) {
            Write-Pass 'Sysmon is already absent; no uninstall action was needed.'
        }
        else {
            $sysmonExecutablePath = Get-ServiceExecutablePath -ServiceName $sysmonService.Name
            Invoke-CheckedNativeCommand `
                -FilePath $sysmonExecutablePath `
                -Arguments @('-u') `
                -Description 'Sysmon uninstalled by explicit -RemoveSysmon request'
        }
    }
    else {
        Write-Host 'INFO: Sysmon retained because -RemoveSysmon was not specified.'
    }

    Write-Host "INFO: State backup retained at $stateDirectory."
    Write-Host 'INFO: Windows Event Logs and Elasticsearch data were not deleted.'
    Write-Host ''
    Write-Host 'Advanced Windows telemetry rollback completed.' -ForegroundColor Green
    exit 0
}
catch {
    Write-Fail $_.Exception.Message
    Write-Host 'Advanced Windows telemetry rollback did not complete.' -ForegroundColor Red
    exit 1
}
