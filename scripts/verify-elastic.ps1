[CmdletBinding()]
param(
    [string]$ExpectedBindIp = '192.168.56.1'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')
$authHeader = Get-AegisElasticAuthHeader

$composeDirectory = Join-Path $PSScriptRoot '..\infra\elastic'
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Pass {
    param([string]$Message)
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    $failures.Add($Message)
    Write-Host "FAIL: $Message" -ForegroundColor Red
}

function Invoke-CheckedNative {
    param(
        [string]$Description,
        [scriptblock]$Command
    )

    try {
        $output = & $Command 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "$Description exited with code $LASTEXITCODE`: $($output -join [Environment]::NewLine)"
        }
        Write-Pass $Description
        return $output
    }
    catch {
        Write-Fail "$Description - $($_.Exception.Message)"
        return $null
    }
}

function Test-Container {
    param(
        [string]$ContainerName,
        [string]$ServiceName
    )

    $state = Invoke-CheckedNative "Inspect $ServiceName container" {
        docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' $ContainerName
    }

    if ($state) {
        $parts = "$state".Trim().Split('|')
        if ($parts[0] -eq 'running') {
            Write-Pass "$ServiceName container is running"
        }
        else {
            Write-Fail "$ServiceName container state is '$($parts[0])'"
        }

        if ($parts.Count -gt 1 -and $parts[1] -eq 'healthy') {
            Write-Pass "$ServiceName container is healthy"
        }
        else {
            Write-Fail "$ServiceName container health is '$($parts[1])'"
        }
    }
}

function Test-Api {
    param(
        [string]$Description,
        [string]$Uri,
        [hashtable]$Headers
    )

    $requestParameters = @{
        Uri        = $Uri
        TimeoutSec = 15
    }

    if ($Headers) {
        $requestParameters.Headers = $Headers
    }

    try {
        $response = Invoke-RestMethod @requestParameters
        Write-Pass "$Description ($Uri)"
        return $response
    }
    catch {
        Write-Fail "$Description ($Uri) - $($_.Exception.Message)"
        return $null
    }
}

function Test-AnonymousAccessRejected {
    param([string]$Uri)

    try {
        Invoke-RestMethod -Uri $Uri -TimeoutSec 15 | Out-Null
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response -and $null -ne $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 401) {
            Write-Pass "Elasticsearch rejects unauthenticated requests (HTTP 401)"
            return
        }

        Write-Fail "Elasticsearch anonymous probe returned an unexpected error: $($_.Exception.Message)"
        return
    }

    Write-Fail "Elasticsearch answered an unauthenticated request; xpack.security is not enforcing authentication"
}

function Test-DockerPortBinding {
    param(
        [string]$ContainerName,
        [string]$ContainerPort,
        [string]$ExpectedIp
    )

    try {
        $portJson = docker inspect --format '{{json .NetworkSettings.Ports}}' $ContainerName 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "docker inspect exited with code $LASTEXITCODE`: $($portJson -join [Environment]::NewLine)"
        }

        $bindings = ($portJson | ConvertFrom-Json).$ContainerPort
        if (-not $bindings) {
            throw "no published binding for $ContainerPort"
        }

        $unexpected = @($bindings | Where-Object { $_.HostIp -ne $ExpectedIp })
        if ($unexpected.Count -gt 0) {
            throw "expected only $ExpectedIp; found $($unexpected.HostIp -join ', ')"
        }

        Write-Pass "$ContainerName publishes $ContainerPort only on $ExpectedIp"
    }
    catch {
        Write-Fail "$ContainerName port binding - $($_.Exception.Message)"
    }
}

Invoke-CheckedNative 'Docker engine is available' { docker info --format '{{.ServerVersion}}' } | Out-Null

Push-Location $composeDirectory
try {
    Invoke-CheckedNative 'docker compose ps' { docker compose --env-file .env ps } | ForEach-Object { Write-Host $_ }
}
finally {
    Pop-Location
}

Test-Container -ContainerName 'aegis-elasticsearch' -ServiceName 'Elasticsearch'
Test-Container -ContainerName 'aegis-kibana' -ServiceName 'Kibana'

Test-Api -Description 'Elasticsearch root API responded' -Uri "http://${ExpectedBindIp}:9200" -Headers $authHeader | Out-Null
$clusterHealth = Test-Api -Description 'Elasticsearch cluster health API responded' -Uri "http://${ExpectedBindIp}:9200/_cluster/health" -Headers $authHeader
$kibanaStatus = Test-Api -Description 'Kibana status API responded' -Uri "http://${ExpectedBindIp}:5601/api/status"

Test-AnonymousAccessRejected -Uri "http://${ExpectedBindIp}:9200/_cluster/health"

if ($clusterHealth -and $clusterHealth.status -in @('green', 'yellow')) {
    Write-Pass "Elasticsearch cluster health is '$($clusterHealth.status)'"
}
elseif ($clusterHealth) {
    Write-Fail "Elasticsearch cluster health is '$($clusterHealth.status)'"
}

if ($kibanaStatus -and $kibanaStatus.status.overall.level -eq 'available') {
    Write-Pass "Kibana overall status is 'available'"
}
elseif ($kibanaStatus) {
    Write-Fail "Kibana overall status is '$($kibanaStatus.status.overall.level)'"
}

Test-DockerPortBinding -ContainerName 'aegis-elasticsearch' -ContainerPort '9200/tcp' -ExpectedIp $ExpectedBindIp
Test-DockerPortBinding -ContainerName 'aegis-kibana' -ContainerPort '5601/tcp' -ExpectedIp $ExpectedBindIp

foreach ($port in 9200, 5601) {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) {
        Write-Pass "Windows does not expose listener metadata for port $port; Docker binding was verified"
        continue
    }

    $unexpectedListeners = @($listeners | Where-Object { $_.LocalAddress -ne $ExpectedBindIp })
    if ($unexpectedListeners.Count -gt 0) {
        Write-Fail "Windows reports port $port on unexpected address(es): $($unexpectedListeners.LocalAddress -join ', ')"
    }
    else {
        Write-Pass "Windows reports port $port only on $ExpectedBindIp"
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`nValidation failed with $($failures.Count) error(s)." -ForegroundColor Red
    exit 1
}

Write-Host "`nElastic Stack validation passed." -ForegroundColor Green
exit 0
