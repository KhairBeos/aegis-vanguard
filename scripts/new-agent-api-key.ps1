[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ElasticsearchUrl = 'http://192.168.56.1:9200',

    [ValidateNotNullOrEmpty()]
    [string]$KeyName = 'aegis-agent-victim-win-01',

    [ValidateNotNullOrEmpty()]
    [string]$Namespace = 'aegis_lab'
)

# Creates a least-privilege Elasticsearch API key for the standalone Elastic Agent.
# The key is printed once and never written to the repository.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$authHeader = Get-AegisElasticAuthHeader

# Only what a standalone Agent needs: report its own health, and append documents
# to this lab's data streams. No read, no delete, no index management.
$request = @{
    name             = $KeyName
    role_descriptors = @{
        aegis_agent_writer = @{
            cluster = @('monitor')
            indices = @(
                @{
                    names      = @(
                        "logs-system.*-$Namespace"
                        "logs-windows.*-$Namespace"
                    )
                    privileges = @('auto_configure', 'create_doc')
                }
            )
        }
    }
}

try {
    $response = Invoke-RestMethod `
        -Method POST `
        -Uri "$($ElasticsearchUrl.TrimEnd('/'))/_security/api_key" `
        -Headers $authHeader `
        -ContentType 'application/json' `
        -Body ($request | ConvertTo-Json -Depth 10 -Compress) `
        -ErrorAction Stop
}
catch {
    Write-Host "FAIL: could not create the API key - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($response.id) -or [string]::IsNullOrWhiteSpace($response.api_key)) {
    Write-Host 'FAIL: Elasticsearch returned no API key material.' -ForegroundColor Red
    exit 1
}

# Standalone Agent expects the plain "<id>:<api_key>" form, not the base64 `encoded` field.
$agentApiKey = '{0}:{1}' -f $response.id, $response.api_key

Write-Host "PASS: created API key '$KeyName' (id $($response.id))." -ForegroundColor Green
Write-Host ''
Write-Host 'Paste this line into the outputs.default block of elastic-agent.yml on victim-win-01:' -ForegroundColor Cyan
Write-Host ''
Write-Host "    api_key: `"$agentApiKey`""
Write-Host ''
Write-Host 'This value is shown once. Do not commit it. To revoke it later, run:' -ForegroundColor Yellow
Write-Host "    Invoke-RestMethod -Method DELETE -Uri '$($ElasticsearchUrl.TrimEnd('/'))/_security/api_key' -Headers (Get-AegisElasticAuthHeader) -ContentType 'application/json' -Body '{`"ids`":[`"$($response.id)`"]}'"

exit 0
