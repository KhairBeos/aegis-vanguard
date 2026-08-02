[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$KibanaUrl = 'http://192.168.56.1:5601',

    [string]$NdjsonPath,

    # Re-importing the same rule_id is the normal update path for this lab.
    [bool]$Overwrite = $true
)

# Imports converted Sigma rules into the Elastic Security detection engine.
# Run scripts/convert-sigma.ps1 first.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
if (-not $NdjsonPath) {
    $NdjsonPath = Join-Path $repositoryRoot 'rules\generated\aegis-detection-rules.ndjson'
}

if (-not (Test-Path -LiteralPath $NdjsonPath)) {
    Write-Host "FAIL: no converted rules at $NdjsonPath" -ForegroundColor Red
    Write-Host '      Run scripts\convert-sigma.ps1 first.' -ForegroundColor Yellow
    exit 1
}

$headers = Get-AegisElasticAuthHeader
$headers['kbn-xsrf'] = 'true'

# Windows PowerShell 5.1 has no -Form parameter, so build the multipart body by hand.
$boundary = [guid]::NewGuid().ToString()
$fileContent = Get-Content -LiteralPath $NdjsonPath -Raw
$multipartBody = (
    "--$boundary`r`n" +
    "Content-Disposition: form-data; name=`"file`"; filename=`"aegis-detection-rules.ndjson`"`r`n" +
    "Content-Type: application/octet-stream`r`n`r`n" +
    "$fileContent`r`n" +
    "--$boundary--`r`n"
)

$uri = '{0}/api/detection_engine/rules/_import?overwrite={1}' -f `
    $KibanaUrl.TrimEnd('/'), $Overwrite.ToString().ToLowerInvariant()

try {
    $response = Invoke-RestMethod `
        -Method POST `
        -Uri $uri `
        -Headers $headers `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -Body ([Text.Encoding]::UTF8.GetBytes($multipartBody)) `
        -ErrorAction Stop
}
catch {
    Write-Host "FAIL: rule import request failed - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '      If Kibana reports a missing detection engine, open Security > Rules once' -ForegroundColor Yellow
    Write-Host '      so Kibana can create its alerts indices, then re-run this script.' -ForegroundColor Yellow
    exit 1
}

$errorCount = @($response.errors).Count

if ($response.success_count -gt 0) {
    Write-Host "PASS: imported $($response.success_count) rule(s) into Elastic Security." -ForegroundColor Green
}

foreach ($importError in @($response.errors)) {
    Write-Host "FAIL: $($importError.rule_id) - $($importError.error.message)" -ForegroundColor Red
}

if (-not $response.success -or $errorCount -gt 0) {
    Write-Host "`nRule import failed with $errorCount error(s)." -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host 'Imported rules are created DISABLED by default in some Kibana versions.' -ForegroundColor Yellow
Write-Host 'Confirm the rule is enabled in Kibana: Security > Rules > Detection rules.'
exit 0
