# Shared Elasticsearch/Kibana credential handling for AEGIS-VANGUARD host scripts.
#
# Dot-source it from a script in scripts/:
#   . (Join-Path $PSScriptRoot 'lib\aegis-elastic.ps1')
#
# Credential precedence:
#   1. $env:AEGIS_ES_USER / $env:AEGIS_ES_PASSWORD
#   2. ELASTIC_PASSWORD in infra/elastic/.env (user defaults to 'elastic')
#
# The .env file is gitignored; no credential is ever written back to the repository.

function Read-AegisEnvFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $values = @{}

    if (-not (Test-Path -LiteralPath $Path)) {
        return $values
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()

        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            continue
        }

        $separatorIndex = $trimmed.IndexOf('=')
        if ($separatorIndex -lt 1) {
            continue
        }

        $key = $trimmed.Substring(0, $separatorIndex).Trim()
        $value = $trimmed.Substring($separatorIndex + 1).Trim()

        # Strip one matched pair of surrounding quotes; a password may legitimately
        # contain '#', so inline comments are deliberately not stripped.
        if ($value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        $values[$key] = $value
    }

    return $values
}

function Get-AegisElasticCredential {
    [CmdletBinding()]
    param(
        [string]$EnvFilePath = (Join-Path $PSScriptRoot '..\..\infra\elastic\.env')
    )

    $username = $env:AEGIS_ES_USER
    $password = $env:AEGIS_ES_PASSWORD

    if ([string]::IsNullOrWhiteSpace($password)) {
        $envValues = Read-AegisEnvFile -Path $EnvFilePath
        $password = $envValues['ELASTIC_PASSWORD']
    }

    if ([string]::IsNullOrWhiteSpace($username)) {
        $username = 'elastic'
    }

    if ([string]::IsNullOrWhiteSpace($password)) {
        throw ("No Elasticsearch password found. Set `$env:AEGIS_ES_PASSWORD, " +
               "or add ELASTIC_PASSWORD to $EnvFilePath.")
    }

    [pscustomobject]@{
        Username = $username
        Password = $password
    }
}

function Get-AegisElasticAuthHeader {
    [CmdletBinding()]
    param(
        [string]$EnvFilePath
    )

    $credentialParameters = @{}
    if ($PSBoundParameters.ContainsKey('EnvFilePath')) {
        $credentialParameters.EnvFilePath = $EnvFilePath
    }

    $credential = Get-AegisElasticCredential @credentialParameters
    $pair = '{0}:{1}' -f $credential.Username, $credential.Password
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))

    @{ Authorization = "Basic $encoded" }
}
