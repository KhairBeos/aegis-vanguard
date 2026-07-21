#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [switch]$Approve
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ruleName = 'AEGIS Phase 1 Elasticsearch Host-Only Inbound'
$ruleGroup = 'AEGIS-VANGUARD Phase 1'
$localAddress = '192.168.15.1'
$remoteAddress = '192.168.15.6'
$localPort = '9200'

function Get-Phase1HostOnlyContext {
  $addressRecords = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $localAddress -ErrorAction Stop)
  $candidates = @()

  foreach ($addressRecord in $addressRecords) {
    $adapter = Get-NetAdapter -InterfaceIndex $addressRecord.InterfaceIndex -ErrorAction Stop
    $identity = '{0} {1}' -f $adapter.Name, $adapter.InterfaceDescription
    if ($adapter.Status -eq 'Up' -and $identity -match '(?i)VirtualBox.*Host.?Only') {
      $candidates += $adapter
    }
  }

  $uniqueAdapters = @($candidates | Sort-Object InterfaceIndex -Unique)
  if ($uniqueAdapters.Count -ne 1) {
    throw "Expected exactly one Up VirtualBox host-only interface with $localAddress; found $($uniqueAdapters.Count)."
  }

  $adapter = $uniqueAdapters[0]
  $connectionProfiles = @(Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop)
  if ($connectionProfiles.Count -ne 1) {
    throw "Expected exactly one connection profile for interface '$($adapter.Name)'; found $($connectionProfiles.Count)."
  }

  $profile = [string]$connectionProfiles[0].NetworkCategory
  if (@('Domain', 'Private', 'Public') -notcontains $profile) {
    throw "The host-only interface has an unsupported or non-specific profile: $profile"
  }

  [pscustomobject]@{
    InterfaceAlias = [string]$adapter.Name
    InterfaceIndex = [int]$adapter.InterfaceIndex
    Profile = $profile
  }
}

function Test-ExactPhase1Rule {
  param(
    [Parameter(Mandatory)]$Rule,
    [Parameter(Mandatory)]$Context
  )

  $portFilters = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule)
  $addressFilters = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule)
  $interfaceFilters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $Rule)
  $applicationFilters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule)
  $serviceFilters = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule)
  if (
    $portFilters.Count -ne 1 -or
    $addressFilters.Count -ne 1 -or
    $interfaceFilters.Count -ne 1 -or
    $applicationFilters.Count -ne 1 -or
    $serviceFilters.Count -ne 1
  ) {
    return $false
  }

  $protocol = [string]$portFilters[0].Protocol
  $ruleProfile = [string]$Rule.Profile
  $interfaceAlias = @($interfaceFilters[0].InterfaceAlias) -join ','

  return (
    [string]$Rule.DisplayName -eq $ruleName -and
    [string]$Rule.Direction -eq 'Inbound' -and
    [string]$Rule.Action -eq 'Allow' -and
    [string]$Rule.Enabled -eq 'True' -and
    $ruleProfile -eq $Context.Profile -and
    [string]$Rule.EdgeTraversalPolicy -eq 'Block' -and
    $protocol -in @('TCP', '6') -and
    [string]$portFilters[0].LocalPort -eq $localPort -and
    [string]$portFilters[0].RemotePort -eq 'Any' -and
    [string]$addressFilters[0].LocalAddress -eq $localAddress -and
    [string]$addressFilters[0].RemoteAddress -eq $remoteAddress -and
    $interfaceAlias -eq $Context.InterfaceAlias -and
    [string]$applicationFilters[0].Program -eq 'Any' -and
    [string]$serviceFilters[0].Service -eq 'Any'
  )
}

$context = Get-Phase1HostOnlyContext
$existingRules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
if ($existingRules.Count -gt 1) {
  throw "Multiple firewall rules use the stable name '$ruleName'; refusing to continue."
}
if ($existingRules.Count -eq 1) {
  if (Test-ExactPhase1Rule -Rule $existingRules[0] -Context $context) {
    Write-Host 'The exact Phase 1 firewall rule already exists; no change is required.'
    return
  }
  throw "A same-name firewall rule differs from the approved filters; refusing to modify it."
}

if (-not $Approve -and -not $WhatIfPreference) {
  throw 'Creating the firewall rule requires -Approve and an explicit ShouldProcess confirmation.'
}

$target = '{0}: TCP {1}, local {2}, remote {3}, interface {4}, profile {5}' -f `
  $ruleName, $localPort, $localAddress, $remoteAddress, $context.InterfaceAlias, $context.Profile
if (-not $PSCmdlet.ShouldProcess($target, 'Create narrow inbound Allow firewall rule')) {
  return
}

$createdRule = New-NetFirewallRule `
  -DisplayName $ruleName `
  -Group $ruleGroup `
  -Direction Inbound `
  -Action Allow `
  -Enabled True `
  -Profile $context.Profile `
  -InterfaceAlias $context.InterfaceAlias `
  -Protocol TCP `
  -LocalPort $localPort `
  -RemotePort Any `
  -LocalAddress $localAddress `
  -RemoteAddress $remoteAddress `
  -EdgeTraversalPolicy Block `
  -PolicyStore PersistentStore

try {
  $verifiedRules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop)
  if ($verifiedRules.Count -ne 1 -or -not (Test-ExactPhase1Rule -Rule $verifiedRules[0] -Context $context)) {
    throw 'The created rule did not match the approved filters.'
  }
}
catch {
  $createdRule | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue
  throw
}

Write-Host 'Created and verified the exact Phase 1 host-only Elasticsearch firewall rule.'
