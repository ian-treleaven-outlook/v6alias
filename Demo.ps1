#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Menu', 'Open', 'Status', 'Stop', 'Help')]
    [string] $Action = 'Menu'
)

$ErrorActionPreference = 'Stop'
# Long-lived terminals may cache an older VM list/schema after an update.
Import-Module (Join-Path $PSScriptRoot 'scripts\LiveDemo.psm1') -Force -ErrorAction Stop
Invoke-V6AliasLiveDemo @PSBoundParameters
