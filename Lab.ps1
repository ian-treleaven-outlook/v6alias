#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Menu', 'Open', 'Status', 'Stop', 'Help')]
    [string] $Action = 'Menu'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'scripts\V6AliasLab.psm1') -ErrorAction Stop

# Forward common parameters as well, so -WhatIf and -Confirm reach the action.
Invoke-V6AliasLab @PSBoundParameters
