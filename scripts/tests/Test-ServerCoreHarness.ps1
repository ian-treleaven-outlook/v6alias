#Requires -Version 7.3
# Offline-only: load selected helper definitions, never the guest-only script body.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-V6AliasServerCore.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Server Core harness syntax is invalid.' }
$legacyCalls = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ieq 'Cli'
}, $true)
if ($legacyCalls.Count) { throw 'A harness call still collides with the built-in cli alias.' }
$definitions = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Invoke-CoreCli', 'Json', 'Assert-True')
}, $true)
if ($definitions.Count -ne 3) { throw 'Expected helper definitions are missing.' }
$testModule = New-Module -ScriptBlock {
    param($Definitions)
    $script:resolver = 'example.yaml'
    $script:lastArguments = @()
    $script:expected = -1
    foreach ($definition in $Definitions) {
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Invoke-Native {
        param([string[]]$ArgumentList, [int]$Expected = 0)
        $script:lastArguments = $ArgumentList
        $script:expected = $Expected
        '{"allowed":false}'
    }
    function Test-Helpers {
        if ((Get-Alias cli).Definition -ne 'Clear-Item') { throw 'Unexpected PowerShell alias baseline.' }
        $result = Invoke-CoreCli @('--help')
        if ($result -ne '{"allowed":false}' -or ($script:lastArguments -join '|') -ne '--config|example.yaml|--color|never|--help') {
            throw 'Renamed helper did not dispatch exactly to the mocked executable.'
        }
        $decision = Json @('policy','explain') -Expected 2 -Config 'custom.yaml' -Color always
        if ($decision.allowed -ne $false -or $script:expected -ne 2 -or
            ($script:lastArguments -join '|') -ne '--config|custom.yaml|--color|always|policy|explain') {
            throw 'JSON helper lost arguments, configuration, or expected exit status.'
        }
    }
    Export-ModuleMember -Function Test-Helpers
} -ArgumentList (,$definitions)
try {
    & $testModule { Test-Helpers }
    Write-Host 'Server Core helper dispatch passed with PowerShell cli alias intact; no native commands ran.'
}
finally { Remove-Module $testModule -Force }
