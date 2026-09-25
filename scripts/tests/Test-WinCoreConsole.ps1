#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$entry = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'WinCoreConsole.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($entry, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "PowerShell parse errors: $errors" }
$source = [IO.File]::ReadAllText($entry)
$count = 0

function Assert([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
    $script:count++
}

# WhatIf must return before tools, file checks, SSH, browsers, or prompts, even with Confirm.
$output = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $entry -WhatIf -Confirm *>&1 | Out-String
Assert ($LASTEXITCODE -eq 0) 'WhatIf failed.'
Assert ($output -match 'What if:') 'WhatIf did not describe its action.'
Assert ($output -notmatch 'Checking the existing VM') 'WhatIf reached operational code.'

foreach ($option in @('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes',
    'HostKeyAlgorithms=ssh-ed25519', 'ForwardAgent=no', 'RemoteCommand=none',
    'ExitOnForwardFailure=yes', 'ClearAllForwardings=no', 'ControlPath=none')) {
    Assert ($source.Contains($option)) "Missing SSH guard: $option"
}
Assert ($source.Contains('127.0.0.1:${localPort}:127.0.0.1:$($remote.port)')) 'Forward is not loopback-pinned.'
Assert ($source.Contains('/home/labagent/work/scout-win2025-20260921/live_demo_host.py')) 'Wrong host guard.'
Assert ($source.Contains('guard.guard(require_off=True)')) 'Host probe does not require the other guests off.'
Assert ($source.Contains("state == `"running`"")) 'Host probe does not require Windows already running.'
Assert ($source.Contains('$probe.WaitForExit(30000)')) 'Host probe lacks its deadline.'
Assert ($source.Contains('$Process.Kill($true)')) 'Child-specific cleanup is missing.'
Assert ($source.Contains('Test-ConsoleBinding $bindings $localPort $tunnel.Id')) 'Forward readiness is not owner-verified.'
Assert ($source -notmatch '(?i)Stop-Process\s+-Name|taskkill\s+/IM|virsh.+(?:start|shutdown|destroy)') 'Unexpected lifecycle operation.'
$reads = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Read-Host'
}, $true))
Assert ($reads.Count -eq 1 -and $reads[0].Extent.Text -match 'Press Enter to close console') 'Unexpected private input prompt.'

$diagnostic = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-ConsoleDiagnostic'
}, $true)
. ([scriptblock]::Create($diagnostic.Extent.Text))
$clean = Read-ConsoleDiagnostic ("`e[31munsafe`e[0m`0" + ('a' * 1400))
Assert ($clean.Length -le 1200 -and $clean -notmatch '[\x00-\x1f\x7f]') 'Diagnostics allow controls or unbounded output.'

$binding = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-ConsoleBinding'
}, $true)
. ([scriptblock]::Create($binding.Extent.Text))
Assert (Test-ConsoleBinding @('  TCP    127.0.0.1:51324    0.0.0.0:0    LISTENING    4567') 51324 4567) 'Exact owner was refused.'
foreach ($row in @(
    '  TCP    127.0.0.1:51324    0.0.0.0:0    LISTENING    9999',
    '  TCP    0.0.0.0:51324      0.0.0.0:0    LISTENING    4567',
    '  TCP    127.0.0.1:51325    0.0.0.0:0    LISTENING    4567',
    '  TCP    [::1]:51324        [::]:0       LISTENING    4567',
    '  TCP    127.0.0.1:51324    127.0.0.1:8  ESTABLISHED  4567'
)) { Assert (-not (Test-ConsoleBinding @($row) 51324 4567)) 'A foreign or non-listening binding was accepted.' }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Server.ExclusiveAddressUse = $true
try {
    $listener.Start()
    $rows = @(& (Join-Path $env:WINDIR 'System32\netstat.exe') -ano -p TCP)
    Assert ($LASTEXITCODE -eq 0) 'Local listener ownership could not be inspected.'
    Assert (Test-ConsoleBinding $rows $listener.LocalEndpoint.Port $PID) 'Real loopback listener owner was not recognized.'
    Assert (-not (Test-ConsoleBinding $rows $listener.LocalEndpoint.Port ($PID + 1))) 'Real listener accepted a foreign owner.'
}
finally { $listener.Stop() }

$start = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-ConsoleChild'
}, $true)
$stop = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Stop-ConsoleChild'
}, $true)
. ([scriptblock]::Create($start.Extent.Text))
. ([scriptblock]::Create($stop.Extent.Text))
$process = $null
try {
    # Local child only. Never resolve or call SSH, Node, a browser, or the lab in this test.
    $process = Start-ConsoleChild (Join-Path $PSHOME 'pwsh.exe') @(
        '-NoProfile', '-Command', '[Console]::Out.WriteLine("ready"); Start-Sleep -Seconds 60')
    $line = $process.StandardOutput.ReadLineAsync()
    Assert ($line.Wait(10000) -and $line.GetAwaiter().GetResult() -ceq 'ready') 'Owned child did not start.'
    $childId = $process.Id
    Stop-ConsoleChild $process; $process = $null
    Assert ($null -eq (Get-Process -Id $childId -ErrorAction SilentlyContinue)) 'Owned child survived cleanup.'
}
finally { Stop-ConsoleChild $process }
Write-Host "$count offline WinCoreConsole assertions passed; no lab/GUI access."
