#Requires -Version 7.3
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'V6AliasDemo.psm1'
$names = @('ping', 'trace', 'tracert', 'traceroute', 'ssh', 'ifconfig',
    'native-ping', 'native-trace', 'native-ssh', 'native-ifconfig')
$module = $null
$testCount = 0
$failures = [System.Collections.Generic.List[string]]::new()
$fixture = Join-Path $PSScriptRoot ('.demo-shortcuts-' + [guid]::NewGuid().ToString('N'))
$binary = Join-Path $fixture 'mock binary.ps1'
$config = Join-Path $fixture 'v6alias.yaml'
$otherConfig = Join-Path $fixture 'other.yaml'
$script:Calls = $null

function Assert-Equal {
    param($Actual, $Expected, [string] $Because)
    if ($Actual -cne $Expected) { throw "$Because (expected '$Expected'; got '$Actual')." }
}

function Assert-Arguments {
    param([object[]] $Actual, [object[]] $Expected)
    Assert-Equal $Actual.Count $Expected.Count 'Argument count'
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        Assert-Equal $Actual[$index] $Expected[$index] "Argument $index"
    }
}

function Assert-Throws {
    param([scriptblock] $Body, [string] $Pattern)
    $caught = $null
    try { & $Body | Out-Null } catch { $caught = $_ }
    if ($null -eq $caught) { throw 'Expected an exception.' }
    if ($caught.Exception.Message -notmatch $Pattern) {
        throw "Unexpected exception: $($caught.Exception.Message)"
    }
}

function Assert-NoShortcuts {
    $existing = @(Get-Command -Name $names -CommandType Function, Alias, Filter, Configuration -All -ListImported -ErrorAction SilentlyContinue)
    Assert-Equal $existing.Count 0 'No shortcuts remain'
}

function Enable-TestDemo {
    param([switch] $Color)
    Enable-V6AliasDemo -Binary $binary -Config $config -Color:$Color
}

function Import-TestModule {
    $script:module = Import-Module $modulePath -PassThru -Force -Global
    $script:Calls = @{
        Invocations = [System.Collections.Generic.List[object]]::new()
        Lookups = [System.Collections.Generic.List[string]]::new()
        ExitCode = 0
        Output = 'mock output'
        Missing = $false
        NativePath = Join-Path $fixture 'never-execute-native.exe'
    }
    & $script:module {
        param($Calls)
        $script:Calls = $Calls
        function script:Invoke-V6AliasDemoProcess {
            param([string] $Executable, [object[]] $ArgumentList)
            $script:Calls.Invocations.Add(@{
                Executable = $Executable
                Arguments = $ArgumentList
            })
            $global:LASTEXITCODE = $script:Calls.ExitCode
            $script:Calls.Output
        }
        # Exercise the production native resolver, mocking only application discovery.
        function script:Get-Command {
            param($Name, $CommandType, $ErrorAction, [switch] $All, [switch] $ListImported)
            if ("$CommandType" -ceq 'Application') {
                $script:Calls.Lookups.Add([string] $Name)
                if (-not $script:Calls.Missing) {
                    [pscustomobject] @{ Path = $script:Calls.NativePath }
                }
                return
            }
            Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
        }
    } $script:Calls
}

function Invoke-Test {
    param([string] $Name, [scriptblock] $Body)
    try {
        $script:Calls.Invocations.Clear()
        $script:Calls.Lookups.Clear()
        $script:Calls.ExitCode = 0
        $script:Calls.Output = 'mock output'
        $script:Calls.Missing = $false
        & $Body | Out-Null
        $script:testCount++
        Write-Host "PASS: $Name"
    }
    catch {
        $script:failures.Add("${Name}: $($_.Exception.Message)")
        Write-Host "FAIL: ${Name}: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $script:module) {
            & $script:module { Disable-V6AliasDemo } 3>$null
        }
    }
}

# Refuse rather than alter an interactive shell's existing functions or aliases.
$existing = @(Get-Command -Name $names -CommandType Function, Alias, Filter, Configuration -All -ListImported -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0 -or (Get-Module V6AliasDemo)) {
    throw 'Run these offline tests in a fresh pwsh -NoProfile process; existing demo names/module will not be changed.'
}

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    # Every normal test captures invocation in memory. This tripwire must never run.
    Set-Content -LiteralPath $binary -Value "throw 'OFFLINE GUARD: unexpected process invocation'"
    Set-Content -LiteralPath $config -Value '# offline fixture'
    Set-Content -LiteralPath $otherConfig -Value '# other offline fixture'
    Import-TestModule

    Invoke-Test 'Exports and activation have no process/native discovery side effects' {
        Assert-Arguments @($module.ExportedFunctions.Keys | Sort-Object) @('Disable-V6AliasDemo', 'Enable-V6AliasDemo')
        $beforePath = $env:PATH
        $beforePrompt = (Get-Item Function:prompt).ScriptBlock
        Enable-TestDemo -Color
        foreach ($name in $names) {
            Assert-Equal (Get-Command $name).CommandType 'Function' "$name installed in caller scope"
        }
        Assert-Equal $script:Calls.Invocations.Count 0 'Activation executes no process'
        Assert-Equal $script:Calls.Lookups.Count 0 'Activation does not discover native commands'
        Assert-Equal $env:PATH $beforePath 'PATH unchanged'
        Assert-Equal ([object]::ReferenceEquals((Get-Item Function:prompt).ScriptBlock, $beforePrompt)) $true 'Prompt unchanged'
    }

    Invoke-Test 'Alias-first ping preserves several options and stdout' {
        Enable-TestDemo
        $output = ping corp:42 -n 3 -w 1000
        Assert-Equal $output 'mock output' 'stdout preserved'
        Assert-Equal $script:Calls.Invocations[0].Executable $binary 'Absolute binary path'
        Assert-Arguments $script:Calls.Invocations[0].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--', '-n', '3', '-w', '1000')
    }

    Invoke-Test 'SSH preserves empty strings, spaces, quotes and PowerShell-like option names' {
        Enable-TestDemo -Color
        ssh corp:42 -l 'scout user' -o '' -v 'a"b' -ErrorAction 'native option'
        Assert-Arguments $script:Calls.Invocations[0].Arguments @(
            '--config', $config, '--color', 'always', 'ssh', 'corp:42', '--',
            '-l', 'scout user', '-o', '', '-v', 'a"b', '-ErrorAction', 'native option')
    }

    Invoke-Test 'Only the first separator is stripped and dry-run after it is native' {
        Enable-TestDemo
        ping corp:42 -n 3 --dry-run -- --dry-run -- ''
        Assert-Arguments $script:Calls.Invocations[0].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--dry-run', '--',
            '-n', '3', '--dry-run', '--', '')
        ping corp:42 -- --dry-run
        Assert-Arguments $script:Calls.Invocations[1].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--', '--dry-run')
    }

    Invoke-Test 'Quoted and array-splatted separators preserve empty and spaced arguments' {
        Enable-TestDemo
        $forwarded = @('corp:42', '--dry-run', '--', '--dry-run', '', 'scout user', '--')
        ping @forwarded
        Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--dry-run', '--',
            '--dry-run', '', 'scout user', '--')
        $forwarded = @('corp:42', '-n', '3')
        ping @forwarded '--' '--dry-run'
        Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--', '-n', '3', '--dry-run')
        Assert-Throws { ping @forwarded -- --dry-run } "quote '--'"
        Assert-Equal $global:LASTEXITCODE 2 'Ambiguous consumed separator rejected'
        Assert-Equal $script:Calls.Invocations.Count 2 'Rejected source never executes'
    }

    Invoke-Test 'Multiline bare separator and colon-style native parameter values retain position' {
        Enable-TestDemo
        ping corp:42 `
            -n:3 `
            -- `
            --dry-run ''
        Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
            '--config', $config, '--color', 'auto', 'ping', 'corp:42', '--', '-n:', '3', '--dry-run', '')
    }

    Invoke-Test 'Nested arrays cannot swallow dry-run and start a native command' {
        Enable-TestDemo
        Assert-Throws { ping corp:42 @('--dry-run', '--', '-n', '3') } 'nested arrays'
        Assert-Throws { ssh corp:42 @('--dry-run', '--', '-l', 'scout user') } 'nested arrays'
        Assert-Throws { native-ping @('--', 'localhost') } 'nested arrays'
        $items = @('--dry-run', '--', '-n', '3').GetEnumerator()
        Assert-Throws { ping corp:42 $items } 'nested arrays'
        $items = @('--dry-run', '--', '-l', 'scout-user').GetEnumerator()
        Assert-Throws { ssh corp:42 $items } 'nested arrays'
        Assert-Equal $global:LASTEXITCODE 2 'Nested argument array rejected'
        Assert-Equal $script:Calls.Invocations.Count 0 'No executable invoked after array rejection'
    }

    Invoke-Test 'Trace spellings share the trace subcommand and closure values do not drift' {
        Enable-TestDemo
        foreach ($name in @('trace', 'tracert', 'traceroute')) {
            & $name corp:7.42 --dry-run -d
            Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
                '--config', $config, '--color', 'auto', 'trace', 'corp:7.42', '--dry-run', '--', '-d')
        }
        ping corp:65535.65535
        Assert-Equal $script:Calls.Invocations[-1].Arguments[4] 'ping' 'Ping closure remains separate'
    }

    Invoke-Test 'Missing alias requests help; interfaces preserves flags including JSON' {
        Enable-TestDemo -Color
        foreach ($name in @('ping', 'ssh', 'trace', 'tracert', 'traceroute')) {
            & $name
            $command = if ($name -in @('tracert', 'traceroute')) { 'trace' } else { $name }
            Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
                '--config', $config, '--color', 'always', $command, '--help')
        }
        $script:Calls.Output = '{"interfaces":[]}'
        Assert-Equal (ifconfig --raw --json --interface 'Ethernet 2') '{"interfaces":[]}' 'JSON unchanged'
        Assert-Arguments $script:Calls.Invocations[-1].Arguments @(
            '--config', $config, '--color', 'always', 'interfaces', '--raw', '--json', '--interface', 'Ethernet 2')
        ifconfig
        Assert-Arguments $script:Calls.Invocations[-1].Arguments @('--config', $config, '--color', 'always', 'interfaces')
    }

    Invoke-Test 'Hostnames, addresses and malformed aliases never reach a process' {
        Enable-TestDemo
        foreach ($invalid in @('localhost', '127.0.0.1', 'fd12::42', 'Corp:42', 'corp:0',
                'corp:01', 'corp:65536', 'corp:65536.1', 'corp:1.2.3', '', '-n')) {
            Assert-Throws { ping $invalid } 'native-ping'
            Assert-Equal $global:LASTEXITCODE 2 'Invalid input exit code'
        }
        Assert-Throws { ssh localhost } 'native-ssh'
        Assert-Throws { trace localhost } 'native-trace'
        Assert-Equal $script:Calls.Invocations.Count 0 'No invalid alias reaches process'
        Assert-Equal $script:Calls.Lookups.Count 0 'No fallback to a native lookup'
    }

    Invoke-Test 'Nonzero child status and ANSI stdout pass through unchanged' {
        Enable-TestDemo
        $script:Calls.ExitCode = 23
        $script:Calls.Output = "$([char]27)[31mchild$([char]27)[0m"
        Assert-Equal (ping corp:42) $script:Calls.Output 'Native stdout is not recolored'
        Assert-Equal $global:LASTEXITCODE 23 'Child status'
    }

    Invoke-Test 'Native escapes resolve only applications and use exact paths without recursion' {
        Enable-TestDemo
        foreach ($name in @('native-ping', 'native-trace', 'native-ssh', 'native-ifconfig')) {
            $script:Calls.ExitCode = 19
            & $name 'native host' '' --dry-run -- -l 'scout user'
            Assert-Equal $global:LASTEXITCODE 19 'Native exit status'
            Assert-Equal $script:Calls.Invocations[-1].Executable $script:Calls.NativePath 'Exact native path'
            Assert-Arguments $script:Calls.Invocations[-1].Arguments @('native host', '', '--dry-run', '--', '-l', 'scout user')
        }
        $traceName = if ($IsWindows) { 'tracert' } else { 'traceroute' }
        Assert-Arguments $script:Calls.Lookups.ToArray() @('ping', $traceName, 'ssh', 'ifconfig')
    }

    Invoke-Test 'Missing native application errors without falling back or invoking' {
        Enable-TestDemo
        $script:Calls.Missing = $true
        Assert-Throws { native-ssh localhost } "Native application 'ssh'.*not installed"
        Assert-Equal $global:LASTEXITCODE 127 'Missing application status'
        Assert-Equal $script:Calls.Invocations.Count 0 'No fallback invocation'
    }

    Invoke-Test 'Missing binary/config and directory paths leave activation untouched' {
        Assert-Throws { Enable-V6AliasDemo -Binary (Join-Path $fixture 'missing.exe') -Config $config } 'does not exist|cannot find'
        Assert-NoShortcuts
        Assert-Throws { Enable-V6AliasDemo -Binary $binary -Config (Join-Path $fixture 'missing.yaml') } 'does not exist|cannot find'
        Assert-NoShortcuts
        Assert-Throws { Enable-V6AliasDemo -Binary $fixture -Config $config } 'filesystem file'
        Assert-NoShortcuts
        Assert-Throws { Enable-V6AliasDemo -Binary $binary -Config '' } 'existing file'
        Assert-NoShortcuts
    }

    Invoke-Test 'Relative binary resolves absolutely and default configuration follows binary' {
        Push-Location $fixture
        try {
            Enable-V6AliasDemo -Binary '.\mock binary.ps1'
            ping corp:42
        }
        finally { Pop-Location }
        Assert-Equal $script:Calls.Invocations[0].Executable $binary 'Resolved binary'
        Assert-Equal $script:Calls.Invocations[0].Arguments[1] $config 'Default config beside binary'
    }

    Invoke-Test 'Default binary is module-relative and a sibling binary takes precedence' {
        Remove-Module $module
        $script:module = $null
        $layout = Join-Path $fixture 'layout'
        $scriptFolder = Join-Path $layout 'scripts'
        $distFolder = Join-Path $layout 'dist\windows-x64'
        New-Item -ItemType Directory -Path $scriptFolder, $distFolder | Out-Null
        $relocatedModule = Join-Path $scriptFolder 'V6AliasDemo.psm1'
        Copy-Item -LiteralPath $modulePath -Destination $relocatedModule
        $distBinary = Join-Path $distFolder 'v6alias.exe'
        $distConfig = Join-Path $distFolder 'v6alias.yaml'
        Set-Content -LiteralPath $distBinary -Value 'offline placeholder, never execute'
        Set-Content -LiteralPath $distConfig -Value '# offline'
        try {
            $script:module = Import-Module $relocatedModule -PassThru -Global
            Enable-V6AliasDemo
            $state = & $module { $script:V6AliasDemoState }
            Assert-Equal $state.Binary $distBinary 'Module-relative distribution binary'
            Assert-Equal $state.Config $distConfig 'Distribution configuration'
            Disable-V6AliasDemo
            $siblingBinary = Join-Path $scriptFolder 'v6alias.exe'
            $siblingConfig = Join-Path $scriptFolder 'v6alias.yaml'
            Set-Content -LiteralPath $siblingBinary -Value 'offline placeholder, never execute'
            Set-Content -LiteralPath $siblingConfig -Value '# offline'
            Enable-V6AliasDemo -Color
            $state = & $module { $script:V6AliasDemoState }
            Assert-Equal $state.Binary $siblingBinary 'Sibling binary precedence'
            Assert-Equal $state.Config $siblingConfig 'Sibling configuration'
            Assert-Equal $state.Color 'always' 'Relocated color setting'
        }
        finally {
            if ($null -ne $module) { Remove-Module $module }
            Import-TestModule
        }
    }

    Invoke-Test 'Every wrapper and escape function conflict rejects activation atomically' {
        foreach ($name in $names) {
            $original = { 'existing user function' }.GetNewClosure()
            Set-Item "Function:global:$name" $original
            try {
                Assert-Throws { Enable-TestDemo } "existing aliases/functions:.*$name"
                Assert-Equal ([object]::ReferenceEquals((Get-Item "Function:$name").ScriptBlock, $original)) $true 'Original function untouched'
                $present = @(Get-Command -Name $names -CommandType Function -All -ListImported -ErrorAction SilentlyContinue)
                Assert-Equal $present.Count 1 'No partial activation'
            }
            finally { Remove-Item "Function:$name" }
        }
    }

    Invoke-Test 'All alias conflicts are reported together and preserved' {
        Set-Alias -Name ping -Value Write-Output -Scope Global
        Set-Alias -Name native-ssh -Value Write-Output -Scope Global
        try {
            Assert-Throws { Enable-TestDemo } 'ping.*native-ssh'
            Assert-Equal (Get-Alias ping).Definition 'Write-Output' 'Existing alias unchanged'
            Assert-Equal (Get-Alias native-ssh).Definition 'Write-Output' 'Existing escape alias unchanged'
            Assert-Equal @(Get-Command -Name $names -CommandType Function -ListImported -ErrorAction SilentlyContinue).Count 0 'No partial functions'
        }
        finally {
            Remove-Item Alias:ping
            Remove-Item Alias:native-ssh
        }
    }

    Invoke-Test 'Existing filters are functions too and must not be overwritten' {
        filter global:ping { 'existing filter' }
        $original = (Get-Item Function:ping).ScriptBlock
        try {
            Assert-Throws { Enable-TestDemo } 'existing aliases/functions:.*ping'
            Assert-Equal (Get-Command ping).CommandType 'Filter' 'Filter retained'
            Assert-Equal ([object]::ReferenceEquals((Get-Item Function:ping).ScriptBlock, $original)) $true 'Filter identity'
        }
        finally { Remove-Item Function:ping }
    }

    Invoke-Test 'Installation failure rolls back already installed functions' {
        & $module {
            function script:Set-Item {
                param($LiteralPath, $Value, $ErrorAction)
                if ($LiteralPath -ceq 'Function:global:ssh') { throw 'Injected installation failure' }
                Microsoft.PowerShell.Management\Set-Item @PSBoundParameters
            }
        }
        try {
            Assert-Throws { Enable-TestDemo } 'Injected installation failure'
            Assert-NoShortcuts
        }
        finally { & $module { Remove-Item Function:Set-Item } }
        Enable-TestDemo
        ping corp:42
        Assert-Equal $script:Calls.Invocations.Count 1 'Reactivation after rollback succeeds'
    }

    Invoke-Test 'Repeated enable is identity preserving; changes require disable; disable repeats safely' {
        Enable-TestDemo
        $installed = (Get-Item Function:ping).ScriptBlock
        Enable-TestDemo
        Assert-Equal ([object]::ReferenceEquals((Get-Item Function:ping).ScriptBlock, $installed)) $true 'Idempotent activation'
        Assert-Throws { Enable-TestDemo -Color } 'Disable-V6AliasDemo first'
        Assert-Throws { Enable-V6AliasDemo -Binary $binary -Config $otherConfig } 'Disable-V6AliasDemo first'
        Disable-V6AliasDemo
        Disable-V6AliasDemo
        Assert-NoShortcuts
        Enable-TestDemo -Color
        ping corp:42
        Assert-Equal $script:Calls.Invocations[-1].Arguments[3] 'always' 'Reactivation uses new settings'
    }

    Invoke-Test 'User replacements survive disable and next activation rejects them' {
        Enable-TestDemo
        $replacement = { 'my replacement' }.GetNewClosure()
        Set-Item Function:global:ping $replacement
        try {
            Disable-V6AliasDemo -WarningVariable warnings 3>$null
            Assert-Equal ([object]::ReferenceEquals((Get-Item Function:ping).ScriptBlock, $replacement)) $true 'Replacement preserved'
            Assert-Equal $warnings.Count 1 'Replacement warning'
            Assert-Throws { Enable-TestDemo } 'existing aliases/functions:.*ping'
        }
        finally { Remove-Item Function:ping }
    }

    Invoke-Test 'Removing the module removes only its installed functions' {
        Enable-TestDemo
        $replacement = { 'replacement SSH' }.GetNewClosure()
        Set-Item Function:global:ssh $replacement
        try {
            Remove-Module $module -WarningVariable warnings 3>$null
            $script:module = $null
            Assert-Equal ([object]::ReferenceEquals((Get-Item Function:ssh).ScriptBlock, $replacement)) $true 'Replacement survives removal'
            Assert-Equal $warnings.Count 1 'Module removal warning'
            Remove-Item Function:ssh
            Assert-NoShortcuts
        }
        finally {
            Remove-Item Function:ssh -ErrorAction SilentlyContinue
            Import-TestModule
        }
    }

    Invoke-Test 'Production process helper preserves argv and nonzero exit with native errors enabled' {
        # Run only a trusted local pwsh child which echoes JSON and exits; no networking.
        $probe = Join-Path $fixture 'echo arguments.ps1'
        Set-Content -LiteralPath $probe -Value 'ConvertTo-Json -InputObject @($args) -Compress; exit 29'
        $cleanModule = New-Module -ScriptBlock ([scriptblock]::Create((Get-Content -LiteralPath $modulePath -Raw)))
        try {
            $process = & $cleanModule { ${function:Invoke-V6AliasDemoProcess} }
            $PSNativeCommandUseErrorActionPreference = $true
            $PSNativeCommandArgumentPassing = 'Legacy'
            $pwsh = (Get-Process -Id $PID).Path
            $result = & $process -Executable $pwsh -ArgumentList @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $probe, '', 'scout user', 'a"b', '--', '-n', '3')
            Assert-Equal $global:LASTEXITCODE 29 'Real child nonzero code'
            Assert-Arguments @(ConvertFrom-Json $result) @('', 'scout user', 'a"b', '--', '-n', '3')
            Assert-Equal $PSNativeCommandUseErrorActionPreference $true 'Caller native error preference unchanged'
            Assert-Equal $PSNativeCommandArgumentPassing 'Legacy' 'Caller argument preference unchanged'
        }
        finally { Remove-Module $cleanModule }
    }
}
finally {
    if ($null -ne $module) { Remove-Module $module -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "FAILURE: $_" }
    throw "$($failures.Count) demo shortcut test(s) failed; $testCount passed."
}
Write-Host "All $testCount offline demo shortcut tests passed."
$global:LASTEXITCODE = 0
