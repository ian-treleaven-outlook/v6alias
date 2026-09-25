#Requires -Version 7.3

Set-StrictMode -Version Latest
$script:V6AliasDemoState = $null

function Resolve-V6AliasDemoFile {
    param([string] $Path, [string] $Label)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label must name an existing file."
    }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) {
        throw "$Label must be a filesystem file: $Path"
    }
    return $item.FullName
}

function Invoke-V6AliasDemoProcess {
    param([string] $Executable, [object[]] $ArgumentList)

    # Override a caller's Legacy setting without changing their preferences.
    $PSNativeCommandArgumentPassing = 'Standard'
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        & $Executable @ArgumentList
        $global:LASTEXITCODE = $LASTEXITCODE
    }
    catch {
        $global:LASTEXITCODE = 1
        throw
    }
}

function Resolve-V6AliasDemoNative {
    param([string] $Name)

    $application = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $application) {
        $global:LASTEXITCODE = 127
        throw "Native application '$Name' is not installed or is not on PATH."
    }
    return $application.Path
}

function Restore-V6AliasDemoSeparator {
    param([object[]] $Forwarded, [System.Management.Automation.InvocationInfo] $Invocation)

    # Collection comparisons in PowerShell filter arrays instead of comparing a
    # scalar flag. Reject nested arrays before they could consume --dry-run.
    foreach ($argument in $Forwarded) {
        if (($argument -is [System.Collections.IEnumerable] -or
             $argument -is [System.Collections.IEnumerator]) -and $argument -isnot [string]) {
            $global:LASTEXITCODE = 2
            throw 'Pass scalar arguments, or splat an argument array with @name; nested arrays are not supported.'
        }
    }
    # PowerShell consumes the first unquoted -- before a function receives $args.
    # Recover only its position from syntax; never evaluate caller source/variables.
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $Invocation.Statement, [ref] $tokens, [ref] $errors)
    $command = $ast.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.CommandAst]
    }, $false)
    if ($null -eq $command) { return ,$Forwarded }
    $elements = $command.CommandElements
    $position = 0
    $separator = -1
    $hasSplat = $false
    for ($index = 1; $index -lt $elements.Count; $index++) {
        $element = $elements[$index]
        if ($element -is [System.Management.Automation.Language.VariableExpressionAst] -and $element.Splatted) {
            $hasSplat = $true
        }
        if (
            $element -is [System.Management.Automation.Language.CommandParameterAst] -and
            $element.Extent.Text -ceq '--'
        ) {
            $separator = $position
        }
        if ($separator -lt 0) {
            $position++
            if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and $null -ne $element.Argument) {
                $position++
            }
        }
    }
    if ($separator -lt 0) { return ,$Forwarded }
    if ($hasSplat) {
        $global:LASTEXITCODE = 2
        throw "When combining splatting with a separator, quote '--' or put it inside the argument array."
    }
    $restored = [System.Collections.Generic.List[object]]::new()
    $restored.AddRange($Forwarded)
    $restored.Insert($separator, '--')
    return ,$restored.ToArray()
}

function Remove-V6AliasDemoFunctions {
    if ($null -eq $script:V6AliasDemoState) { return }

    foreach ($entry in $script:V6AliasDemoState.Functions.GetEnumerator()) {
        # Function:global:name is valid for Set-Item, but not for Get/Remove-Item.
        $current = Get-Item -LiteralPath "Function:$($entry.Key)" -ErrorAction SilentlyContinue
        if ($null -eq $current) { continue }
        if ([object]::ReferenceEquals($current.ScriptBlock, $entry.Value)) {
            Remove-Item -LiteralPath "Function:$($entry.Key)" -ErrorAction Stop
        }
        else {
            Write-Warning "Leaving '$($entry.Key)' unchanged: it was replaced after demo activation."
        }
    }
    $script:V6AliasDemoState = $null
}

function Enable-V6AliasDemo {
    <#
    .SYNOPSIS
    Opt in to alias-first demo commands in this PowerShell process only.
    .DESCRIPTION
    Installs ping, trace, tracert, traceroute, ssh, and ifconfig functions, plus
    native-ping, native-trace, native-ssh, and native-ifconfig escape functions.
    Existing aliases/functions are never overwritten. No profiles, PATH, prompt,
    host networking, or VMs are changed. Enabling does not execute applications.
    Native invocations require PowerShell 7.3+ for lossless argument forwarding.
    When combining splatting and a separator, quote '--' or include it in the
    splatted array: PowerShell otherwise consumes it before the function runs.
    .PARAMETER Binary
    Binary path. Defaults to v6alias.exe beside this module when present, otherwise
    ..\dist\windows-x64\v6alias.exe relative to this module, not the working directory.
    .PARAMETER Config
    Configuration path. Defaults to v6alias.yaml beside the selected binary.
    .PARAMETER Color
    Request colored CLI command output (--color always); otherwise use auto.
    Does not change the prompt or add ANSI escapes to native output or JSON.
    .EXAMPLE
    Enable-V6AliasDemo -Color
    ping corp:42 -n 3
    ssh corp:42 -l 'scout user'
    trace corp:42 --dry-run -- -d
    ifconfig --json --interface Ethernet
    native-ping localhost
    Disable-V6AliasDemo
    #>
    [CmdletBinding()]
    param(
        [string] $Binary,
        [string] $Config,
        [switch] $Color
    )

    if (-not $PSBoundParameters.ContainsKey('Binary')) {
        $sibling = Join-Path $PSScriptRoot 'v6alias.exe'
        $Binary = if (Test-Path -LiteralPath $sibling -PathType Leaf) {
            $sibling
        }
        else {
            Join-Path $PSScriptRoot '..\dist\windows-x64\v6alias.exe'
        }
    }
    $binaryPath = Resolve-V6AliasDemoFile -Path $Binary -Label Binary
    if (-not $PSBoundParameters.ContainsKey('Config')) {
        $Config = Join-Path ([System.IO.Path]::GetDirectoryName($binaryPath)) 'v6alias.yaml'
    }
    $configPath = Resolve-V6AliasDemoFile -Path $Config -Label Config
    $colorMode = if ($Color) { 'always' } else { 'auto' }

    if ($null -ne $script:V6AliasDemoState) {
        $comparison = if ($IsWindows) {
            [StringComparison]::OrdinalIgnoreCase
        }
        else {
            [StringComparison]::Ordinal
        }
        if (
            [string]::Equals($binaryPath, $script:V6AliasDemoState.Binary, $comparison) -and
            [string]::Equals($configPath, $script:V6AliasDemoState.Config, $comparison) -and
            $colorMode -ceq $script:V6AliasDemoState.Color
        ) { return }
        throw 'Demo shortcuts are already enabled with different settings. Run Disable-V6AliasDemo first.'
    }

    $commands = [ordered] @{
        ping = 'ping'
        trace = 'trace'
        tracert = 'trace'
        traceroute = 'trace'
        ssh = 'ssh'
        ifconfig = 'interfaces'
    }
    $nativeCommands = [ordered] @{
        'native-ping' = 'ping'
        'native-trace' = $(if ($IsWindows) { 'tracert' } else { 'traceroute' })
        'native-ssh' = 'ssh'
        'native-ifconfig' = 'ifconfig'
    }
    $names = @($commands.Keys) + @($nativeCommands.Keys)
    $conflicts = @(
        Get-Command -Name $names -CommandType Alias, Function, Filter, Configuration -All -ListImported -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name -Unique
    )
    if ($conflicts.Count -gt 0) {
        throw "Demo activation refused; existing aliases/functions: $($conflicts -join ', '). Nothing was changed."
    }

    # Capture bound scriptblocks, not private helper names: GetNewClosure creates
    # a dynamic module which cannot resolve this module's private functions.
    $invokeProcess = ${function:Invoke-V6AliasDemoProcess}
    $resolveNative = ${function:Resolve-V6AliasDemoNative}
    $restoreSeparator = ${function:Restore-V6AliasDemoSeparator}
    $dispatch = {
        param([string] $Subcommand, [object[]] $Forwarded, $Invocation)

        $Forwarded = & $restoreSeparator -Forwarded $Forwarded -Invocation $Invocation
        $cliArguments = [System.Collections.Generic.List[object]]::new()
        $cliArguments.AddRange([object[]] @('--config', $configPath, '--color', $colorMode, $Subcommand))
        if ($Subcommand -ceq 'interfaces') {
            $cliArguments.AddRange($Forwarded)
        }
        elseif ($Forwarded.Count -eq 0) {
            $cliArguments.Add('--help')
        }
        else {
            $alias = [string] $Forwarded[0]
            $match = [regex]::Match($alias, '\A[a-z0-9-]+:(?:(0|[1-9][0-9]{0,4})\.)?([1-9][0-9]{0,4})\z')
            if (
                -not $match.Success -or
                ($match.Groups[1].Success -and [int] $match.Groups[1].Value -gt 65535) -or
                ($match.Success -and [int] $match.Groups[2].Value -gt 65535)
            ) {
                $global:LASTEXITCODE = 2
                throw "Use '$Subcommand corp:42 [options]' (or profile:subnet.device). Hostnames/IPs require native-$Subcommand."
            }
            $cliArguments.Add($alias)
            $nativeArguments = [System.Collections.Generic.List[object]]::new()
            $afterSeparator = $false
            $dryRun = $false
            for ($index = 1; $index -lt $Forwarded.Count; $index++) {
                $argument = $Forwarded[$index]
                if (-not $afterSeparator -and $argument -ceq '--') {
                    $afterSeparator = $true
                }
                elseif (-not $afterSeparator -and $argument -ceq '--dry-run') {
                    $dryRun = $true
                }
                else {
                    $nativeArguments.Add($argument)
                }
            }
            if ($dryRun) { $cliArguments.Add('--dry-run') }
            $cliArguments.Add('--')
            $cliArguments.AddRange($nativeArguments)
        }
        & $invokeProcess -Executable $binaryPath -ArgumentList $cliArguments.ToArray()
    }.GetNewClosure()
    $nativeDispatch = {
        param([string] $Application, [object[]] $Forwarded, $Invocation)

        $Forwarded = & $restoreSeparator -Forwarded $Forwarded -Invocation $Invocation
        $applicationPath = & $resolveNative -Name $Application
        & $invokeProcess -Executable $applicationPath -ArgumentList $Forwarded
    }.GetNewClosure()

    $functions = [ordered] @{}
    foreach ($entry in $commands.GetEnumerator()) {
        $subcommand = $entry.Value
        # Deliberately not advanced functions: all native options belong in $args.
        $functions[$entry.Key] = { & $dispatch $subcommand $args $MyInvocation }.GetNewClosure()
    }
    foreach ($entry in $nativeCommands.GetEnumerator()) {
        $applicationName = $entry.Value
        $functions[$entry.Key] = { & $nativeDispatch $applicationName $args $MyInvocation }.GetNewClosure()
    }

    $script:V6AliasDemoState = @{
        Binary = $binaryPath
        Config = $configPath
        Color = $colorMode
        Functions = [ordered] @{}
    }
    try {
        foreach ($entry in $functions.GetEnumerator()) {
            Set-Item -LiteralPath "Function:global:$($entry.Key)" -Value $entry.Value -ErrorAction Stop
            $script:V6AliasDemoState.Functions[$entry.Key] = $entry.Value
        }
    }
    catch {
        Remove-V6AliasDemoFunctions
        throw
    }
    Write-Host 'V6Alias demo shortcuts enabled for this PowerShell session only.'
    Write-Host 'Use ping/trace/ssh ALIAS [native options], or ifconfig. Use --dry-run for previews.'
    Write-Host 'Native escape: native-ping, native-trace, native-ssh. Undo: Disable-V6AliasDemo.'
}

function Disable-V6AliasDemo {
    <#
    .SYNOPSIS
    Remove only unchanged demo functions installed by this module.
    .DESCRIPTION
    User replacements are retained with a warning. Removal is idempotent.
    Removing this module also disables its shortcuts.
    #>
    [CmdletBinding()]
    param()

    Remove-V6AliasDemoFunctions
    Write-Host 'V6Alias demo shortcuts disabled; unchanged native command names are available again.'
}

$removeFunctions = ${function:Remove-V6AliasDemoFunctions}
$ExecutionContext.SessionState.Module.OnRemove = { & $removeFunctions }.GetNewClosure()
Export-ModuleMember -Function Enable-V6AliasDemo, Disable-V6AliasDemo
