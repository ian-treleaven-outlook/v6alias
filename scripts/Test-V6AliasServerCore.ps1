#Requires -Version 7.3
<#
Offline, read-only host checks plus disposable native CLI state; no network probes.
Run in the prepared CORP-44 guest after its link/address has been verified:
  C:\V6Alias\PowerShell7\pwsh.exe -NoLogo -NoProfile -File E:\Test-V6AliasServerCore.ps1
Media layout beside this script:
  fixtures\service.example.yaml    <- repository service.example.yaml
  fixtures\v6alias.example.yaml    <- repository v6alias.example.yaml
  fixtures\device.json             <- repository examples\offline\device.json
  fixtures\observation.json        <- repository examples\offline\observation.json
  fixtures\unknown.json            <- repository examples\offline\unknown.json
Root must already contain v6alias.exe, v6alias.yaml and V6AliasDemo.psm1.
Interface JSON stays in memory: reports contain counts, never machine addresses.
#>
[CmdletBinding()]
param(
    [string] $Root = 'C:\V6Alias',
    [string] $FixturesRoot = (Join-Path $PSScriptRoot 'fixtures')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$reportPath = $null
$module = $null
$currentTest = 'Guest identity gate'
$report = [ordered]@{ status = 'running'; started_utc = [datetime]::UtcNow.ToString('o')
    tests = [System.Collections.Generic.List[object]]::new()
    diagnostics = [System.Collections.Generic.List[object]]::new(); facts = @{} }

function Assert-True($Condition, [string] $Message) {
    if (-not $Condition) { throw [InvalidOperationException]::new($Message) }
}
function Protect-Message([string] $Text) {
    $Text = $Text -replace '\x1b\[[0-9;]*m', ''
    $Text = $Text -replace '(?i)(?<![a-z0-9])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.]*(?:%[\w.-]+)?', '[IPv6]'
    $Text = $Text -replace '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IPv4]'
    $Text = $Text -replace '[\r\n]+', ' '
    return $Text.Substring(0, [Math]::Min($Text.Length, 1500))
}
function Save-Report {
    if ($null -ne $script:reportPath) {
        [IO.File]::WriteAllText($script:reportPath, ($report | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
    }
}
function Test-Case([string] $Label, [scriptblock] $Body) {
    $script:currentTest = $Label
    & $Body | Out-Null
    $report.tests.Add(@{ label = $Label; status = 'pass' })
    Save-Report
    Write-Host "PASS: $Label"
}
function Assert-LocalPath([string] $Path) {
    Assert-True ($Path -match '^[A-Za-z]:\\') 'Only absolute local drive paths are permitted.'
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            Assert-True (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse-point paths are not permitted.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Invoke-Native([string[]] $ArgumentList, [int] $Expected = 0) {
    # Every actual child is the supplied CLI, never a shell or a native network tool.
    foreach ($tool in @('ping', 'trace', 'tracert', 'traceroute', 'ssh')) {
        $position = [Array]::IndexOf($ArgumentList, $tool)
        if ($position -ge 0) {
            $separator = [Array]::IndexOf($ArgumentList, '--')
            $dryRun = [Array]::IndexOf($ArgumentList, '--dry-run')
            Assert-True ($dryRun -gt $position -and ($separator -lt 0 -or $dryRun -lt $separator)) 'Network execution refused: dry-run must precede the separator.'
        }
    }
    $start = [Diagnostics.ProcessStartInfo]::new($script:binary)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WorkingDirectory = $script:runDirectory
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $ArgumentList) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-True ($process.Start()) 'Native process could not start.'
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            if (-not $process.HasExited) { $process.Kill() } # Only this owned PID; never the process tree.
            $null = $process.WaitForExit(5000)
            throw [TimeoutException]::new('Native CLI exceeded 30000 ms; its owned PID was stopped.')
        }
        $text = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($errorText) {
            $report.diagnostics.Add(@{ test = $script:currentTest; exit_code = $process.ExitCode; message = (Protect-Message $errorText) })
        }
        if ($process.ExitCode -ne $Expected) {
            $failure = [InvalidOperationException]::new("Native CLI returned $($process.ExitCode); expected $Expected. See report diagnostics.")
            $failure.Data['ExitCode'] = $process.ExitCode
            throw $failure
        }
        if ($Expected -eq 1) { Assert-True ($errorText -match '(?i)error') 'Rejected input did not produce an error diagnostic.' }
        return $text.TrimEnd()
    }
    finally { $process.Dispose() }
}
function Invoke-CoreCli([string[]] $Arguments, [int] $Expected = 0, [string] $Config = $script:resolver, [string] $Color = 'never') {
    Invoke-Native (@('--config', $Config, '--color', $Color) + $Arguments) $Expected
}
function Json([string[]] $Arguments, [int] $Expected = 0, [string] $Config = $script:resolver, [string] $Color = 'never') {
    $text = Invoke-CoreCli $Arguments $Expected $Config $Color
    Assert-True (-not $text.Contains([char]27)) 'JSON contains ANSI escapes.'
    return ,(ConvertFrom-Json -InputObject $text -AsHashtable -NoEnumerate)
}
function Normalize-Json($Value) {
    if ($Value -is [Collections.IDictionary]) {
        $sorted = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) { $sorted[$key] = Normalize-Json $Value[$key] }
        return $sorted
    }
    if ($Value -is [array]) {
        $items = @()
        foreach ($item in $Value) { $items += ,(Normalize-Json $item) }
        return ,$items
    }
    return $Value
}
function Same($Actual, $Expected) {
    $left = ConvertTo-Json -InputObject (Normalize-Json $Actual) -Depth 30 -Compress
    $right = ConvertTo-Json -InputObject (Normalize-Json $Expected) -Depth 30 -Compress
    Assert-True ($left -ceq $right) 'Structured results differ.'
}
function Write-Fixture([string] $Name, $Value) {
    $path = Join-Path $script:runDirectory $Name
    Assert-True (-not (Test-Path -LiteralPath $path)) 'Refusing to overwrite a fixture.'
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Value -Depth 30), [Text.UTF8Encoding]::new($false))
    return $path
}
function Canonical([string] $Address) { ([Net.IPAddress]::Parse(($Address -split '%')[0])).ToString() }
function Address-Map($Interfaces) {
    $map = @{}
    foreach ($interface in $Interfaces) {
        foreach ($address in $interface.addresses) {
            $key = "$($interface.index)|$(Canonical $address.address)"
            Assert-True (-not $map.ContainsKey($key)) 'Duplicate interface/address pair.'
            $map[$key] = $address
        }
    }
    return $map
}
function Assert-Plan($Plan, [string] $Basis, [int] $Reservations, [int] $Records, [int[]] $Changes) {
    Assert-True ($Plan.mode -ceq 'dry_run' -and $Plan.basis -ceq $Basis) 'Plan mode/basis mismatch.'
    Assert-True ($Plan.desired.schema_version -eq 1 -and $Plan.desired.owner -ceq 'v6alias') 'Snapshot schema/owner mismatch.'
    Assert-True ($Plan.desired.reservations.Count -eq $Reservations -and $Plan.desired.dns_records.Count -eq $Records) 'Desired record count mismatch.'
    $fields = @('add_reservations', 'remove_reservations', 'add_dns_records', 'remove_dns_records')
    for ($i = 0; $i -lt $fields.Count; $i++) {
        Assert-True ($Plan.changes[$fields[$i]].Count -eq $Changes[$i]) 'Change count mismatch.'
    }
}

try {
    Assert-True ($IsWindows -and $env:COMPUTERNAME -ceq 'CORP-44') 'Restricted to the CORP-44 Windows guest.'
    $os = Get-CimInstance Win32_OperatingSystem -Property Caption, Version, BuildNumber, ProductType, FreePhysicalMemory
    $edition = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType, EditionID
    Assert-True ($edition.InstallationType -ceq 'Server Core' -and $edition.EditionID -ceq 'ServerStandard' -and $os.ProductType -eq 3) 'Expected standalone Windows Server Standard Core.'
    Assert-LocalPath $Root
    $Root = [IO.Path]::GetFullPath($Root)
    Assert-True (Test-Path -LiteralPath $Root -PathType Container) 'Prepared Root is missing.'
    $state = Join-Path $Root 'state'
    Assert-LocalPath $state
    $runDirectory = Join-Path $state ("core-smoke-{0}-{1}" -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'), [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $runDirectory
    $reportPath = Join-Path $runDirectory 'report.json'
    Save-Report
    Test-Case 'Windows Server Standard Core identity and build' {
        Assert-True ($os.Caption -match 'Windows Server 2025 Standard' -and [int]$os.BuildNumber -eq 26100) 'Expected Windows Server 2025 build 26100.'
        $report.facts.os = @{ version = $os.Version; build = $os.BuildNumber; edition = $edition.EditionID; installation = $edition.InstallationType }
    }
    Test-Case 'Workgroup and generic resources' {
        $computer = Get-CimInstance Win32_ComputerSystem -Property PartOfDomain, Domain, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors
        Assert-True (-not $computer.PartOfDomain -and $computer.Domain -ieq 'WORKGROUP') 'Expected an unjoined WORKGROUP guest.'
        Assert-True ($computer.TotalPhysicalMemory -gt 0 -and $computer.NumberOfLogicalProcessors -gt 0 -and $os.FreePhysicalMemory -gt 0) 'Invalid resource counters.'
        $report.facts.resources = @{ memory_bytes = $computer.TotalPhysicalMemory; free_memory_kib = $os.FreePhysicalMemory; processors = $computer.NumberOfProcessors; logical_processors = $computer.NumberOfLogicalProcessors; workgroup = 'WORKGROUP' }
    }
    Test-Case 'Prepared PowerShell and payload paths' {
        Assert-True ($PSVersionTable.PSVersion -ge [version]'7.3' -and $PSHOME -ieq (Join-Path $Root 'PowerShell7')) 'Use the prepared Root\PowerShell7\pwsh.exe, version 7.3 or newer.'
        $report.facts.powershell = $PSVersionTable.PSVersion.ToString()
        $script:binary = Join-Path $Root 'v6alias.exe'
        $script:liveConfig = Join-Path $Root 'v6alias.yaml'
        $script:modulePath = Join-Path $Root 'V6AliasDemo.psm1'
        foreach ($path in @($binary, $liveConfig, $modulePath)) {
            Assert-LocalPath $path
            Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'A prepared payload file is missing.'
        }
    }
    Test-Case 'Secure Boot read-only optional observation' {
        $report.facts.secure_boot = @{ status = 'unavailable' }
        try { $report.facts.secure_boot = @{ status = 'observed'; enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } }
        catch { $report.facts.secure_boot.reason = Protect-Message $_.Exception.Message }
    }
    Test-Case 'One IPv6-only NIC; IPv4 unbound and DHCPv6/RA disabled' {
        $script:adapters = @(Get-NetAdapter -Physical)
        Assert-True ($adapters.Count -eq 1) 'Expected exactly one physical NIC.'
        $ipInterfaces = @(Get-NetIPInterface -InterfaceIndex $adapters[0].ifIndex)
        $binding = Get-NetAdapterBinding -Name $adapters[0].Name -ComponentID ms_tcpip
        Assert-True (-not $binding.Enabled) 'IPv4 must be unbound on the dedicated test NIC.'
        $entry = @($ipInterfaces | Where-Object { "$($_.AddressFamily)" -eq 'IPv6' })
        Assert-True ($entry.Count -eq 1 -and "$($entry[0].Dhcp)" -eq 'Disabled') 'DHCPv6 must be disabled.'
        Assert-True ("$($entry[0].RouterDiscovery)" -eq 'Disabled') 'IPv6 router discovery must be disabled.'
        $report.facts.physical_adapter_count = $adapters.Count
    }
    Test-Case 'No default routes and SSH server stopped' {
        Assert-True (@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0', '::/0')).Count -eq 0) 'A default route exists.'
        $ssh = @(Get-Service | Where-Object Name -eq 'sshd')
        Assert-True ($ssh.Count -eq 0 -or "$($ssh[0].Status)" -eq 'Stopped') 'SSH server must be absent or stopped.'
        $report.facts.default_routes = 0
        $report.facts.ssh_server = if ($ssh.Count) { 'stopped' } else { 'absent' }
    }
    Test-Case 'Isolated example fixtures and new database path' {
        Assert-LocalPath $FixturesRoot
        $fixtureDirectory = Join-Path $runDirectory 'fixtures'
        $null = New-Item -ItemType Directory -Path $fixtureDirectory
        foreach ($name in @('service.example.yaml', 'v6alias.example.yaml', 'device.json', 'observation.json', 'unknown.json')) {
            $source = Join-Path $FixturesRoot $name
            Assert-LocalPath $source
            Copy-Item -LiteralPath $source -Destination (Join-Path $fixtureDirectory $name)
        }
        $script:resolver = Join-Path $fixtureDirectory 'v6alias.example.yaml'
        $script:serviceConfig = Join-Path $fixtureDirectory 'service.example.yaml'
        $script:device = Join-Path $fixtureDirectory 'device.json'
        $script:observation = Join-Path $fixtureDirectory 'observation.json'
        $script:unknown = Join-Path $fixtureDirectory 'unknown.json'
        $script:database = Join-Path $runDirectory 'inventory.sqlite'
        Assert-True (-not (Test-Path -LiteralPath $database)) 'Database must not exist before initialization.'
        $script:inventory = @('inventory', '--database', $database)
        $script:service = @('service', '--database', $database, '--service-config', $serviceConfig)
        $script:policy = @('policy', '--database', $database, '--service-config', $serviceConfig)
        $script:knownArgs = @('--observation', $observation, '--trusted-link', 'corp-link')
    }
    Test-Case 'Native Windows binary version' { Assert-True ((Invoke-Native @('--version')) -match '^v6alias \d+\.\d+\.\d+') 'Unexpected native version output.' }
    Test-Case 'CLI usage and interface command alias' {
        $help = Invoke-CoreCli @('--help')
        Assert-True ($help -match 'Usage:' -and $help -match 'ifconfig' -and $help -match 'inventory') 'Expected CLI usage is missing.'
        $help = Invoke-CoreCli @('ifconfig', '--help')
        Assert-True ($help -match '--raw' -and $help -match '--json' -and $help -match '--interface') 'Interface alias help is incomplete.'
    }
    Test-Case 'Example corp:42 resolve and reverse' {
        $script:exampleAddress = Invoke-CoreCli @('resolve', 'corp:42')
        Assert-True ($exampleAddress -ceq 'fd7a:115c:a1e0:17::2a') 'Example resolver result mismatch.'
        Assert-True ((Invoke-CoreCli @('reverse', $exampleAddress)) -ceq 'corp:42') 'Example reverse mismatch.'
    }
    foreach ($tool in @('ping', 'trace', 'tracert', 'traceroute', 'ssh')) {
        Test-Case "Windows $tool exact offline dry-run" {
            $program = if ($tool -in @('trace', 'tracert', 'traceroute')) { 'tracert' } else { $tool }
            $options = switch ($program) {
                'ping' { @('-n', '2', '-w', '1000') }
                'tracert' { @('-d', '-h', '2') }
                'ssh' { @('-l', 'example user') }
            }
            $display = if ($program -eq 'ssh') { '-l "example user"' } else { $options -join ' ' }
            $text = Invoke-CoreCli (@($tool, 'corp:42', '--dry-run', '--') + $options)
            Assert-True ($text -ceq "Resolved: corp:42 -> $exampleAddress`nCommand:  $program -6 $display $exampleAddress") 'Exact Windows dry-run invocation mismatch.'
        }
    }
    Test-Case 'ANSI always versus never; resolver stays plain' {
        Assert-True ((Invoke-CoreCli @('ping', 'corp:42', '--dry-run') -Color always).Contains([char]27)) 'Explicit ANSI color is missing.'
        Assert-True (-not (Invoke-CoreCli @('ping', 'corp:42', '--dry-run')).Contains([char]27)) 'Never-color output contains ANSI.'
        Assert-True ((Invoke-CoreCli @('resolve', 'corp:42') -Color always) -ceq $exampleAddress) 'Resolver acquired presentation color.'
    }
    Test-Case 'Raw and configured interface JSON retain every address' {
        $script:raw = Json @('interfaces', '--raw', '--json') -Config (Join-Path $runDirectory 'absent.yaml') -Color always
        $script:configured = Json @('ifconfig', '--json') -Config $liveConfig -Color always
        $script:rawMap = Address-Map $raw
        $script:configuredMap = Address-Map $configured
        Same @($rawMap.Keys | Sort-Object) @($configuredMap.Keys | Sort-Object)
        foreach ($key in $rawMap.Keys) {
            Assert-True ($null -eq $rawMap[$key].alias) 'Raw output includes an alias.'
            Same $rawMap[$key].prefix_length $configuredMap[$key].prefix_length
        }
        $report.facts.interfaces = @{ count = $configured.Count; addresses = $configuredMap.Count }
    }
    Test-Case 'OS IPv4/IPv6 index/address parity and known prefix lengths' {
        $script:osAddresses = @(Get-NetIPAddress -AddressFamily IPv4, IPv6)
        $osMap = @{}
        foreach ($address in $osAddresses) { $osMap["$($address.InterfaceIndex)|$(Canonical $address.IPAddress)"] = $address }
        Same @($osMap.Keys | Sort-Object) @($configuredMap.Keys | Sort-Object)
        foreach ($key in $osMap.Keys) {
            $prefix = $configuredMap[$key].prefix_length
            # The Windows enumeration library may not supply an IPv6 netmask.
            if ($null -ne $prefix) { Assert-True ($prefix -eq $osMap[$key].PrefixLength) 'Reported prefix disagrees with the OS.' }
            elseif ("$($osMap[$key].AddressFamily)" -eq 'IPv4') { throw 'IPv4 prefix unexpectedly missing.' }
        }
    }
    Test-Case 'Live corp:44 static address and every reported alias round-trip' {
        $actual = Canonical (Invoke-CoreCli @('resolve', 'corp:44') -Config $liveConfig)
        $key = "$($adapters[0].ifIndex)|$actual"
        Assert-True ($configuredMap.ContainsKey($key) -and $configuredMap[$key].alias -ceq 'corp:44') 'Live corp:44 is not visible on the physical NIC; verify link/address readiness.'
        $assigned = @($osAddresses | Where-Object { $_.InterfaceIndex -eq $adapters[0].ifIndex -and (Canonical $_.IPAddress) -ceq $actual })
        Assert-True ($assigned.Count -eq 1 -and "$($assigned[0].PrefixOrigin)" -eq 'Manual') 'Expected the static corp:44 OS address.'
        foreach ($entry in $configuredMap.Values) {
            if ($null -ne $entry.alias) {
                Assert-True ((Canonical (Invoke-CoreCli @('resolve', $entry.alias) -Config $liveConfig)) -ceq (Canonical $entry.address)) 'Interface alias resolution mismatch.'
                Assert-True ((Invoke-CoreCli @('reverse', (Canonical $entry.address)) -Config $liveConfig) -ceq $entry.alias) 'Interface reverse alias mismatch.'
            }
        }
    }
    Test-Case 'Inventory initialization, normalized registration and exact replay' {
        Same (Json ($inventory + 'init')) @{ initialized = $true; schema_version = 1 }
        Assert-True (Test-Path -LiteralPath $database -PathType Leaf) 'Initialization did not create the isolated database.'
        $script:registered = Json ($inventory + @('register', '--device', $device))
        Same $registered @{ asset_id = 'demo-workstation'; dns_label = 'demo-workstation'; duid = '000400112233445566778899aabbccddeeff'; iaid = 1; managed = $true }
        Same (Json ($inventory + @('register', '--device', $device))) $registered
        Same (Json ($inventory + 'list')) @($registered)
    }
    Test-Case 'Unknown policy denial exits 2 and creates no assignment' {
        $denied = Json ($policy + @('explain', '--observation', $unknown, '--trusted-link', 'corp-link')) 2
        Assert-True ($denied.allowed -eq $false -and $denied.reason) 'Unknown identity was not explicitly denied.'
        $null = Invoke-CoreCli ($service + @('allocate', '--observation', $unknown, '--trusted-link', 'corp-link')) 1
        Same (Json ($service + 'assignments')) @()
    }
    Test-Case 'Known policy allowed without allocation' {
        $decision = Json ($policy + 'explain' + $knownArgs)
        Assert-True ($decision.allowed -eq $true -and $decision.matched_rule -ceq 'managed-corporate' -and $decision.profile -ceq 'corp' -and $decision.subnet -eq 23) 'Known policy result mismatch.'
        Same (Json ($service + 'assignments')) @()
    }
    Test-Case 'Lowest allocation is stable across native process restarts' {
        $script:assignment = Json ($service + 'allocate' + $knownArgs)
        Assert-True ($assignment.device -eq 2 -and $assignment.state -ceq 'active' -and $assignment.asset_id -ceq $registered.asset_id) 'Lowest allocation mismatch.'
        Assert-True ($assignment.address -ceq (Invoke-CoreCli @('resolve', 'corp:2'))) 'Allocated address mismatch.'
        Same (Json ($service + 'allocate' + $knownArgs)) $assignment
        Same (Json ($service + 'assignments')) @($assignment)
    }
    Test-Case 'Desired-only plan has one reservation, two records, no proposed changes' {
        $script:plan = Json ($service + 'plan')
        Assert-Plan $plan 'desired_only' 1 2 @(0, 0, 0, 0)
        Same @($plan.desired.dns_records.type | Sort-Object) @('AAAA', 'PTR')
        $script:observed = Write-Fixture 'observed.json' $plan.desired
        Assert-True (-not ([IO.File]::ReadAllBytes($observed)[0] -eq 239)) 'Snapshot must be UTF-8 without BOM.'
    }
    Test-Case 'Matching snapshot is unchanged; empty snapshot proposes only additions' {
        $matching = Json ($service + @('plan', '--observed', $observed))
        Assert-Plan $matching 'owned_snapshot' 1 2 @(0, 0, 0, 0)
        Same $matching.desired $plan.desired
        $empty = Write-Fixture 'empty.json' @{ schema_version = 1; owner = 'v6alias'; reservations = @(); dns_records = @() }
        Assert-Plan (Json ($service + @('plan', '--observed', $empty))) 'owned_snapshot' 1 2 @(1, 0, 2, 0)
    }
    Test-Case 'Drifted and unknown snapshot records are rejected' {
        foreach ($kind in @('drift', 'unknown')) {
            $snapshot = Get-Content -LiteralPath $observed -Raw | ConvertFrom-Json -AsHashtable
            if ($kind -eq 'drift') { $snapshot.dns_records[0].ttl = 301 }
            else { $snapshot.reservations[0].asset_id = 'unknown-asset' }
            $bad = Write-Fixture "$kind.json" $snapshot
            $null = Invoke-CoreCli ($service + @('plan', '--observed', $bad)) 1
        }
        Same (Json ($service + 'assignments')) @($assignment)
    }
    Test-Case 'Malformed JSON and missing input fail without changing inventory' {
        $bad = Join-Path $runDirectory 'malformed.json'
        [IO.File]::WriteAllText($bad, '{', [Text.UTF8Encoding]::new($false))
        foreach ($inputPath in @($bad, (Join-Path $runDirectory 'missing.json'))) {
            $null = Invoke-CoreCli ($inventory + @('register', '--device', $inputPath)) 1
            $null = Invoke-CoreCli ($policy + @('explain', '--observation', $inputPath, '--trusted-link', 'corp-link')) 1
            $null = Invoke-CoreCli ($service + @('allocate', '--observation', $inputPath, '--trusted-link', 'corp-link')) 1
            $null = Invoke-CoreCli ($service + @('plan', '--observed', $inputPath)) 1
        }
        Same (Json ($inventory + 'list')) @($registered)
        Same (Json ($service + 'assignments')) @($assignment)
    }
    Test-Case 'Changed pinned configuration fails closed and original state survives' {
        $original = Get-Content -LiteralPath $serviceConfig -Raw
        $changed = $original.Replace('dns_zone: v6alias.home.arpa', 'dns_zone: other.home.arpa')
        Assert-True ($changed -cne $original) 'Expected example DNS zone was not found.'
        $changedPath = Join-Path $runDirectory 'changed-service.yaml'
        [IO.File]::WriteAllText($changedPath, $changed, [Text.UTF8Encoding]::new($false))
        $alternate = @('service', '--database', $database, '--service-config', $changedPath)
        foreach ($operation in @('assignments', 'plan')) { $null = Invoke-CoreCli ($alternate + $operation) 1 }
        $null = Invoke-CoreCli ($alternate + 'allocate' + $knownArgs) 1
        $null = Invoke-CoreCli ($alternate + @('retire', '--asset-id', $registered.asset_id)) 1
        $null = Invoke-CoreCli (@('policy', '--database', $database, '--service-config', $changedPath, 'explain') + $knownArgs) 1
        Same (Json ($service + 'assignments')) @($assignment)
        Same (Json ($service + 'plan')) $plan
    }
    Test-Case 'Read-only missing databases create neither files nor sidecars' {
        foreach ($operation in @('list', 'explain', 'assignments', 'plan')) {
            $missing = Join-Path $runDirectory "missing-$operation.sqlite"
            $group = if ($operation -eq 'list') { 'inventory' } elseif ($operation -eq 'explain') { 'policy' } else { 'service' }
            $arguments = @($group, '--database', $missing)
            if ($group -ne 'inventory') { $arguments += @('--service-config', $serviceConfig) }
            $arguments += $operation
            if ($operation -eq 'explain') { $arguments += $knownArgs }
            $null = Invoke-CoreCli $arguments 1
            Assert-True (@(Get-ChildItem -LiteralPath $runDirectory -Filter "missing-$operation.sqlite*" -Force).Count -eq 0) 'Read-only operation created a database or sidecar.'
        }
    }
    Test-Case 'Retirement retains tombstone and proposes one reservation/two DNS deletes' {
        $retired = Json ($service + @('retire', '--asset-id', $registered.asset_id))
        $expectedRetired = $assignment.Clone()
        $expectedRetired.state = 'retired'
        Same $retired $expectedRetired
        Same (Json ($service + 'assignments')) @($retired)
        $null = Invoke-CoreCli ($service + 'allocate' + $knownArgs) 1
        Assert-Plan (Json ($service + 'plan')) 'desired_only' 0 0 @(0, 0, 0, 0)
        $removals = Json ($service + @('plan', '--observed', $observed))
        Assert-Plan $removals 'owned_snapshot' 0 0 @(0, 1, 0, 2)
        Same $removals.changes.remove_reservations $plan.desired.reservations
        Same $removals.changes.remove_dns_records $plan.desired.dns_records
    }
    Test-Case 'Next asset receives device 3, never retired device 2' {
        $next = Get-Content -LiteralPath $device -Raw | ConvertFrom-Json -AsHashtable
        $next.asset_id = $next.dns_label = 'demo-workstation-2'
        $next.duid = (Get-Content -LiteralPath $unknown -Raw | ConvertFrom-Json).duid
        $nextPath = Write-Fixture 'next-device.json' $next
        $null = Json ($inventory + @('register', '--device', $nextPath))
        $arguments = $service + @('allocate', '--observation', $unknown, '--trusted-link', 'corp-link')
        $allocated = Json $arguments
        Assert-True ($allocated.device -eq 3 -and $allocated.state -ceq 'active' -and $allocated.address -ceq (Invoke-CoreCli @('resolve', 'corp:3'))) 'Retired ID was reused or next allocation differs.'
        Same (Json $arguments) $allocated
        Assert-True ((Json ($service + 'assignments')).Count -eq 2) 'Retired history was lost.'
    }
    Test-Case 'Actual demo module: temporary color shortcuts, dry-runs and cleanup' {
        $names = @('ping', 'trace', 'tracert', 'traceroute', 'ssh', 'ifconfig', 'native-ping', 'native-trace', 'native-ssh', 'native-ifconfig', 'Enable-V6AliasDemo', 'Disable-V6AliasDemo')
        $conflicts = @(Get-Command -Name $names -CommandType Alias, Function, Filter, Configuration -All -ListImported -ErrorAction SilentlyContinue)
        Assert-True ($conflicts.Count -eq 0 -and -not (Get-Module V6AliasDemo)) 'Existing demo names/module conflict; run a fresh pwsh -NoProfile. Nothing was replaced.'
        $beforePath = $env:PATH
        try {
            $script:module = Import-Module $modulePath -PassThru -Scope Local
            # Keep the real module dispatch and actual executable; only bound its process transport.
            & $module {
                param($Runner, $Binary)
                $script:smokeRunner = $Runner
                $script:smokeBinary = $Binary
                function script:Invoke-V6AliasDemoProcess {
                    param([string] $Executable, [object[]] $ArgumentList)
                    if ($Executable -ine $script:smokeBinary) { throw 'Unexpected demo executable.' }
                    & $script:smokeRunner -ArgumentList ([string[]]$ArgumentList)
                }
            } ${function:Invoke-Native} $binary
            Enable-V6AliasDemo -Binary $binary -Config $resolver -Color 6>$null
            foreach ($name in @('ping', 'trace', 'tracert', 'traceroute', 'ssh')) {
                $text = & $name corp:42 --dry-run -- -l 'example user'
                Assert-True ($text.Contains([char]27)) 'Demo color forwarding failed.'
                $plain = $text -replace '\x1b\[[0-9;]*m', ''
                $command = if ($name -in @('trace', 'tracert', 'traceroute')) { 'trace' } else { $name }
                Assert-True ($plain -ceq (Invoke-CoreCli @($command, 'corp:42', '--dry-run', '--', '-l', 'example user'))) 'Demo argument forwarding differs.'
            }
            $text = ifconfig --raw --json
            Assert-True (-not $text.Contains([char]27)) 'Demo JSON includes ANSI.'
            $demoMap = Address-Map (ConvertFrom-Json -InputObject $text -AsHashtable -NoEnumerate)
            Same @($demoMap.Keys | Sort-Object) @($rawMap.Keys | Sort-Object)
        }
        finally {
            if ($null -ne $module) {
                try { & $module { Disable-V6AliasDemo } 6>$null }
                finally { Remove-Module $module -Force; $script:module = $null }
            }
        }
        Assert-True ($env:PATH -ceq $beforePath) 'Demo altered PATH.'
        Assert-True (@(Get-Command -Name $names -CommandType Alias, Function, Filter, Configuration -All -ListImported -ErrorAction SilentlyContinue).Count -eq 0) 'Demo functions leaked into the caller.'
    }
    $report.status = 'passed'
}
catch {
    $report.status = 'failed'
    $code = if ($_.Exception.Data.Contains('ExitCode')) { $_.Exception.Data['ExitCode'] } elseif ($_.Exception -is [TimeoutException]) { 'timeout' } else { $_.FullyQualifiedErrorId }
    $report.error = @{ test = $currentTest; code = $code; message = (Protect-Message $_.Exception.Message) }
    $report.tests.Add(@{ label = $currentTest; status = 'failed' })
    Write-Host "FAIL: $currentTest (details retained in report; no further tests run)"
}
finally {
    $report.finished_utc = [datetime]::UtcNow.ToString('o')
    Save-Report
    if ($reportPath) { Write-Host "Report: $reportPath" }
    else { Write-Host 'No report written: guest identity/path gate refused local writes.' }
}
Write-Host "$($report.status): $(@($report.tests | Where-Object status -eq 'pass').Count) checks passed; no network probes or system changes."
if ($report.status -ne 'passed') { exit 1 }
