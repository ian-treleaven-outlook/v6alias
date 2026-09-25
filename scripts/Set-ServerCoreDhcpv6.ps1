#Requires -Version 7.3
<#
.DESCRIPTION
Console-only CORP-44 helper. Default Inspect is read-only; this file never contacts
a VM host. Apply requires a separately approved, guest-local JSON plan:
  {"ExpectedMac":"52:54:00:11:22:33","ExpectedInterfaceGuid":"<GUID>",
   "ExpectedDuid":"00-01-00-01-11-22-33-44-52-54-00-11-22-33",
   "ExpectedIaid":123,"OldAddress":"fd12:3456:789a:1::44",
   "NewAddress":"fd12:3456:789a:1::144","RouterDns":"fd12:3456:789a:1::1",
   "PrivateFqdn":"corp-44.example.test","ExpectedDnsTtl":3600}
Apply also requires a NEW StateDirectory under C:\V6Alias\state. Verify/Rollback use
SnapshotPath, ExpectedSnapshotSha256 and ExpectedJournalSha256 printed by Apply.
After a crash, review the durable journal and approve its current hash separately.
RollbackOnFailure is opt-in and must be included in the operator's approval.
WhatIf performs reads, but creates no files and issues no configuration commands.

RollbackStrategy defaults to "Guest". A persistent RA-DNS "Default" baseline has
no known exact guest restore API and blocks Apply under that strategy. Only an
explicitly approved plan with "RollbackStrategy":"VmSnapshot" and a nonempty
"RecoverySnapshot":"cold-snapshot-proof-name" authorizes that baseline. The
reference is an opaque 1..128 character name (letters/digits, dot, underscore,
hyphen), NOT a path or command, and is the operator's attestation that an approved
prechange cold VM snapshot exists; this guest cannot verify its existence.
Inspect/backup retain Default, never substitute Enabled. VmSnapshot recovery
never claims guest rollback: RollbackOnFailure only attempts a journaled, owned
acquisition stop and reports VM_SNAPSHOT_RESTORE_REQUIRED. Explicit Rollback
refuses without changing settings. The operator must cleanly power off and
restore the approved snapshot separately at the hypervisor. This script never
invokes that operation. Verify still checks the Disabled target in both stores.

No DUID/IAID registry writes, IPv4 operations, privacy/global settings, firewall,
service or remote-management changes. The isolated router's M=1/A=0 policy and
absence of rogue RAs MUST be established separately. IgnoreDefaultRoutes is not
a firewall. Inspect's English netsh evidence must be validated on the console:
unrecognized/localized RA-DNS output blocks Apply rather than guessing a backup.
Native child commands/DNS queries have 15s deadlines; lease polling is bounded.
NetTCPIP CIM provider calls themselves use Windows' native provider timeouts.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Inspect', 'Apply', 'Verify', 'Rollback')][string]$Action = 'Inspect',
    [string]$PlanPath,
    [string]$StateDirectory,
    [string]$SnapshotPath,
    [string]$ExpectedSnapshotSha256,
    [string]$ExpectedJournalSha256,
    [ValidateRange(1, 90)][int]$LeaseTimeoutSeconds = 90,
    [switch]$RollbackOnFailure
)

function Assert-Core($Condition, [string]$Message) {
    if (-not $Condition) { throw [InvalidOperationException]::new($Message) }
}
function Convert-CoreIp([string]$Value) {
    Assert-Core ($Value -notmatch '[%\s]') 'Scoped/whitespace addresses are not supported.'
    $ip = [Net.IPAddress]::Parse($Value)
    Assert-Core ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) 'Expected IPv6.'
    $ip.ToString().ToLowerInvariant()
}
function Convert-CoreNativeAddress([string]$Value, [int]$Index) {
    if ($Value.Contains('%')) {
        Assert-Core ($Value -cmatch '^(?<address>[0-9a-fA-F:]+)%(?<scope>[1-9][0-9]{0,9})\z') 'Invalid native IPv6 scope.'
        $address = $Matches.address
        Assert-Core ([uint64]$Matches.scope -eq $Index -and
            [Net.IPAddress]::Parse($address).IsIPv6LinkLocal) 'Native scope must identify this NIC on a link-local address.'
        return Convert-CoreIp $address
    }
    Convert-CoreIp $Value
}
function Get-CorePrefix([string]$Address) {
    $bytes = [Net.IPAddress]::Parse((Convert-CoreIp $Address)).GetAddressBytes()
    for ($i = 8; $i -lt 16; $i++) { $bytes[$i] = 0 }
    [Net.IPAddress]::new($bytes).ToString().ToLowerInvariant() + '/64'
}
function Convert-CoreMac([string]$Value) {
    Assert-Core ($Value -match '^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$') 'Invalid MAC literal.'
    ($Value -replace '[:-]', '').ToUpperInvariant()
}
function Convert-CoreDuid([string]$Value) {
    Assert-Core ($Value -match '^(?:[0-9a-fA-F]{2}-){1,127}[0-9a-fA-F]{2}$') 'Expected 2..128 hyphenated DUID bytes.'
    $Value.ToUpperInvariant()
}
function Assert-CorePlan($Plan) {
    foreach ($field in @('ExpectedMac','ExpectedInterfaceGuid','ExpectedDuid','ExpectedIaid',
            'OldAddress','NewAddress','RouterDns','PrivateFqdn','ExpectedDnsTtl')) {
        Assert-Core ($Plan.Contains($field) -and $null -ne $Plan[$field]) "Missing plan field: $field"
    }
    $Plan.ExpectedMac = Convert-CoreMac $Plan.ExpectedMac
    $Plan.ExpectedInterfaceGuid = ([guid]$Plan.ExpectedInterfaceGuid).ToString('B').ToUpperInvariant()
    $Plan.ExpectedDuid = Convert-CoreDuid $Plan.ExpectedDuid
    Assert-Core ("$($Plan.ExpectedIaid)" -match '^\d+$' -and
        [decimal]$Plan.ExpectedIaid -le [uint32]::MaxValue) 'Invalid unsigned IAID.'
    $Plan.ExpectedIaid = [uint32]$Plan.ExpectedIaid
    $prefixes = @()
    foreach ($field in @('OldAddress','NewAddress','RouterDns')) {
        $Plan[$field] = Convert-CoreIp $Plan[$field]
        $bytes = [Net.IPAddress]::Parse($Plan[$field]).GetAddressBytes()
        Assert-Core ($bytes[0] -eq 0xfd) 'Only locally assigned fd00::/8 ULA literals are permitted.'
        Assert-Core (@($bytes[8..15] | Where-Object { $_ -ne 0 }).Count -gt 0) 'Subnet-router anycast is not a node address.'
        $prefixes += [Convert]::ToHexString($bytes[0..7])
    }
    Assert-Core (@($prefixes | Select-Object -Unique).Count -eq 1) 'All addresses must share one ULA /64.'
    Assert-Core (@($Plan.OldAddress,$Plan.NewAddress,$Plan.RouterDns | Select-Object -Unique).Count -eq 3) 'Addresses must be distinct.'
    Assert-Core ($Plan.PrivateFqdn -match '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$') 'Expected a literal private FQDN.'
    Assert-Core ($Plan.ExpectedDnsTtl -eq 3600) 'This narrowly scoped plan expects the approved 3600-second DNS TTL.'
    if (-not $Plan.Contains('RollbackStrategy')) { $Plan.RollbackStrategy = 'Guest' }
    Assert-Core ($Plan.RollbackStrategy -is [string] -and $Plan.RollbackStrategy -cin @('Guest','VmSnapshot')) 'Invalid RollbackStrategy; use Guest or VmSnapshot.'
    if ($Plan.RollbackStrategy -ceq 'VmSnapshot') {
        Assert-Core ($Plan.Contains('RecoverySnapshot') -and $Plan.RecoverySnapshot -is [string] -and
            $Plan.RecoverySnapshot -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z') 'VmSnapshot requires a fixed opaque RecoverySnapshot name, not a path or command.'
    }
    else { Assert-Core (-not $Plan.Contains('RecoverySnapshot')) 'RecoverySnapshot requires explicit VmSnapshot approval.' }
}
function Assert-CorePath([string]$Path, [switch]$State) {
    Assert-Core ($Path -match '^[A-Za-z]:\\' -and $Path -notmatch '[/\x00-\x1f]' -and
        $Path.Substring(2) -notmatch ':' -and $Path -notmatch '(?:^|\\)\.\.?(?:\\|$)') 'Only absolute local paths without traversal/ADS are permitted.'
    $full = [IO.Path]::GetFullPath($Path)
    if ($State) {
        Assert-Core ($full -match '^C:\\V6Alias\\state\\[A-Za-z0-9_-]+(?:\\[A-Za-z0-9_.-]+)?$') 'State must be under a dedicated C:\V6Alias\state\<run> directory.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    Assert-Core ($drive.DriveType -eq [IO.DriveType]::Fixed) 'Only a fixed local volume is permitted.'
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            Assert-Core (-not ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse-point paths are forbidden.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Invoke-CoreProcess([string]$Executable, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-Core ($process.Start()) 'Child command failed to start.'
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            if (-not $process.HasExited) { $process.Kill() }
            $null = $process.WaitForExit(3000)
            throw [TimeoutException]::new('Owned child command exceeded 15 seconds.')
        }
        $text = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        Assert-Core ($text.Length -le 65536 -and $errorText.Length -le 8192) 'Unexpectedly large child output.'
        Assert-Core ($process.ExitCode -eq 0) "Child command failed ($($process.ExitCode)): $errorText"
        $text
    }
    finally { $process.Dispose() }
}
function Invoke-CoreNetsh([string[]]$Arguments) {
    Invoke-CoreProcess (Join-Path $env:SystemRoot 'System32\netsh.exe') $Arguments
}
function Get-CoreRaDns([int]$Index, [string]$Store) {
    Assert-Core ($Store -in @('active','persistent')) 'Invalid RA-DNS store.'
    $raw = Invoke-CoreNetsh @('interface','ipv6','show','interfaces',"interface=$Index",'level=verbose',"store=$Store")
    $raMatches = [regex]::Matches($raw, '(?im)^[ \t]*RA[ \t]+Based[ \t]+DNS[ \t]+Config(?:[ \t]*\([ \t]*RFC[ \t]+6106[ \t]*\))?[ \t]*:[ \t]*([^\r\n]*)\r?$')
    $value = 'Unknown'
    $diagnostic = 'Unrecognized, duplicate or localized RA-DNS output; Apply is blocked.'
    if ((Get-UICulture).Name -match '^en-' -and $raMatches.Count -eq 1) {
        switch ($raMatches[0].Groups[1].Value.Trim().ToLowerInvariant()) {
            'enabled' { $value = 'Enabled'; $diagnostic = $null }
            'disabled' { $value = 'Disabled'; $diagnostic = $null }
            'default' {
                if ($Store -eq 'persistent') {
                    $value = 'Default'
                    $diagnostic = 'Exact guest restoration is unsupported; Apply requires approved VmSnapshot recovery.'
                }
                else { $diagnostic = 'Active Default is unresolved; Apply is blocked.' }
            }
        }
    }
    [ordered]@{ Value = $value; Raw = $raw; Store = $Store; GuestRestorable = ($value -in @('Enabled','Disabled')); Diagnostic = $diagnostic }
}
function Get-CoreGuard {
    Assert-Core ($IsWindows -and $PSVersionTable.PSVersion -ge [version]'7.3') 'Windows PowerShell 7.3+ is required.'
    Assert-Core ($env:COMPUTERNAME -ceq 'CORP-44') 'Restricted to the CORP-44 console.'
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Assert-Core ($os.InstallationType -eq 'Server Core' -and $os.EditionID -eq 'ServerStandard' -and
        $os.CurrentBuildNumber -eq '26100') 'Expected Server 2025 Standard Core build 26100.'
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    Assert-Core ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'An elevated guest console is required.'
    foreach ($exe in @((Join-Path $env:SystemRoot 'System32\netsh.exe'), (Join-Path $PSHOME 'pwsh.exe'))) {
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        Assert-Core ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match 'O=Microsoft Corporation') 'Native executable signature is not trusted.'
    }
    [ordered]@{ Computer = $env:COMPUTERNAME; Installation = $os.InstallationType; Edition = $os.EditionID; Build = $os.CurrentBuildNumber }
}
function Get-CoreRegistry([string]$Guid) {
    $root = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    $interface = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
    Assert-Core ($root.GetValueKind('Dhcpv6DUID') -eq [Microsoft.Win32.RegistryValueKind]::Binary) 'Native DUID is not REG_BINARY.'
    $duid = $root.GetValue('Dhcpv6DUID')
    Assert-Core ($duid -is [byte[]] -and $duid.Length -ge 2 -and $duid.Length -le 128) 'Invalid native DUID bytes.'
    Assert-Core ($interface.GetValueKind('Dhcpv6Iaid') -eq [Microsoft.Win32.RegistryValueKind]::DWord) 'Native IAID is not REG_DWORD.'
    $iaid = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$interface.GetValue('Dhcpv6Iaid')), 0)
    $nameServerExists = $interface.GetValueNames() -contains 'NameServer'
    $nameServer = $null
    if ($nameServerExists) {
        Assert-Core ($interface.GetValueKind('NameServer') -eq [Microsoft.Win32.RegistryValueKind]::String) 'Unexpected IPv6 NameServer registry type.'
        $nameServer = $interface.GetValue('NameServer')
    }
    [ordered]@{ Duid = [BitConverter]::ToString($duid); Iaid = $iaid; NameServerExists = $nameServerExists; NameServer = $nameServer }
}
function Get-CoreDnsEvidence($Registry, $Dns) {
    $evidence = [ordered]@{ Mode = 'Unknown'; Servers = @(); Consistent = $false; Drift = 'Missing or invalid NameServer presence/value evidence.' }
    if (-not $Registry.Contains('NameServerExists') -or $Registry.NameServerExists -isnot [bool] -or
        -not $Registry.Contains('NameServer')) { return $evidence }
    if ((-not $Registry.NameServerExists -and $null -eq $Registry.NameServer) -or
        ($Registry.NameServerExists -and $Registry.NameServer -is [string] -and $Registry.NameServer -ceq '')) {
        $evidence.Mode = 'Automatic'; $evidence.Consistent = $true; $evidence.Drift = $null
        return $evidence
    }
    if (-not $Registry.NameServerExists -or $Registry.NameServer -isnot [string]) { return $evidence }
    $evidence.Mode = 'Static'
    $evidence.Drift = 'Invalid static NameServer list.'
    if ($Registry.NameServer -notmatch '^\s*[0-9a-fA-F:.]+(?:(?:\s*[,;]\s*|\s+)[0-9a-fA-F:.]+)*\s*$') { return $evidence }
    foreach ($literal in @($Registry.NameServer.Trim() -split '[,;\s]+')) {
        $ip = $null
        if (-not [Net.IPAddress]::TryParse($literal, [ref]$ip) -or
            $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { return $evidence }
        $evidence.Servers += $ip.ToString().ToLowerInvariant()
    }
    $evidence.Consistent = Test-CoreSame $evidence.Servers $Dns
    $evidence.Drift = $(if ($evidence.Consistent) { $null } else { 'Static registry and effective IPv6 DNS disagree.' })
    $evidence
}
function Assert-CoreDnsConsistency($State) {
    $evidence = Get-CoreDnsEvidence $State.Registry $State.Dns
    Assert-Core ($evidence.Consistent -and $State.DnsMode -ceq $evidence.Mode) "Foreign DNS configuration: $($evidence.Drift)"
    $evidence
}
function Get-CoreAddressObjects([int]$Index, [string]$Family, [string]$Store) {
    # Filter after enumeration: CIM's keyed query can throw ObjectNotFound for
    # the intentionally empty IPv4 / post-removal IPv6 address lists.
    @(Get-NetIPAddress -PolicyStore $Store -IncludeAllCompartments -ErrorAction Stop |
        Where-Object { $_.InterfaceIndex -eq $Index -and "$($_.AddressFamily)" -eq $Family })
}
function Get-CoreState {
    $identity = Get-CoreGuard
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object { $_.HardwareInterface -or "$($_.Status)" -eq 'Up' })
    Assert-Core ($adapters.Count -eq 1 -and $adapters[0].HardwareInterface) 'Exactly one hardware NIC and no additional adapters are required.'
    $adapter = $adapters[0]
    $index = [int]$adapter.ifIndex
    $guid = ([guid]$adapter.InterfaceGuid).ToString('B').ToUpperInvariant()
    $registry = Get-CoreRegistry $guid
    $ipv4 = @(Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip -ErrorAction Stop)
    $ipv6 = @(Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop)
    Assert-Core ($ipv4.Count -eq 1 -and -not $ipv4[0].Enabled -and $ipv6.Count -eq 1 -and $ipv6[0].Enabled) 'Expected IPv4 unbound and IPv6 bound.'
    $stores = [ordered]@{}
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $items = @(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -PolicyStore $store -ErrorAction Stop)
        Assert-Core ($items.Count -eq 1) "Expected one IPv6 interface in $store."
        $i = $items[0]
        $addresses = @(Get-CoreAddressObjects $index 'IPv6' $store | Sort-Object IPAddress |
            ForEach-Object { [ordered]@{ Address = (Convert-CoreNativeAddress $_.IPAddress $index); PrefixLength = [int]$_.PrefixLength;
                PrefixOrigin = "$($_.PrefixOrigin)"; SuffixOrigin = "$($_.SuffixOrigin)";
                SkipAsSource = [bool]$_.SkipAsSource; State = "$($_.AddressState)" } })
        $routes = @(Get-NetRoute -PolicyStore $store -IncludeAllCompartments -ErrorAction Stop |
            Where-Object { "$($_.AddressFamily)" -eq 'IPv6' -or $_.DestinationPrefix -eq '0.0.0.0/0' } |
            Sort-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric |
            ForEach-Object { [ordered]@{ InterfaceIndex = [int]$_.InterfaceIndex; Destination = $_.DestinationPrefix;
                NextHop = $_.NextHop; Protocol = "$($_.Protocol)"; Metric = [int]$_.RouteMetric } })
        $stores[$store] = [ordered]@{
            Dhcp = "$($i.Dhcp)"; RouterDiscovery = "$($i.RouterDiscovery)"; IgnoreDefaultRoutes = "$($i.IgnoreDefaultRoutes)"
            Advertising = "$($i.Advertising)"; Forwarding = "$($i.Forwarding)"
            Addresses = $addresses; Routes = $routes
            RaDns = (Get-CoreRaDns $index $(if ($store -eq 'ActiveStore') { 'active' } else { 'persistent' }))
        }
    }
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction Stop)
    Assert-Core ($dns.Count -eq 1) 'Expected exactly one IPv6 DNS object.'
    $servers = @($dns[0].ServerAddresses | ForEach-Object { Convert-CoreIp $_ })
    $dnsEvidence = Get-CoreDnsEvidence $registry $servers
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { [ordered]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)" } })
    $services = @(Get-CimInstance Win32_Service -Filter "Name='sshd' OR Name='WinRM'" -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { [ordered]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode } })
    [ordered]@{
        Identity = $identity; Index = $index; Guid = $guid; Mac = (Convert-CoreMac $adapter.MacAddress)
        Registry = $registry; Stores = $stores
        Dns = $servers; DnsMode = $dnsEvidence.Mode; DnsEvidence = $dnsEvidence
        IPv4 = @(Get-CoreAddressObjects $index 'IPv4' 'ActiveStore')
        Firewall = $profiles; Services = $services
        Profiles = @(Get-NetConnectionProfile -InterfaceIndex $index -ErrorAction Stop | Sort-Object Name |
            ForEach-Object { [ordered]@{ Name = $_.Name; Category = "$($_.NetworkCategory)" } })
    }
}
function Test-CoreSame($Left, $Right) {
    (ConvertTo-Json -InputObject $Left -Depth 40 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 40 -Compress)
}
function Get-CoreGlobals($State, [string]$Store = 'ActiveStore') {
    @($State.Stores[$Store].Addresses | Where-Object { -not [Net.IPAddress]::Parse($_.Address).IsIPv6LinkLocal })
}
function Assert-CoreIdentity($State, $Plan) {
    Assert-Core ($State.Mac -ceq $Plan.ExpectedMac -and $State.Guid -ceq $Plan.ExpectedInterfaceGuid) 'MAC/GUID identity mismatch.'
    Assert-Core ($State.Registry.Duid -ceq $Plan.ExpectedDuid -and $State.Registry.Iaid -eq $Plan.ExpectedIaid) 'Native DUID/IAID mismatch; identifiers are never rewritten.'
    Assert-Core ($State.IPv4.Count -eq 0) 'Unexpected IPv4 address.'
    Assert-Core ($State.Firewall.Count -eq 3 -and @($State.Firewall | Where-Object Enabled -ne 'True').Count -eq 0) 'All firewall profiles must remain enabled.'
    Assert-Core (@($State.Services | Where-Object { $_.State -ne 'Stopped' -or $_.StartMode -ne 'Disabled' }).Count -eq 0 -and
        @($State.Services | Where-Object Name -eq 'WinRM').Count -eq 1) 'Management services must be stopped and disabled (sshd may be absent).'
    $null = Assert-CoreDnsConsistency $State
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $s = $State.Stores[$store]
        foreach ($field in @('Advertising','Forwarding')) {
            # Native PersistentStore represents inherited disabled defaults as empty.
            Assert-Core ($s[$field] -ceq 'Disabled' -or
                ($store -eq 'PersistentStore' -and $s[$field] -ceq '' -and
                 $State.Stores.ActiveStore[$field] -ceq 'Disabled')) 'Advertising/forwarding must remain disabled.'
        }
        Assert-Core ($s.RaDns.Value -in @('Enabled','Disabled') -or
            ($store -eq 'PersistentStore' -and $s.RaDns.Value -eq 'Default')) 'RA-DNS baseline is unknown/unresolved: inspect native English console output/help before applying.'
    }
}
function Assert-CoreNoDefaults($State) {
    foreach ($store in @('ActiveStore','PersistentStore')) {
        Assert-Core (@($State.Stores[$store].Routes | Where-Object { $_.Destination -in @('::/0','0.0.0.0/0') }).Count -eq 0) "Unexpected default route in $store (all compartments)."
    }
}
function Assert-CoreBaseline($State, $Plan) {
    Assert-CoreIdentity $State $Plan
    Assert-Core ($State.Stores.PersistentStore.RaDns.Value -ne 'Default' -or
        ($Plan.Contains('RollbackStrategy') -and $Plan.RollbackStrategy -ceq 'VmSnapshot' -and
        $Plan.Contains('RecoverySnapshot') -and $Plan.RecoverySnapshot -is [string] -and
        $Plan.RecoverySnapshot -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z')) 'Persistent RA-DNS Default cannot be restored by a known guest API; explicit VmSnapshot/RecoverySnapshot approval is required.'
    Assert-CoreNoDefaults $State
    Assert-Core ($State.Stores.ActiveStore.Dhcp -eq 'Disabled') 'Baseline DHCPv6 must be disabled.'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $s = $State.Stores[$store]
        Assert-Core ($s.RouterDiscovery -eq 'Disabled' -and $s.IgnoreDefaultRoutes -eq 'Disabled') "Unexpected $store interface baseline."
        $globals = @(Get-CoreGlobals $State $store)
        Assert-Core ($globals.Count -eq 1 -and $globals[0].Address -eq $Plan.OldAddress -and
            $globals[0].PrefixLength -eq 64 -and $globals[0].PrefixOrigin -eq 'Manual') "Expected exactly the old manual /64 in $store."
    }
    Assert-Core (@(Get-CoreGlobals $State)[0].State -eq 'Preferred') 'Old address is not Preferred.'
}
function Assert-CoreUnchanged($State, $Baseline) {
    foreach ($key in @('Identity','Index','Guid','Mac','Firewall','Services','Profiles')) {
        Assert-Core (Test-CoreSame $State[$key] $Baseline[$key]) "Foreign change in $key; manual intervention required."
    }
    foreach ($store in @('ActiveStore','PersistentStore')) {
        foreach ($field in @('Advertising','Forwarding')) {
            Assert-Core (Test-CoreSame $State.Stores[$store][$field] $Baseline.Stores[$store][$field]) "Foreign $field persistence change; manual intervention required."
        }
        $before = @($Baseline.Stores[$store].Routes | Where-Object { $_.Protocol -eq 'NetMgmt' })
        $now = @($State.Stores[$store].Routes | Where-Object { $_.Protocol -eq 'NetMgmt' })
        Assert-Core (Test-CoreSame $before $now) 'Explicit routes changed; manual intervention required.'
    }
}
function New-CorePrivateDirectory([string]$Path) {
    Assert-CorePath $Path -State
    Assert-Core (-not (Test-Path -LiteralPath $Path)) 'State directory already exists; never overwrite a run.'
    Assert-Core (Test-Path -LiteralPath (Split-Path $Path -Parent) -PathType Container) 'Create/review the state parent before approval.'
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($user)
    foreach ($sid in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $directory = [IO.DirectoryInfo]::new($Path)
    [IO.FileSystemAclExtensions]::Create($directory, $acl)
}
function Assert-CorePrivateDirectory([string]$Path) {
    Assert-CorePath $Path -State
    $acl = Get-Acl -LiteralPath $Path
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-Core ($acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $user) 'State directory must be private and owned by this console account.'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-Core ($rules.Count -ge 1 -and @($rules | Where-Object {
        $_.IdentityReference.Value -notin @($user,'S-1-5-18') -or $_.AccessControlType -ne 'Allow'
    }).Count -eq 0) 'State directory ACL permits unexpected principals.'
}
function Write-CoreFile([string]$Path, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 40))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
function Add-CoreJournal($Context, [string]$Step, [string]$Status, [string]$Detail = '') {
    $entry = [ordered]@{ Time = [datetime]::UtcNow.ToString('o'); SnapshotSha256 = $Context.Digest; Step = $Step; Status = $Status; Detail = $Detail }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($entry | ConvertTo-Json -Compress) + "`n")
    $stream = [IO.File]::Open((Join-Path $Context.Directory 'journal.jsonl'), [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if ($Status -eq 'BEGIN') { $Context.Started.Add($Step) }
}
function Invoke-CoreStep($Context, [string]$Step, [scriptblock]$Body) {
    if ($Step -ne 'SafetyStop') {
        $current = Get-CoreState
        if ($Step.StartsWith('Rollback', [StringComparison]::Ordinal)) { Assert-CoreOwned $Context $current }
        else { Assert-CoreSafe $Context $current }
    }
    Add-CoreJournal $Context $Step 'BEGIN'
    & $Body | Out-Null
    Add-CoreJournal $Context $Step 'DONE'
}
function Set-CoreInterface($Context, [hashtable]$Values) {
    Set-NetIPInterface -InterfaceIndex $Context.Snapshot.Baseline.Index -AddressFamily IPv6 @Values -ErrorAction Stop
}
function Set-CoreDns($Context, [string[]]$Servers, [switch]$Reset) {
    $inputObject = @(Get-DnsClientServerAddress -InterfaceIndex $Context.Snapshot.Baseline.Index -AddressFamily IPv6 -ErrorAction Stop)
    Assert-Core ($inputObject.Count -eq 1) 'Expected one IPv6 DNS input object.'
    if ($Reset) { Set-DnsClientServerAddress -InputObject $inputObject[0] -ResetServerAddresses -ErrorAction Stop }
    else { Set-DnsClientServerAddress -InputObject $inputObject[0] -ServerAddresses $Servers -ErrorAction Stop }
}
function Set-CoreRaDns($Context, [string]$Value, [string]$Store) {
    Assert-Core ($Value -in @('Enabled','Disabled') -and $Store -in @('active','persistent')) 'Invalid RA-DNS operation.'
    Invoke-CoreNetsh @('interface','ipv6','set','interface',"$($Context.Snapshot.Baseline.Index)",
        "rabaseddnsconfig=$($Value.ToLowerInvariant())","store=$Store")
}
function Remove-CoreOld($Context) {
    $b = $Context.Snapshot.Baseline
    foreach ($store in @('PersistentStore','ActiveStore')) {
        $items = @(Get-CoreAddressObjects $b.Index 'IPv6' $store |
            Where-Object { (Convert-CoreNativeAddress $_.IPAddress $b.Index) -eq $Context.Snapshot.Plan.OldAddress })
        foreach ($item in $items) {
            Assert-Core ($item.PrefixOrigin -eq 'Manual' -and $item.PrefixLength -eq 64) 'Old address changed concurrently.'
            Remove-NetIPAddress -InputObject $item -Confirm:$false -ErrorAction Stop
        }
    }
}
function Assert-CoreOwned($Context, $State) {
    $b = $Context.Snapshot.Baseline
    $p = $Context.Snapshot.Plan
    Assert-CoreIdentity $State $p
    Assert-CoreUnchanged $State $b
    Assert-CoreNoDefaults $State
    $baselineDns = Assert-CoreDnsConsistency $b
    $currentDns = Assert-CoreDnsConsistency $State
    $rawBaseline = $State.Registry.NameServerExists -eq $b.Registry.NameServerExists -and
        (Test-CoreSame $State.Registry.NameServer $b.Registry.NameServer)
    # Only our journaled restore can legitimately normalize the baseline's
    # spelling/separators or the absent-versus-empty automatic registry value.
    $restoredDns = $Context.Started.Contains('RollbackDns') -and (Test-CoreSame $currentDns.Servers $baselineDns.Servers)
    $dnsBaseline = ($rawBaseline -or $restoredDns) -and $State.DnsMode -eq $b.DnsMode -and (Test-CoreSame $State.Dns $b.Dns)
    $dnsOwned = $Context.Started.Contains('PinDns') -and $State.DnsMode -eq 'Static' -and
        $State.Registry.NameServer -cmatch '^[0-9a-fA-F:.]+\z' -and
        (Test-CoreSame $currentDns.Servers @($p.RouterDns)) -and (Test-CoreSame $State.Dns @($p.RouterDns))
    Assert-Core ($dnsBaseline -or $dnsOwned) 'Foreign DNS configuration; rollback will not overwrite it.'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        foreach ($field in @('RouterDiscovery','IgnoreDefaultRoutes')) {
            $step = $(if ($field -eq 'RouterDiscovery') { 'EnableRa' } else { 'IgnoreDefaults' })
            Assert-Core ($State.Stores[$store][$field] -eq $b.Stores[$store][$field] -or
                ($Context.Started.Contains($step) -and $State.Stores[$store][$field] -eq 'Enabled')) "Foreign $field setting."
        }
        $ra = $State.Stores[$store].RaDns.Value
        Assert-Core ($ra -eq $b.Stores[$store].RaDns.Value -or ($Context.Started.Contains('DisableRaDns') -and $ra -eq 'Disabled')) 'Foreign RA-DNS setting.'
        $globals = @(Get-CoreGlobals $State $store)
        Assert-Core ($Context.Started.Contains('RemoveOld') -or @($globals | Where-Object Address -eq $p.OldAddress).Count -eq 1) 'Old address disappeared before the journaled removal.'
        foreach ($address in $globals) {
            $old = $address.Address -eq $p.OldAddress -and $address.PrefixOrigin -eq 'Manual' -and
                $address.PrefixLength -eq 64 -and $address.SkipAsSource -eq @(Get-CoreGlobals $b $store)[0].SkipAsSource
            $new = $Context.Started.Contains('EnableDhcp') -and $address.Address -eq $p.NewAddress -and
                $address.PrefixOrigin -eq 'Dhcp' -and $address.PrefixLength -in @(64,128) -and -not $address.SkipAsSource
            Assert-Core ($old -or $new) 'Foreign/SLAAC address; rollback requires manual intervention.'
        }
    }
    Assert-Core ($State.Stores.ActiveStore.Dhcp -eq 'Disabled' -or
        ($Context.Started.Contains('EnableDhcp') -and $State.Stores.ActiveStore.Dhcp -eq 'Enabled')) 'Foreign DHCP setting.'
}
function Stop-CoreAcquisition($Context, $State) {
    # The only emergency exception to ownership checks: stop learning immediately.
    # Never delete an unrelated route; quarantine does not claim full isolation.
    Assert-Core ($State.Mac -eq $Context.Snapshot.Baseline.Mac -and $State.Guid -eq $Context.Snapshot.Baseline.Guid -and
        $State.Index -eq $Context.Snapshot.Baseline.Index) 'Cannot quarantine a changed NIC identity.'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $ra = $State.Stores[$store].RouterDiscovery
        Assert-Core ($ra -eq $Context.Snapshot.Baseline.Stores[$store].RouterDiscovery -or
            ($Context.Started.Contains('EnableRa') -and $ra -eq 'Enabled')) 'Cannot stop foreign RA acquisition.'
    }
    Assert-Core ($State.Stores.ActiveStore.Dhcp -eq $Context.Snapshot.Baseline.Stores.ActiveStore.Dhcp -or
        ($Context.Started.Contains('EnableDhcp') -and $State.Stores.ActiveStore.Dhcp -eq 'Enabled')) 'Cannot stop foreign DHCP acquisition.'
    Invoke-CoreStep $Context 'SafetyStop' { Set-CoreInterface $Context @{ RouterDiscovery = 'Disabled'; Dhcp = 'Disabled' } }
}
function Assert-CoreSafe($Context, $State) {
    $p = $Context.Snapshot.Plan
    $defaults = @($State.Stores.ActiveStore.Routes + $State.Stores.PersistentStore.Routes | Where-Object { $_.Destination -in @('::/0','0.0.0.0/0') })
    $foreign = @(Get-CoreGlobals $State | Where-Object {
        $_.Address -notin @($p.OldAddress,$p.NewAddress) -or
        ($_.Address -eq $p.NewAddress -and $_.PrefixOrigin -ne 'Dhcp')
    })
    if ($defaults.Count -or $foreign.Count) {
        Stop-CoreAcquisition $Context $State
        throw 'UNSAFE: unexpected default/SLAAC/foreign address; DHCP and RA stopped. Routes retained for console investigation; isolation is NOT guaranteed. Disconnect the guest NIC at the host.'
    }
    Assert-CoreOwned $Context $State
}
function Assert-CoreTarget($Context, $State) {
    Assert-CoreOwned $Context $State
    $p = $Context.Snapshot.Plan
    Assert-Core ($State.Stores.ActiveStore.Dhcp -eq 'Enabled') 'DHCPv6 runtime is not enabled.'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $s = $State.Stores[$store]
        Assert-Core ($s.RouterDiscovery -eq 'Enabled' -and $s.IgnoreDefaultRoutes -eq 'Enabled' -and $s.RaDns.Value -eq 'Disabled') "Target controls not retained in $store."
        Assert-Core (@(Get-CoreGlobals $State $store | Where-Object { $_.Address -eq $p.OldAddress }).Count -eq 0) 'Old address remains.'
    }
    $globals = @(Get-CoreGlobals $State)
    # DHCPv6 IA_NA conveys an address, not an on-link subnet: Windows may expose
    # the lease as /128. The RA's separate /64 on-link route is what matters.
    Assert-Core ($globals.Count -eq 1 -and $globals[0].Address -eq $p.NewAddress -and
        $globals[0].PrefixOrigin -eq 'Dhcp' -and $globals[0].PrefixLength -in @(64,128) -and
        $globals[0].State -eq 'Preferred') 'Expected only the Preferred native DHCPv6 lease.'
    $prefix = Get-CorePrefix $p.NewAddress
    Assert-Core (@($State.Stores.ActiveStore.Routes | Where-Object {
        $_.InterfaceIndex -eq $State.Index -and $_.Destination -eq $prefix -and $_.NextHop -eq '::'
    }).Count -ge 1) 'The approved ULA /64 has no on-link route; the pinned router DNS is not proven on-link.'
    Assert-Core ($State.DnsMode -eq 'Static' -and (Test-CoreSame $State.Dns @($p.RouterDns))) 'IPv6 DNS is not pinned to the approved router.'
}
function Resolve-CoreDns([string]$Name, [string]$Type, [string]$Server) {
    Assert-Core ($Name -match '^[a-zA-Z0-9.:-]+$' -and $Type -in @('AAAA','PTR')) 'Invalid DNS query.'
    $serverArgument = ''
    if ($Server) { $Server = Convert-CoreIp $Server; $serverArgument = " -Server '$Server'" }
    $command = "`$ErrorActionPreference='Stop'; @(Resolve-DnsName -Name '$Name' -Type $Type -DnsOnly -NoHostsFile -QuickTimeout$serverArgument -ErrorAction Stop) | ConvertTo-Json -Depth 8 -Compress"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $raw = Invoke-CoreProcess (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded)
    @(ConvertFrom-Json -InputObject $raw -AsHashtable)
}
function Test-CoreDns($Plan) {
    $hex = [Convert]::ToHexString([Net.IPAddress]::Parse($Plan.NewAddress).GetAddressBytes()).ToLowerInvariant().ToCharArray()
    [array]::Reverse($hex)
    $reverse = ($hex -join '.') + '.ip6.arpa'
    foreach ($server in @($Plan.RouterDns, '')) {
        $aaaa = @(Resolve-CoreDns $Plan.PrivateFqdn 'AAAA' $server | Where-Object { "$($_.Type)" -in @('AAAA','28') })
        $ptr = @(Resolve-CoreDns $reverse 'PTR' $server | Where-Object { "$($_.Type)" -in @('PTR','12') })
        Assert-Core ($aaaa.Count -eq 1 -and (Convert-CoreIp $aaaa[0].IPAddress) -eq $Plan.NewAddress -and
            $aaaa[0].Name.TrimEnd('.') -ieq $Plan.PrivateFqdn.TrimEnd('.')) 'AAAA answer/owner mismatch.'
        Assert-Core ($ptr.Count -eq 1 -and $ptr[0].Name.TrimEnd('.') -ieq $reverse -and
            $ptr[0].NameHost.TrimEnd('.') -ieq $Plan.PrivateFqdn.TrimEnd('.')) 'PTR answer/owner mismatch.'
        if ($server) {
            Assert-Core ($aaaa[0].TTL -eq $Plan.ExpectedDnsTtl -and $ptr[0].TTL -eq $Plan.ExpectedDnsTtl) 'Direct-router DNS TTL mismatch.'
        }
    }
}
function Invoke-CoreMigration($Context, [int]$TimeoutSeconds) {
    $p = $Context.Snapshot.Plan
    Assert-CoreBaseline (Get-CoreState) $p
    Invoke-CoreStep $Context 'IgnoreDefaults' { Set-CoreInterface $Context @{ IgnoreDefaultRoutes = 'Enabled' } }
    $state = Get-CoreState
    Assert-CoreSafe $Context $state
    foreach ($store in @('ActiveStore','PersistentStore')) {
        Assert-Core ($state.Stores[$store].IgnoreDefaultRoutes -eq 'Enabled' -and $state.Stores[$store].RouterDiscovery -eq 'Disabled') 'Default rejection must persist before any RA is enabled.'
    }
    Invoke-CoreStep $Context 'DisableRaDns' {
        Set-CoreRaDns $Context 'Disabled' 'persistent'
        Set-CoreRaDns $Context 'Disabled' 'active'
    }
    Invoke-CoreStep $Context 'PinDns' { Set-CoreDns $Context @($p.RouterDns) }
    $state = Get-CoreState
    Assert-CoreSafe $Context $state
    Assert-Core ($state.DnsMode -eq 'Static' -and (Test-CoreSame $state.Dns @($p.RouterDns)) -and
        $state.Stores.ActiveStore.RaDns.Value -eq 'Disabled' -and $state.Stores.PersistentStore.RaDns.Value -eq 'Disabled') 'DNS protections failed readback.'
    Invoke-CoreStep $Context 'RemoveOld' { Remove-CoreOld $Context }
    Assert-CoreSafe $Context (Get-CoreState)
    Invoke-CoreStep $Context 'EnableDhcp' { Set-CoreInterface $Context @{ Dhcp = 'Enabled' } }
    Assert-CoreSafe $Context (Get-CoreState)
    Invoke-CoreStep $Context 'EnableRa' { Set-CoreInterface $Context @{ RouterDiscovery = 'Enabled' } }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $state = Get-CoreState
        Assert-CoreSafe $Context $state
        $lease = @(Get-CoreGlobals $state | Where-Object { $_.Address -eq $p.NewAddress -and $_.State -eq 'Preferred' })
        $prefix = Get-CorePrefix $p.NewAddress
        $onLink = @($state.Stores.ActiveStore.Routes | Where-Object {
            $_.InterfaceIndex -eq $state.Index -and $_.Destination -eq $prefix -and $_.NextHop -eq '::'
        })
        if ($lease.Count -eq 1 -and $onLink.Count) { break }
        Assert-Core ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) 'Timed out waiting for the native DHCPv6 lease.'
        Start-Sleep -Milliseconds 500
    } while ($true)
    Assert-CoreTarget $Context $state
    Test-CoreDns $p
    Assert-CoreTarget $Context (Get-CoreState)
    Add-CoreJournal $Context 'Migration' 'VERIFIED'
}
function Test-CoreSnapshotRecovery($Context) {
    ($Context.Snapshot.Plan.Contains('RollbackStrategy') -and $Context.Snapshot.Plan.RollbackStrategy -ceq 'VmSnapshot') -or
        $Context.Snapshot.Baseline.Stores.PersistentStore.RaDns.Value -eq 'Default'
}
function Assert-CoreGuestRollback($Context) {
    if (Test-CoreSnapshotRecovery $Context) {
        $reference = $(if ($Context.Snapshot.Plan.Contains('RecoverySnapshot')) { $Context.Snapshot.Plan.RecoverySnapshot } else { 'unavailable' })
        throw "VM_SNAPSHOT_RESTORE_REQUIRED: $reference. No exact guest Default restore is implemented; cleanly power off and restore the approved VM snapshot separately."
    }
}
function Invoke-CoreSnapshotStop($Context) {
    $state = Get-CoreState
    Assert-CoreOwned $Context $state
    if ($state.Stores.ActiveStore.Dhcp -eq 'Disabled' -and
        $state.Stores.ActiveStore.RouterDiscovery -eq 'Disabled' -and $state.Stores.PersistentStore.RouterDiscovery -eq 'Disabled') { return 'Not needed' }
    Invoke-CoreStep $Context 'RollbackStop' { Set-CoreInterface $Context @{ RouterDiscovery = 'Disabled'; Dhcp = 'Disabled' } }
    $state = Get-CoreState
    Assert-CoreOwned $Context $state
    Assert-Core ($state.Stores.ActiveStore.Dhcp -eq 'Disabled' -and
        $state.Stores.ActiveStore.RouterDiscovery -eq 'Disabled' -and
        $state.Stores.PersistentStore.RouterDiscovery -eq 'Disabled') 'Snapshot recovery acquisition stop failed readback.'
    'STOPPED'
}
function Invoke-CoreRollback($Context) {
    Assert-CoreGuestRollback $Context
    $b = $Context.Snapshot.Baseline
    $p = $Context.Snapshot.Plan
    Assert-CoreOwned $Context (Get-CoreState)
    Invoke-CoreStep $Context 'RollbackStop' { Set-CoreInterface $Context @{ RouterDiscovery = 'Disabled'; Dhcp = 'Disabled' } }
    Assert-CoreOwned $Context (Get-CoreState)
    Invoke-CoreStep $Context 'RollbackLease' {
        foreach ($store in @('ActiveStore','PersistentStore')) {
            $items = @(Get-CoreAddressObjects $b.Index 'IPv6' $store |
                Where-Object { (Convert-CoreNativeAddress $_.IPAddress $b.Index) -eq $p.NewAddress })
            foreach ($item in $items) {
                Assert-Core ($item.PrefixOrigin -eq 'Dhcp') 'Refusing to remove a non-DHCP address.'
                Remove-NetIPAddress -InputObject $item -Confirm:$false -ErrorAction Stop
            }
        }
    }
    Invoke-CoreStep $Context 'RollbackOld' {
        foreach ($store in @('PersistentStore','ActiveStore')) {
            $current = @(Get-CoreAddressObjects $b.Index 'IPv6' $store |
                Where-Object { (Convert-CoreNativeAddress $_.IPAddress $b.Index) -eq $p.OldAddress })
            if (-not $current.Count) {
                New-NetIPAddress -InterfaceIndex $b.Index -AddressFamily IPv6 -IPAddress $p.OldAddress -PrefixLength 64 `
                    -SkipAsSource @(Get-CoreGlobals $b $store)[0].SkipAsSource -PolicyStore $store -ErrorAction Stop | Out-Null
            }
        }
    }
    Invoke-CoreStep $Context 'RollbackDns' {
        if ($b.DnsMode -eq 'Automatic') { Set-CoreDns $Context -Reset }
        else { Set-CoreDns $Context $b.Dns }
        Set-CoreRaDns $Context $b.Stores.PersistentStore.RaDns.Value 'persistent'
        Set-CoreRaDns $Context $b.Stores.ActiveStore.RaDns.Value 'active'
    }
    $state = Get-CoreState
    Assert-CoreOwned $Context $state
    foreach ($store in @('ActiveStore','PersistentStore')) {
        Assert-Core ($state.Stores[$store].RouterDiscovery -eq 'Disabled') 'Do not restore default acceptance while RA is enabled.'
    }
    Invoke-CoreStep $Context 'RollbackIgnoreDefaults' { Set-CoreInterface $Context @{ IgnoreDefaultRoutes = 'Disabled' } }
    Assert-CoreRestored $Context (Get-CoreState)
    Add-CoreJournal $Context 'Rollback' 'VERIFIED'
}
function Assert-CoreRestored($Context, $State) {
    Assert-CoreGuestRollback $Context
    $b = $Context.Snapshot.Baseline
    Assert-CoreBaseline $State $Context.Snapshot.Plan
    Assert-CoreOwned $Context $State
    Assert-Core ($State.DnsMode -eq $b.DnsMode -and (Test-CoreSame $State.Dns $b.Dns)) 'DNS rollback did not restore original mode/list.'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        Assert-Core ($State.Stores[$store].RaDns.Value -eq $b.Stores[$store].RaDns.Value) 'RA-DNS rollback mismatch.'
    }
}
function Read-CoreSnapshot([string]$Path, [string]$Digest, [string]$JournalDigest) {
    Assert-CorePath $Path -State
    Assert-Core ((Split-Path $Path -Leaf) -eq 'snapshot.json') 'Expected snapshot.json.'
    $directory = Split-Path $Path -Parent
    Assert-CorePrivateDirectory $directory
    Assert-Core ($Digest -match '^[a-fA-F0-9]{64}$') 'An out-of-band snapshot SHA256 is required.'
    Assert-Core ($JournalDigest -match '^[a-fA-F0-9]{64}$') 'An out-of-band journal SHA256 is required.'
    Assert-Core ((Get-Item -LiteralPath $Path).Length -le 1048576) 'Snapshot exceeds 1 MiB.'
    Assert-Core ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Digest) 'Snapshot checksum mismatch.'
    $snapshot = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    Assert-Core ($snapshot.Version -eq 1 -and $snapshot.Phase -eq 'PREPARED') 'Unsupported/incomplete snapshot.'
    # Stored plans are already normalized; validate a separate copy through the input format.
    $plan = $snapshot.Plan
    $plan.ExpectedMac = ([regex]::Matches($plan.ExpectedMac, '..').Value -join ':')
    Assert-CorePlan $plan
    Assert-CoreBaseline $snapshot.Baseline $plan
    $journal = Join-Path $directory 'journal.jsonl'
    Assert-CorePath $journal -State
    Assert-Core ((Get-Item -LiteralPath $journal).Length -le 4194304) 'Journal exceeds 4 MiB.'
    Assert-Core ((Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash -eq $JournalDigest) 'Journal checksum mismatch.'
    $started = [Collections.Generic.List[string]]::new()
    $entries = @(Get-Content -LiteralPath $journal | ForEach-Object { ConvertFrom-Json -InputObject $_ -AsHashtable })
    Assert-Core ($entries.Count -ge 1 -and $entries[0].Step -eq 'Snapshot' -and $entries[0].Status -eq 'PREPARED') 'Journal is missing PREPARED.'
    foreach ($entry in $entries) {
        Assert-Core ($entry.SnapshotSha256 -eq $Digest) 'Journal belongs to another snapshot.'
        Assert-Core ($entry.Step -in @('Snapshot','IgnoreDefaults','DisableRaDns','PinDns','RemoveOld','EnableDhcp','EnableRa',
            'SafetyStop','RollbackStop','RollbackLease','RollbackOld','RollbackDns','RollbackIgnoreDefaults','Migration',
            'Rollback','Apply') -and $entry.Status -in @('PREPARED','BEGIN','DONE','FAILED','VERIFIED')) 'Unexpected journal operation.'
        if ($entry.Status -eq 'BEGIN') { $started.Add($entry.Step) }
    }
    [ordered]@{ Snapshot = $snapshot; Digest = $Digest.ToUpperInvariant(); Directory = $directory; Started = $started }
}
function Add-CoreSecondaryError($Errors, [string]$Stage, $Failure) {
    if ($Errors.Count -ge 8) { return }
    $message = $Failure.Exception.Message -replace '[\x00-\x1f\x7f]', ' '
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    $Errors.Add([ordered]@{ Stage = $Stage; Error = $message })
}
function Invoke-CoreMain($Options, $Cmdlet) {
    $context = $null
    $lock = $null
    $mutex = $null
    $mutexOwned = $false
    $writable = $false
    try {
        $state = Get-CoreState
        if ($Options.Action -eq 'Inspect') {
            [ordered]@{ Action = 'Inspect'; Status = 'READ_ONLY'; State = $state;
                Note = 'Unknown/active Default RA-DNS blocks Apply. Persistent Default requires explicit VmSnapshot/RecoverySnapshot approval; no guest Default restore. DNS evidence reports registry/effective drift. No changes or proof of isolated-router policy.' } | ConvertTo-Json -Depth 40
            return
        }
        if ($Options.Action -eq 'Apply') {
            Assert-CorePath $Options.PlanPath
            $plan = Get-Content -LiteralPath $Options.PlanPath -Raw | ConvertFrom-Json -AsHashtable
            Assert-CorePlan $plan
            Assert-CoreBaseline $state $plan
            Assert-CorePath $Options.StateDirectory -State
            Assert-Core (-not (Test-Path -LiteralPath $Options.StateDirectory)) 'State directory already exists.'
            if (-not $Cmdlet.ShouldProcess('CORP-44 / ' + $state.Guid, 'Apply the exact DHCPv6 plan and create a private rollback snapshot')) { return }
            $mutex = [Threading.Mutex]::new($false, 'Global\V6Alias-CORP-44-Dhcpv6')
            try { $mutexOwned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexOwned = $true }
            Assert-Core $mutexOwned 'Another DHCPv6 operation is running.'
            New-CorePrivateDirectory $Options.StateDirectory
            $lock = [IO.File]::Open((Join-Path $Options.StateDirectory 'operation.lock'), 'CreateNew', 'ReadWrite', 'None')
            $snapshot = [ordered]@{ Version = 1; Phase = 'PREPARED'; Time = [datetime]::UtcNow.ToString('o'); Plan = $plan; Baseline = $state }
            $path = Join-Path $Options.StateDirectory 'snapshot.json'
            Write-CoreFile $path $snapshot
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $context = [ordered]@{ Snapshot = $snapshot; Digest = $digest; Directory = $Options.StateDirectory; Started = [Collections.Generic.List[string]]::new() }
            Add-CoreJournal $context 'Snapshot' 'PREPARED'
            $writable = $true
            [ordered]@{ Status = 'PREPARED'; SnapshotPath = $path; SnapshotSha256 = $digest } | ConvertTo-Json -Compress
            # Re-read immediately before the first mutation, including source and identity.
            $fresh = Get-CoreState
            Assert-CoreBaseline $fresh $plan
            Assert-Core (Test-CoreSame $fresh $state) 'Baseline changed after snapshot; no changes applied.'
            Invoke-CoreMigration $context $Options.LeaseTimeoutSeconds
        }
        else {
            $context = Read-CoreSnapshot $Options.SnapshotPath $Options.ExpectedSnapshotSha256 $Options.ExpectedJournalSha256
            if ($Options.Action -eq 'Rollback') { Assert-CoreGuestRollback $context }
            Assert-CoreOwned $context $state
            if ($Options.Action -eq 'Verify') {
                Assert-CoreTarget $context $state
                Test-CoreDns $context.Snapshot.Plan
                Assert-CoreTarget $context (Get-CoreState)
            }
            else {
                if (-not $Cmdlet.ShouldProcess('CORP-44 / ' + $state.Guid, 'Restore only this snapshot-owned DHCPv6 migration')) { return }
                $mutex = [Threading.Mutex]::new($false, 'Global\V6Alias-CORP-44-Dhcpv6')
                try { $mutexOwned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexOwned = $true }
                Assert-Core $mutexOwned 'Another DHCPv6 operation is running.'
                $lockPath = Join-Path $context.Directory 'operation.lock'
                Assert-CorePath $lockPath -State
                $lock = [IO.File]::Open($lockPath, 'Open', 'ReadWrite', 'None')
                $context = Read-CoreSnapshot $Options.SnapshotPath $Options.ExpectedSnapshotSha256 $Options.ExpectedJournalSha256
                $writable = $true
                Invoke-CoreRollback $context
            }
        }
        $finalState = Get-CoreState
        if ($Options.Action -eq 'Apply') {
            Assert-CoreSafe $context $finalState
            Assert-CoreTarget $context $finalState
        }
        elseif ($Options.Action -eq 'Verify') { Assert-CoreTarget $context $finalState }
        else { Assert-CoreRestored $context $finalState }
        $report = [ordered]@{ Action = $Options.Action; Status = 'VERIFIED'; SnapshotSha256 = $context.Digest;
            JournalSha256 = (Get-FileHash -LiteralPath (Join-Path $context.Directory 'journal.jsonl') -Algorithm SHA256).Hash
            RollbackStrategy = $context.Snapshot.Plan.RollbackStrategy
            RecoverySnapshot = $(if ($context.Snapshot.Plan.Contains('RecoverySnapshot')) { $context.Snapshot.Plan.RecoverySnapshot } else { $null })
            Time = [datetime]::UtcNow.ToString('o'); State = $finalState }
        # Verify is strictly read-only. Apply/Rollback reports never overwrite.
        if ($Options.Action -ne 'Verify') { Write-CoreFile (Join-Path $context.Directory ("report-" + [guid]::NewGuid().ToString('N') + '.json')) $report }
        $report | ConvertTo-Json -Depth 40
    }
    catch {
        $failure = $_
        $rollback = 'Not attempted'
        $secondary = [Collections.Generic.List[object]]::new()
        $recovery = [ordered]@{ Code = 'NOT_ATTEMPTED'; RecoverySnapshot = $null; AcquisitionStop = 'Not attempted';
            Instruction = 'Review the original error and durable journal before any manual recovery.' }
        $snapshotRecovery = $context -and (Test-CoreSnapshotRecovery $context)
        if ($snapshotRecovery) {
            $rollback = 'VM_SNAPSHOT_RESTORE_REQUIRED'
            $recovery.Code = 'VM_SNAPSHOT_RESTORE_REQUIRED'
            if ($context.Snapshot.Plan.Contains('RecoverySnapshot')) { $recovery.RecoverySnapshot = $context.Snapshot.Plan.RecoverySnapshot }
            $recovery.Instruction = 'Cleanly power off and restore the approved VM snapshot separately at the hypervisor. Guest rollback cannot restore Default.'
        }
        if ($context -and $writable) {
            try { Add-CoreJournal $context $Options.Action 'FAILED' $failure.Exception.Message }
            catch { Add-CoreSecondaryError $secondary 'FailureJournal' $_ }
            if ($Options.Action -eq 'Apply' -and $Options.RollbackOnFailure -and $context.Started.Count) {
                try {
                    if ($snapshotRecovery) { $recovery.AcquisitionStop = Invoke-CoreSnapshotStop $context }
                    else { Invoke-CoreRollback $context; $rollback = 'VERIFIED'; $recovery.Code = 'GUEST_ROLLBACK_VERIFIED' }
                }
                catch {
                    $recoveryFailure = $_
                    Add-CoreSecondaryError $secondary 'Recovery' $recoveryFailure
                    if ($snapshotRecovery) { $recovery.AcquisitionStop = 'FAILED_OR_UNCONFIRMED' }
                    else { $rollback = 'FAILED'; $recovery.Code = 'RECOVERY_FAILED' }
                    $recovery.Instruction += ' Acquisition may remain enabled. No recovery mutation is allowed without its durable BEGIN; console/host intervention is required.'
                    try { Add-CoreJournal $context 'Rollback' 'FAILED' $recoveryFailure.Exception.Message }
                    catch { Add-CoreSecondaryError $secondary 'RecoveryFailureJournal' $_ }
                }
            }
        }
        $journalHash = $null
        if ($context) {
            try {
                $journal = Join-Path $context.Directory 'journal.jsonl'
                if (Test-Path -LiteralPath $journal -ErrorAction Stop) {
                    $journalHash = (Get-FileHash -LiteralPath $journal -Algorithm SHA256 -ErrorAction Stop).Hash
                }
            }
            catch { Add-CoreSecondaryError $secondary 'JournalHash' $_ }
        }
        $report = [ordered]@{ Action = $Options.Action; Status = 'FAILED'; Error = $failure.Exception.Message; Rollback = $rollback;
            Recovery = $recovery; SecondaryErrors = $secondary;
            SnapshotSha256 = $(if ($context) { $context.Digest } else { $null }); JournalSha256 = $journalHash }
        if ($context -and $writable) {
            try { Write-CoreFile (Join-Path $context.Directory ("failure-" + [guid]::NewGuid().ToString('N') + '.json')) $report }
            catch { Add-CoreSecondaryError $secondary 'FailureReport' $_ }
        }
        $report | ConvertTo-Json -Depth 40 -Compress
        throw $failure
    }
    finally {
        if ($lock) { $lock.Dispose() }
        if ($mutexOwned) { $mutex.ReleaseMutex() }
        if ($mutex) { $mutex.Dispose() }
    }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Invoke-CoreMain @{
    Action = $Action; PlanPath = $PlanPath; StateDirectory = $StateDirectory; SnapshotPath = $SnapshotPath
    ExpectedSnapshotSha256 = $ExpectedSnapshotSha256; LeaseTimeoutSeconds = $LeaseTimeoutSeconds
    ExpectedJournalSha256 = $ExpectedJournalSha256
    RollbackOnFailure = [bool]$RollbackOnFailure
} $PSCmdlet
