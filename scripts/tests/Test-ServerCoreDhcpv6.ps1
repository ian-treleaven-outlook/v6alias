#Requires -Version 7.3
# AST-imported helpers only. Never run the guest script body or native networking.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Set-ServerCoreDhcpv6.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$definitions = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)
$module = New-Module -ScriptBlock {
    param($Definitions, $TestRoot)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    foreach ($definition in $Definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
    $script:RealWriteFile = ${function:Write-CoreFile}
    $script:RealReadSnapshot = ${function:Read-CoreSnapshot}
    $script:RealJournal = ${function:Add-CoreJournal}
    $script:RealMain = ${function:Invoke-CoreMain}
    $script:RealPath = ${function:Assert-CorePath}
    $script:RealGuard = ${function:Get-CoreGuard}
    $script:RealRegistry = ${function:Get-CoreRegistry}
    $script:RealState = ${function:Get-CoreState}
    $script:RealRa = ${function:Get-CoreRaDns}
    $script:Checks = 0
    $script:Root = $TestRoot
    function Check($Condition, [string]$Message) {
        if (-not $Condition) { throw "OFFLINE ASSERTION: $Message" }
        $script:Checks++
    }
    function Reject([scriptblock]$Body, [string]$Pattern) {
        $caught = $null
        try { & $Body | Out-Null } catch { $caught = $_.Exception.Message }
        Check ($null -ne $caught -and $caught -match $Pattern) "Expected failure /$Pattern/, got '$caught'"
    }
    function Copy-Value($Value) { ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 40) -AsHashtable }
    function Reset-Fixture {
        $script:Plan = [ordered]@{
            ExpectedMac = '52:54:00:11:22:33'; ExpectedInterfaceGuid = '{12345678-1234-1234-1234-123456789ABC}'
            ExpectedDuid = '00-01-00-01-11-22-33-44-52-54-00-11-22-33'; ExpectedIaid = 4294967295
            OldAddress = 'fd12:3456:789a:1::44'; NewAddress = 'fd12:3456:789a:1::144'
            RouterDns = 'fd12:3456:789a:1::1'; PrivateFqdn = 'corp-44.example.test'; ExpectedDnsTtl = 3600
        }
        Assert-CorePlan $script:Plan
        $stores = [ordered]@{}
        foreach ($store in @('ActiveStore','PersistentStore')) {
            $stores[$store] = [ordered]@{
                Dhcp = 'Disabled'; RouterDiscovery = 'Disabled'; IgnoreDefaultRoutes = 'Disabled'
                Advertising = 'Disabled'; Forwarding = 'Disabled'
                Addresses = @([ordered]@{ Address = $script:Plan.OldAddress; PrefixLength = 64; PrefixOrigin = 'Manual'; SuffixOrigin = 'Manual'; SkipAsSource = $false; State = 'Preferred' })
                Routes = @()
                RaDns = [ordered]@{ Value = 'Enabled'; Raw = 'RA Based DNS Config : enabled' }
            }
        }
        $script:State = [ordered]@{
            Identity = [ordered]@{ Computer = 'CORP-44'; Installation = 'Server Core'; Edition = 'ServerStandard'; Build = '26100' }
            Index = 27; Guid = $script:Plan.ExpectedInterfaceGuid; Mac = $script:Plan.ExpectedMac
            Registry = [ordered]@{ Duid = $script:Plan.ExpectedDuid; Iaid = [uint32]::MaxValue; NameServerExists = $true; NameServer = '' }
            Stores = $stores; Dns = @('fec0:0:0:ffff::1','fec0:0:0:ffff::2','fec0:0:0:ffff::3')
            DnsMode = 'Automatic'; IPv4 = @()
            Firewall = @('Domain','Private','Public' | ForEach-Object { [ordered]@{ Name = $_; Enabled = 'True' } })
            Services = @([ordered]@{ Name = 'WinRM'; State = 'Stopped'; StartMode = 'Disabled' })
            Profiles = @([ordered]@{ Name = 'Unidentified network'; Category = 'Public' })
        }
        $snapshot = [ordered]@{ Version = 1; Phase = 'PREPARED'; Plan = (Copy-Value $script:Plan); Baseline = (Copy-Value $script:State) }
        $script:Context = [ordered]@{ Snapshot = $snapshot; Digest = ('A' * 64); Directory = 'C:\V6Alias\state\offline'; Started = [Collections.Generic.List[string]]::new() }
        $script:Calls = [Collections.Generic.List[string]]::new()
        $script:Events = [Collections.Generic.List[string]]::new()
        $script:Fail = ''
        $script:FailNew = $false
        $script:NoLease = $false
        $script:UnexpectedDefault = $false
        $script:ForeignLease = $false
        $script:IgnorePersistent = $false
        $script:BadPtr = $false
        $script:BadTtl = $false
        $script:RawRa = 'RA Based DNS Config : enabled'
        $script:Culture = 'en-US'
        $script:FileWrites = 0
        $script:JournalFault = ''
        $script:JournalFaultActive = $false
        $script:HashFault = $false
        $script:ReportFault = $false
        $script:FailureSeen = $false
    }
    function Get-CoreState { $script:Events.Add('READ'); Copy-Value $script:State }
    function Add-CoreJournal($Context, [string]$Step, [string]$Status, [string]$Detail = '') {
        $script:Events.Add("JOURNAL:$Step/$Status")
        if ($Status -eq 'BEGIN') { $Context.Started.Add($Step) }
    }
    function Record-Write([string]$Name) {
        Check ($script:Context.Snapshot.Phase -eq 'PREPARED') 'snapshot before write'
        Check ($script:Context.Snapshot.Baseline.Dns.Count -eq 3 -or $script:Context.Snapshot.Baseline.DnsMode -eq 'Static') 'complete DNS backup before write'
        Check ($script:Events.Count -gt 0 -and $script:Context.Started.Count -gt 0) 'durable BEGIN before write'
        $script:Calls.Add($Name)
        $script:Events.Add("WRITE:$Name")
        if ($script:Fail -and $Name -match $script:Fail) { throw "Injected failure: $Name" }
    }
    function Set-NetIPInterface {
        param($InterfaceIndex, $AddressFamily, $IgnoreDefaultRoutes, $Dhcp, $RouterDiscovery, $ErrorAction)
        Check ($InterfaceIndex -eq 27 -and $AddressFamily -eq 'IPv6') 'dynamic NIC and IPv6-only interface write'
        Record-Write "INTERFACE:$IgnoreDefaultRoutes/$Dhcp/$RouterDiscovery"
        foreach ($store in @('ActiveStore','PersistentStore')) {
            if ($IgnoreDefaultRoutes -and -not ($script:IgnorePersistent -and $store -eq 'PersistentStore')) { $script:State.Stores[$store].IgnoreDefaultRoutes = $IgnoreDefaultRoutes }
            if ($RouterDiscovery) { $script:State.Stores[$store].RouterDiscovery = $RouterDiscovery }
        }
        # PersistentStore DHCP is deliberately NOT updated: it is not a valid readback.
        if ($Dhcp) { $script:State.Stores.ActiveStore.Dhcp = $Dhcp }
        if ($RouterDiscovery -eq 'Enabled') {
            Check ($script:State.Stores.ActiveStore.IgnoreDefaultRoutes -eq 'Enabled' -and
                $script:State.Stores.PersistentStore.IgnoreDefaultRoutes -eq 'Enabled') 'both stores protected before RA'
            if (-not $script:NoLease) {
                $script:State.Stores.ActiveStore.Addresses = @([ordered]@{
                    Address = $(if ($script:ForeignLease) { 'fd12:3456:789a:1::999' } else { $script:Plan.NewAddress })
                    PrefixLength = 128; PrefixOrigin = 'Dhcp'; SuffixOrigin = 'Dhcp'; SkipAsSource = $false; State = 'Preferred'
                })
                $script:State.Stores.ActiveStore.Routes = @([ordered]@{ InterfaceIndex = 27; Destination = 'fd12:3456:789a:1::/64'; NextHop = '::'; Protocol = 'Icmp'; Metric = 256 })
            }
            if ($script:UnexpectedDefault) {
                $script:State.Stores.ActiveStore.Routes += [ordered]@{ InterfaceIndex = 27; Destination = '::/0'; NextHop = 'fe80::1'; Protocol = 'Icmp'; Metric = 256 }
            }
        }
    }
    function Invoke-CoreNetsh([string[]]$Arguments) {
        Check (($Arguments[0..1] -join ' ') -eq 'interface ipv6') 'netsh IPv6-only'
        if ($Arguments[2] -eq 'show') { return $script:RawRa }
        Check ($Arguments[3] -eq 'interface' -and $Arguments[4] -eq '27') 'netsh bound NIC index'
        $value = $Arguments[5].Split('=')[1]
        Check ($value -in @('enabled','disabled')) 'native setter accepts only documented RA-DNS values'
        $store = $(if ($Arguments[6] -eq 'store=active') { 'ActiveStore' } else { 'PersistentStore' })
        Record-Write "RADNS:$store/$value"
        $script:State.Stores[$store].RaDns.Value = $(if ($value -eq 'enabled') { 'Enabled' } else { 'Disabled' })
    }
    function Get-UICulture { [cultureinfo]::GetCultureInfo($script:Culture) }
    function Get-DnsClientServerAddress {
        param($InterfaceIndex, $AddressFamily, $ErrorAction)
        Check ($InterfaceIndex -eq 27 -and $AddressFamily -eq 'IPv6') 'DNS reads scoped IPv6'
        [pscustomobject]@{ AddressFamily = 23; InterfaceIndex = 27; ServerAddresses = @($script:State.Dns) }
    }
    function Set-DnsClientServerAddress {
        param($InputObject, $ServerAddresses, [switch]$ResetServerAddresses, $ErrorAction)
        Check ($InputObject.AddressFamily -eq 23 -and $InputObject.InterfaceIndex -eq 27) 'DNS mutation uses IPv6 InputObject, never index-only reset'
        Record-Write "DNS:reset=$ResetServerAddresses"
        if ($ResetServerAddresses) {
            $script:State.Dns = @($script:Context.Snapshot.Baseline.Dns)
            $script:State.DnsMode = 'Automatic'
            $script:State.Registry.NameServer = ''
        }
        else {
            $script:State.Dns = @($ServerAddresses)
            $script:State.DnsMode = 'Static'
            $script:State.Registry.NameServer = $ServerAddresses -join ','
        }
        $script:State.Registry.NameServerExists = $true
    }
    function Get-CoreAddressObjects {
        param($InterfaceIndex, $AddressFamily, $PolicyStore, $ErrorAction)
        Check ($InterfaceIndex -eq 27 -and $AddressFamily -eq 'IPv6') 'address operations scoped IPv6'
        foreach ($a in $script:State.Stores[$PolicyStore].Addresses) {
            [pscustomobject]@{ IPAddress = $a.Address; PrefixLength = $a.PrefixLength; PrefixOrigin = $a.PrefixOrigin; PolicyStore = $PolicyStore }
        }
    }
    function Remove-NetIPAddress {
        param($InputObject, $Confirm, $ErrorAction)
        Record-Write "REMOVE:$($InputObject.PolicyStore)/$($InputObject.IPAddress)"
        $script:State.Stores[$InputObject.PolicyStore].Addresses = @($script:State.Stores[$InputObject.PolicyStore].Addresses |
            Where-Object Address -ne $InputObject.IPAddress)
    }
    function New-NetIPAddress {
        param($InterfaceIndex, $AddressFamily, $IPAddress, $PrefixLength, $SkipAsSource, $PolicyStore, $ErrorAction)
        Check ($InterfaceIndex -eq 27 -and $AddressFamily -eq 'IPv6') 'restore only scoped IPv6'
        Record-Write "NEW:$PolicyStore/$IPAddress"
        if ($script:FailNew) { throw 'Injected restore failure' }
        $script:State.Stores[$PolicyStore].Addresses += [ordered]@{
            Address = $IPAddress; PrefixLength = $PrefixLength; PrefixOrigin = 'Manual'; SuffixOrigin = 'Manual'; SkipAsSource = $SkipAsSource; State = 'Preferred'
        }
    }
    function Resolve-CoreDns([string]$Name, [string]$Type, [string]$Server) {
        $script:Events.Add("QUERY:$Type/$Server")
        $ttl = $(if (-not $Server) { 42 } elseif ($script:BadTtl) { 1800 } else { 3600 })
        if ($Type -eq 'AAAA') { @{ Type = 'AAAA'; Name = $Name; IPAddress = $script:Plan.NewAddress; TTL = $ttl } }
        else { @{ Type = 'PTR'; Name = $Name; NameHost = $(if ($script:BadPtr) { 'wrong.example.test' } else { $script:Plan.PrivateFqdn }); TTL = $ttl } }
    }
    # Deny native/process/service/firewall operations even if a regression adds one.
    function Invoke-CoreProcess { throw 'OFFLINE: native execution forbidden' }
    function Set-Service { throw 'OFFLINE: service mutation forbidden' }
    function Stop-Service { throw 'OFFLINE: service mutation forbidden' }
    function Set-NetFirewallProfile { throw 'OFFLINE: firewall mutation forbidden' }
    function Set-NetAdapterBinding { throw 'OFFLINE: binding mutation forbidden' }
    function Disable-NetAdapterBinding { throw 'OFFLINE: binding mutation forbidden' }
    function Invoke-TestCases {
        Reset-Fixture
        Assert-CoreBaseline $script:State $script:Plan
        Check ($script:State.Dns.Count -eq 3) 'Windows DNS placeholders are a valid automatic baseline'
        Invoke-CoreMigration $script:Context 2
        Check ($script:Calls[0] -eq 'INTERFACE:Enabled//') 'ignore-defaults first'
        Check ($script:State.Stores.PersistentStore.Dhcp -eq 'Disabled') 'ignore meaningless persistent DHCP runtime readback'
        Check (@(Get-CoreGlobals $script:State)[0].PrefixLength -eq 128) 'native /128 IA_NA accepted with distinct RA on-link /64'
        Check (($script:Events | Where-Object { $_ -like 'QUERY:*' }).Count -eq 4) 'AAAA/PTR direct and default resolution'
        Check ($script:Calls.IndexOf('INTERFACE:/Enabled/') -lt $script:Calls.IndexOf('INTERFACE://Enabled')) 'DHCP before RA'
        Invoke-CoreRollback $script:Context
        Check ($script:State.Stores.ActiveStore.Dhcp -eq 'Disabled') 'rollback stops DHCP'
        Check ($script:State.DnsMode -eq 'Automatic' -and $script:State.Dns.Count -eq 3) 'rollback restores automatic placeholder DNS'
        Check ($script:Calls[$script:Calls.Count - 1] -eq 'INTERFACE:Disabled//') 'restore IgnoreDefaultRoutes last'
        Check (@(Get-CoreGlobals $script:State)[0].Address -eq $script:Plan.OldAddress) 'old address restored'
        Reset-Fixture
        foreach ($field in @('Advertising','Forwarding','Dhcp')) { $script:State.Stores.PersistentStore[$field] = '' }
        $script:Context.Snapshot.Baseline = Copy-Value $script:State
        Assert-CoreBaseline $script:State $script:Plan
        Invoke-CoreMigration $script:Context 2
        foreach ($field in @('Advertising','Forwarding','Dhcp')) {
            Check ($script:State.Stores.PersistentStore[$field] -ceq '') 'inherited persistent metadata remains unchanged'
        }
        foreach ($field in @('Advertising','Forwarding')) {
            $bad = Copy-Value $script:State
            $bad.Stores.ActiveStore[$field] = ''
            Reject { Assert-CoreOwned $script:Context $bad } 'must remain disabled'
            $bad = Copy-Value $script:State
            $bad.Stores.PersistentStore[$field] = 'Enabled'
            Reject { Assert-CoreOwned $script:Context $bad } 'must remain disabled'
            $bad.Stores.PersistentStore[$field] = 'Disabled'
            Reject { Assert-CoreOwned $script:Context $bad } 'persistence change'
        }
        Invoke-CoreRollback $script:Context
        Check ($script:State.Stores.PersistentStore.Advertising -ceq '' -and
            $script:State.Stores.PersistentStore.Forwarding -ceq '') 'rollback does not replace inherited native defaults'
        foreach ($values in @(@('Disabled','Disabled'),@('Enabled','Disabled'),@('Disabled','Enabled'))) {
            Reset-Fixture
            $script:State.Stores.ActiveStore.RaDns.Value = $values[0]
            $script:State.Stores.PersistentStore.RaDns.Value = $values[1]
            $script:Context.Snapshot.Baseline = Copy-Value $script:State
            Invoke-CoreMigration $script:Context 1
            Invoke-CoreRollback $script:Context
            Check ($script:State.Stores.ActiveStore.RaDns.Value -eq $values[0] -and
                $script:State.Stores.PersistentStore.RaDns.Value -eq $values[1]) 'all known Enabled/Disabled store combinations restore exactly'
        }

        foreach ($case in @('MAC','GUID','DUID','IAID','Extra','Source','IPv4','Firewall','Service','RADNS','StaticDNS')) {
            Reset-Fixture
            switch ($case) {
                MAC { $script:State.Mac = '525400AABBCC' }
                GUID { $script:State.Guid = '{00000000-0000-0000-0000-000000000000}' }
                DUID { $script:State.Registry.Duid = '00-02' }
                IAID { $script:State.Registry.Iaid = 0 }
                Extra { $script:State.Stores.ActiveStore.Addresses += (Copy-Value $script:State.Stores.ActiveStore.Addresses[0]) }
                Source { $script:State.Stores.ActiveStore.Addresses[0].PrefixOrigin = 'RouterAdvertisement' }
                IPv4 { $script:State.IPv4 = @('192.0.2.1') }
                Firewall { $script:State.Firewall[0].Enabled = 'False' }
                Service { $script:State.Services[0].State = 'Running' }
                RADNS { $script:State.Stores.PersistentStore.RaDns.Value = 'Unknown' }
                StaticDNS { $script:State.DnsMode = 'Static'; $script:State.Registry.NameServer = 'fd12:3456:789a:1::9' }
            }
            Reject { Invoke-CoreMigration $script:Context 1 } '.+'
            Check ($script:Calls.Count -eq 0) "$case rejected before mutation"
        }
        Reset-Fixture
        $script:IgnorePersistent = $true
        Reject { Invoke-CoreMigration $script:Context 1 } 'must persist'
        Check ($script:Calls.Count -eq 1) 'no RA or DHCP if persistent default protection fails'
        Reset-Fixture
        $script:UnexpectedDefault = $true
        Reject { Invoke-CoreMigration $script:Context 1 } 'UNSAFE'
        Check ($script:State.Stores.ActiveStore.RouterDiscovery -eq 'Disabled' -and $script:State.Stores.ActiveStore.Dhcp -eq 'Disabled') 'immediate default-route acquisition stop'
        Check (@($script:State.Stores.ActiveStore.Routes | Where-Object Destination -eq '::/0').Count -eq 1) 'unsafe routes not silently deleted'
        Reset-Fixture
        $script:ForeignLease = $true
        Reject { Invoke-CoreMigration $script:Context 1 } 'UNSAFE'
        $count = $script:Calls.Count
        Reject { Invoke-CoreRollback $script:Context } 'Foreign/SLAAC'
        Check ($script:Calls.Count -eq $count) 'foreign address blocks destructive rollback'
        Reset-Fixture
        $script:NoLease = $true
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Reject { Invoke-CoreMigration $script:Context 1 } 'Timed out'
        Check ($timer.Elapsed.TotalSeconds -lt 4) 'bounded lease wait'
        Invoke-CoreRollback $script:Context
        Reset-Fixture
        $script:Fail = 'RADNS:ActiveStore'
        Reject { Invoke-CoreMigration $script:Context 1 } 'Injected'
        $script:Fail = ''
        Invoke-CoreRollback $script:Context
        Check ($script:State.Stores.PersistentStore.RaDns.Value -eq 'Enabled') 'partial RA-DNS mutation restored'
        Reset-Fixture
        Invoke-CoreMigration $script:Context 1
        $script:FailNew = $true
        Reject { Invoke-CoreRollback $script:Context } 'restore failure'
        Check ($script:State.Stores.ActiveStore.IgnoreDefaultRoutes -eq 'Enabled') 'failed rollback retains default rejection'
        Reset-Fixture
        Invoke-CoreMigration $script:Context 1
        $script:State.Dns = @('fd12:3456:789a:1::9')
        $count = $script:Calls.Count
        Reject { Assert-CoreTarget $script:Context $script:State } 'Foreign DNS'
        Reject { Invoke-CoreRollback $script:Context } 'Foreign DNS'
        Check ($script:Calls.Count -eq $count) 'foreign DNS not overwritten'
        Reset-Fixture
        $script:State.DnsMode = 'Static'
        $script:State.Dns = @('fd12:3456:789a:1::10')
        $script:State.Registry.NameServer = $script:State.Dns[0]
        $script:Context.Snapshot.Baseline = Copy-Value $script:State
        Invoke-CoreMigration $script:Context 1
        Invoke-CoreRollback $script:Context
        Check ($script:State.DnsMode -eq 'Static' -and $script:State.Dns[0] -eq 'fd12:3456:789a:1::10') 'static DNS restored without resetting IPv4'
        foreach ($case in @('different','extra','junk','trailing','duplicate','delimiter','absent','raw-only')) {
            Reset-Fixture
            if ($case -eq 'raw-only') {
                $script:State.DnsMode = 'Static'
                $script:State.Dns = @('fd12:3456:789a:1::10')
                $script:State.Registry.NameServer = $script:State.Dns[0]
                $script:Context.Snapshot.Baseline = Copy-Value $script:State
                $script:State.Registry.NameServer = 'FD12:3456:789A:1::10'
            }
            else {
                Invoke-CoreMigration $script:Context 1
                switch ($case) {
                    different { $script:State.Registry.NameServer = 'fd12:3456:789a:1::9' }
                    extra { $script:State.Registry.NameServer += ',fd12:3456:789a:1::9' }
                    junk { $script:State.Registry.NameServer += ',junk' }
                    trailing { $script:State.Registry.NameServer += ',' }
                    duplicate { $script:State.Registry.NameServer += ',' + $script:Plan.RouterDns }
                    delimiter { $script:State.Registry.NameServer += ';' }
                    absent { $script:State.Registry.NameServerExists = $false; $script:State.Registry.NameServer = $null }
                }
            }
            $count = $script:Calls.Count
            Reject { Assert-CoreTarget $script:Context $script:State } 'Foreign DNS'
            Reject { Invoke-CoreRollback $script:Context } 'Foreign DNS'
            Check ($script:Calls.Count -eq $count) "$case raw registry drift rejected before any rollback write"
        }
        Reset-Fixture
        $script:State.Registry.NameServerExists = $false
        $script:State.Registry.NameServer = $null
        Reject { Assert-CoreOwned $script:Context $script:State } 'Foreign DNS'
        $script:Context.Snapshot.Baseline = Copy-Value $script:State
        Invoke-CoreMigration $script:Context 1
        Invoke-CoreRollback $script:Context
        Check ($script:State.DnsMode -eq 'Automatic' -and $script:State.Registry.NameServer -ceq '') 'journaled native reset may normalize absent registry value to empty, not static'
        Reset-Fixture
        $script:State.DnsMode = 'Static'
        $script:State.Dns = @('fd12:3456:789a:1::10','fd12:3456:789a:1::11')
        $script:State.Registry.NameServer = 'FD12:3456:789A:1::10 ; fd12:3456:789a:1::11'
        $script:Context.Snapshot.Baseline = Copy-Value $script:State
        Invoke-CoreMigration $script:Context 1
        Invoke-CoreRollback $script:Context
        Check ($script:State.Registry.NameServer -ceq 'fd12:3456:789a:1::10,fd12:3456:789a:1::11') 'journaled static restore accepts native canonical formatting only with baseline mode and exact canonical list'
        Reset-Fixture
        Invoke-CoreMigration $script:Context 1
        $script:State.Registry.NameServer = 'FD12:3456:789A:0001:0000:0000:0000:0001'
        Assert-CoreTarget $script:Context $script:State
        Check ($true) 'owned single-router DNS allows equivalent IPv6 spelling'
        $script:Context.Snapshot.Baseline.Registry.NameServer = 'fd12:3456:789a:1::9'
        Reject { Invoke-CoreRollback $script:Context } 'Foreign DNS'
        Reset-Fixture
        $script:BadPtr = $true
        Reject { Test-CoreDns $script:Plan } 'PTR'
        $script:BadPtr = $false; $script:BadTtl = $true
        Reject { Test-CoreDns $script:Plan } 'TTL'
        $script:BadTtl = $false
        Test-CoreDns $script:Plan
        Check ($true) 'cached default TTL can differ'
        Reset-Fixture
        $script:State.Stores.ActiveStore.Addresses = @()
        Reject { Assert-CoreOwned $script:Context $script:State } 'disappeared'
        Reset-Fixture
        $script:State.Stores.PersistentStore.Routes = @([ordered]@{ InterfaceIndex = 81; Destination = '0.0.0.0/0'; NextHop = '192.0.2.1'; Protocol = 'NetMgmt'; Metric = 1 })
        Reject { Assert-CoreBaseline $script:State $script:Plan } 'default route'
        Reset-Fixture
        Invoke-CoreMigration $script:Context 1
        $script:State.Profiles[0].Category = 'Private'
        Reject { Invoke-CoreRollback $script:Context } 'Foreign change in Profiles'
        Reset-Fixture
        Invoke-CoreMigration $script:Context 1
        $script:State.Stores.ActiveStore.Routes = @()
        Reject { Assert-CoreTarget $script:Context $script:State } 'no on-link route'

        Reset-Fixture
        $ra = & $script:RealRa 27 'active'
        Check ($ra.Value -eq 'Enabled') 'recognized English RA-DNS parsed'
        $script:RawRa = 'Unknown new label : enabled'
        Check ((& $script:RealRa 27 'active').Value -eq 'Unknown') 'unknown RA label fails closed'
        $script:RawRa = 'RA Based DNS Config : enabled'; $script:Culture = 'fr-FR'
        Check ((& $script:RealRa 27 'active').Value -eq 'Unknown') 'localized environment fails closed'
        $script:Culture = 'en-US'
        foreach ($store in @('active','persistent')) {
            foreach ($value in @('enabled','disabled','default')) {
                $script:RawRa = "Interface 3`r`nRA Based DNS Config (RFC 6106)     : $value`r`n"
                $parsed = & $script:RealRa 3 $store
                $expected = $(if ($value -eq 'default' -and $store -eq 'active') { 'Unknown' } else { $value })
                Check ($parsed.Value -ieq $expected -and $parsed.Raw -ceq $script:RawRa -and $parsed.Store -eq $store) 'actual RFC 6106 label and evidence retained'
                Check ($parsed.GuestRestorable -eq ($value -in @('enabled','disabled'))) 'Default is never advertised as guest-restorable'
            }
        }
        foreach ($raw in @(" RA`tBased DNS Config  ( RFC  6106 ) : disabled  `r`n", 'RA Based DNS Config : disabled')) {
            $script:RawRa = $raw
            Check ((& $script:RealRa 3 'persistent').Value -eq 'Disabled') 'flexible label spacing and legacy exact label'
        }
        foreach ($raw in @('RA Based DNS Config (RFC 9999) : enabled','RA Based DNS Config (RFC 6106) : mystery',
                "RA Based DNS Config : enabled`nRA Based DNS Config (RFC 6106) : default",
                'RA Based DNS Config (RFC 6106) : enabled unexpected')) {
            $script:RawRa = $raw
            Check ((& $script:RealRa 3 'persistent').Value -eq 'Unknown') 'ambiguous or unsupported label/value fails closed'
        }
        Reset-Fixture
        $script:State.Stores.PersistentStore.RaDns.Value = 'Default'
        $script:State.Stores.PersistentStore.RaDns.Raw = 'RA Based DNS Config (RFC 6106)     : default'
        Reject { Invoke-CoreMigration $script:Context 1 } 'explicit VmSnapshot'
        Check ($script:Calls.Count -eq 0) 'default plan refuses persistent Default before any mutation'
        $script:Plan.RollbackStrategy = 'VmSnapshot'
        $script:Plan.RecoverySnapshot = 'synthetic-cold-before-dhcpv6'
        $script:Context.Snapshot.Plan = Copy-Value $script:Plan
        $script:Context.Snapshot.Baseline = Copy-Value $script:State
        Invoke-CoreMigration $script:Context 1
        Assert-CoreTarget $script:Context $script:State
        Check ($script:Context.Snapshot.Baseline.Stores.PersistentStore.RaDns.Value -eq 'Default') 'approved snapshot strategy retains original Default in backup'
        $count = $script:Calls.Count
        Reject { Invoke-CoreRollback $script:Context } 'VM_SNAPSHOT_RESTORE_REQUIRED'
        Check ($script:Calls.Count -eq $count) 'explicit Default rollback refuses before all mutations'
        Check ((Invoke-CoreSnapshotStop $script:Context) -eq 'STOPPED') 'snapshot recovery only stops owned acquisition'
        Check ($script:Calls.Count -eq $count + 1 -and $script:State.Stores.PersistentStore.RaDns.Value -eq 'Disabled' -and
            $script:State.Registry.NameServer -eq $script:Plan.RouterDns -and
            $script:State.Stores.ActiveStore.IgnoreDefaultRoutes -eq 'Enabled') 'snapshot stop does not pretend to restore DNS/default rejection/address baseline'
        Reject { Set-CoreRaDns $script:Context 'Default' 'persistent' } 'Invalid RA-DNS operation'
        Check (@($script:Calls | Where-Object { $_ -like 'RADNS:*/default' }).Count -eq 0) 'never guesses unsupported rabaseddnsconfig=default'
        $script:State.Registry.NameServer = 'fd12:3456:789a:1::9'
        $count = $script:Calls.Count
        Reject { Invoke-CoreSnapshotStop $script:Context } 'Foreign DNS'
        Check ($script:Calls.Count -eq $count) 'snapshot stop fails closed on foreign ownership before all settings writes'
        Reset-Fixture
        $script:State.Stores.ActiveStore.Dhcp = 'Enabled'
        $count = $script:Calls.Count
        Reject { Stop-CoreAcquisition $script:Context $script:State } 'foreign DHCP'
        Check ($script:Calls.Count -eq $count) 'emergency stop does not overwrite unowned DHCP acquisition'
        Reset-Fixture
        $script:State.Stores.ActiveStore.RaDns.Value = 'Default'
        Reject { Assert-CoreIdentity $script:State $script:Plan } 'unknown/unresolved'
        foreach ($case in @('missing','empty','path','command','newline','long','array','strategy','unapproved')) {
            Reset-Fixture
            $plan = Copy-Value $script:Plan
            $plan.ExpectedMac = '52:54:00:11:22:33'
            $plan.RollbackStrategy = 'VmSnapshot'
            switch ($case) {
                empty { $plan.RecoverySnapshot = '' }
                path { $plan.RecoverySnapshot = 'C:\snapshots\before' }
                command { $plan.RecoverySnapshot = 'restore; run.exe' }
                newline { $plan.RecoverySnapshot = "before`n" }
                long { $plan.RecoverySnapshot = 'a' * 129 }
                array { $plan.RecoverySnapshot = @('a','b') }
                strategy { $plan.RollbackStrategy = 'GuessDefault' }
                unapproved { $plan.RollbackStrategy = 'Guest'; $plan.RecoverySnapshot = 'before' }
            }
            Reject { Assert-CorePlan $plan } 'RollbackStrategy|RecoverySnapshot'
        }
        Check ((Convert-CoreNativeAddress 'fe80::abcd%3' 3) -ceq 'fe80::abcd') 'native NIC-scoped link-local normalized'
        foreach ($value in @('fe80::abcd%4','fd12:3456:789a:1::44%3','fe80::abcd%nic','fe80::abcd%0','fe80::abcd%3%3')) {
            Reject { Convert-CoreNativeAddress $value 3 } 'scope'
        }
        Reset-Fixture
        $plan = Copy-Value $script:Plan
        $plan.ExpectedMac = '52:54:00:11:22:33'
        $plan.OldAddress += '%3'
        Reject { Assert-CorePlan $plan } 'Scoped'
        foreach ($path in @('\\server\share\x','C:\V6Alias\state\..\other','C:\V6Alias\state\x:stream','relative')) {
            Reject { & $script:RealPath $path } '.+'
        }
        # Pure OS gate proof: it rejects before native reads; never impersonate CORP-44.
        $originalName = $env:COMPUTERNAME
        try {
            $env:COMPUTERNAME = 'OFFLINE-TEST'
            Reject { & $script:RealGuard } 'CORP-44|Windows PowerShell'
        }
        finally { $env:COMPUTERNAME = $originalName }
    }
    function Invoke-RegistryCases {
        Reset-Fixture
        $script:RegistryDuid = [byte[]]@(0,1,0,1,17,34,51,68,82,84,0,17,34,51)
        $script:RegistryType = [Microsoft.Win32.RegistryValueKind]::Binary
        $script:RegistryIaidType = [Microsoft.Win32.RegistryValueKind]::DWord
        $script:RegistryNameServer = ''
        $script:RegistryNameServerExists = $true
        $key = [pscustomobject]@{}
        $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value {
            param($Name)
            switch ($Name) {
                Dhcpv6DUID { $script:RegistryType }
                Dhcpv6Iaid { $script:RegistryIaidType }
                NameServer { [Microsoft.Win32.RegistryValueKind]::String }
                default { throw "Unexpected registry name $Name" }
            }
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
            param($Name, $Default)
            switch ($Name) {
                Dhcpv6DUID { ,$script:RegistryDuid }
                Dhcpv6Iaid { [int32]-1 }
                NameServer { $script:RegistryNameServer }
                default { throw "Unexpected registry name $Name" }
            }
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value {
            @('Dhcpv6DUID','Dhcpv6Iaid')
            if ($script:RegistryNameServerExists) { 'NameServer' }
        }
        function Get-Item {
            param($Path)
            Check ($Path -like 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters*') 'only IPv6 native identity registry read'
            $key
        }
        $actual = & $script:RealRegistry $script:Plan.ExpectedInterfaceGuid
        Check ($actual.Iaid -eq [uint32]::MaxValue -and $actual.Duid -eq $script:Plan.ExpectedDuid) 'native signed DWORD converts losslessly to unsigned IAID'
        Check ($actual.NameServer -ceq '' -and $actual.NameServerExists) 'empty static policy explicitly retained independently of effective DNS'
        $script:RegistryNameServerExists = $false
        $actual = & $script:RealRegistry $script:Plan.ExpectedInterfaceGuid
        Check ($null -eq $actual.NameServer -and -not $actual.NameServerExists) 'absent registry value is distinct from empty string'
        $script:RegistryNameServerExists = $true
        $script:RegistryType = [Microsoft.Win32.RegistryValueKind]::String
        Reject { & $script:RealRegistry $script:Plan.ExpectedInterfaceGuid } 'REG_BINARY'
        $script:RegistryType = [Microsoft.Win32.RegistryValueKind]::Binary
        $script:RegistryDuid = [byte[]]@(1)
        Reject { & $script:RealRegistry $script:Plan.ExpectedInterfaceGuid } 'DUID bytes'
        $script:RegistryDuid = [byte[]]@(0,1)
        $script:RegistryIaidType = [Microsoft.Win32.RegistryValueKind]::String
        Reject { & $script:RealRegistry $script:Plan.ExpectedInterfaceGuid } 'REG_DWORD'
    }
    function Invoke-NativeStateCases {
        Reset-Fixture
        function Get-CoreGuard { Copy-Value $script:State.Identity }
        function Get-CoreRegistry { param($Guid) Copy-Value $script:State.Registry }
        function Get-NetAdapter {
            param([switch]$IncludeHidden, $ErrorAction)
            [pscustomobject]@{ HardwareInterface = $true; Status = 'Up'; ifIndex = 27; Name = 'Ethernet';
                InterfaceGuid = $script:Plan.ExpectedInterfaceGuid; MacAddress = '52-54-00-11-22-33' }
        }
        function Get-NetAdapterBinding {
            param($Name, $ComponentID, $ErrorAction)
            [pscustomobject]@{ Enabled = ($ComponentID -eq 'ms_tcpip6') }
        }
        function Get-NetIPInterface {
            param($InterfaceIndex, $AddressFamily, $PolicyStore, $ErrorAction)
            Check ($InterfaceIndex -eq 27 -and $AddressFamily -eq 'IPv6') 'native interface queries remain adapter-scoped'
            $value = Copy-Value $script:State.Stores[$PolicyStore]
            $value.InterfaceIndex = $(if ($PolicyStore -eq 'PersistentStore') { 0 } else { 27 })
            [pscustomobject]$value
        }
        function Get-CoreAddressObjects {
            param($Index, $Family, $Store)
            if ($Family -eq 'IPv4') { return }
            foreach ($a in $script:State.Stores[$Store].Addresses) {
                [pscustomobject]@{ IPAddress = $a.Address; PrefixLength = $a.PrefixLength; PrefixOrigin = $a.PrefixOrigin;
                    SuffixOrigin = $a.SuffixOrigin; SkipAsSource = $a.SkipAsSource; AddressState = $a.State }
            }
            [pscustomobject]@{ IPAddress = 'fe80::abcd%27'; PrefixLength = 64; PrefixOrigin = 'WellKnown';
                SuffixOrigin = 'Link'; SkipAsSource = $false; AddressState = 'Preferred' }
        }
        function Get-NetRoute { param($PolicyStore, [switch]$IncludeAllCompartments, $ErrorAction) }
        function Get-NetFirewallProfile {
            param($PolicyStore, $ErrorAction)
            $script:State.Firewall | ForEach-Object { [pscustomobject]$_ }
        }
        function Get-CimInstance {
            param($ClassName, $Filter, $ErrorAction)
            Check ($ClassName -eq 'Win32_Service') 'native fixture only supplies management service state'
            $script:State.Services | ForEach-Object { [pscustomobject]$_ }
        }
        function Get-NetConnectionProfile {
            param($InterfaceIndex, $ErrorAction)
            $script:State.Profiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; NetworkCategory = $_.Category } }
        }
        function Get-CoreRaDns {
            param($Index, $Store)
            $script:RawRa = 'RA Based DNS Config (RFC 6106)     : ' + $(if ($Store -eq 'persistent') { 'default' } else { 'enabled' })
            & $script:RealRa $Index $Store
        }
        function Get-CoreState { & $script:RealState }
        $inspect = & $script:RealMain @{ Action = 'Inspect' } $null | ConvertFrom-Json -AsHashtable
        Check ($inspect.Status -eq 'READ_ONLY' -and $script:Calls.Count -eq 0) 'real state reader and Inspect execute only mocked native reads'
        Check ($inspect.State.Index -eq 27 -and
            $inspect.State.Stores.PersistentStore.RaDns.Value -eq 'Default' -and
            -not $inspect.State.Stores.PersistentStore.RaDns.GuestRestorable) 'persistent native index zero does not replace NIC identity and Default metadata survives Inspect'
        Check (@($inspect.State.Stores.ActiveStore.Addresses | Where-Object Address -eq 'fe80::abcd').Count -eq 1) 'real state reader normalizes matching native link-local scope'
        Check ($inspect.State.DnsEvidence.Consistent -and $inspect.State.DnsMode -eq 'Automatic') 'automatic Windows placeholders are not treated as static'
        $script:State.Registry.NameServer = 'fd12:3456:789a:1::9,junk'
        $inspect = & $script:RealMain @{ Action = 'Inspect' } $null | ConvertFrom-Json -AsHashtable
        Check ($inspect.Status -eq 'READ_ONLY' -and -not $inspect.State.DnsEvidence.Consistent -and
            $inspect.State.Registry.NameServer -ceq 'fd12:3456:789a:1::9,junk') 'Inspect reports raw registry drift without pretending it is safe or failing the read'
        Reject { Assert-CoreIdentity $inspect.State $script:Plan } 'Foreign DNS'
    }
    function Invoke-FileCases {
        Reset-Fixture
        $directory = Join-Path $script:Root ('dhcpv6-offline-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $directory -ItemType Directory
        try {
            # Only local synthetic file I/O; bypass guest path restriction for this one test directory.
            function Assert-CorePath { param($Path, [switch]$State) Check ($Path.StartsWith($directory)) 'offline file confinement' }
            function Assert-CorePrivateDirectory { param($Path) Check ($Path -eq $directory) 'offline snapshot parent confinement' }
            $path = Join-Path $directory 'snapshot.json'
            & $script:RealWriteFile $path $script:Context.Snapshot
            Reject { & $script:RealWriteFile $path @{} } 'exists'
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $script:Context.Directory = $directory
            $script:Context.Digest = $digest
            & $script:RealJournal $script:Context 'Snapshot' 'PREPARED'
            & $script:RealJournal $script:Context 'IgnoreDefaults' 'BEGIN'
            $journalPath = Join-Path $directory 'journal.jsonl'
            $journalDigest = (Get-FileHash -LiteralPath $journalPath -Algorithm SHA256).Hash
            $loaded = & $script:RealReadSnapshot $path $digest $journalDigest
            Check ($loaded.Started.Contains('IgnoreDefaults')) 'persisted journal supports crash recovery'
            Check ($loaded.Snapshot.Baseline.DnsMode -eq 'Automatic') 'baseline DNS mode persisted'
            Reject { & $script:RealReadSnapshot $path ('0' * 64) $journalDigest } 'checksum'
            Reject { & $script:RealReadSnapshot $path $digest ('0' * 64) } 'Journal checksum'
            [IO.File]::AppendAllText($path, ' ')
            Reject { & $script:RealReadSnapshot $path $digest $journalDigest } 'checksum'
        }
        finally { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
    function Invoke-WhatIfCase {
        Reset-Fixture
        $directory = Join-Path $script:Root ('dhcpv6-whatif-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $directory -ItemType Directory
        try {
            $plan = Copy-Value $script:Plan
            $plan.ExpectedMac = '52:54:00:11:22:33'
            $path = Join-Path $directory 'plan.json'
            & $script:RealWriteFile $path $plan
            function Assert-CorePath { param($Path, [switch]$State) }
            function New-CorePrivateDirectory { throw 'WhatIf attempted directory creation' }
            function Run-Main {
                [CmdletBinding(SupportsShouldProcess)]
                param($Options)
                & $script:RealMain $Options $PSCmdlet
            }
            Run-Main -Options @{ Action = 'Apply'; PlanPath = $path; StateDirectory = (Join-Path $directory 'unused');
                LeaseTimeoutSeconds = 1; RollbackOnFailure = $false } -WhatIf
            Check ($script:Calls.Count -eq 0 -and -not (Test-Path (Join-Path $directory 'unused'))) 'WhatIf has no mutation/file effects'
        }
        finally { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
    function Invoke-MainCases {
        $directory = Join-Path $script:Root ('dhcpv6-main-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $directory -ItemType Directory
        try {
            function Assert-CorePath { param($Path, [switch]$State) Check ($Path.StartsWith($directory)) 'main test file confinement' }
            function Assert-CorePrivateDirectory { param($Path) Check ($Path.StartsWith($directory)) 'main test private parent confinement' }
            function New-CorePrivateDirectory { param($Path) $null = New-Item -Path $Path -ItemType Directory }
            function Add-CoreJournal {
                param($Context, $Step, $Status, $Detail = '')
                $script:Context = $Context
                $script:Events.Add("JOURNAL:$Step/$Status")
                if ($Step -eq 'Apply' -and $Status -eq 'FAILED') {
                    $script:FailureSeen = $true
                    if ($script:JournalFault -eq 'once') {
                        $script:JournalFault = ''
                        throw "Injected journal failure`nONCE"
                    }
                    $script:JournalFaultActive = $true
                }
                if ($script:JournalFaultActive -and ($script:JournalFault -eq 'always' -or
                    ($script:JournalFault -eq 'rollback-log' -and $Step -eq 'Rollback' -and $Status -eq 'FAILED'))) {
                    throw "Injected journal failure`nPERSISTENT"
                }
                & $script:RealJournal $Context $Step $Status $Detail
            }
            function Get-FileHash {
                param($LiteralPath, $Algorithm = 'SHA256', $ErrorAction)
                if ($script:HashFault -and $script:FailureSeen -and (Split-Path $LiteralPath -Leaf) -eq 'journal.jsonl') { throw 'Injected hash read failure' }
                Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm -ErrorAction Stop
            }
            function Write-CoreFile {
                param($Path, $Value)
                if ($script:ReportFault -and (Split-Path $Path -Leaf) -like 'failure-*') { throw 'Injected failure report write failure' }
                & $script:RealWriteFile $Path $Value
            }
            $approval = [pscustomobject]@{}
            $approval | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param($Target, $Operation) $true }
            foreach ($case in @('success','auto-rollback','failed-rollback')) {
                Reset-Fixture
                $plan = Copy-Value $script:Plan
                $plan.ExpectedMac = '52:54:00:11:22:33'
                $planPath = Join-Path $directory "$case-plan.json"
                & $script:RealWriteFile $planPath $plan
                $run = Join-Path $directory $case
                $options = @{ Action = 'Apply'; PlanPath = $planPath; StateDirectory = $run;
                    LeaseTimeoutSeconds = 1; RollbackOnFailure = $true }
                if ($case -eq 'success') {
                    $outputs = @(& $script:RealMain $options $approval)
                    $report = $outputs[-1] | ConvertFrom-Json -AsHashtable
                    Check ($report.Status -eq 'VERIFIED') 'main success returns verified report'
                    Check ($report.JournalSha256 -eq (Get-FileHash -LiteralPath (Join-Path $run 'journal.jsonl')).Hash) 'main reports current journal hash'
                    Check (@(Get-ChildItem -LiteralPath $run -Filter 'report-*.json').Count -eq 1) 'main persists report'
                    $snapshotPath = Join-Path $run 'snapshot.json'
                    $verify = @{ Action = 'Verify'; SnapshotPath = $snapshotPath; ExpectedSnapshotSha256 = $report.SnapshotSha256;
                        ExpectedJournalSha256 = $report.JournalSha256; RollbackOnFailure = $false }
                    $count = $script:Calls.Count
                    $verified = @(& $script:RealMain $verify $approval)[-1] | ConvertFrom-Json -AsHashtable
                    Check ($verified.Status -eq 'VERIFIED' -and $script:Calls.Count -eq $count) 'Verify has no configuration writes'
                    Check (@(Get-ChildItem -LiteralPath $run -Filter 'report-*.json').Count -eq 1) 'Verify does not write report files'
                    $originalDns = $script:State.Registry.NameServer
                    $script:State.Registry.NameServer = 'fd12:3456:789a:1::9'
                    $eventsBefore = $script:Events.Count
                    Reject { & $script:RealMain $verify $approval } 'Foreign DNS'
                    $verify.Action = 'Rollback'
                    Reject { & $script:RealMain $verify $approval } 'Foreign DNS'
                    $newEvents = @($script:Events.GetRange($eventsBefore, $script:Events.Count - $eventsBefore))
                    Check ($script:Calls.Count -eq $count -and
                        @($newEvents | Where-Object { $_ -like 'QUERY:*' -or $_ -like 'JOURNAL:*' }).Count -eq 0) 'actual Main Verify/Rollback reject inactive foreign registry DNS before queries, journals or network writes'
                    $script:State.Registry.NameServer = $originalDns
                    $verify.Action = 'Rollback'
                    $restored = @(& $script:RealMain $verify $approval)[-1] | ConvertFrom-Json -AsHashtable
                    Check ($restored.Status -eq 'VERIFIED' -and $script:State.DnsMode -eq 'Automatic') 'main checksummed rollback restores snapshot'
                    $count = $script:Calls.Count
                    Reject { & $script:RealMain $verify $approval } 'Journal checksum'
                    Check ($script:Calls.Count -eq $count) 'stale journal digest refuses all configuration writes'
                }
                else {
                    $script:BadPtr = $true
                    $script:FailNew = $case -eq 'failed-rollback'
                    Reject { & $script:RealMain $options $approval } 'PTR'
                    $entries = @(Get-Content -LiteralPath (Join-Path $run 'journal.jsonl') | ConvertFrom-Json -AsHashtable)
                    Check (@($entries | Where-Object { $_.Step -eq 'Apply' -and $_.Status -eq 'FAILED' }).Count -eq 1) 'original failure durable'
                    Check (@(Get-ChildItem -LiteralPath $run -Filter 'report-*.json').Count -eq 0) 'failure never emits a success report'
                    if ($case -eq 'auto-rollback') {
                        Check ($entries[-1].Step -eq 'Rollback' -and $entries[-1].Status -eq 'VERIFIED') 'approved automatic rollback completes yet original call fails'
                    }
                    else {
                        Check ($entries[-1].Step -eq 'Rollback' -and $entries[-1].Status -eq 'FAILED') 'failed rollback durable and explicit'
                        Check ($script:State.Stores.ActiveStore.IgnoreDefaultRoutes -eq 'Enabled') 'failed automatic rollback keeps default rejection'
                    }
                }
            }
            foreach ($case in @('snapshot-success','snapshot-failure','snapshot-disk-failure','journal-once','journal-always','journal-rollback-log','journal-all-io')) {
                Reset-Fixture
                if ($case -like 'snapshot-*') {
                    $script:Plan.RollbackStrategy = 'VmSnapshot'
                    $script:Plan.RecoverySnapshot = 'synthetic-cold-proof-20260925'
                    $script:State.Stores.PersistentStore.RaDns.Value = 'Default'
                    $script:State.Stores.PersistentStore.RaDns.Raw = 'RA Based DNS Config (RFC 6106)     : default'
                }
                $plan = Copy-Value $script:Plan
                $plan.ExpectedMac = '52:54:00:11:22:33'
                $planPath = Join-Path $directory "$case-plan.json"
                & $script:RealWriteFile $planPath $plan
                $run = Join-Path $directory $case
                $options = @{ Action = 'Apply'; PlanPath = $planPath; StateDirectory = $run;
                    LeaseTimeoutSeconds = 1; RollbackOnFailure = $true }
                if ($case -eq 'snapshot-success') {
                    $report = @(& $script:RealMain $options $approval)[-1] | ConvertFrom-Json -AsHashtable
                    Check ($report.Status -eq 'VERIFIED' -and $script:State.Stores.PersistentStore.RaDns.Value -eq 'Disabled' -and
                        $report.RollbackStrategy -eq 'VmSnapshot' -and $report.RecoverySnapshot -eq $plan.RecoverySnapshot) 'approved Default baseline reaches verifiable Disabled target with explicit recovery metadata'
                    $verify = @{ Action = 'Verify'; SnapshotPath = (Join-Path $run 'snapshot.json'); ExpectedSnapshotSha256 = $report.SnapshotSha256;
                        ExpectedJournalSha256 = $report.JournalSha256; RollbackOnFailure = $false }
                    $count = $script:Calls.Count
                    $verified = @(& $script:RealMain $verify $approval)[-1] | ConvertFrom-Json -AsHashtable
                    Check ($verified.Status -eq 'VERIFIED' -and $script:Calls.Count -eq $count) 'snapshot strategy Verify is read-only and uses persisted original Default'
                    $snapshot = Get-Content -LiteralPath $verify.SnapshotPath -Raw | ConvertFrom-Json -AsHashtable
                    Check ($snapshot.Baseline.Stores.PersistentStore.RaDns.Value -eq 'Default' -and
                        $snapshot.Plan.RecoverySnapshot -eq $plan.RecoverySnapshot) 'Default and approved opaque snapshot reference durably recorded'
                    $verify.Action = 'Rollback'
                    $output = [Collections.Generic.List[string]]::new()
                    $caught = $null
                    try { & $script:RealMain $verify $approval | ForEach-Object { $output.Add($_) } } catch { $caught = $_ }
                    $failureReport = $output[-1] | ConvertFrom-Json -AsHashtable
                    Check ($caught.Exception.Message -match 'VM_SNAPSHOT_RESTORE_REQUIRED' -and
                        $failureReport.Recovery.Code -eq 'VM_SNAPSHOT_RESTORE_REQUIRED' -and
                        $failureReport.Recovery.RecoverySnapshot -eq $plan.RecoverySnapshot) 'explicit Rollback fails with structured approved snapshot requirement'
                    Check ($script:Calls.Count -eq $count -and
                        (Get-FileHash -LiteralPath (Join-Path $run 'journal.jsonl')).Hash -eq $report.JournalSha256 -and
                        @(Get-ChildItem -LiteralPath $run -Filter 'failure-*.json').Count -eq 0) 'snapshot manual Rollback mutates no settings or journal/report files'
                    continue
                }
                $script:BadPtr = $true
                switch ($case) {
                    journal-once { $script:JournalFault = 'once' }
                    journal-always { $script:JournalFault = 'always' }
                    journal-rollback-log { $script:JournalFault = 'rollback-log'; $script:FailNew = $true }
                    journal-all-io { $script:JournalFault = 'always'; $script:HashFault = $true; $script:ReportFault = $true }
                    snapshot-disk-failure { $script:JournalFault = 'always' }
                }
                $output = [Collections.Generic.List[string]]::new()
                $caught = $null
                try { & $script:RealMain $options $approval | ForEach-Object { $output.Add($_) } } catch { $caught = $_ }
                $failureReport = $output[-1] | ConvertFrom-Json -AsHashtable
                Check ($caught.Exception.Message -ceq 'PTR answer/owner mismatch.' -and $caught.Exception -is [InvalidOperationException]) "$case retains original thrown failure, not logging/recovery errors"
                Check ($failureReport.Status -eq 'FAILED' -and $failureReport.Error -ceq $caught.Exception.Message) "$case emits structured stdout original error even when disk recovery fails"
                Check (@($failureReport.SecondaryErrors).Count -le 8 -and
                    @($failureReport.SecondaryErrors | Where-Object { $_.Error -match '[\x00-\x1f\x7f]' -or $_.Error.Length -gt 512 }).Count -eq 0) 'secondary errors are bounded and sanitized'
                Check ($script:Events.Contains('WRITE:INTERFACE:/Enabled/') -and $script:Events.Contains('WRITE:INTERFACE://Enabled')) 'injected failure occurs after DHCP and RA actually enabled in simulated state'
                Check (@(Get-ChildItem -LiteralPath $run -Filter 'report-*.json').Count -eq 0) 'failure path never persists a success report'
                if ($case -eq 'journal-all-io') {
                    Check ($null -eq $failureReport.JournalSha256 -and
                        @($failureReport.SecondaryErrors.Stage).Contains('JournalHash') -and
                        @($failureReport.SecondaryErrors.Stage).Contains('FailureReport')) 'hash and report faults are independent secondary errors with stdout fallback'
                }
                else {
                    $failedFiles = @(Get-ChildItem -LiteralPath $run -Filter 'failure-*.json')
                    Check ($failedFiles.Count -eq 1) 'failed report durably saved separately when storage permits'
                    $persisted = Get-Content -LiteralPath $failedFiles[0].FullName -Raw | ConvertFrom-Json -AsHashtable
                    Check ($persisted.Error -ceq $failureReport.Error -and $persisted.Recovery.Code -eq $failureReport.Recovery.Code) 'persisted failure preserves original and recovery outcome'
                }
                if ($case -eq 'journal-once') {
                    Check ($failureReport.Rollback -eq 'VERIFIED' -and $failureReport.Recovery.Code -eq 'GUEST_ROLLBACK_VERIFIED' -and
                        $script:State.Stores.ActiveStore.Dhcp -eq 'Disabled') 'one-shot FAILED append fault does not prevent independently journaled guest rollback'
                    Check (@($failureReport.SecondaryErrors.Stage).Contains('FailureJournal') -and
                        $script:Context.Started.Contains('RollbackStop') -and $script:Context.Started.Contains('RollbackDns')) 'rollback BEGIN durability succeeds after transient logging fault'
                }
                elseif ($case -eq 'snapshot-failure') {
                    Check ($failureReport.Rollback -eq 'VM_SNAPSHOT_RESTORE_REQUIRED' -and $failureReport.Recovery.AcquisitionStop -eq 'STOPPED' -and
                        $failureReport.Recovery.RecoverySnapshot -eq $plan.RecoverySnapshot) 'snapshot error never claims guest rollback VERIFIED'
                    Check ($script:State.Stores.ActiveStore.Dhcp -eq 'Disabled' -and $script:State.Stores.ActiveStore.RouterDiscovery -eq 'Disabled' -and
                        $script:State.Stores.PersistentStore.RaDns.Value -eq 'Disabled' -and $script:State.DnsMode -eq 'Static' -and
                        -not $script:Context.Started.Contains('RollbackDns') -and -not $script:Context.Started.Contains('RollbackOld')) 'snapshot failure only stops acquisition; original Default requires external restore'
                }
                elseif ($case -eq 'journal-rollback-log') {
                    Check ($failureReport.Recovery.Code -eq 'RECOVERY_FAILED' -and
                        @($failureReport.SecondaryErrors.Stage).Contains('Recovery') -and
                        @($failureReport.SecondaryErrors.Stage).Contains('RecoveryFailureJournal')) 'rollback failure and its logging failure both retain original error'
                }
                else {
                    $failureIndex = $script:Events.IndexOf('JOURNAL:Apply/FAILED')
                    $later = @($script:Events.GetRange($failureIndex + 1, $script:Events.Count - $failureIndex - 1))
                    Check (@($later | Where-Object { $_ -like 'WRITE:*' }).Count -eq 0 -and
                        -not $script:Context.Started.Contains('RollbackStop')) 'persistent journal failure permits NO unjournaled recovery network mutation'
                    Check ($script:State.Stores.ActiveStore.Dhcp -eq 'Enabled' -and $script:State.Stores.ActiveStore.RouterDiscovery -eq 'Enabled' -and
                        $failureReport.Recovery.Instruction -match 'Acquisition may remain enabled') 'failed durable BEGIN explicitly reports acquisition is not proven stopped'
                    if ($case -eq 'snapshot-disk-failure') {
                        Check ($failureReport.Recovery.Code -eq 'VM_SNAPSHOT_RESTORE_REQUIRED' -and
                            $failureReport.Recovery.AcquisitionStop -eq 'FAILED_OR_UNCONFIRMED') 'snapshot disk failure retains external recovery requirement'
                    }
                    else { Check ($failureReport.Recovery.Code -eq 'RECOVERY_FAILED') 'guest disk failure explicitly requires manual intervention' }
                }
            }
        }
        finally { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
    function Invoke-All {
        Invoke-TestCases
        Invoke-RegistryCases
        Invoke-NativeStateCases
        Invoke-FileCases
        Invoke-WhatIfCase
        Invoke-MainCases
        $processDefinition = @($Definitions | Where-Object Name -eq 'Invoke-CoreProcess')[0].Extent.Text
        Check ($processDefinition -match 'WaitForExit\(15000\)' -and $processDefinition -match '\.Kill\(\)' -and
            $processDefinition -match 'UseShellExecute = \$false' -and $processDefinition -match 'ArgumentList.Add') 'bounded native commands use fixed executable/argument vector and owned process'
        $calls = @($Definitions | ForEach-Object { $_.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) } |
            ForEach-Object { $_.GetCommandName() })
        foreach ($forbidden in @('Set-Service','Stop-Service','Set-NetFirewallProfile','Disable-NetAdapterBinding','Set-ItemProperty','Invoke-Expression','Invoke-Command','ssh')) {
            Check ($calls -notcontains $forbidden) "no forbidden production command $forbidden"
        }
        "PASS: $script:Checks offline assertions; AST-imported helpers and mocked networking only."
    }
    Export-ModuleMember -Function Invoke-All
} -ArgumentList $definitions, $PSScriptRoot
try { & $module { Invoke-All } }
finally { Remove-Module $module -Force }
