#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WhatIfPreference = $false
$ConfirmPreference = 'None'
$script:Count = 0
$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:VMs = @('scout-v6alias', 'scout-admin', 'scout-corp-client', 'scout-pfsense', 'scout-lab-client')
$script:Entry = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Demo.ps1'
$script:Module = Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'LiveDemo.psm1') -Force -PassThru
$script:Clock = [System.Diagnostics.Stopwatch]::StartNew()

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected '$Expected', got '$Actual'." }
}

function Assert-Throws([scriptblock] $Body, [string] $Pattern = '.') {
    $caught = $null
    try { & $Body | Out-Null } catch { $caught = $_ }
    if ($null -eq $caught) { throw 'Expected failure, but operation succeeded.' }
    if ($caught.Exception.Message -notmatch $Pattern) { throw "Unexpected error: $caught" }
}

function New-Response {
    param(
        [string] $Action = 'status',
        [string] $State = 'shut off',
        [hashtable] $Overrides = @{},
        [string[]] $Remove = @()
    )
    $states = @{}
    foreach ($name in $script:VMs) { $states[$name] = $State }
    $value = @{
        mode = 'routed_demo'; action = $Action; states = $states
        isolation = 'verified'; other_vms_off = $true; changed = @()
    }
    foreach ($key in $Overrides.get_Keys()) { $value[$key] = $Overrides[$key] }
    foreach ($key in $Remove) { $value.Remove($key) }
    ConvertTo-Json $value -Depth 5 -Compress
}

function Read-Response([string] $Json, [string] $Action = 'status') {
    & $script:Module {
        param($Json, $Action)
        ConvertFrom-DemoHostResponse $Json $Action
    } $Json $Action
}

function Reset-State {
    $states = @{}
    foreach ($name in $script:VMs) { $states[$name] = 'shut off' }
    $script:State = [pscustomobject] @{
        States = $states
        Actions = @(); FailAction = ''; Overrides = @{}; ReadCalls = 0; NativeCalls = 0
        Queue = [System.Collections.Generic.Queue[string]]::new()
        Clock = $script:Clock
    }
    & $script:Module { param($State) $script:DemoTest = $State } $script:State
}

function Test-Case([string] $CaseName, [scriptblock] $Body) {
    try {
        Reset-State
        if ($script:Clock.Elapsed.TotalSeconds -gt 40) { throw 'Offline test deadline exceeded.' }
        & $Body | Out-Null
        Assert-Equal $script:State.NativeCalls 0
        $schema = & $script:Module { (Get-Item Function:ConvertFrom-DemoHostResponse).ScriptBlock }
        if (-not [object]::ReferenceEquals($schema, $script:Schema)) { throw 'Real schema validator was replaced.' }
        $script:Count++
        Write-Host "PASS: $CaseName"
    }
    catch {
        $script:Failures.Add("${CaseName}: $_")
        Write-Host "FAIL: ${CaseName}: $_"
    }
}

try {
    $script:Schema = & $script:Module { (Get-Item Function:ConvertFrom-DemoHostResponse).ScriptBlock }
    # All injections are in-memory. No test opens SSH, a console, or interactive input.
    & $script:Module {
        function script:Get-DemoSshPath {
            $script:DemoTest.NativeCalls++
            throw 'OFFLINE GUARD: native SSH lookup is forbidden.'
        }
        function script:Invoke-DemoHost {
            param([string] $Action)
            $script:DemoTest.Actions += $Action
            if ($Action -ceq $script:DemoTest.FailAction) { throw "Mock $Action failure." }
            $states = $script:DemoTest.States.Clone()
            $changed = @()
            if ($Action -cne 'status') {
                $wanted = if ($Action -ceq 'start') { 'running' } else { 'shut off' }
                foreach ($name in $script:DemoVMs) {
                    if ($states[$name] -cne $wanted) { $changed += $name }
                    $states[$name] = $wanted
                }
            }
            $json = if ($script:DemoTest.Overrides.ContainsKey($Action)) {
                $script:DemoTest.Overrides[$Action]
            }
            else {
                ConvertTo-Json -Depth 5 -Compress -InputObject @{
                    mode = 'routed_demo'; action = $Action; states = $states
                    isolation = 'verified'; other_vms_off = $true; changed = $changed
                }
            }
            $response = ConvertFrom-DemoHostResponse $json $Action
            $script:DemoTest.States = $response.states
            $response
        }
        function script:Invoke-DemoConsole {
            $script:DemoTest.Actions += 'console'
            foreach ($state in $script:DemoTest.States.Values) {
                if ($state -cne 'running') { throw 'Console requires all five guests running.' }
            }
            if ($script:DemoTest.FailAction -ceq 'console') { throw 'Mock console failure.' }
        }
        function script:Read-Host {
            param([string] $Prompt)
            $script:DemoTest.ReadCalls++
            if ($script:DemoTest.ReadCalls -gt 8 -or $script:DemoTest.Clock.Elapsed.TotalSeconds -gt 40 -or
                $script:DemoTest.Queue.Count -eq 0) {
                throw 'OFFLINE GUARD: unexpected prompt or menu did not exit.'
            }
            $script:DemoTest.Queue.Dequeue()
        }
    }

    Test-Case 'Open starts all five and then attaches console' {
        Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status,start,console'
    }
    Test-Case 'Open starts missing guests from mixed state' {
        $script:State.States['scout-admin'] = 'running'
        Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status,start,console'
    }
    Test-Case 'Open reuses all five running guests' {
        foreach ($name in $script:VMs) { $script:State.States[$name] = 'running' }
        Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status,console'
    }
    foreach ($name in @('scout-pfsense', 'scout-lab-client')) {
        Test-Case "Open starts missing $name even when corp guests are running" {
            foreach ($vm in $script:VMs) { $script:State.States[$vm] = 'running' }
            $script:State.States[$name] = 'shut off'
            Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null
            Assert-Equal ($script:State.Actions -join ',') 'status,start,console'
        }
        Test-Case "Open refuses unconfirmed $name startup" {
            $states = @{}
            foreach ($vm in $script:VMs) { $states[$vm] = 'running' }
            $states[$name] = 'shut off'
            $script:State.Overrides.start = New-Response start running @{ states = $states }
            Assert-Throws { Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null } 'not confirmed'
            Assert-Equal ($script:State.Actions -join ',') 'status,start'
        }
    }
    Test-Case 'Status is read-only' {
        Invoke-V6AliasLiveDemo -Action Status -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status'
        Assert-Equal $script:State.States['scout-admin'] 'shut off'
    }
    Test-Case 'Stop uses only clean controller action' {
        foreach ($name in $script:VMs) { $script:State.States[$name] = 'running' }
        Invoke-V6AliasLiveDemo -Action Stop -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'stop'
        foreach ($value in $script:State.States.Values) { Assert-Equal $value 'shut off' }
    }
    foreach ($action in @('Menu', 'Open', 'Status', 'Stop', 'Help')) {
        Test-Case "$action WhatIf does not connect or prompt even with Confirm" {
            Invoke-V6AliasLiveDemo -Action $action -WhatIf -Confirm 6>$null
            Assert-Equal $script:State.Actions.Count 0
            Assert-Equal $script:State.ReadCalls 0
        }
    }
    Test-Case 'Menu Open then Exit returns after mocked console detach' {
        $script:State.Queue.Enqueue('1')
        $script:State.Queue.Enqueue('0')
        Invoke-V6AliasLiveDemo -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status,start,console'
        Assert-Equal $script:State.ReadCalls 2
    }
    Test-Case 'Menu invalid input Help Status Stop Exit are bounded' {
        foreach ($inputValue in @('wrong', '4', '2', '3', '0')) { $script:State.Queue.Enqueue($inputValue) }
        Invoke-V6AliasLiveDemo -Confirm:$false 6>$null
        Assert-Equal ($script:State.Actions -join ',') 'status,stop'
        Assert-Equal $script:State.ReadCalls 5
    }
    foreach ($failure in @('status', 'start', 'console')) {
        Test-Case "Open propagates $failure failure without success fallback" {
            $script:State.FailAction = $failure
            Assert-Throws { Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null } "Mock $failure failure"
            if ($failure -cne 'console' -and $script:State.Actions -contains 'console') {
                throw 'Opened console after failed preflight or startup.'
            }
        }
    }
    Test-Case 'Open refuses unconfirmed startup' {
        $script:State.Overrides.start = New-Response start 'shut off'
        Assert-Throws { Invoke-V6AliasLiveDemo -Action Open -Confirm:$false 6>$null } 'not confirmed'
        Assert-Equal ($script:State.Actions -join ',') 'status,start'
    }
    Test-Case 'Stop failure remains an error' {
        $script:State.Overrides.stop = New-Response stop 'running'
        Assert-Throws { Invoke-V6AliasLiveDemo -Action Stop -Confirm:$false 6>$null } 'not confirmed'
    }
    foreach ($action in @('status', 'start', 'stop')) {
        Test-Case "Valid $action schema" {
            $state = if ($action -ceq 'start') { 'running' } else { 'shut off' }
            $result = Read-Response (New-Response $action $state) $action
            Assert-Equal $result.action $action
        }
    }
    Test-Case 'Valid start changed array contains approved names only' {
        $response = Read-Response (New-Response start running @{ changed = @('scout-admin', 'scout-pfsense', 'scout-lab-client') }) start
        Assert-Equal $response.changed.Count 3
    }
    Test-Case 'Exact five VM allowlist and unchanged public action API' {
        $names = & $script:Module { $script:DemoVMs }
        Assert-Equal ($names -join ',') ($script:VMs -join ',')
        $command = Get-Command Invoke-V6AliasLiveDemo
        Assert-Equal $command.Parameters.ContainsKey('Mode') $false
        $validation = $command.Parameters['Action'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        Assert-Equal ($validation.ValidValues -join ',') 'Menu,Open,Status,Stop,Help'
    }
    foreach ($action in @('start', 'stop')) {
        Test-Case "$action accepts changed list containing exactly the five approved guests" {
            $state = if ($action -ceq 'start') { 'running' } else { 'shut off' }
            $response = Read-Response (New-Response $action $state @{ changed = $script:VMs }) $action
            Assert-Equal $response.changed.Count $script:VMs.Count
        }
        foreach ($name in @('scout-quar-client', 'foo', 'ScOuT-pfsense')) {
            Test-Case "$action refuses unapproved changed guest $name" {
                $state = if ($action -ceq 'start') { 'running' } else { 'shut off' }
                Assert-Throws { Read-Response (New-Response $action $state @{ changed = @($name) }) $action } 'unapproved'
            }
        }
    }
    foreach ($name in $script:VMs) {
        Test-Case "Schema refuses missing approved guest $name" {
            $states = $script:State.States.Clone()
            $states.Remove($name)
            Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) } 'schema|missing'
        }
    }
    Test-Case 'Schema refuses an old three guest payload even with routed mode' {
        $states = @{ 'scout-v6alias' = 'shut off'; 'scout-admin' = 'shut off'; 'scout-corp-client' = 'shut off' }
        Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) } 'schema'
    }
    Test-Case 'Schema refuses a sixth quarantine guest even when shut off' {
        $states = $script:State.States.Clone()
        $states['scout-quar-client'] = 'shut off'
        Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) } 'schema'
    }
    Test-Case 'Routed instructions retain source login and command order without readiness claims' {
        $text = (& $script:Module { Show-DemoGuestInstructions } 6>&1 | Out-String)
        if ($text -notmatch 'Console login: scout-user' -or $text -notmatch 'source service is corp-10') {
            throw 'Source identity changed.'
        }
        if ($text -notmatch '(?s)source ~/v6alias/live-demo.bash.*ifconfig.*ping corp:43 -c 3.*ping lab:7.15 -c 3.*ssh corp:42 -l scout-user.*hostname.*exit') {
            throw 'Routed command sequence missing or out of order.'
        }
        foreach ($expected in @('does not mean guest-ready', 'pfSense boot can take several minutes',
                                'retry pings', 'routes are manually staged', 'not automatically configured',
                                'No guest Internet access or default route', 'Existing firewall policy is unchanged')) {
            if ($text -notmatch [regex]::Escape($expected)) { throw "Missing guidance: $expected" }
        }
    }
    Test-Case 'Status describes router and lab target running without claiming guest readiness' {
        $response = Read-Response (New-Response -State running)
        $text = (& $script:Module { param($Status) Show-DemoStatus $Status } $response 6>&1 | Out-String)
        foreach ($expected in @('pfSense router and lab target are running', 'guest readiness is not yet verified',
                                'scout-quar-client remains off')) {
            if ($text -notmatch [regex]::Escape($expected)) { throw "Missing status: $expected" }
        }
    }
    Test-Case 'Off status does not claim router and lab target are running' {
        $response = Read-Response (New-Response)
        $text = (& $script:Module { param($Status) Show-DemoStatus $Status } $response 6>&1 | Out-String)
        if ($text -match 'router and lab target are running') { throw 'False running status.' }
        foreach ($name in $script:VMs) {
            if ($text -notmatch [regex]::Escape("$name : shut off")) { throw "Missing off status for $name" }
        }
    }
    $invalid = @(
        @{ Name = 'string safety boolean'; Fields = @{ other_vms_off = 'true' } }
        @{ Name = 'numeric safety boolean'; Fields = @{ other_vms_off = 1 } }
        @{ Name = 'null safety boolean'; Fields = @{ other_vms_off = $null } }
        @{ Name = 'false safety boolean'; Fields = @{ other_vms_off = $false } }
        @{ Name = 'wrong mode'; Fields = @{ mode = 'single_vm' } }
        @{ Name = 'legacy three VM mode'; Fields = @{ mode = 'three_vm_demo' } }
        @{ Name = 'case mismatched mode'; Fields = @{ mode = 'Routed_demo' } }
        @{ Name = 'wrong action'; Fields = @{ action = 'start' } }
        @{ Name = 'case mismatched action'; Fields = @{ action = 'Status' } }
        @{ Name = 'unverified isolation'; Fields = @{ isolation = 'unverified' } }
        @{ Name = 'changed string'; Fields = @{ changed = 'scout-admin' } }
        @{ Name = 'changed boolean'; Fields = @{ changed = $true } }
        @{ Name = 'changed null'; Fields = @{ changed = $null } }
        @{ Name = 'changed unknown VM'; Fields = @{ changed = @('lab-other') } }
        @{ Name = 'changed blocked VM'; Fields = @{ changed = @('scout-quar-client') } }
        @{ Name = 'changed duplicate VM'; Fields = @{ changed = @('scout-admin', 'scout-admin') } }
        @{ Name = 'status cannot change'; Fields = @{ changed = @('scout-admin') } }
        @{ Name = 'extra response field'; Fields = @{ extra = 1 } }
        @{ Name = 'shadowed dictionary Count'; Fields = @{ Count = 6 } }
        @{ Name = 'shadowed dictionary Keys'; Fields = @{ Keys = @('mode', 'action', 'states', 'isolation', 'other_vms_off', 'changed') } }
        @{ Name = 'states is array'; Fields = @{ states = @() } }
        @{ Name = 'states is null'; Fields = @{ states = $null } }
    )
    foreach ($case in $invalid) {
        Test-Case "Schema rejects $($case.Name)" {
            Assert-Throws { Read-Response (New-Response -Overrides $case.Fields) }
        }
    }
    foreach ($field in @('mode', 'action', 'states', 'isolation', 'other_vms_off', 'changed')) {
        Test-Case "Schema rejects missing $field" {
            Assert-Throws { Read-Response (New-Response -Remove @($field)) }
        }
    }
    foreach ($state in @('paused', 'RUNNING', '', $true, 1, $null)) {
        Test-Case "Schema rejects unknown state '$state'" {
            $states = $script:State.States.Clone()
            $states['scout-admin'] = $state
            Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) }
        }
    }
    foreach ($name in @('lab-other', 'scout-quar-client', 'ScOut-admin')) {
        Test-Case "Schema rejects unapproved or case mismatched VM $name" {
            $states = $script:State.States.Clone()
            $states.Remove('scout-admin')
            $states[$name] = 'shut off'
            Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) }
        }
    }
    Test-Case 'Schema rejects extra VM key even if it shadows dictionary Count' {
        $states = $script:State.States.Clone()
        $states['Count'] = $script:VMs.Count
        Assert-Throws { Read-Response (New-Response -Overrides @{ states = $states }) }
    }
    foreach ($json in @('', '{broken', 'null', 'true', '"text"', '[]', '[{},{}]')) {
        Test-Case "Schema rejects invalid or nonobject JSON '$json'" {
            Assert-Throws { Read-Response $json }
        }
    }
    Test-Case 'Schema rejects a single status object wrapped in array' {
        Assert-Throws { Read-Response ('[' + (New-Response) + ']') }
    }
    Test-Case 'Pinned SSH options and timeout are safe without native access' {
        & $script:Module {
            if ($script:DemoHost -cne 'labagent@labhost' -or $script:DemoTimeoutMilliseconds -ne 900000) {
                throw 'Unexpected SSH target or insufficient shutdown timeout.'
            }
            foreach ($option in @('StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                                   'ClearAllForwardings=yes', 'HostKeyAlgorithms=ssh-ed25519')) {
                if ($script:DemoSshOptions -cnotcontains $option) { throw "Missing SSH safety option: $option" }
            }
        }
    }
    Test-Case 'Root entry forwards WhatIf without preflight or prompt' {
        & $script:Entry -Action Open -WhatIf 6>$null
        Assert-Equal $script:State.Actions.Count 0
        Assert-Equal $script:State.ReadCalls 0
    }
    Test-Case 'Root Help is local only' {
        & $script:Entry -Action Help 6>$null
        Assert-Equal $script:State.Actions.Count 0
        Assert-Equal $script:State.ReadCalls 0
    }
    Test-Case 'Root entry refreshes a cached three-VM module and accepts the five-VM schema' {
        # Reproduce a long-lived PowerShell session whose module predates the
        # routed-demo update. No files or remote resources are changed.
        & $script:Module {
            $script:DemoVMs = @('scout-v6alias', 'scout-admin', 'scout-corp-client')
            function script:Show-DemoHelp { Write-Host 'Three-VM live demo (cached)' }
        }
        $help = (& $script:Entry -Action Help 6>&1 | Out-String)
        if ($help -notmatch 'Five-VM routed live demo' -or $help -match 'Three-VM') {
            throw 'The launcher reused stale session state instead of reloading the current module.'
        }
        $fresh = Get-Module LiveDemo
        if ($null -eq $fresh) { throw 'Reloaded module was not registered.' }
        $json = New-Response status running
        $response = & $fresh {
            param($Json)
            ConvertFrom-DemoHostResponse $Json status
        } $json
        Assert-Equal $response.states.Count 5
        Assert-Equal $response.mode 'routed_demo'
    }
}
finally {
    Remove-Module LiveDemo -Force -ErrorAction SilentlyContinue
}

Write-Host "Final count: $script:Count PASS, $($script:Failures.Count) FAIL."
if ($script:Failures.Count) {
    foreach ($failure in $script:Failures) { Write-Host $failure }
    exit 1
}
