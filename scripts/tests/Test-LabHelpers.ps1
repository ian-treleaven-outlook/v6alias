#Requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WhatIfPreference = $false
$ConfirmPreference = 'None'

# Offline control-flow/schema tests only: these mocks do not test infrastructure,
# SSH, isolation, VM operations, or an actual interactive serial console.
$script:LabModule = $null
$script:TestCount = 0
$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:TestClock = [System.Diagnostics.Stopwatch]::StartNew()
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'V6AliasLab.psm1'
$script:EntryPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Lab.ps1'

function Reset-TestState {
    $script:TestState = [pscustomobject] @{
        State = 'shut off'
        Actions = @()
        Responses = @()
        FailAction = ''
        JsonOverrides = @{}
        InputQueue = [System.Collections.Generic.Queue[string]]::new()
        ReadCalls = 0
        NativeCalls = 0
        Clock = $script:TestClock
    }
    & $script:LabModule {
        param($State)
        $script:LabTestState = $State
    } $script:TestState
}

function Assert-Equal {
    param($Actual, $Expected, [string] $Because)
    if ($Actual -cne $Expected) {
        throw "$Because (expected '$Expected'; got '$Actual')."
    }
}

function Assert-Actions {
    param([string[]] $Expected = @())
    Assert-Equal ($script:TestState.Actions -join ',') ($Expected -join ',') 'Action order'
}

function Assert-Throws {
    param([scriptblock] $Body, [string] $MessagePattern)
    $caught = $null
    try { & $Body | Out-Null }
    catch { $caught = $_ }
    if ($null -eq $caught) {
        throw 'Expected an exception, but the operation succeeded.'
    }
    if ($caught.Exception.Message -notmatch $MessagePattern) {
        throw "Wrong exception: $($caught.Exception.Message)"
    }
}

function New-TestJson {
    param(
        [string] $Action = 'status',
        [string] $State = 'shut off',
        [bool] $Changed = $false,
        [hashtable] $Overrides = @{},
        [string[]] $Remove = @()
    )
    $fixture = [ordered] @{
        vm = 'scout-v6alias'
        state = $State
        isolation = 'verified'
        other_vms_off = $true
        changed = $Changed
        action = $Action
    }
    foreach ($key in $Overrides.Keys) { $fixture[$key] = $Overrides[$key] }
    foreach ($key in $Remove) { $fixture.Remove($key) }
    ConvertTo-Json -InputObject $fixture -Compress
}

function Read-TestResponse {
    param([string] $Json, [string] $Action = 'status')
    & $script:LabModule {
        param($Json, $Action)
        ConvertFrom-LabHostResponse -Json $Json -ExpectedAction $Action
    } $Json $Action
}

function Invoke-Test {
    param([string] $Name, [scriptblock] $Body)
    $savedWhatIf = $WhatIfPreference
    $savedConfirm = $ConfirmPreference
    $savedError = $ErrorActionPreference
    try {
        $WhatIfPreference = $false
        $ConfirmPreference = 'None'
        $ErrorActionPreference = 'Stop'
        Reset-TestState
        if ($script:TestClock.Elapsed.TotalSeconds -ge 40) {
            throw 'Offline test time budget exceeded.'
        }
        & $Body | Out-Null
        Assert-Equal $script:TestState.NativeCalls 0 'No native SSH lookup may escape the mocks'
        $schema = & $script:LabModule { (Get-Item Function:ConvertFrom-LabHostResponse).ScriptBlock }
        if (-not [object]::ReferenceEquals($schema, $script:OriginalSchema)) {
            throw 'The real schema helper was replaced.'
        }
        $script:TestCount++
        Write-Host "PASS: $Name"
    }
    catch {
        $script:Failures.Add("${Name}: $($_.Exception.Message)")
        Write-Host "FAIL: ${Name}: $($_.Exception.Message)"
    }
    finally {
        Reset-TestState
        $WhatIfPreference = $savedWhatIf
        $ConfirmPreference = $savedConfirm
        $ErrorActionPreference = $savedError
    }
}

try {
    $script:LabModule = Import-Module $modulePath -Force -PassThru -ErrorAction Stop
    $script:OriginalSchema = & $script:LabModule {
        (Get-Item Function:ConvertFrom-LabHostResponse).ScriptBlock
    }

    # Inject into this imported module's memory only; never rewrite production files.
    & $script:LabModule {
        function script:Get-LabSshPath {
            $script:LabTestState.NativeCalls++
            throw 'OFFLINE GUARD: native SSH access is forbidden in these tests.'
        }

        function script:Invoke-LabHost {
            param(
                [Parameter(Mandatory)]
                [ValidateSet('status', 'start', 'stop')]
                [string] $Action
            )
            $Action = $Action.ToLowerInvariant()
            $script:LabTestState.Actions += $Action
            if ($script:LabTestState.FailAction -ceq $Action) {
                throw "Mock remote failure for $Action."
            }
            $nextState = switch ($Action) {
                'start' { 'running' }
                'stop' { 'shut off' }
                default { $script:LabTestState.State }
            }
            if ($script:LabTestState.JsonOverrides.ContainsKey($Action)) {
                $json = $script:LabTestState.JsonOverrides[$Action]
            }
            else {
                # Exact wire fields emitted by lab_host.py; validate with the real parser.
                $json = ConvertTo-Json -Compress -InputObject ([ordered] @{
                    vm = 'scout-v6alias'
                    state = $nextState
                    isolation = 'verified'
                    other_vms_off = $true
                    changed = ($nextState -cne $script:LabTestState.State)
                    action = $Action
                })
            }
            $response = ConvertFrom-LabHostResponse -Json $json -ExpectedAction $Action
            $script:LabTestState.Responses += $response
            if ($Action -cne 'status') { $script:LabTestState.State = $response.state }
            return $response
        }

        function script:Invoke-LabConsole {
            $script:LabTestState.Actions += 'console'
            if ($script:LabTestState.State -cne 'running') {
                throw 'Mock console requires a confirmed running VM.'
            }
        }

        function script:Read-Host {
            param([string] $Prompt)
            $script:LabTestState.ReadCalls++
            if (
                $script:LabTestState.ReadCalls -gt 8 -or
                $script:LabTestState.Clock.Elapsed.TotalSeconds -ge 40 -or
                $script:LabTestState.InputQueue.Count -eq 0
            ) {
                throw 'OFFLINE GUARD: unexpected Read-Host or menu failed to exit.'
            }
            return $script:LabTestState.InputQueue.Dequeue()
        }
    }

    Invoke-Test 'Open from off checks status, starts, then opens mock console' {
        Invoke-V6AliasLab -Action Open -Confirm:$false 6>$null
        Assert-Actions @('status', 'start', 'console')
        Assert-Equal $script:TestState.State 'running' 'Start state'
        Assert-Equal $script:TestState.Responses[1].changed $true 'Start confirms change'
    }

    Invoke-Test 'Open running VM checks status and reuses mock console without starting' {
        $script:TestState.State = 'running'
        Invoke-V6AliasLab -Action Open -Confirm:$false 6>$null
        Assert-Actions @('status', 'console')
        Assert-Equal $script:TestState.State 'running' 'Open never stops the VM'
    }

    foreach ($state in @('shut off', 'running')) {
        Invoke-Test "Status is read-only for $state" {
            $script:TestState.State = $state
            Invoke-V6AliasLab -Action Status -Confirm:$false 6>$null
            Assert-Actions @('status')
            Assert-Equal $script:TestState.State $state 'Status must not mutate state'
            Assert-Equal $script:TestState.Responses[0].changed $false 'Status reports no change'
        }
        Invoke-Test "Stop confirms shut off from $state without console" {
            $script:TestState.State = $state
            Invoke-V6AliasLab -Action Stop -Confirm:$false 6>$null
            Assert-Actions @('stop')
            Assert-Equal $script:TestState.State 'shut off' 'Confirmed shutdown'
            Assert-Equal $script:TestState.Responses[0].state 'shut off' 'Reported shutdown'
            Assert-Equal $script:TestState.Responses[0].changed ($state -ceq 'running') 'Stop change flag'
        }
    }

    foreach ($action in @('Menu', 'Open', 'Stop', 'Status')) {
        Invoke-Test "$action -WhatIf performs no host, console, or Read-Host calls" {
            Invoke-V6AliasLab -Action $action -WhatIf 6>$null
            Assert-Actions
            Assert-Equal $script:TestState.ReadCalls 0 'WhatIf must not prompt'
            Assert-Equal $script:TestState.State 'shut off' 'WhatIf must not change state'
        }
    }

    Invoke-Test 'Menu Help then Exit returns after exactly two queued reads' {
        $script:TestState.InputQueue.Enqueue('4')
        $script:TestState.InputQueue.Enqueue('0')
        $output = Invoke-V6AliasLab -Action Menu -Confirm:$false 6>&1 | Out-String
        Assert-Equal ($output -match 'Guest commands:') $true 'Help must be displayed'
        Assert-Actions
        Assert-Equal $script:TestState.ReadCalls 2 'Menu must exit on 0'
        Assert-Equal $script:TestState.InputQueue.Count 0 'All menu input consumed'
    }

    Invoke-Test 'Menu Status then Exit performs one read-only host action and returns' {
        $script:TestState.InputQueue.Enqueue('2')
        $script:TestState.InputQueue.Enqueue('0')
        Invoke-V6AliasLab -Action Menu -Confirm:$false 6>$null
        Assert-Actions @('status')
        Assert-Equal $script:TestState.ReadCalls 2 'Menu must exit on 0'
        Assert-Equal $script:TestState.State 'shut off' 'Menu Status must not start VM'
    }

    Invoke-Test 'Menu rejects invalid input then Exit returns without looping' {
        $script:TestState.InputQueue.Enqueue('invalid')
        $script:TestState.InputQueue.Enqueue('0')
        $output = Invoke-V6AliasLab -Action Menu -Confirm:$false 6>&1 | Out-String
        Assert-Equal ($output -match 'Enter 1, 2, 3, 4, or 0\.') $true 'Invalid choice guidance'
        Assert-Actions
        Assert-Equal $script:TestState.ReadCalls 2 'Invalid choice must not prevent exit'
    }

    foreach ($failedAction in @('status', 'start')) {
        Invoke-Test "Open remote $failedAction failure prevents any console" {
            $script:TestState.FailAction = $failedAction
            Assert-Throws {
                Invoke-V6AliasLab -Action Open -Confirm:$false 6>$null
            } "^Mock remote failure for $failedAction\."
            if ($failedAction -ceq 'status') { Assert-Actions @('status') }
            else { Assert-Actions @('status', 'start') }
            Assert-Equal $script:TestState.State 'shut off' 'Failed remote action cannot confirm a change'
        }
    }

    Invoke-Test 'Open unexpected status state fails schema before start or console' {
        $script:TestState.JsonOverrides.status = New-TestJson -State paused
        Assert-Throws {
            Invoke-V6AliasLab -Action Open -Confirm:$false 6>$null
        } 'did not confirm the expected VM'
        Assert-Actions @('status')
        Assert-Equal $script:TestState.State 'shut off' 'Invalid schema must not mutate state'
    }

    Invoke-Test 'Open unconfirmed start fails before console' {
        $script:TestState.JsonOverrides.start = New-TestJson -Action start -State 'shut off'
        Assert-Throws {
            Invoke-V6AliasLab -Action Open -Confirm:$false 6>$null
        } "did not confirm the requested 'start' state"
        Assert-Actions @('status', 'start')
        Assert-Equal $script:TestState.State 'shut off' 'Unconfirmed start must not commit mock state'
    }

    Invoke-Test 'Stop rejects a response that still reports running' {
        $script:TestState.State = 'running'
        $script:TestState.JsonOverrides.stop = New-TestJson -Action stop -State running
        Assert-Throws {
            Invoke-V6AliasLab -Action Stop -Confirm:$false 6>$null
        } "did not confirm the requested 'stop' state"
        Assert-Actions @('stop')
        Assert-Equal $script:TestState.State 'running' 'Unconfirmed stop must not claim shutdown'
    }

    $validCases = @(
        @{ Action = 'status'; State = 'shut off'; Changed = $false },
        @{ Action = 'status'; State = 'running'; Changed = $false },
        @{ Action = 'start'; State = 'running'; Changed = $true },
        @{ Action = 'start'; State = 'running'; Changed = $false },
        @{ Action = 'stop'; State = 'shut off'; Changed = $true },
        @{ Action = 'stop'; State = 'shut off'; Changed = $false }
    )
    foreach ($case in $validCases) {
        Invoke-Test "Schema accepts $($case.Action)/$($case.State)/changed=$($case.Changed)" {
            $response = Read-TestResponse -Json (New-TestJson @case) -Action $case.Action
            Assert-Equal $response.action $case.Action 'Accepted action'
            Assert-Equal $response.state $case.State 'Accepted state'
            Assert-Equal $response.changed $case.Changed 'Accepted change flag'
            Assert-Equal ($response.changed -is [bool]) $true 'Changed remains a boolean'
            Assert-Equal ($response.other_vms_off -is [bool]) $true 'Safety flag remains a boolean'
            Assert-Actions
        }
    }

    $invalidFields = @(
        @{ Name = 'string safety boolean'; Fields = @{ other_vms_off = 'true' } },
        @{ Name = 'string changed boolean'; Fields = @{ changed = 'false' } },
        @{ Name = 'numeric safety boolean'; Fields = @{ other_vms_off = 1 } },
        @{ Name = 'numeric changed boolean'; Fields = @{ changed = 0 } },
        @{ Name = 'null safety boolean'; Fields = @{ other_vms_off = $null } },
        @{ Name = 'null changed boolean'; Fields = @{ changed = $null } },
        @{ Name = 'other VMs not off'; Fields = @{ other_vms_off = $false } },
        @{ Name = 'wrong VM'; Fields = @{ vm = 'another-vm' } },
        @{ Name = 'wrong VM case'; Fields = @{ vm = 'SCOUT-V6ALIAS' } },
        @{ Name = 'unverified isolation'; Fields = @{ isolation = 'unverified' } },
        @{ Name = 'unexpected state'; Fields = @{ state = 'paused' } },
        @{ Name = 'wrong state case'; Fields = @{ state = 'Running' } },
        @{ Name = 'non-string state'; Fields = @{ state = @('running') } },
        @{ Name = 'wrong action'; Fields = @{ action = 'start' } },
        @{ Name = 'wrong action case'; Fields = @{ action = 'STATUS' } },
        @{ Name = 'extra field'; Fields = @{ unexpected = $true } }
    )
    foreach ($case in $invalidFields) {
        Invoke-Test "Schema rejects $($case.Name)" {
            Assert-Throws {
                Read-TestResponse -Json (New-TestJson -Overrides $case.Fields)
            } 'unexpected status schema|did not confirm the expected VM'
            Assert-Actions
        }
    }

    foreach ($field in @('vm', 'state', 'isolation', 'other_vms_off', 'changed', 'action')) {
        Invoke-Test "Schema rejects missing $field" {
            Assert-Throws {
                Read-TestResponse -Json (New-TestJson -Remove $field)
            } 'unexpected status schema|missing the required'
            Assert-Actions
        }
    }

    Invoke-Test 'Schema rejects case-mismatched field name with unchanged field count' {
        $json = (New-TestJson) -creplace '"vm":', '"VM":'
        Assert-Throws { Read-TestResponse -Json $json } "missing the required 'vm'"
        Assert-Actions
    }

    foreach ($json in @('', '{broken', 'null', 'true', '"text"', '[]', '[{},{}]')) {
        Invoke-Test "Schema rejects malformed or non-object JSON '$json'" {
            Assert-Throws { Read-TestResponse -Json $json } 'invalid JSON|single status object'
            Assert-Actions
        }
    }

    Invoke-Test 'Schema rejects even a single valid object wrapped in an array' {
        $json = '[' + (New-TestJson) + ']'
        Assert-Throws { Read-TestResponse -Json $json } 'single status object'
        Assert-Actions
    }

    Invoke-Test 'Root Lab.ps1 forwards Open -WhatIf without SSH, console, or input' {
        & $script:EntryPath -Action Open -WhatIf 6>$null
        Assert-Actions
        Assert-Equal $script:TestState.ReadCalls 0 'Root WhatIf must not prompt'
        Assert-Equal $script:TestState.State 'shut off' 'Root WhatIf must not mutate state'
    }

    Invoke-Test 'Root Lab.ps1 Help displays help without SSH, console, or input' {
        $output = & $script:EntryPath -Action Help 6>&1 | Out-String
        Assert-Equal ($output -match 'Guest commands:') $true 'Root must forward Help'
        Assert-Equal ($output -match 'Ctrl\+\]') $true 'Help includes console detach instructions'
        Assert-Actions
        Assert-Equal $script:TestState.ReadCalls 0 'Root Help must not prompt'
    }
}
finally {
    if ($null -ne $script:LabModule) {
        Remove-Module -ModuleInfo $script:LabModule -Force -ErrorAction Stop
    }
    $script:TestClock.Stop()
}

Write-Host "Final count: $($script:TestCount) PASS, $($script:Failures.Count) FAIL."
if ($script:Failures.Count -gt 0) {
    throw ("Offline lab helper tests failed:`n" + ($script:Failures -join "`n"))
}
