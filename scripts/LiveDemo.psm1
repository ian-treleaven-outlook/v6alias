#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DemoHost = 'labagent@labhost'
$script:DemoVMs = @('scout-v6alias', 'scout-admin', 'scout-corp-client', 'scout-pfsense', 'scout-lab-client')
$script:DemoTimeoutMilliseconds = 900000
$script:DemoSshOptions = @(
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'ClearAllForwardings=yes',
    '-o', 'HostKeyAlgorithms=ssh-ed25519',
    '-o', 'ConnectTimeout=10'
)

function Get-DemoSshPath {
    $command = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        throw 'Windows OpenSSH ssh.exe is required. Configure authentication and trust the existing Ed25519 host key before using Demo.ps1.'
    }
    $command.Source
}

function Assert-DemoKeys {
    param($Object, [string[]] $Keys)
    if ($Object -isnot [System.Collections.IDictionary]) {
        throw 'Unexpected demo response schema.'
    }
    # JSON keys named Count/Keys can shadow PowerShell dictionary properties.
    $actualKeys = @($Object.get_Keys())
    if ($actualKeys.Count -ne $Keys.Count) {
        throw 'Unexpected demo response schema.'
    }
    foreach ($key in $Keys) {
        if ($actualKeys -cnotcontains $key) {
            throw "Demo response is missing the exact field '$key'."
        }
    }
}

function ConvertFrom-DemoHostResponse {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Json,
        [Parameter(Mandatory)][ValidateSet('status', 'start', 'stop')][string] $ExpectedAction
    )
    try {
        $response = ConvertFrom-Json -InputObject $Json -AsHashtable -NoEnumerate -ErrorAction Stop
    }
    catch {
        throw 'The demo host returned invalid JSON. Run .\Demo.ps1 -Action Status before retrying.'
    }
    Assert-DemoKeys $response @('mode', 'action', 'states', 'isolation', 'other_vms_off', 'changed')
    Assert-DemoKeys $response.states $script:DemoVMs
    if (
        $response.mode -isnot [string] -or $response.mode -cne 'routed_demo' -or
        $response.action -isnot [string] -or $response.action -cne $ExpectedAction -or
        $response.isolation -isnot [string] -or $response.isolation -cne 'verified' -or
        $response.other_vms_off -isnot [bool] -or -not $response.other_vms_off -or
        $response.changed -isnot [array]
    ) {
        throw 'The demo response did not confirm the requested action and isolation.'
    }
    foreach ($name in $script:DemoVMs) {
        $state = $response.states[$name]
        if ($state -isnot [string] -or @('running', 'shut off') -cnotcontains $state) {
            throw "Unexpected state for $name."
        }
        if (($ExpectedAction -ceq 'start' -and $state -cne 'running') -or
            ($ExpectedAction -ceq 'stop' -and $state -cne 'shut off')) {
            throw "The '$ExpectedAction' state was not confirmed for all five VMs. Check Status."
        }
    }
    $seen = @()
    foreach ($name in $response.changed) {
        if ($name -isnot [string] -or $script:DemoVMs -cnotcontains $name -or $seen -ccontains $name) {
            throw 'The changed list contains an unapproved or repeated VM name.'
        }
        $seen += $name
    }
    if ($ExpectedAction -ceq 'status' -and $response.changed.Count -ne 0) {
        throw 'Read-only Status cannot report changes.'
    }
    [pscustomobject] $response
}

function Wait-DemoTask {
    param([System.Threading.Tasks.Task] $Task, [System.Diagnostics.Stopwatch] $Clock)
    $remaining = $script:DemoTimeoutMilliseconds - $Clock.ElapsedMilliseconds
    if ($remaining -le 0 -or -not $Task.Wait([int] $remaining)) {
        throw [System.TimeoutException]::new('Local SSH deadline expired.')
    }
}

function Get-DemoErrorDetail {
    param([AllowEmptyString()][string] $Text)
    $text = ($Text -replace '\x1B\[[0-?]*[ -/]*[@-~]', '' -replace '[\x00-\x08\x0B-\x1F\x7F-\x9F]', '').Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return 'No stderr detail was returned.' }
    if ($text.Length -gt 4000) { return $text.Substring(0, 4000) + ' [truncated]' }
    $text
}

function Invoke-DemoHost {
    param([Parameter(Mandatory)][ValidateSet('status', 'start', 'stop')][string] $Action)
    $Action = $Action.ToLowerInvariant()
    $ssh = Get-DemoSshPath
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $source = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'live_demo_host.py'), $utf8)
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $ssh
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardInputEncoding = $utf8
    $info.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($argument in (@('-T') + $script:DemoSshOptions + @($script:DemoHost, "python3 - $Action"))) {
        $info.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'The local SSH controller could not be started.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $inputFailed = $false
        try {
            # Source only, never passwords or key contents, goes through stdin.
            Wait-DemoTask ($process.StandardInput.WriteAsync($source)) $clock
            Wait-DemoTask ($process.StandardInput.FlushAsync()) $clock
            $process.StandardInput.Close()
        }
        catch [System.TimeoutException] { throw }
        catch {
            $inputFailed = $true
            try { $process.StandardInput.BaseStream.Close() }
            catch { Write-Verbose 'SSH stdin was already closed.' }
        }
        $remaining = $script:DemoTimeoutMilliseconds - $clock.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $process.WaitForExit([int] $remaining)) {
            throw [System.TimeoutException]::new('Local SSH deadline expired.')
        }
        Wait-DemoTask $stdout $clock
        Wait-DemoTask $stderr $clock
        $output = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Demo '$Action' failed (SSH exit $($process.ExitCode)): $(Get-DemoErrorDetail $errorText)"
        }
        if ($inputFailed) {
            throw "Controller source could not be fully sent: $(Get-DemoErrorDetail $errorText) Check Status."
        }
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            Write-Warning (Get-DemoErrorDetail $errorText)
        }
        ConvertFrom-DemoHostResponse $output $Action
    }
    catch [System.TimeoutException] {
        throw "Demo '$Action' exceeded 900 seconds. Only this local SSH process is being cancelled. The host operation may still be running; check Status before retrying. No guest shutdown is assumed or forced."
    }
    finally {
        try {
            if ($started -and -not $process.HasExited) {
                # Kill only this specific local process, never other SSH sessions.
                $process.Kill()
            }
        }
        catch { Write-Warning 'Could not cancel this local SSH process. Check Status before retrying.' }
        finally {
            $clock.Stop()
            $process.Dispose()
        }
    }
}

function Show-DemoStatus {
    param([psobject] $Status)
    foreach ($name in $script:DemoVMs) { Write-Host "$name : $($Status.states[$name])" }
    Write-Host 'Isolation verified; quarantine client scout-quar-client remains off.'
    if ($Status.states['scout-pfsense'] -ceq 'running' -and $Status.states['scout-lab-client'] -ceq 'running') {
        Write-Host 'pfSense router and lab target are running; guest readiness is not yet verified.'
    }
    if ($Status.changed.Count) { Write-Host "Changed: $($Status.changed -join ', ')" }
    else { Write-Host 'No state changes were needed.' }
}

function Show-DemoGuestInstructions {
    Write-Host @'
Console login: scout-user (password typing is not displayed).
VM running does not mean guest-ready; pfSense boot can take several minutes.
Wait for guest readiness established during rehearsal; retry pings after boot if needed.
Press Enter if the console is blank. Run these commands inside the guest:
  source ~/v6alias/live-demo.bash
  ifconfig
  ping corp:43 -c 3
  ping lab:7.15 -c 3
  ssh corp:42 -l scout-user
  hostname
  exit
The source service is corp-10, admin is corp-43, client is corp-42, and lab target is lab:7.15.
Addresses and scoped cross-subnet routes are manually staged, not automatically configured.
This is not a live allocator demonstration. No guest Internet access or default route is provided.
Existing firewall policy is unchanged.
The guest-local dedicated SSH key must already be staged and verified.
Ctrl+] detaches to the menu without stopping VMs; choose Stop when finished.
'@
}

function Invoke-DemoConsole {
    $ssh = Get-DemoSshPath
    $arguments = @('-t') + $script:DemoSshOptions +
        @($script:DemoHost, 'virsh --connect qemu:///system console scout-v6alias')
    # Inherit the terminal; never capture guest passwords or steal a console.
    $PSNativeCommandUseErrorActionPreference = $false
    & $ssh @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Serial console failed (SSH exit $LASTEXITCODE). If busy, detach the existing console with Ctrl+] first. VMs were not automatically stopped."
    }
}

function Show-DemoHelp {
    Write-Host @'
Five-VM routed live demo - PowerShell 7
  .\Demo.ps1                  Menu: 1 Open, 2 Status, 3 Stop, 4 Help, 0 Exit
  .\Demo.ps1 -Action Open      Verify isolation, start/reuse five VMs, open source service console
  .\Demo.ps1 -Action Status    Read-only state and isolation check
  .\Demo.ps1 -Action Stop      Cleanly stop source, corp client, admin, lab target, pfSense
                             (120 seconds each; 900-second controller deadline; no force)
  .\Demo.ps1 -Action Help
  .\Demo.ps1 -Action Open -WhatIf

Pinned host: labagent@labhost (ian-thinkpad), system libvirt qemu:///system.
The corp guests scout-v6alias, scout-admin, and scout-corp-client use only scout-lan.
scout-pfsense uses exactly scout-wan, scout-lan, scout-lab, and scout-quar.
scout-lab-client uses only scout-lab; scout-quar-client must remain off on scout-quar.
All four scout networks remain isolated: no host addressing, forwarding, or uplinks.
Startup order: pfSense, lab target, admin, corp client, source service last.
No VM/network creation or changes, host package installation,
snapshot creation, credential collection, or private key reading is performed.
Existing SSH authentication and a previously trusted Ed25519 host key are required.
-WhatIf performs no SSH, preflight, or input prompts. -Confirm asks before connecting.
Start reuses already-running guests; failure cleans up only this invocation's starts.
Route-isolation incidents require operator handoff to stop all six scout VMs,
including pre-existing guests; an unsafe guard refuses normal Stop.
Lab.ps1 is unchanged: its single-VM guard refuses while the other demo guests are running.
Use Demo.ps1 for this five-VM routed session.
'@
    Show-DemoGuestInstructions
}

function Invoke-V6AliasLiveDemo {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Menu', 'Open', 'Status', 'Stop', 'Help')]
        [string] $Action = 'Menu'
    )
    if ($Action -eq 'Help') { Show-DemoHelp; return }
    if ($Action -eq 'Menu') {
        if ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess('Five-VM routed demo menu', 'Show choices without connecting or prompting')
            return
        }
        while ($true) {
            Write-Host "`nFive-VM routed live demo on $script:DemoHost"
            Write-Host "1 Open`n2 Status`n3 Stop all five cleanly`n4 Help`n0 Exit"
            $choice = Read-Host 'Choose'
            if ($choice -eq '0') { return }
            $selected = switch ($choice) {
                '1' { 'Open' }
                '2' { 'Status' }
                '3' { 'Stop' }
                '4' { 'Help' }
                default { $null }
            }
            if ($null -eq $selected) { Write-Host 'Enter 1, 2, 3, 4, or 0.'; continue }
            $forward = @{}
            foreach ($key in $PSBoundParameters.Keys) { $forward[$key] = $PSBoundParameters[$key] }
            $forward.Action = $selected
            Invoke-V6AliasLiveDemo @forward
        }
    }
    if (-not $PSCmdlet.ShouldProcess("Five approved demo VMs on $script:DemoHost", "$Action with isolation verification")) {
        return
    }
    switch ($Action) {
        'Status' {
            Write-Host 'Checking all six allowlisted scout states and isolation (read-only)...'
            Show-DemoStatus (Invoke-DemoHost status)
        }
        'Stop' {
            Write-Host 'Checking isolation; cleanly stopping source service, corp client, admin, lab target, then pfSense. No force power-off...'
            Show-DemoStatus (Invoke-DemoHost stop)
        }
        'Open' {
            Write-Host '[1/3] Checking guest states and live/persistent isolation...'
            $status = Invoke-DemoHost status
            if (@($status.states.Values | Where-Object { $_ -cne 'running' }).Count) {
                Write-Host '[2/3] Starting pfSense, lab target, admin, corp client, then source service; reusing any already running...'
                $status = Invoke-DemoHost start
            }
            else { Write-Host '[2/3] All five guests are already running; reusing them.' }
            Show-DemoStatus $status
            Write-Host '[3/3] Opening the service serial console through the SSH host...'
            Show-DemoGuestInstructions
            try { Invoke-DemoConsole }
            finally { Write-Host 'Choose 3 (Stop), or .\Demo.ps1 -Action Stop, when finished. Detaching does not stop VMs.' }
        }
    }
}

Export-ModuleMember -Function Invoke-V6AliasLiveDemo
