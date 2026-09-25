#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LabHost = 'labagent@labhost'
$script:LabVm = 'scout-v6alias'
$script:LabHostTimeoutMilliseconds = 240000

# Use existing SSH authentication and a previously trusted Ed25519 host key.
# Never prompt for credentials, accept a new host key, or inherit SSH forwards.
$script:LabSshOptions = @(
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'ClearAllForwardings=yes',
    '-o', 'HostKeyAlgorithms=ssh-ed25519',
    '-o', 'ConnectTimeout=10'
)

function Get-LabSshPath {
    $command = Get-Command ssh.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        throw 'ssh.exe was not found. Install the Windows OpenSSH client and configure SSH authentication and host trust before using this lab.'
    }
    return $command.Source
}

function ConvertFrom-LabHostResponse {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Json,

        [Parameter(Mandatory)]
        [ValidateSet('status', 'start', 'stop')]
        [string] $ExpectedAction
    )

    try {
        $response = ConvertFrom-Json -InputObject $Json -AsHashtable -NoEnumerate -ErrorAction Stop
    }
    catch {
        throw 'The lab host returned invalid JSON. No safe VM state could be confirmed; run .\Lab.ps1 -Action Status before proceeding.'
    }

    $fields = @('vm', 'state', 'isolation', 'other_vms_off', 'changed', 'action')
    if ($response -isnot [System.Collections.IDictionary]) {
        throw 'The lab host response must be a single status object.'
    }
    $keys = @($response.Keys)
    if ($keys.Count -ne $fields.Count) {
        throw 'The lab host response has an unexpected status schema.'
    }
    foreach ($field in $fields) {
        if ($keys -cnotcontains $field) {
            throw "The lab host response is missing the required '$field' field."
        }
    }

    if (
        $response.vm -isnot [string] -or $response.vm -cne $script:LabVm -or
        $response.state -isnot [string] -or @('running', 'shut off') -cnotcontains $response.state -or
        $response.isolation -isnot [string] -or $response.isolation -cne 'verified' -or
        $response.other_vms_off -isnot [bool] -or $response.other_vms_off -ne $true -or
        $response.changed -isnot [bool] -or
        $response.action -isnot [string] -or $response.action -cne $ExpectedAction
    ) {
        throw 'The lab host response did not confirm the expected VM, action, state, and isolation. No further action will be taken.'
    }
    if (
        ($ExpectedAction -ceq 'start' -and $response.state -cne 'running') -or
        ($ExpectedAction -ceq 'stop' -and $response.state -cne 'shut off')
    ) {
        throw "The lab host did not confirm the requested '$ExpectedAction' state. Run .\Lab.ps1 -Action Status before retrying."
    }

    return [pscustomobject] $response
}

function Wait-LabHostTask {
    param(
        [Parameter(Mandatory)]
        [System.Threading.Tasks.Task] $Task,

        [Parameter(Mandatory)]
        [System.Diagnostics.Stopwatch] $Clock
    )

    # One deadline covers sending source, process completion, and both output streams.
    $remaining = $script:LabHostTimeoutMilliseconds - $Clock.ElapsedMilliseconds
    if ($remaining -le 0 -or -not $Task.Wait([int] $remaining)) {
        throw [System.TimeoutException]::new('The local SSH controller deadline expired.')
    }
}

function Wait-LabHostExit {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process,

        [Parameter(Mandatory)]
        [System.Diagnostics.Stopwatch] $Clock
    )

    # WaitForExit(int) also works on the .NET runtime shipped with PowerShell 7.0.
    $remaining = $script:LabHostTimeoutMilliseconds - $Clock.ElapsedMilliseconds
    if ($remaining -le 0 -or -not $Process.WaitForExit([int] $remaining)) {
        throw [System.TimeoutException]::new('The local SSH controller deadline expired.')
    }
}

function Get-LabRemoteError {
    param([AllowEmptyString()][string] $Text)

    # Keep SSH/controller diagnostics readable without terminal control sequences.
    $message = ($Text -replace '\x1B\[[0-?]*[ -/]*[@-~]', '' -replace '[\x00-\x08\x0B-\x1F\x7F-\x9F]', '').Trim()
    if ([string]::IsNullOrWhiteSpace($message)) {
        return 'No error detail was returned on stderr.'
    }
    if ($message.Length -gt 2000) {
        return $message.Substring(0, 2000) + ' [truncated]'
    }
    return $message
}

function Invoke-LabHost {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('status', 'start', 'stop')]
        [string] $Action
    )

    $Action = $Action.ToLowerInvariant()
    $sshPath = Get-LabSshPath
    $sourcePath = Join-Path $PSScriptRoot 'lab_host.py'
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "The local controller is missing: $sourcePath. Restore scripts\lab_host.py before using the lab."
    }

    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $source = [System.IO.File]::ReadAllText($sourcePath, $utf8)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $sshPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardInputEncoding = $utf8
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($argument in (@('-T') + $script:LabSshOptions + @($script:LabHost, "python3 - $Action"))) {
        $startInfo.ArgumentList.Add($argument)
    }

    # Only the local Python source goes to stdin; no credentials or keys are read.
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $started = $process.Start()
        if (-not $started) {
            throw 'The local SSH controller process could not be started.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $inputFailed = $false
        try {
            $inputTask = $process.StandardInput.WriteAsync($source)
            Wait-LabHostTask -Task $inputTask -Clock $clock
            Wait-LabHostTask -Task ($process.StandardInput.FlushAsync()) -Clock $clock
            $process.StandardInput.Close()
        }
        catch [System.TimeoutException] {
            throw
        }
        catch {
            # Early SSH rejection can break stdin first; still collect its real stderr.
            $inputFailed = $true
            try {
                $process.StandardInput.BaseStream.Close()
            }
            catch {
                Write-Verbose 'SSH stdin was already closed.'
            }
        }
        Wait-LabHostExit -Process $process -Clock $clock
        Wait-LabHostTask -Task $stdoutTask -Clock $clock
        Wait-LabHostTask -Task $stderrTask -Clock $clock

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $detail = Get-LabRemoteError -Text $stderr
            throw "Lab host action '$Action' failed (SSH exit code $($process.ExitCode)): $detail"
        }
        if ($inputFailed) {
            $detail = Get-LabRemoteError -Text $stderr
            throw "The local controller source could not be sent completely: $detail Run .\Lab.ps1 -Action Status before retrying."
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            Write-Warning (Get-LabRemoteError -Text $stderr)
        }
        ConvertFrom-LabHostResponse -Json $stdout -ExpectedAction $Action
    }
    catch [System.TimeoutException] {
        throw "Lab host action '$Action' timed out after 240 seconds. Only the local SSH child process is being terminated; the action may still be running on the host. Run .\Lab.ps1 -Action Status before retrying. No VM shutdown is assumed or forced."
    }
    finally {
        try {
            if ($started -and -not $process.HasExited) {
                $process.Kill($true)
            }
        }
        catch {
            Write-Warning 'The local SSH child process could not be terminated. The host action may still be running; check Status before retrying.'
        }
        finally {
            $clock.Stop()
            $process.Dispose()
        }
    }
}

function Show-LabStatus {
    param([Parameter(Mandatory)][psobject] $Status)

    Write-Host "VM: $($Status.vm) | State: $($Status.state)"
    Write-Host 'Isolation: verified; the other five scout VMs are off.'
    if ($Status.changed) {
        Write-Host 'The requested VM state change is confirmed.'
    }
    else {
        Write-Host 'No VM state change was needed.'
    }
}

function Invoke-LabConsole {
    $sshPath = Get-LabSshPath
    $arguments = @('-t') + $script:LabSshOptions + @($script:LabHost, "virsh console $script:LabVm")

    # SSH reaches the host; virsh provides the guest serial console, not guest SSH.
    # Inherit the terminal: do not redirect input/output or steal a console with --force.
    $PSNativeCommandUseErrorActionPreference = $false
    & $sshPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "The serial console disconnected with SSH exit code $LASTEXITCODE. If the console is in use, detach the existing console session with Ctrl+] and retry Open. The VM has not been stopped automatically."
    }
}

function Show-LabHelp {
    Write-Host @'
V6Alias lab - PowerShell 7

  .\Lab.ps1                    Open the menu
  .\Lab.ps1 -Action Open        Check isolation, start if needed, then open the console
  .\Lab.ps1 -Action Status      Check the VM state and isolation without changing them
  .\Lab.ps1 -Action Stop        Request a clean shutdown; never force power-off
  .\Lab.ps1 -Action Help        Show this help without connecting
  .\Lab.ps1 -Action Open -WhatIf
  .\Lab.ps1 -Action Stop -Confirm

The pinned SSH destination is labagent@labhost; the only managed VM is scout-v6alias.
SSH must already authenticate, with the host's Ed25519 key trusted in known_hosts.
No credentials are collected, and no private key files are read by these scripts.
The guest is accessed through the host's serial console, not direct guest SSH.
Actions require verified isolation and the other five scout VMs off; they do not configure
VMs, networking, or guest files. Status never starts or stops a VM.

Console login: scout-user. Password typing is not displayed.
Press Enter if the console screen is blank.
Detach with Ctrl+]. This does not stop the VM or log out the guest session.
Use Stop when you want a clean shutdown. Open reuses an already-running VM.

Guest commands:
  python3 ~/v6alias/demo.py
  cd ~/v6alias; ./v6alias ifconfig
Demo addresses are fictional examples, not host or guest IP configuration.

-WhatIf makes no SSH connections. -Confirm asks before a connected action.
'@
}

function Invoke-V6AliasLab {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Menu', 'Open', 'Status', 'Stop', 'Help')]
        [string] $Action = 'Menu'
    )

    switch ($Action) {
        'Help' {
            Show-LabHelp
            return
        }
        'Menu' {
            if ($WhatIfPreference) {
                $null = $PSCmdlet.ShouldProcess('V6Alias lab menu', 'Show choices Open, Status, Stop, Help, and Exit without connecting')
                return
            }
            while ($true) {
                Write-Host "`nV6Alias lab - $script:LabVm on $script:LabHost"
                Write-Host '1 Open'
                Write-Host '2 Status'
                Write-Host '3 Stop'
                Write-Host '4 Help'
                Write-Host '0 Exit'
                $choice = Read-Host 'Choose'
                $selectedAction = switch ($choice) {
                    '1' { 'Open' }
                    '2' { 'Status' }
                    '3' { 'Stop' }
                    '4' { 'Help' }
                    '0' { return }
                    default { $null }
                }
                if ($null -eq $selectedAction) {
                    Write-Host 'Enter 1, 2, 3, 4, or 0.'
                    continue
                }
                $forward = @{}
                foreach ($key in $PSBoundParameters.Keys) {
                    $forward[$key] = $PSBoundParameters[$key]
                }
                $forward.Action = $selectedAction
                Invoke-V6AliasLab @forward
            }
        }
        'Status' {
            if (-not $PSCmdlet.ShouldProcess("$script:LabVm on $script:LabHost", 'Read VM state and verify isolation')) {
                return
            }
            Write-Host 'Checking VM state and isolation (read-only)...'
            $status = Invoke-LabHost -Action status
            Show-LabStatus -Status $status
            return
        }
        'Stop' {
            if (-not $PSCmdlet.ShouldProcess("$script:LabVm on $script:LabHost", 'Verify isolation and request a clean shutdown (no force)')) {
                return
            }
            Write-Host 'Checking isolation and requesting a clean shutdown; no force power-off...'
            $status = Invoke-LabHost -Action stop
            if ($status.state -cne 'shut off') {
                throw 'Shutdown was not confirmed. Run .\Lab.ps1 -Action Status before retrying.'
            }
            Show-LabStatus -Status $status
            return
        }
        'Open' {
            # One approval precedes every connection, including the read-only preflight.
            if (-not $PSCmdlet.ShouldProcess("$script:LabVm on $script:LabHost", 'Verify isolation, start the VM if needed, and open its serial console')) {
                return
            }
            Write-Host '[1/3] Checking VM state and isolation...'
            $status = Invoke-LabHost -Action status
            if ($status.state -ceq 'shut off') {
                Write-Host '[2/3] Starting the VM; the host controller rechecks safety first...'
                $status = Invoke-LabHost -Action start
            }
            else {
                Write-Host '[2/3] Reusing the already-running VM; no start request is needed.'
            }
            Show-LabStatus -Status $status
            Write-Host '[3/3] Opening the guest serial console through the SSH host...'
            Write-Host 'Login: scout-user'
            Write-Host 'Press Enter if the console screen is blank. At the password prompt, typing is not displayed.'
            Write-Host 'Detach with Ctrl+] to leave the guest session available; this does not shut down the VM.'
            Write-Host 'Guest commands:'
            Write-Host '  python3 ~/v6alias/demo.py'
            Write-Host '  cd ~/v6alias; ./v6alias ifconfig'
            Write-Host 'Demo addresses are fictional examples, not host or guest IP configuration.'
            try {
                Invoke-LabConsole
            }
            finally {
                Write-Host 'Detaching does not stop the VM. Choose 3 (Stop) in the menu, or run .\Lab.ps1 -Action Stop for a clean shutdown.'
            }
            return
        }
    }
}

Export-ModuleMember -Function Invoke-V6AliasLab
