#Requires -Version 7.0
<#
.SYNOPSIS
Opens a private, loopback-only graphical console for the already-running scout-win2025.
.DESCRIPTION
Requires existing Windows OpenSSH authentication/host trust, Node.js, and Windows netstat. Upstream noVNC
and ws must already be staged under state\windows-server-2025\console. Nothing is installed.
The read-only host guard must pass with all six original guests off. This launcher never
changes VM state, networking, or passwords. Type the Administrator password only in the
browser's Windows console, never in Scout/chat or this PowerShell window.
.EXAMPLE
pwsh -NoProfile -File D:\v6alias\WinCoreConsole.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $PSCmdlet.ShouldProcess('scout-win2025 on labagent@labhost',
        'Read-only safety check and private local graphical console')) { return }

$console = Join-Path $PSScriptRoot 'state\windows-server-2025\console'
$root = Join-Path $console 'noVNC'
$dependencies = Join-Path $console 'node_modules'
$proxyFile = Join-Path $PSScriptRoot 'scripts\windows-console-proxy.cjs'
foreach ($file in @((Join-Path $root 'vnc.html'), (Join-Path $dependencies 'ws\package.json'), $proxyFile)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw 'Console files are not staged. Ask the operator to stage upstream noVNC and ws first.'
    }
}
$ssh = (Get-Command ssh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$node = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$netstat = Join-Path $env:WINDIR 'System32\netstat.exe'
if (-not (Test-Path -LiteralPath $netstat -PathType Leaf)) { throw 'Windows netstat is required to verify the SSH listener owner.' }
$sshOptions = @(
    '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
    '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
    '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'RemoteCommand=none',
    '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no', '-o', 'ControlPath=none'
)
$probeSource = @'
import importlib.util
import json
import sys
import xml.etree.ElementTree as ET

try:
    spec = importlib.util.spec_from_file_location(
        "console_guard", "/home/labagent/work/scout-win2025-20260921/live_demo_host.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    states = guard.guard(require_off=True)
    expected = {"scout-v6alias", "scout-admin", "scout-corp-client",
                "scout-pfsense", "scout-lab-client", "scout-quar-client"}
    guard.require(set(states) == expected and all(s == "shut off" for s in states.values()),
                  "All six original guests must remain off.")
    name = "scout-win2025"
    state = guard.run("virsh", "domstate", name)
    guard.require(state == "running", "scout-win2025 must already be running.")
    xml = ET.fromstring(guard.run("virsh", "dumpxml", name))
    guard.require(xml.tag == "domain" and xml.findtext("name") == name, "Wrong domain.")
    nics = xml.findall("./devices/interface")
    guard.require(len(nics) == 1 and nics[0].get("type") == "network", "Unexpected NIC.")
    sources = nics[0].findall("source")
    links = nics[0].findall("link")
    guard.require(len(sources) == 1 and sources[0].get("network") == "scout-lan"
                  and len(links) <= 1 and all(link.get("state") in ("up", "down") for link in links),
                  "Unexpected scout-lan NIC source/link.")
    graphics = xml.findall("./devices/graphics")
    guard.require(len(graphics) == 1 and graphics[0].get("type") == "vnc",
                  "Exactly one VNC console is required.")
    vnc = graphics[0]
    listeners = vnc.findall("listen")
    guard.require(vnc.get("listen") == "127.0.0.1" and len(listeners) == 1
                  and listeners[0].get("type") == "address"
                  and listeners[0].get("address") == "127.0.0.1"
                  and not vnc.get("passwd") and vnc.get("socket") is None
                  and vnc.get("websocket", "-1") == "-1" and vnc.get("tlsPort", "-1") == "-1",
                  "VNC must listen only on 127.0.0.1 without a second transport.")
    port = int(vnc.get("port", "0"))
    guard.require(5900 <= port <= 65535, "VNC has no valid active port.")
    print(json.dumps({"name": name, "state": state, "host": "127.0.0.1", "port": port}))
except Exception as error:
    print("Read-only console probe failed: " + str(error), file=sys.stderr)
    sys.exit(1)
'@

function Start-ConsoleChild([string] $File, [string[]] $Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Could not start a local console helper.' }
        return $process
    }
    catch { $process.Dispose(); throw }
}

function Stop-ConsoleChild($Process) {
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) { $Process.Kill($true); $null = $Process.WaitForExit(5000) }
    }
    finally { $Process.Dispose() }
}

function Read-ConsoleDiagnostic([string] $Text) {
    $clean = ($Text -replace '\x1B\[[0-?]*[ -/]*[@-~]', '' -replace '[^\x20-\x7E\r\n]', '').Trim()
    if ($clean.Length -gt 1200) { $clean = $clean.Substring(0, 1200) }
    return $clean
}

function Test-ConsoleBinding([string[]] $Rows, [int] $Port, [int] $ProcessId) {
    # An unconnected IPv4 endpoint, exact local address/port and owner; state labels are localized.
    $pattern = "^\s*TCP\s+127\.0\.0\.1:${Port}\s+0\.0\.0\.0:0\s+\S+\s+${ProcessId}\s*$"
    return @($Rows -cmatch $pattern).Count -eq 1
}

$probe = $null; $tunnel = $null; $proxy = $null
try {
    Write-Host 'Checking the existing VM and isolation (read-only; no guest changes)...'
    $probe = Start-ConsoleChild $ssh ($sshOptions + @('-o', 'ClearAllForwardings=yes',
        'labagent@labhost', 'python3 -'))
    $probeOut = $probe.StandardOutput.ReadToEndAsync()
    $probeError = $probe.StandardError.ReadToEndAsync()
    $probe.StandardInput.WriteLine($probeSource)
    $probe.StandardInput.Close()
    if (-not $probe.WaitForExit(30000)) { throw 'Read-only console probe timed out after 30 seconds.' }
    if ($probe.ExitCode -ne 0) {
        throw ("Read-only console check failed. " + (Read-ConsoleDiagnostic $probeError.GetAwaiter().GetResult()))
    }
    $remote = ConvertFrom-Json -InputObject $probeOut.GetAwaiter().GetResult() -AsHashtable -NoEnumerate
    if ($remote -isnot [System.Collections.IDictionary] -or $remote.get_Count() -ne 4 -or
        $remote.name -cne 'scout-win2025' -or $remote.state -cne 'running' -or
        $remote.host -cne '127.0.0.1' -or $remote.port -isnot [long] -or
        $remote.port -lt 5900 -or $remote.port -gt 65535) { throw 'Unverified console endpoint; refusing.' }
    Stop-ConsoleChild $probe; $probe = $null

    # OpenSSH cannot inherit this reservation. A bind race must fail, never select another endpoint.
    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $reservation.Server.ExclusiveAddressUse = $true
    try { $reservation.Start(); $localPort = $reservation.LocalEndpoint.Port }
    finally { $reservation.Stop() }
    $tunnel = Start-ConsoleChild $ssh ($sshOptions + @('-N', '-o', 'ClearAllForwardings=no',
        '-o', 'ExitOnForwardFailure=yes', '-o', 'GatewayPorts=no',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
        '-L', "127.0.0.1:${localPort}:127.0.0.1:$($remote.port)", 'labagent@labhost'))
    $tunnel.StandardInput.Close()
    $tunnelOut = $tunnel.StandardOutput.ReadToEndAsync()
    $tunnelError = $tunnel.StandardError.ReadToEndAsync()
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    while (-not $ready -and $deadline.Elapsed.TotalSeconds -lt 15) {
        if ($tunnel.HasExited) { throw 'SSH forwarding failed; no graphical console was opened.' }
        # Do not accept a greeting from another process that won the reservation/SSH bind race.
        $bindings = @(& $netstat -ano -p TCP)
        if ($LASTEXITCODE -ne 0) { throw 'Could not verify the local SSH listener owner.' }
        if (-not (Test-ConsoleBinding $bindings $localPort $tunnel.Id)) {
            Start-Sleep -Milliseconds 150
            continue
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            if (-not $client.ConnectAsync('127.0.0.1', $localPort).Wait(500)) { continue }
            $stream = $client.GetStream()
            $stream.ReadTimeout = 2000
            $banner = [byte[]]::new(12); $offset = 0
            while ($offset -lt 12) {
                $count = $stream.Read($banner, $offset, 12 - $offset)
                if ($count -eq 0) { throw 'VNC closed before its protocol greeting.' }
                $offset += $count
            }
            $ready = [Text.Encoding]::ASCII.GetString($banner) -cmatch '^RFB 003\.00[378]\n$'
        }
        catch { $ready = $false }
        finally { $client.Dispose() }
        if (-not $ready) { Start-Sleep -Milliseconds 150 }
    }
    if (-not $ready -or $tunnel.WaitForExit(300)) { throw 'The private SSH forward did not verify a VNC greeting.' }

    $proxy = Start-ConsoleChild $node @($proxyFile, '--root', $root, '--dependency-dir',
        $dependencies, '--vnc-port', [string]$localPort)
    $proxy.StandardInput.Close()
    $proxyError = $proxy.StandardError.ReadToEndAsync()
    $line = $proxy.StandardOutput.ReadLineAsync()
    if (-not $line.Wait(10000) -or $proxy.HasExited) { throw 'Local console proxy did not start.' }
    $announcement = ConvertFrom-Json -InputObject $line.GetAwaiter().GetResult() -AsHashtable
    $url = [uri]$announcement.url
    if ($announcement.get_Count() -ne 1 -or $url.Scheme -cne 'http' -or
        $url.Host -cne '127.0.0.1' -or $url.Port -lt 1 -or $url.AbsolutePath -cne '/vnc.html' -or
        $url.UserInfo -ne '' -or $url.Fragment -ne '' -or
        $url.Query -cnotmatch '^\?autoconnect=1&resize=scale&path=websockify%3Ftoken%3D[0-9a-f]{64}$' -or
        $tunnel.HasExited) { throw 'The local console URL was not verified.' }
    Write-Host 'Enter/set Administrator credentials ONLY inside the Windows screen in your browser.'
    Write-Host 'No console recording is made. Do not share the browser URL or use assistant screenshots/input.'
    Write-Host 'Keep this window open; press Enter here when finished. This never stops the VM.'
    Start-Process -FilePath $url.AbsoluteUri
    $null = Read-Host 'Press Enter to close console'
}
finally {
    # Each object refers only to a child created by this invocation; never kill by process name.
    foreach ($child in @($proxy, $tunnel, $probe)) {
        try { Stop-ConsoleChild $child }
        catch { Write-Warning 'A console helper could not be cleaned up; check only this invocation''s child processes.' }
    }
}
