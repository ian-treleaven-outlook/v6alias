# Finish the first offline bootstrap without reinstalling or overwriting user data.
# This script is for the one new CORP-44 Server Core guest, not the Windows laptop.
#Requires -Version 7.3
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:COMPUTERNAME -ne 'CORP-44' -or
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType -ne 'Server Core') {
    throw 'This script is restricted to the CORP-44 Server Core guest.'
}
$statusPath = 'C:\V6Alias\setup-status.json'
$status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json -AsHashtable
if ($status.status -ne 'prepared-offline') { throw 'Initial bootstrap is not in its expected prepared state.' }
$adapter = @(Get-NetAdapter -Physical)
if ($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Disconnected') {
    throw 'The sole test NIC must still be disconnected before this final setup step.'
}
# Do not invent IPv4 addressing merely to suppress DHCP. The test link is IPv6-only.
Disable-NetAdapterBinding -Name $adapter[0].Name -ComponentID ms_tcpip | Out-Null
Set-NetIPInterface -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv6 -Dhcp Disabled -RouterDiscovery Disabled
if ((Get-NetAdapterBinding -Name $adapter[0].Name -ComponentID ms_tcpip).Enabled) {
    throw 'IPv4 binding is unexpectedly still enabled.'
}
$v6 = Get-NetIPInterface -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv6
if ($v6.Dhcp -ne 'Disabled' -or $v6.RouterDiscovery -ne 'Disabled') {
    throw 'IPv6 DHCP or Router Discovery is unexpectedly enabled.'
}
if (@(Get-NetRoute | Where-Object DestinationPrefix -in @('::/0','0.0.0.0/0')).Count) {
    throw 'Unexpected default route; keep the guest disconnected.'
}
if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) {
    throw 'A Windows firewall profile is disabled; manual review required.'
}
# No remote management is needed for this initial client-only testing phase.
Stop-Service WinRM -ErrorAction Stop
Set-Service WinRM -StartupType Disabled
$status.Remove('dhcp')
$status.ipv4_binding = 'Disabled'
$status.dhcpv6 = 'Disabled'
$status.winrm = 'Disabled'
$status.router_discovery = 'Disabled'
$status.default_routes = 0
$status | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8NoBOM
Write-Host 'CORP-44 prepared: IPv6-only static test NIC; no DHCP, Router Discovery, default route or remote management.'
