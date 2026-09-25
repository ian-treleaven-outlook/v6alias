# Bootstrap for the NEW isolated Windows test guest only. Run from its tools CD.
# Windows PowerShell is used only to install the offline PowerShell 7 payload.
# No product key, password, private SSH key, or Internet download belongs here.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$MediaRoot)
$ErrorActionPreference = 'Stop'
$root = 'C:\V6Alias'

if ($env:COMPUTERNAME -ne 'CORP-44') {
    throw 'This bootstrap is restricted to the corp-44 Windows test guest.'
}
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ($os.InstallationType -ne 'Server Core' -or $os.EditionID -ne 'ServerStandard') {
    throw 'Expected Windows Server Standard, Server Core installation.'
}
if (-not (Test-Path -LiteralPath (Join-Path $MediaRoot 'SCOUT_WIN2025_TOOLS.txt'))) {
    throw 'The approved offline tools media is not present.'
}
if (Test-Path -LiteralPath $root) {
    throw 'C:\V6Alias already exists. Review its state instead of overwriting it.'
}
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $payload = Get-Content -LiteralPath (Join-Path $MediaRoot 'payload.json') -Raw | ConvertFrom-Json
    foreach ($entry in $payload.files) {
        if ($entry.name -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid payload filename.' }
        $source = Join-Path $MediaRoot $entry.name
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash -ne $entry.sha256) {
            throw "Offline payload checksum failed: $($entry.name)"
        }
    }
    Copy-Item -LiteralPath (Join-Path $MediaRoot 'v6alias.exe') -Destination $root
    Copy-Item -LiteralPath (Join-Path $MediaRoot 'v6alias.yaml') -Destination $root
    Copy-Item -LiteralPath (Join-Path $MediaRoot 'V6AliasDemo.psm1') -Destination $root
    $powershell = Join-Path $root 'PowerShell7'
    Expand-Archive -LiteralPath (Join-Path $MediaRoot $payload.powershell_archive) -DestinationPath $powershell
    $pwsh = Join-Path $powershell 'pwsh.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $pwsh
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'Offline PowerShell executable is not validly signed by Microsoft.'
    }

    # Exactly one virtual NIC, kept disconnected by libvirt until host-side
    # approval checks finish. No default gateway, DNS server, or DHCP is added.
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw 'Expected exactly one detected Ethernet adapter; driver review required.' }
    $index = $adapters[0].ifIndex
    # With no static IPv4 address, Windows may keep reporting IPv4 DHCP enabled.
    # This test NIC is IPv6-only; unbind IPv4 instead of adding an unwanted address.
    Disable-NetAdapterBinding -Name $adapters[0].Name -ComponentID ms_tcpip | Out-Null
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -Dhcp Disabled -RouterDiscovery Disabled
    $defaults = @(Get-NetRoute -InterfaceIndex $index -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
    if ($defaults.Count) { throw 'Unexpected default route. Guest must remain disconnected for review.' }
    $existing = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 |
        Where-Object { $_.IPAddress -notlike 'fe80:*' })
    if ($existing.Count) { throw 'Unexpected pre-existing non-link-local IPv6 address.' }
    New-NetIPAddress -InterfaceIndex $index -IPAddress $payload.address -PrefixLength 64 |
        Out-Null
    $check = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6
    if ($check.Dhcp -ne 'Disabled' -or $check.RouterDiscovery -ne 'Disabled') {
        throw 'The required DHCP/RA isolation settings were not retained.'
    }
    if ((Get-NetAdapterBinding -Name $adapters[0].Name -ComponentID ms_tcpip).Enabled) {
        throw 'IPv4 must remain unbound on the dedicated IPv6 test NIC.'
    }
    # Keep remote administration disabled until its scoped credentials and
    # firewall rules are explicitly arranged. Local console testing works now.
    Set-Service -Name sshd -StartupType Disabled
    Stop-Service -Name sshd -ErrorAction Stop
    $version = & $pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    if ($LASTEXITCODE -ne 0) { throw 'PowerShell 7 failed to launch on Server Core.' }
    $toolVersion = & (Join-Path $root 'v6alias.exe') --version
    if ($LASTEXITCODE -ne 0) { throw 'V6Alias failed to launch on Server Core.' }
    @{
        status = 'prepared-offline'; computer = $env:COMPUTERNAME
        edition = $os.EditionID; installation = $os.InstallationType
        powershell = "$version"; v6alias = "$toolVersion"; adapter_count = $adapters.Count
        ipv4_binding = 'Disabled'; dhcpv6 = 'Disabled'; router_discovery = 'Disabled'; default_routes = 0
        guest_network_link_requires_host_approval = $true
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'setup-status.json') -Encoding UTF8
}
catch {
    @{status = 'failed'; error = $_.Exception.Message; guest_must_remain_disconnected = $true} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'setup-status.json') -Encoding UTF8
    throw
}
