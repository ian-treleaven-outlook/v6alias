# Synthetic native Windows smoke: local files and processes only, no router/VM/network calls.
[CmdletBinding()]
param(
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot '..\..\target\x86_64-pc-windows-gnu\release')
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bins = (Resolve-Path $BinaryDirectory).Path
$cli = Join-Path $bins 'v6alias.exe'
$native = Join-Path $bins 'v6alias-pfsense.exe'
$example = Join-Path $root 'examples\pfsense'
$owned = Join-Path $root ('state\pfsense-native-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($owned) | Out-Null
$db = Join-Path $owned 'inventory.sqlite'
$capture = Join-Path $owned 'capture.json'
$request = Join-Path $owned 'request.json'
$simulationPath = Join-Path $owned 'simulation.json'
$current = Join-Path $owned 'current.json'
$stderr = Join-Path $owned 'stderr.json'
$utf8 = [Text.UTF8Encoding]::new($false)
$checks = 0

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

function Save-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 80), $utf8)
}

function Invoke-Local([string]$Exe, [string[]]$Arguments) {
    $lines = @(& $Exe @Arguments 2> $stderr)
    [pscustomobject]@{
        Code = $LASTEXITCODE
        Text = ($lines -join "`n")
        ErrorText = [IO.File]::ReadAllText($stderr)
    }
}

try {
    foreach ($tail in @(@('init'), @('register', '--device', (Join-Path $example 'device.json')))) {
        $result = Invoke-Local $cli (@('inventory', '--database', $db) + $tail)
        Assert-That ($result.Code -eq 0) 'Inventory setup failed'
    }
    $config = Join-Path $example 'service.yaml'
    $result = Invoke-Local $cli @('service', '--database', $db, '--service-config', $config, 'allocate',
        '--observation', (Join-Path $example 'observation.json'), '--trusted-link', 'demo-link')
    Assert-That ($result.Code -eq 0) 'Allocation failed'
    Assert-That (($result.Text | ConvertFrom-Json).address -eq 'fd12:3456:789a:a::2') 'Wrong synthetic allocation'
    $dbHash = (Get-FileHash -LiteralPath $db).Hash
    $baseline = Get-Content -Raw (Join-Path $example 'native-foreign.json') | ConvertFrom-Json
    # Only this synthetic example may be retimestamped. Never refresh real captures this way.
    $baseline.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    Save-Json $capture $baseline
    $captureHash = (Get-FileHash -LiteralPath $capture).Hash
    $common = @('--database', $db, '--service-config', $config, '--bindings',
        (Join-Path $example 'bindings.json'), '--capture', $capture)
    $result = Invoke-Local $native ($common + @('plan'))
    Assert-That ($result.Code -eq 0) 'Native planning failed'
    $plan = $result.Text | ConvertFrom-Json
    Assert-That ($plan.mode -eq 'native_plan' -and $plan.changes.Count -eq 2) 'Wrong native plan shape'
    Assert-That (-not $plan.network_writes -and $plan.approval_required) 'Missing offline safety boundary'
    Save-Json $request $plan
    $result = Invoke-Local $native ($common + @('simulate', '--request', $request))
    Assert-That ($result.Code -eq 0) 'Offline application failed'
    $simulation = $result.Text | ConvertFrom-Json
    Save-Json $simulationPath $simulation
    Save-Json $current $simulation.projection
    Assert-That ($simulation.projection.config.unbound.hosts.Count -eq 2) 'Host was not appended'
    Assert-That ($simulation.projection.config.unbound.hosts[0].descr -eq 'operator-owned') 'Foreign host was lost'
    Assert-That ($simulation.projection.config.dhcpdv6.lan.staticmap[1].earlydnsregpolicy -eq 'disable') 'Wrong native staticmap'
    Assert-That ($simulation.projection.config_revision_sha256 -eq $baseline.config_revision_sha256) 'Invented a router revision'
    $candidateArgs = @('--database', $db, '--service-config', $config, '--bindings',
        (Join-Path $example 'bindings.json'), '--capture', $current)
    $result = Invoke-Local $native ($candidateArgs + @('plan'))
    Assert-That ($result.Code -eq 0 -and ($result.Text | ConvertFrom-Json).changes.Count -eq 0) 'Exact replay was not a no-op'
    $rollbackArgs = $common + @('rollback', '--simulation', $simulationPath, '--current', $current)
    $result = Invoke-Local $native $rollbackArgs
    Assert-That ($result.Code -eq 0) 'Rollback failed'
    $rolled = $result.Text | ConvertFrom-Json
    Assert-That ($rolled.projection.config.unbound.hosts.Count -eq 1) 'Rollback did not restore hosts'
    Assert-That ($rolled.projection.config.dhcpdv6.lan.staticmap.Count -eq 1) 'Rollback did not restore staticmaps'
    Save-Json $current $rolled.projection
    $result = Invoke-Local $native $rollbackArgs
    Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) 'Rollback replay was not rejected'
    $simulation.projection.config.opaque_synthetic_note.z = 'concurrent unrelated change'
    Save-Json $current $simulation.projection
    $currentHash = (Get-FileHash -LiteralPath $current).Hash
    $result = Invoke-Local $native $rollbackArgs
    Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) 'Concurrent edit was not rejected'
    Assert-That ((Get-FileHash -LiteralPath $current).Hash -eq $currentHash) 'Failed rollback overwrote current projection'
    Assert-That ((Get-FileHash -LiteralPath $capture).Hash -eq $captureHash) 'Adapter changed original capture'
    $baseline.config_revision_sha256 = '3' * 64
    Save-Json $capture $baseline
    $result = Invoke-Local $native ($common + @('simulate', '--request', $request))
    Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) 'Stale request revision was accepted'
    $baseline.captured_at_unix_secs = 100
    Save-Json $capture $baseline
    $result = Invoke-Local $native ($common + @('plan'))
    Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) 'Stale capture produced a plan'
    $baseline.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $fixedAddress = $baseline.config.interfaces.lan.ipaddrv6
    $baseline.config.interfaces.lan.ipaddrv6 = 'track6'
    Save-Json $capture $baseline
    $result = Invoke-Local $native ($common + @('plan'))
    Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) 'Tracked native interface produced a plan'
    $baseline.config.interfaces.lan.ipaddrv6 = $fixedAddress
    $baseline.config.opaque_synthetic_note.z = 'RAW_NUMBER'
    foreach ($number in @('18446744073709551616', '18446744073709551617', '0.1')) {
        $raw = ($baseline | ConvertTo-Json -Depth 80).Replace('"RAW_NUMBER"', $number)
        [IO.File]::WriteAllText($capture, $raw, $utf8)
        $result = Invoke-Local $native ($common + @('plan'))
        Assert-That ($result.Code -ne 0 -and $result.Text.Length -eq 0) "Lossy opaque number was accepted: $number"
    }
    $baseline.config.opaque_synthetic_note.z = 'retained first'
    Save-Json $capture $baseline
    $result = Invoke-Local $native ($common + @('plan'))
    Assert-That ($result.Code -eq 0) 'Fixed interface and valid opaque values did not recover'
    Assert-That ((Get-FileHash -LiteralPath $db).Hash -eq $dbHash) 'Read-only native workflow changed inventory bytes'
    $result = Invoke-Local $cli @('service', '--database', $db, '--service-config', $config, 'plan')
    Assert-That ($result.Code -eq 0) 'Provider-neutral plan failed'
    $records = ($result.Text | ConvertFrom-Json).desired.dns_records
    Assert-That ($records.Count -eq 2 -and @($records | Where-Object ttl -ne 3600).Count -eq 0) 'AAAA/PTR TTL differs from 3600'
    Write-Output "Native Windows pfSense offline smoke passed: $checks assertions; inventory SHA256 unchanged."
} finally {
    if (Test-Path -LiteralPath $owned) { Remove-Item -LiteralPath $owned -Recurse -Force }
}
