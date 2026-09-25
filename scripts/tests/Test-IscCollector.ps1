# Native Windows smoke; entirely synthetic and local, no VM/network operations.
[CmdletBinding()]
param(
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot '..\..\target\x86_64-pc-windows-gnu\release')
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bins = (Resolve-Path $BinaryDirectory).Path
$cli = Join-Path $bins 'v6alias.exe'
$collector = Join-Path $bins 'v6alias-collect-isc.exe'
$daemon = Join-Path $bins 'v6aliasd.exe'
foreach ($exe in @($cli, $collector, $daemon)) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing executable: $exe" }
}
$owned = Join-Path $root ('state\isc-native-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($owned) | Out-Null
$db = Join-Path $owned 'inventory.sqlite'
$config = Join-Path $root 'service.example.yaml'
$capture = Join-Path $owned 'capture.json'
$snapshot = Join-Path $owned 'observations.json'
$stderr = Join-Path $owned 'stderr.jsonl'
$utf8 = [Text.UTF8Encoding]::new($false)

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-CheckedNative([string]$Exe, [string[]]$Arguments) {
    $lines = @(& $Exe @Arguments 2> $stderr)
    [pscustomobject]@{
        Code = $LASTEXITCODE
        Text = ($lines -join "`n")
        ErrorText = [IO.File]::ReadAllText($stderr)
    }
}

function Write-Capture([string]$Leases, [long]$Time) {
    $value = @{
        schema_version = 1
        source = 'synthetic-isc'
        captured_at_unix_secs = $Time
        lease_file = $Leases
    }
    [IO.File]::WriteAllText($capture, ($value | ConvertTo-Json -Depth 10 -Compress), $utf8)
}

try {
    foreach ($tail in @(
        @('init'),
        @('register', '--device', (Join-Path $root 'examples\offline\device.json'))
    )) {
        $result = Invoke-CheckedNative $cli (@('inventory', '--database', $db) + $tail)
        Assert-That ($result.Code -eq 0) "Inventory setup failed: $($result.ErrorText)"
    }
    $time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $leases = [IO.File]::ReadAllText((Join-Path $root 'examples\isc\synthetic-active.leases'))
    $leases = $leases.Replace('ends never;', "ends epoch $($time + 3600);")
    Write-Capture $leases $time
    $captureHash = (Get-FileHash -LiteralPath $capture).Hash
    $dbHash = (Get-FileHash -LiteralPath $db).Hash
    $collectArgs = @('--capture', $capture, '--service-config', $config, '--source', 'synthetic-isc', '--trusted-link', 'corp-link', '--once')
    $daemonArgs = @('--database', $db, '--service-config', $config, '--observations', $snapshot, '--source', 'synthetic-isc', '--trusted-link', 'corp-link', '--once')
    $result = Invoke-CheckedNative $collector $collectArgs
    Assert-That ($result.Code -eq 0) "Collection failed: $($result.ErrorText)"
    Assert-That (-not $result.Text.Contains([char]27)) 'ANSI in collector stdout'
    Assert-That ((Get-FileHash -LiteralPath $capture).Hash -eq $captureHash) 'Collector changed capture'
    Assert-That ((Get-FileHash -LiteralPath $db).Hash -eq $dbHash) 'Collector changed DB'
    $normalized = $result.Text | ConvertFrom-Json
    Assert-That ($normalized.captured_at_unix_secs -eq $time) 'Capture timestamp was relabeled'
    Assert-That ($normalized.observations.Count -eq 1) 'Wrong selected observation count'
    Assert-That ($null -eq $normalized.observations[0].hostname) 'Hostname was not null'
    [IO.File]::WriteAllText($snapshot, $result.Text + "`n", $utf8)
    $aliases = @()
    1..2 | ForEach-Object {
        $result = Invoke-CheckedNative $daemon $daemonArgs
        Assert-That ($result.Code -eq 0) "Daemon failed: $($result.ErrorText)"
        $cycle = $result.Text | ConvertFrom-Json
        $aliases += $cycle.outcomes[0].alias
        Assert-That ($cycle.outcomes[0].assignment.address -eq 'fd7a:115c:a1e0:17::2') 'Unstable address'
        Assert-That ($cycle.outcomes[0].assignment.fqdn -eq 'demo-workstation.v6alias.home.arpa.') 'DNS did not use inventory'
    }
    Assert-That (($aliases -join ',') -eq 'corp:2,corp:2') 'Replay did not preserve corp:2'

    $unknown = "`nia-na 01:00:00:00:cc:dd { iaaddr fd7a:115c:a1e0:17::1001 { binding state active; preferred-life 60; max-life 120; ends epoch $($time + 3600); } }"
    Write-Capture ($leases + $unknown) $time
    $result = Invoke-CheckedNative $collector $collectArgs
    Assert-That ($result.Code -eq 0) 'Unknown identity should normalize, not authorize'
    [IO.File]::WriteAllText($snapshot, $result.Text + "`n", $utf8)
    $result = Invoke-CheckedNative $daemon $daemonArgs
    Assert-That ($result.Code -eq 0) 'Unknown identity broke the shadow cycle'
    $cycle = $result.Text | ConvertFrom-Json
    $denied = @($cycle.outcomes | Where-Object duid -eq 'ccdd')
    Assert-That ($denied.Count -eq 1 -and -not $denied[0].decision.allowed -and $null -eq $denied[0].assignment) 'Unknown identity was not denied'
    $result = Invoke-CheckedNative $cli @('inventory', '--database', $db, 'list')
    Assert-That ($result.Code -eq 0) 'Inventory read failed'
    $inventory = $result.Text | ConvertFrom-Json
    Assert-That (@($inventory).Count -eq 1) 'Unknown identity was registered'

    $dbHash = (Get-FileHash -LiteralPath $db).Hash
    foreach ($case in @('stale', 'future', 'malformed')) {
        switch ($case) {
            stale { Write-Capture $leases ($time - 1000) }
            future { Write-Capture $leases ($time + 3600) }
            malformed { Write-Capture ($leases + "`nia-na 01:00:00:00:aa:bb {") $time }
        }
        $result = Invoke-CheckedNative $collector $collectArgs
        Assert-That ($result.Code -eq 1 -and $result.Text.Length -eq 0) "$case capture was not rejected without stdout"
        $diagnostic = $result.ErrorText | ConvertFrom-Json
        Assert-That ($diagnostic.event -eq 'fatal') "$case rejection did not have a structured diagnostic"
        Assert-That ((Get-FileHash -LiteralPath $db).Hash -eq $dbHash) "$case capture changed DB"
    }
    Write-Capture ([IO.File]::ReadAllText((Join-Path $root 'examples\isc\synthetic-empty.leases'))) $time
    $result = Invoke-CheckedNative $collector $collectArgs
    Assert-That ($result.Code -eq 0) 'Empty synthetic header failed'
    Assert-That (($result.Text | ConvertFrom-Json).observations.Count -eq 0) 'Empty capture produced observations'
    [pscustomobject]@{
        mode = 'synthetic_native_windows_smoke'
        stable_aliases = $aliases
        unknown_denied = $true
        auto_registered = $false
        rejected = @('stale', 'future', 'malformed')
        empty_observations = 0
        result = 'passed'
    } | ConvertTo-Json -Depth 5 -Compress
}
finally {
    # Only this invocation's uniquely named synthetic child directory is removed.
    Remove-Item -LiteralPath $owned -Recurse -Force
}
