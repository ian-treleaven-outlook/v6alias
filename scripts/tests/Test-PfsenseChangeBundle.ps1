#requires -Version 7.3
# Synthetic local files/processes only. No router, VM, credentials, or network.
[CmdletBinding()]
param(
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot '..\..\target\x86_64-pc-windows-gnu\release')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bins = [IO.Path]::GetFullPath($BinaryDirectory)
$cli = Join-Path $bins 'v6alias.exe'
$native = Join-Path $bins 'v6alias-pfsense.exe'
$prepare = Join-Path $root 'scripts\Prepare-PfsenseChange.ps1'
$example = Join-Path $root 'examples\pfsense'
$owned = Join-Path $root ('state\bundle-test-' + [Guid]::NewGuid().ToString('N'))
$inputs = Join-Path $owned 'inputs with spaces & [literal]'
$utf8 = [Text.UTF8Encoding]::new($false)
$checks = 0

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

function Save-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 80), $utf8)
}

function Read-Json([string]$Path) {
    return [IO.File]::ReadAllText($Path) | ConvertFrom-Json -Depth 80
}

function Get-Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Local([string]$Exe, [string[]]$Arguments) {
    $stderr = Join-Path $owned 'stderr.json'
    $lines = @(& $Exe @Arguments 2> $stderr)
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($lines -join "`n") }
}

function Assert-Refused([hashtable]$Arguments, [string]$Message, [string]$ErrorPattern = '') {
    $failed = $false
    $text = ''
    try { $null = & $prepare @Arguments 6>$null }
    catch { $failed = $true; $text = $_.Exception.Message }
    Assert-That $failed $Message
    if ($ErrorPattern) { Assert-That ($text -match $ErrorPattern) "Unexpected refusal reason: $Message" }
    Assert-That (-not [IO.Path]::Exists($Arguments.OutputDirectory)) "Failed preparation published output: $Message"
    Assert-That (@(Get-ChildItem -LiteralPath $owned -Directory -Force -Filter '.pfsense-prepare-*').Count -eq 0) 'Staging directory leaked'
}

try {
    [IO.Directory]::CreateDirectory($inputs) | Out-Null
    $db = Join-Path $inputs 'inventory.sqlite'
    $config = Join-Path $inputs 'service configuration.yaml'
    $binding = Join-Path $inputs 'binding data.json'
    $capture = Join-Path $inputs 'captured projection.json'
    [IO.File]::Copy((Join-Path $example 'service.yaml'), $config)
    [IO.File]::Copy((Join-Path $example 'bindings.json'), $binding)
    foreach ($tail in @(@('init'), @('register', '--device', (Join-Path $example 'device.json')))) {
        $result = Invoke-Local $cli (@('inventory', '--database', $db) + $tail)
        Assert-That ($result.Code -eq 0) 'Synthetic inventory setup failed'
    }
    $result = Invoke-Local $cli @('service', '--database', $db, '--service-config', $config, 'allocate',
        '--observation', (Join-Path $example 'observation.json'), '--trusted-link', 'demo-link')
    Assert-That ($result.Code -eq 0) 'Synthetic allocation failed'
    $baseline = Read-Json (Join-Path $example 'native-foreign.json')
    # This fixture is synthetic. Actual captures must never be retimestamped.
    $baseline.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $baseline.config.unbound.hosts[0].opaque_host_note[1] = [uint64]::MaxValue
    $baseline.config.opaque_synthetic_note.z = 'Untrusted $(throw "never execute") ; & opaque data'
    Save-Json $capture $baseline
    $original = @{}
    foreach ($file in @($db, $config, $binding, $capture, $native)) { $original[$file] = Get-Hash $file }
    $parameters = @{ Database = $db; ServiceConfig = $config; Bindings = $binding; Capture = $capture
        OutputDirectory = (Join-Path $owned 'review bundle & [literal]'); BinaryDirectory = $bins; MaxAgeSeconds = 300 }
    $result = & $prepare @parameters 6>$null
    Assert-That ($result.actions -eq 2 -and -not $result.approval_granted -and -not $result.live_changes) 'Wrong preparation result'
    $bundle = $result.bundle_path
    $manifest = Read-Json (Join-Path $bundle 'manifest.json')
    $review = Read-Json (Join-Path $bundle 'review.json')
    $request = Read-Json (Join-Path $bundle 'request.json')
    $simulation = Read-Json (Join-Path $bundle 'simulation.json')
    Assert-That ($manifest.schema_version -eq 1 -and $manifest.mode -eq 'approval_bundle') 'Wrong manifest schema'
    Assert-That (-not $manifest.live_changes -and -not $manifest.network_writes -and
        -not $manifest.approval_granted -and $manifest.approval_required) 'Manifest claimed live authority'
    Assert-That ($manifest.request_sha256 -ceq $simulation.rollback.request_sha256 -and
        $result.request_sha256 -ceq $manifest.request_sha256 -and $review.request_sha256 -ceq $manifest.request_sha256) 'Canonical request proof not propagated'
    Assert-That ($manifest.request_sha256 -cne (Get-Hash (Join-Path $bundle 'request.json'))) 'Canonical digest confused with raw artifact digest'
    Assert-That ($result.manifest_sha256 -ceq (Get-Hash (Join-Path $bundle 'manifest.json'))) 'Manifest digest mismatch'
    Assert-That ($manifest.captured_at_unix_secs -eq $baseline.captured_at_unix_secs -and
        (Read-Json (Join-Path $bundle 'baseline.json')).captured_at_unix_secs -eq $baseline.captured_at_unix_secs) 'Capture was relabeled'
    Assert-That ([DateTimeOffset]::Parse($manifest.expires_at).ToUnixTimeSeconds() -eq
        $baseline.captured_at_unix_secs + 300) 'Expiry is not frozen to original capture'
    Assert-That ($manifest.expected_revision_sha256 -ceq $baseline.config_revision_sha256 -and
        $request.expected_revision_sha256 -ceq $baseline.config_revision_sha256) 'Original revision lost'
    Assert-That ($manifest.source -ceq 'synthetic-native' -and $manifest.actions -eq 2 -and
        $manifest.counters.Count -eq 2 -and $manifest.approved_paths.Count -eq 2) 'Missing review metadata'
    Assert-That (($review.changes | ConvertTo-Json -Depth 80 -Compress) -ceq
        ($request.changes | ConvertTo-Json -Depth 80 -Compress)) 'Review changed native before/after data'
    Assert-That ([IO.File]::ReadAllText((Join-Path $bundle 'review.json')).Contains('18446744073709551615')) 'Review lost opaque uint64 precision'
    Assert-That (-not $review.approval_granted -and -not $review.live_changes -and
        $review.blocked_action_reason -match 'explicit_operator_approval') 'Review granted approval'
    foreach ($property in $manifest.artifacts.PSObject.Properties) {
        $file = Join-Path $bundle $property.Name
        Assert-That ((Get-Hash $file) -ceq $property.Value.sha256) "Artifact digest mismatch: $($property.Name)"
        Assert-That ((Get-Item -LiteralPath $file).Length -eq $property.Value.bytes) "Artifact length mismatch: $($property.Name)"
    }
    foreach ($property in $manifest.source_files.PSObject.Properties) {
        Assert-That ((Get-Hash $property.Value.path) -ceq $property.Value.sha256) 'Manifest source digest mismatch'
        Assert-That ($property.Value.identity.Length -gt 30) 'Missing source identity'
    }
    Assert-That ($manifest.generator.sha256 -ceq $original[$native] -and -not $manifest.generator.copied -and
        $manifest.generator.version -match '^v6alias-pfsense ') 'Generator provenance missing'
    $expected = @('baseline.json', 'bindings.json', 'manifest.json', 'request.json', 'review.json', 'service.yaml', 'simulation.json')
    $actual = @(Get-ChildItem -LiteralPath $bundle -File | Select-Object -ExpandProperty Name | Sort-Object)
    Assert-That (($actual -join '|') -ceq ($expected -join '|')) 'Unexpected file, database, binary or raw config included'
    foreach ($pair in @(@($capture, 'baseline.json'), @($config, 'service.yaml'), @($binding, 'bindings.json'))) {
        Assert-That ((Get-Hash (Join-Path $bundle $pair[1])) -ceq $original[$pair[0]]) 'Bundled input bytes changed'
    }
    $acl = Get-Acl -LiteralPath $bundle
    Assert-That $acl.AreAccessRulesProtected 'Bundle inherits a potentially public ACL'
    $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expectedSids = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18') | Sort-Object -Unique
    Assert-That (($sids -join '|') -ceq ($expectedSids -join '|')) 'Bundle ACL not limited to user and SYSTEM'
    $common = @('--database', $db, '--service-config', $config, '--bindings', $binding, '--capture', $capture)
    $again = Invoke-Local $native ($common + @('simulate', '--request', (Join-Path $bundle 'request.json')))
    Assert-That ($again.Code -eq 0 -and ($again.Text | ConvertFrom-Json).rollback.request_sha256 -ceq
        $manifest.request_sha256) 'Independent Rust simulation rejected bundled request'

    $occupied = Join-Path $owned 'already occupied'
    [IO.Directory]::CreateDirectory($occupied) | Out-Null
    $sentinel = Join-Path $occupied 'foreign.txt'
    [IO.File]::WriteAllText($sentinel, 'never overwrite')
    $negative = $parameters.Clone(); $negative.OutputDirectory = $occupied
    $failed = $false
    try { $null = & $prepare @negative 6>$null } catch { $failed = $true }
    Assert-That ($failed -and [IO.File]::ReadAllText($sentinel) -ceq 'never overwrite') 'Occupied foreign directory was modified'
    $negative.OutputDirectory = Join-Path $owned 'occupied file'
    [IO.File]::WriteAllText($negative.OutputDirectory, 'foreign file')
    $failed = $false
    try { $null = & $prepare @negative 6>$null } catch { $failed = $true }
    Assert-That ($failed -and [IO.File]::ReadAllText($negative.OutputDirectory) -ceq 'foreign file') 'Occupied file was modified'

    $badCapture = Join-Path $inputs 'invalid capture.json'
    $negative = $parameters.Clone(); $negative.Capture = $badCapture
    $negative.OutputDirectory = Join-Path $owned 'stale output'
    $baseline.captured_at_unix_secs = 100
    Save-Json $badCapture $baseline
    Assert-Refused $negative 'Stale capture accepted' 'new capture'
    $baseline.captured_at_unix_secs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600
    Save-Json $badCapture $baseline
    Assert-Refused $negative 'Future capture accepted' 'new capture'
    $baseline = Read-Json $capture
    $baseline.config.interfaces.lan.ipaddrv6 = 'track6'
    Save-Json $badCapture $baseline
    Assert-Refused $negative 'Native compiler rejection was ignored' 'planner/simulator failed'
    [IO.File]::WriteAllText($badCapture, '{"schema_version":1')
    Assert-Refused $negative 'Malformed input accepted'
    $baseline = Read-Json $capture
    $baseline.config | Add-Member -NotePropertyName system -NotePropertyValue @{ password = 'SYNTHETIC-DO-NOT-PRINT' }
    Save-Json $badCapture $baseline
    Assert-Refused $negative 'Raw configuration or credentials accepted' 'Secret-free'

    $negative = $parameters.Clone(); $negative.OutputDirectory = Join-Path $owned 'rejected output'
    $negative.Capture = Join-Path $inputs 'missing.json'
    Assert-Refused $negative 'Missing input accepted'
    $negative.Capture = '\\localhost\never-contact\capture.json'
    Assert-Refused $negative 'UNC input accepted'
    $negative.Capture = 'relative.json'
    Assert-Refused $negative 'Relative input accepted'
    $negative.Capture = $capture + ':stream'
    Assert-Refused $negative 'Alternate stream accepted'
    $negative.Capture = $inputs
    Assert-Refused $negative 'Directory used as an input file'
    $negative.Capture = $capture
    $negative.BinaryDirectory = '.\target'
    Assert-Refused $negative 'Relative binary directory accepted'
    $negative.BinaryDirectory = $bins
    $negative.MaxAgeSeconds = 0
    Assert-Refused $negative 'Zero maximum age accepted'
    $negative.MaxAgeSeconds = 86401
    Assert-Refused $negative 'Unbounded maximum age accepted'
    $negative = $parameters.Clone()
    $negative.OutputDirectory = Join-Path $root ('scripts\never-create-' + [Guid]::NewGuid().ToString('N'))
    Assert-Refused $negative 'Output under repository code accepted'
    $negative.OutputDirectory = Join-Path $owned 'rejected output'
    $oversize = Join-Path $inputs 'oversize.json'
    $stream = [IO.File]::OpenWrite($oversize)
    try { $stream.SetLength(16MB + 1) } finally { $stream.Dispose() }
    $negative.Capture = $oversize
    Assert-Refused $negative 'Oversized JSON accepted'
    $negative.Capture = $capture
    $negative.ServiceConfig = $oversize
    Assert-Refused $negative 'Oversized YAML accepted'
    $negative.ServiceConfig = $config
    $linked = Join-Path $inputs 'hardlinked.json'
    New-Item -ItemType HardLink -Path $linked -Target $capture | Out-Null
    $negative.Capture = $linked
    Assert-Refused $negative 'Hardlinked input accepted'
    Remove-Item -LiteralPath $linked
    $junction = Join-Path $owned 'reparse directory'
    New-Item -ItemType Junction -Path $junction -Target $inputs | Out-Null
    $negative.Capture = Join-Path $junction 'captured projection.json'
    Assert-Refused $negative 'Reparse ancestor accepted'
    Remove-Item -LiteralPath $junction
    $negative.Capture = $capture
    $sidecar = $db + '-wal'
    [IO.File]::WriteAllText($sidecar, 'synthetic sidecar')
    Assert-Refused $negative 'Unhashed inventory sidecar accepted'
    Remove-Item -LiteralPath $sidecar

    $badRequest = Join-Path $inputs 'bad request.json'
    $request.expected_revision_sha256 = '3' * 64
    Save-Json $badRequest $request
    $invalid = Invoke-Local $native ($common + @('simulate', '--request', $badRequest))
    Assert-That ($invalid.Code -ne 0 -and $invalid.Text.Length -eq 0) 'Tampered reviewed request passed native simulation'
    Assert-That (-not [IO.Path]::Exists($negative.OutputDirectory)) 'Bad request produced a final bundle'

    $noOpCapture = Join-Path $inputs 'no op capture.json'
    Save-Json $noOpCapture $simulation.projection
    $noOp = $parameters.Clone(); $noOp.Capture = $noOpCapture; $noOp.OutputDirectory = Join-Path $owned 'no op bundle'
    $noOpResult = & $prepare @noOp 6>$null
    $noOpManifest = Read-Json (Join-Path $noOpResult.bundle_path 'manifest.json')
    Assert-That ($noOpResult.actions -eq 0 -and $noOpManifest.no_op -and
        $noOpManifest.blocked_action_reason -match 'no_changes' -and -not $noOpManifest.approval_granted) 'No-op bundle is misleading'

    $spaceBins = Join-Path $owned 'bin with spaces & [literal]'
    [IO.Directory]::CreateDirectory($spaceBins) | Out-Null
    [IO.File]::Copy($native, (Join-Path $spaceBins 'v6alias-pfsense.exe'))
    $spaceArgs = $parameters.Clone(); $spaceArgs.BinaryDirectory = $spaceBins
    $spaceArgs.OutputDirectory = Join-Path $owned 'space binary bundle'
    $spaceResult = & $prepare @spaceArgs 6>$null
    Assert-That ($spaceResult.request_sha256 -ceq $result.request_sha256) 'Executable path argument handling changed request'
    $defaults = $parameters.Clone()
    if (-not $PSBoundParameters.ContainsKey('BinaryDirectory')) {
        $defaults.Remove('BinaryDirectory')
    }
    $defaults.Remove('MaxAgeSeconds')
    $defaults.OutputDirectory = Join-Path $owned 'default bundle'
    $defaultResult = & $prepare @defaults 6>$null
    Assert-That ($defaultResult.request_sha256 -ceq $result.request_sha256) 'Selected binary path or default freshness policy changed request'

    # Unit probes reuse only reviewed functions; no mock compiler or altered approval proof.
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($prepare, [ref]$tokens, [ref]$parseErrors)
    Assert-That ($parseErrors.Count -eq 0) 'Preparation script parse errors'
    foreach ($name in @('Get-LocalPath', 'Get-StreamHash', 'Open-Source', 'Assert-StableSources')) {
        $definition = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $changing = Join-Path $inputs 'changing.txt'
    [IO.File]::WriteAllText($changing, 'before')
    $snapshot = Open-Source $changing 1MB
    try {
        $failed = $false
        try { [IO.File]::WriteAllText($changing, 'during') } catch { $failed = $true }
        Assert-That $failed 'Source handle allowed a concurrent writer'
    } finally { $snapshot.stream.Dispose() }
    [IO.File]::WriteAllText($changing, 'after!')
    $failed = $false
    try { Assert-StableSources @{ changing = $snapshot } } catch { $failed = $true }
    Assert-That $failed 'Changed source was not detected by identity/hash comparison'
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    $payload = 'literal spaces & [] "quote" --not-an-option'
    $argumentProbe = Join-Path $owned 'argument probe.ps1'
    [IO.File]::WriteAllText($argumentProbe, 'param([string]$Value) [Console]::Write($Value)', $utf8)
    $argResult = [PfsensePreparation.Local]::Run($pwsh,
        @('-NoProfile', '-NonInteractive', '-File', $argumentProbe, '-Value', $payload), $owned)
    Assert-That ($argResult -ceq $payload) 'ArgumentList did not preserve opaque arguments'
    $failed = $false
    $pidPath = Join-Path $owned 'owned child pid.txt'
    $timeoutProbe = Join-Path $owned 'timeout probe.ps1'
    [IO.File]::WriteAllText($timeoutProbe,
        'param([string]$PidFile) [IO.File]::WriteAllText($PidFile, [string]$PID); Start-Sleep -Seconds 30', $utf8)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try { $null = [PfsensePreparation.Local]::Run($pwsh,
        @('-NoProfile', '-NonInteractive', '-File', $timeoutProbe, '-PidFile', $pidPath), $owned, 3000) } catch { $failed = $true }
    Assert-That $failed 'Process timeout was not bounded'
    Assert-That ($clock.Elapsed.TotalSeconds -lt 10) 'Child timeout exceeded its bounded wait'
    Assert-That ([IO.File]::Exists($pidPath)) 'Timeout probe did not start'
    $childId = [int][IO.File]::ReadAllText($pidPath)
    $alive = $false
    try { $process = [Diagnostics.Process]::GetProcessById($childId); $alive = -not $process.HasExited; $process.Dispose() } catch [ArgumentException] {}
    Assert-That (-not $alive) 'Owned child survived timeout'
    foreach ($script in @('[Console]::Write("x" * 100000)', '[Console]::Error.Write("x" * 100000)', 'exit 7')) {
        $failed = $false
        try { $null = [PfsensePreparation.Local]::Run($pwsh,
            @('-NoProfile', '-NonInteractive', '-Command', $script), $owned, 30000, 1024, 1024) } catch { $failed = $true }
        Assert-That $failed 'Child failure/output limit was ignored'
    }
    foreach ($file in $original.Keys) { Assert-That ((Get-Hash $file) -ceq $original[$file]) 'Original input changed' }
    Assert-That (@(Get-ChildItem -LiteralPath $owned -Directory -Force -Filter '.pfsense-prepare-*').Count -eq 0) 'Final staging leak'
    Write-Output "Local pfSense approval bundle tests passed: $checks assertions; inputs unchanged; no live actions."
} finally {
    if ([IO.Directory]::Exists($owned)) { Remove-Item -LiteralPath $owned -Recurse -Force }
}
