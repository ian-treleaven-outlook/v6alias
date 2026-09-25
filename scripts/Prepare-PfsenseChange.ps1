#requires -Version 7.3
<#
.SYNOPSIS
Prepares a private, LOCAL-ONLY pfSense change bundle for operator review.
.DESCRIPTION
Runs the native read-only planner and simulator, never a router/VM/SSH command.
Requires Windows PowerShell 7.3+ (pwsh), existing local inputs, and an existing
output parent directory. OutputDirectory must not exist. Inside this repository,
only state\ is an allowed output location; choose a private local parent elsewhere
if preferred. A sibling staging directory is created with inheritance disabled
and access limited to the current Windows user and SYSTEM, then renamed atomically.
Parent directories and the generator must be trusted. This ACL is not protection
against another process running as the same user or an administrator swapping
directories. Manifest hashes provide integrity references, not authenticity.

Inputs must be secret-free project projections/configuration, NOT config.xml.
Known credential-bearing fields are refused; arbitrary opaque text cannot be
certified secret-free. Review inputs before use. No database or binary is copied.
Input handles deny concurrent writes/deletes, and identities and SHA256 hashes
are checked again before publication. Cargo's hardlinked generator executables
are accepted under the same read lock; data inputs must have exactly one link.
Close inventory writers first. Limits:
database 512 MiB, executable 128 MiB, YAML 1 MiB, JSON/stdout 16 MiB,
stderr 64 KiB, paths 240 characters (output parents at most 172 characters),
and each child process 30 seconds.

The original capture timestamp is never refreshed. Expired captures require a
new independently obtained capture. The simulation's canonical request hash is
an operator review reference, NOT an approval token. Nothing grants approval,
installs a helper, persists router configuration, or activates services.
Subsequent explicit approval, installation, fresh validation and any live action
are separate steps. Manifest artifact hashes exclude the manifest itself;
retain its separately returned SHA256 if distributing the bundle.

Returns one object with bundle_path, request_sha256, manifest_sha256, actions,
approval_granted and live_changes. A concise summary uses the information stream.
.EXAMPLE
.\scripts\Prepare-PfsenseChange.ps1 -Database D:\v6alias\state\inventory.sqlite `
  -ServiceConfig D:\v6alias\state\service.yaml -Bindings D:\v6alias\state\bindings.json `
  -Capture D:\v6alias\state\capture.json -OutputDirectory D:\v6alias\state\review-001
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Database,
    [Parameter(Mandatory)][string]$ServiceConfig,
    [Parameter(Mandatory)][string]$Bindings,
    [Parameter(Mandatory)][string]$Capture,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$BinaryDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\target\x86_64-pc-windows-gnu\release')),
    [ValidateRange(1, 86400)][int]$MaxAgeSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Preparation requires Windows and local Windows files.' }

if (-not ('PfsensePreparation.Local' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace PfsensePreparation {
    public static class Local {
        [StructLayout(LayoutKind.Sequential)]
        private struct Info {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes {
            public int Length;
            public IntPtr Descriptor;
            public int Inherit;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

        public static void CreatePrivateDirectory(string path, byte[] descriptor) {
            var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try {
                var attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject(), Inherit = 0
                };
                // Unlike Directory.CreateDirectory, this fails if the name already exists.
                if (!CreateDirectoryW(path, ref attributes)) throw new IOException("Private directory creation refused.");
            } finally { pinned.Free(); }
        }

        public static string Identity(FileStream file, bool allowHardlinks = false) {
            if (!GetFileInformationByHandle(file.SafeFileHandle, out Info i) ||
                i.Links == 0 || (!allowHardlinks && i.Links != 1) || (i.Attributes & (0x10 | 0x400)) != 0)
                throw new IOException("Regular single-link non-reparse file required.");
            return $"{i.Volume:x8}:{i.IndexHigh:x8}{i.IndexLow:x8}:" +
                $"{i.Creation.dwHighDateTime:x8}{i.Creation.dwLowDateTime:x8}:" +
                $"{i.Write.dwHighDateTime:x8}{i.Write.dwLowDateTime:x8}:{file.Length}:{i.Links}";
        }

        private static async Task<byte[]> ReadBounded(Stream input, int limit) {
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) != 0) {
                if (output.Length + n > limit) throw new IOException("Output limit exceeded.");
                output.Write(buffer, 0, n);
            }
            return output.ToArray();
        }

        public static string Run(string exe, string[] args, string directory, int timeoutMs = 30000,
                                 int stdoutLimit = 16777216, int stderrLimit = 65536) {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo(exe) {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory,
                RedirectStandardOutput = true, RedirectStandardError = true,
                RedirectStandardInput = true
            };
            foreach (string arg in args) process.StartInfo.ArgumentList.Add(arg);
            bool started = false;
            try {
                started = process.Start();
                if (!started) throw new IOException("Unable to start local generator.");
                process.StandardInput.Close();
                var stdout = ReadBounded(process.StandardOutput.BaseStream, stdoutLimit);
                var stderr = ReadBounded(process.StandardError.BaseStream, stderrLimit);
                var clock = Stopwatch.StartNew();
                while (!process.HasExited || !stdout.IsCompleted || !stderr.IsCompleted) {
                    if (stdout.IsFaulted || stderr.IsFaulted)
                        throw new IOException("Bounded generator output failed.");
                    if (clock.ElapsedMilliseconds >= timeoutMs)
                        throw new IOException("Local generator timed out.");
                    System.Threading.Thread.Sleep(10);
                }
                if (process.ExitCode != 0 || stderr.GetAwaiter().GetResult().Length != 0)
                    throw new IOException("Local generator refused input.");
                return new UTF8Encoding(false, true).GetString(stdout.GetAwaiter().GetResult());
            } finally {
                // Only the process we started (and its children) may be terminated.
                if (started && !process.HasExited) {
                    process.Kill(true);
                    process.WaitForExit(5000);
                }
            }
        }
    }
}
'@
}

function Get-LocalPath([string]$Path) {
    if ($Path.Length -gt 240 -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2) -match '[:/*?"<>|\x00-\x1f]' -or
        $Path -match '(?:^|\\)[^\\]*[. ](?:\\|$)') {
        throw 'Require bounded absolute local paths without alternate streams or ambiguous components.'
    }
    $full = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Path))
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) {
        throw 'Network and non-local drives are not supported.'
    }
    # Inspect parents before descendants: never traverse a junction to a network share.
    $ancestor = [IO.Path]::GetPathRoot($full)
    foreach ($component in @('') + $full.Substring($ancestor.Length).Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component) { $ancestor = Join-Path $ancestor $component }
        try { $attributes = [IO.File]::GetAttributes($ancestor) }
        catch [IO.FileNotFoundException] { break }
        catch [IO.DirectoryNotFoundException] { break }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse points are not allowed in local paths.'
        }
    }
    return $full
}

function Get-StreamHash([IO.FileStream]$Stream) {
    $Stream.Position = 0
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Stream)).ToLowerInvariant()
    $Stream.Position = 0
    return $hash
}

function Open-Source([string]$Path, [long]$Limit, [bool]$AllowHardlinks = $false) {
    $path = Get-LocalPath $Path
    if (-not [IO.File]::Exists($path)) { throw 'A required regular input is missing.' }
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -eq 0 -or $stream.Length -gt $Limit) { throw 'Input exceeds the size bound or is empty.' }
        $identity = [PfsensePreparation.Local]::Identity($stream, $AllowHardlinks)
        $hash = Get-StreamHash $stream
        if ([PfsensePreparation.Local]::Identity($stream, $AllowHardlinks) -cne $identity) { throw 'Input changed while reading.' }
        return [pscustomobject]@{ path = $path; length = $stream.Length; sha256 = $hash
            identity = $identity; stream = $stream; limit = $Limit; allow_hardlinks = $AllowHardlinks }
    } catch { $stream.Dispose(); throw }
}

function Assert-StableSources($Sources) {
    foreach ($source in $Sources.Values) {
        $current = Open-Source $source.path $source.limit $source.allow_hardlinks
        try {
            if ($current.identity -cne $source.identity -or $current.sha256 -cne $source.sha256) {
                throw 'Source identity or SHA256 changed during preparation.'
            }
        } finally { $current.stream.Dispose() }
    }
}

function Read-SourceText($Source) {
    $bytes = [byte[]]::new([int]$Source.length)
    $Source.stream.Position = 0
    $Source.stream.ReadExactly($bytes)
    $Source.stream.Position = 0
    return [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xfeff)
}

function Write-Source($Source, [string]$Path) {
    $output = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $Source.stream.Position = 0; $Source.stream.CopyTo($output); $output.Flush($true) }
    finally { $output.Dispose(); $Source.stream.Position = 0 }
}

function Write-Text([string]$Path, [string]$Text) {
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Text)
    if ($bytes.Length -gt 16MB) { throw 'Bundle artifact exceeds the size bound.' }
    $output = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $output.Write($bytes); $output.Flush($true) } finally { $output.Dispose() }
}

function Assert-SecretFreeJson([System.Text.Json.JsonElement]$Value, [int]$Depth = 0) {
    if ($Depth -gt 64) { throw 'Projection nesting exceeds the review bound.' }
    if ($Value.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        foreach ($property in $Value.EnumerateObject()) {
            if ($property.Name -match '(?i)(password|passwd|passphrase|secret|private.?key|pre.?shared.?key|credential|authorization|access.?token|api.?key)' -or
                $property.Name -match '^(?i:pwd|psk|prv|community|config_xml|raw_xml)$') {
                throw 'Credential-bearing or raw configuration fields are not accepted.'
            }
            Assert-SecretFreeJson $property.Value ($Depth + 1)
        }
    } elseif ($Value.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Value.EnumerateArray()) { Assert-SecretFreeJson $item ($Depth + 1) }
    } elseif ($Value.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
        if ($Value.GetString() -match '(?i)(-----BEGIN .*PRIVATE KEY-----|<\?xml|<pfsense[ >]|://[^/\s]+:[^/\s]+@)') {
            throw 'Credential or raw configuration content is not accepted.'
        }
    }
}

function Assert-FreshCapture([long]$Captured, [int]$MaxAge) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($Captured -lt 0 -or $Captured -gt $now -or $now - $Captured -gt $MaxAge) {
        throw 'Capture is expired or future-dated. Obtain a new capture; never relabel its timestamp.'
    }
}

$sources = [ordered]@{}
$documents = [Collections.Generic.List[System.Text.Json.JsonDocument]]::new()
$staging = $null
$failure = 'Input validation failed (local, regular, single-link, stable, bounded files are required).'
try {
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $output = Get-LocalPath $OutputDirectory
    $parent = Get-LocalPath ([IO.Path]::GetDirectoryName($output))
    if (-not [IO.Directory]::Exists($parent) -or [IO.Path]::Exists($output) -or
        $output.Length -gt 200 -or $parent.Length -gt 172) {
        throw 'Output must be new with an existing local parent and room for artifact names.'
    }
    if (($output -ieq $repo -or $output.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase)) -and
        -not $output.StartsWith($repo + '\state\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Repository output is restricted to state directories, never source code.'
    }
    $bins = Get-LocalPath $BinaryDirectory
    $sources.database = Open-Source $Database 512MB
    $sources.service_config = Open-Source $ServiceConfig 1MB
    $sources.bindings = Open-Source $Bindings 16MB
    $sources.capture = Open-Source $Capture 16MB
    $sources.generator = Open-Source (Join-Path $bins 'v6alias-pfsense.exe') 128MB $true
    $sources.preparer = Open-Source $PSCommandPath 1MB
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($source in $sources.Values) {
        if (-not $seen.Add($source.identity.Split(':')[0..1] -join ':') -or
            $output -ieq $source.path -or $output.StartsWith($source.path + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Input/output identities must not collide.'
        }
    }
    # Sidecar-backed SQLite would not be fully represented by the database hash.
    foreach ($suffix in @('-wal', '-shm', '-journal')) {
        if ([IO.Path]::Exists($sources.database.path + $suffix)) { throw 'Quiescent sidecar-free inventory required.' }
    }
    $failure = 'Secret-free native projection and project configuration required; no raw configuration or credentials.'
    $captureText = Read-SourceText $sources.capture
    $captureDoc = [System.Text.Json.JsonDocument]::Parse($captureText)
    $documents.Add($captureDoc)
    $baseline = $captureDoc.RootElement
    Assert-SecretFreeJson $baseline
    foreach ($property in $baseline.GetProperty('config').EnumerateObject()) {
        if ($property.Name -cnotin @('interfaces', 'dhcpdv6', 'unbound', 'opaque_synthetic_note') -or
            ($property.Name -ceq 'opaque_synthetic_note' -and $baseline.GetProperty('source').GetString() -cne 'synthetic-native')) {
            throw 'Not a secret-free native configuration projection.'
        }
    }
    $yaml = Read-SourceText $sources.service_config
    if ($yaml -match '(?im)(password|passwd|passphrase|secret|private.?key|credential|access.?token|api.?key)\s*[:=]' -or
        $yaml -match '(?i)(-----BEGIN .*PRIVATE KEY-----|<\?xml|<pfsense[ >]|://[^/\s]+:[^/\s]+@)') {
        throw 'Credential-bearing service configuration is not accepted.'
    }
    $failure = 'Capture is expired or future-dated. Obtain a new capture; never relabel its timestamp.'
    $captured = $baseline.GetProperty('captured_at_unix_secs').GetInt64()
    Assert-FreshCapture $captured $MaxAgeSeconds
    $expires = [DateTimeOffset]::FromUnixTimeSeconds($captured + $MaxAgeSeconds).ToString('o')
    $failure = 'Unable to create a private staging directory; no existing output may be overwritten.'
    $stagePath = Join-Path $parent ('.pfsense-prepare-' + [Guid]::NewGuid().ToString('N'))
    if ([IO.Path]::Exists($stagePath)) { throw 'Staging collision.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($userSid)
    foreach ($sid in @($userSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [PfsensePreparation.Local]::CreatePrivateDirectory($stagePath, $acl.GetSecurityDescriptorBinaryForm())
    $staging = $stagePath
    $failure = 'Local planner/simulator failed, timed out, or exceeded its output bound; no approval was granted.'
    $exe = $sources.generator.path
    $version = [PfsensePreparation.Local]::Run($exe, @('--version'), $staging).Trim()
    if ($version -cnotmatch '^v6alias-pfsense [0-9]+\.[0-9]+\.[0-9]+[-+.A-Za-z0-9]*$') {
        throw 'Unexpected generator version response.'
    }
    $common = @('--database', $sources.database.path, '--service-config', $sources.service_config.path,
        '--bindings', $sources.bindings.path, '--capture', $sources.capture.path,
        '--max-age-secs', $MaxAgeSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))
    $requestText = [PfsensePreparation.Local]::Run($exe, ($common + @('plan')), $staging)
    $requestPath = Join-Path $staging 'request.json'
    Write-Text $requestPath $requestText
    $simulationText = [PfsensePreparation.Local]::Run($exe,
        ($common + @('simulate', '--request', $requestPath)), $staging)
    $requestDoc = [System.Text.Json.JsonDocument]::Parse($requestText)
    $simulationDoc = [System.Text.Json.JsonDocument]::Parse($simulationText)
    $documents.Add($requestDoc); $documents.Add($simulationDoc)
    $request = $requestDoc.RootElement
    $simulation = $simulationDoc.RootElement
    $failure = 'Native request/simulation safety proof does not match the reviewed source.'
    if ($request.GetProperty('schema_version').GetInt32() -ne 1 -or
        $request.GetProperty('mode').GetString() -cne 'native_plan' -or
        $request.GetProperty('network_writes').GetBoolean() -or
        -not $request.GetProperty('approval_required').GetBoolean() -or
        $simulation.GetProperty('schema_version').GetInt32() -ne 1 -or
        $simulation.GetProperty('mode').GetString() -cne 'offline_simulation' -or
        $simulation.GetProperty('network_writes').GetBoolean() -or
        -not $simulation.GetProperty('approval_required').GetBoolean() -or
        [System.Text.Json.JsonSerializer]::Serialize($request, [System.Text.Json.JsonElement], [System.Text.Json.JsonSerializerOptions]::Default) -cne
        [System.Text.Json.JsonSerializer]::Serialize($simulation.GetProperty('request'), [System.Text.Json.JsonElement], [System.Text.Json.JsonSerializerOptions]::Default)) {
        throw 'Unexpected native simulation proof.'
    }
    $rollback = $simulation.GetProperty('rollback')
    foreach ($key in @('expected_revision_sha256', 'baseline_projection_sha256', 'authority_sha256', 'candidate_projection_sha256')) {
        if ($request.GetProperty($key).GetString() -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid native digest.' }
        if ($key -ne 'authority_sha256' -and $request.GetProperty($key).GetString() -cne $rollback.GetProperty($key).GetString()) {
            throw 'Mismatched native rollback proof.'
        }
    }
    $requestHash = $rollback.GetProperty('request_sha256').GetString()
    $revision = $request.GetProperty('expected_revision_sha256').GetString()
    if ($requestHash -cnotmatch '^[a-f0-9]{64}$' -or
        $revision -cne $baseline.GetProperty('config_revision_sha256').GetString() -or
        $simulation.GetProperty('projection').GetProperty('config_revision_sha256').GetString() -cne $revision -or
        $simulation.GetProperty('projection').GetProperty('captured_at_unix_secs').GetInt64() -ne $captured) {
        throw 'Mismatched original capture identity.'
    }
    $changes = $request.GetProperty('changes')
    $actions = $changes.GetArrayLength()
    $paths = @($request.GetProperty('allowed_paths').EnumerateArray() | ForEach-Object { $_.GetString() })
    foreach ($path in $paths) {
        if ($path -cnotmatch '^(unbound/hosts|dhcpdv6/[A-Za-z0-9_]+/staticmap)$') { throw 'Unexpected approved collection path.' }
    }
    $counters = @()
    $index = 0
    foreach ($change in $changes.EnumerateArray()) {
        $nativePath = $change.GetProperty('path')
        $path = switch ($nativePath.GetProperty('kind').GetString()) {
            'unbound_hosts' { 'unbound/hosts' }
            'dhcpv6_staticmap' { 'dhcpdv6/' + $nativePath.GetProperty('interface').GetString() + '/staticmap' }
            default { throw 'Unexpected native collection kind.' }
        }
        if ($path -cnotin $paths) { throw 'Change outside approved paths.' }
        $counters += [ordered]@{ path = $path; before_records = $change.GetProperty('before').GetArrayLength()
            after_records = $change.GetProperty('after').GetArrayLength(); exact_change = "request.json#/changes/$index" }
        $index++
    }
    $blocked = if ($actions -eq 0) { 'no_changes; no live action is necessary' }
        else { 'explicit_operator_approval_and_separate_installation_and_live_revalidation_required' }
    $review = [ordered]@{ schema_version = 1; mode = 'operator_review'; live_changes = $false
        approval_granted = $false; request_sha256 = $requestHash; expected_revision_sha256 = $revision
        actions = $actions; no_op = ($actions -eq 0); blocked_action_reason = $blocked
        approved_paths = $paths; counters = $counters; exact_changes_reference = 'request.json#/changes'
        note = 'Hashes are review references, not approval. Native fields are data, never commands.' }
    # Preserve native before/after JSON exactly, including integer values, key and array order.
    $reviewText = ($review | ConvertTo-Json -Depth 16 -Compress)
    $reviewText = $reviewText.Substring(0, $reviewText.Length - 1) + ',"changes":' + $changes.GetRawText() + '}'
    Write-Source $sources.capture (Join-Path $staging 'baseline.json')
    Write-Source $sources.bindings (Join-Path $staging 'bindings.json')
    Write-Source $sources.service_config (Join-Path $staging 'service.yaml')
    Write-Text (Join-Path $staging 'simulation.json') $simulationText
    Write-Text (Join-Path $staging 'review.json') $reviewText
    $failure = 'Source identity or SHA256 changed; discard this preparation and obtain stable inputs.'
    Assert-StableSources $sources
    foreach ($suffix in @('-wal', '-shm', '-journal')) {
        if ([IO.Path]::Exists($sources.database.path + $suffix)) { throw 'Inventory sidecar appeared.' }
    }
    $artifacts = [ordered]@{}
    foreach ($name in @('request.json', 'baseline.json', 'bindings.json', 'service.yaml', 'simulation.json', 'review.json')) {
        $file = Open-Source (Join-Path $staging $name) 16MB
        try { $artifacts[$name] = [ordered]@{ sha256 = $file.sha256; bytes = $file.length } }
        finally { $file.stream.Dispose() }
    }
    $sourceHashes = [ordered]@{}
    foreach ($key in $sources.Keys) {
        $file = $sources[$key]
        $sourceHashes[$key] = [ordered]@{ path = $file.path; sha256 = $file.sha256; bytes = $file.length; identity = $file.identity }
    }
    $manifest = [ordered]@{ schema_version = 1; mode = 'approval_bundle'; live_changes = $false
        network_writes = $false; approval_required = $true; approval_granted = $false
        source = $baseline.GetProperty('source').GetString(); prepared_utc = [DateTimeOffset]::UtcNow.ToString('o')
        captured_at_unix_secs = $captured; max_age_seconds = $MaxAgeSeconds; expires_at = $expires
        request_sha256 = $requestHash; request_hash_basis = 'validated simulation.rollback.request_sha256 (native canonical JSON)'
        expected_revision_sha256 = $revision; baseline_projection_sha256 = $request.GetProperty('baseline_projection_sha256').GetString()
        authority_sha256 = $request.GetProperty('authority_sha256').GetString()
        candidate_projection_sha256 = $request.GetProperty('candidate_projection_sha256').GetString()
        generator = [ordered]@{ name = 'v6alias-pfsense.exe'; version = $version; sha256 = $sources.generator.sha256; copied = $false }
        source_files = $sourceHashes; artifacts = $artifacts; approved_paths = $paths
        actions = $actions; no_op = ($actions -eq 0); counters = $counters; blocked_action_reason = $blocked
        exact_changes_reference = 'request.json#/changes'; review = 'review.json'
        manifest_hash_note = 'Manifest cannot hash itself; its SHA256 is returned separately. No signatures or approval tokens are issued.' }
    Write-Text (Join-Path $staging 'manifest.json') ($manifest | ConvertTo-Json -Depth 16)
    $manifestFile = Open-Source (Join-Path $staging 'manifest.json') 16MB
    try { $manifestHash = $manifestFile.sha256 } finally { $manifestFile.stream.Dispose() }
    $failure = 'Capture expired during preparation. Obtain a new capture; never relabel its timestamp.'
    Assert-FreshCapture $captured $MaxAgeSeconds
    $failure = 'Atomic publication refused; output must remain absent and its parent must remain local.'
    $null = Get-LocalPath $parent
    if ([IO.Path]::Exists($output)) { throw 'Output appeared during preparation.' }
    [IO.Directory]::Move($staging, $output)
    $staging = $null
    Write-Information "Prepared $actions collection change(s); approval NOT granted. Request SHA256: $requestHash; bundle: $output" -InformationAction Continue
    [pscustomobject]@{ bundle_path = $output; request_sha256 = $requestHash; manifest_sha256 = $manifestHash
        actions = $actions; approval_granted = $false; live_changes = $false }
} catch {
    throw [InvalidOperationException]::new("$failure No bundle was published by this invocation.")
} finally {
    foreach ($document in $documents) { $document.Dispose() }
    foreach ($source in $sources.Values) { $source.stream.Dispose() }
    if ($null -ne $staging -and [IO.Directory]::Exists($staging)) {
        # Never remove the caller's final output, input files, or any shared parent.
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
