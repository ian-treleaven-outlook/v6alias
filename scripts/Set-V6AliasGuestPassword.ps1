#Requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Write-Host 'Set the password for the standard scout-user account in scout-v6alias.'
Write-Host 'Use 12-128 printable ASCII characters. Nothing typed here is sent to Scout chat.'
Write-Host 'This starts only scout-v6alias after setting the password offline.'
Write-Host 'Password installation and verification run separately; please allow a few minutes.'

$password = Read-Host 'New guest password' -AsSecureString
$confirmation = Read-Host 'Repeat guest password' -AsSecureString
$first = [IntPtr]::Zero
$second = [IntPtr]::Zero
$process = $null
try {
    $first = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $second = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmation)
    if ($password.Length -lt 12 -or $password.Length -gt 128) {
        throw 'Password must be 12-128 printable ASCII characters.'
    }
    if ($password.Length -ne $confirmation.Length) { throw 'Passwords do not match.' }
    $chars = [char[]]::new($password.Length)
    for ($i = 0; $i -lt $password.Length; $i++) {
        $value = [Runtime.InteropServices.Marshal]::ReadInt16($first, $i * 2)
        if ($value -ne [Runtime.InteropServices.Marshal]::ReadInt16($second, $i * 2)) {
            throw 'Passwords do not match.'
        }
        if ($value -lt 32 -or $value -gt 126) {
            throw 'Password must contain only printable ASCII characters.'
        }
        $chars[$i] = [char]$value
    }

    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in @(
        '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'ClearAllForwardings=yes',
        '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
        'labagent@labhost',
        'python3 /home/labagent/work/scout-console-access-20260917/set_scout_password.py'
    )) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not launch SSH.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    # Send via encrypted SSH stdin, never via command arguments or a Windows file.
    $process.StandardInput.Write($chars, 0, $chars.Length)
    $process.StandardInput.Write("`n")
    $process.StandardInput.Close()
    [Array]::Clear($chars, 0, $chars.Length)
    $process.WaitForExit()
    $output = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    if ($output) { Write-Host $output.TrimEnd() }
    if ($process.ExitCode -ne 0) {
        if ($errors) { Write-Host $errors.TrimEnd() }
        throw 'Guest setup failed. Do not start or modify other VMs; report the non-secret error.'
    }
    Write-Host 'Run: ssh -t labagent@labhost "virsh console scout-v6alias"'
    Write-Host 'Log in as scout-user. Press Ctrl+] to detach without logging out.'
}
finally {
    if ($null -ne $chars) { [Array]::Clear($chars, 0, $chars.Length) }
    if ($first -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($first) }
    if ($second -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($second) }
    $password.Dispose()
    $confirmation.Dispose()
    if ($null -ne $process) { $process.Dispose() }
}
