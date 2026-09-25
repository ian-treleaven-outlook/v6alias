# Export only our non-secret setup/test reports through the VM's serial port.
# This is one-way output, not a command shell or remote management service.
#Requires -Version 7.3
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ne 'CORP-44') { throw 'Expected CORP-44.' }
$report = Get-ChildItem -Path 'C:\V6Alias\state\core-smoke-*\report.json' -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $report -or $report.Length -gt 2MB) { throw 'No bounded smoke report is available.' }
$data = @{
    setup = Get-Content 'C:\V6Alias\setup-status.json' -Raw | ConvertFrom-Json
    smoke = Get-Content $report.FullName -Raw | ConvertFrom-Json
} | ConvertTo-Json -Depth 35 -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))
$port = [IO.Ports.SerialPort]::new('COM1', 115200, [IO.Ports.Parity]::None, 8, [IO.Ports.StopBits]::One)
$port.WriteTimeout = 15000
try {
    $port.Open()
    $port.WriteLine('SCOUT_CORE_REPORT_BEGIN')
    for ($offset = 0; $offset -lt $encoded.Length; $offset += 256) {
        $port.WriteLine($encoded.Substring($offset, [Math]::Min(256, $encoded.Length - $offset)))
    }
    $port.WriteLine('SCOUT_CORE_REPORT_END')
}
finally { $port.Dispose() }
Write-Host 'Non-secret setup/test report exported over COM1.'
