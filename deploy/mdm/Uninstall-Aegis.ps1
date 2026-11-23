#Requires -Version 5.1
# Intune uninstall wrapper. State under ProgramData is retained by default.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$uninstallRoots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
$entries = @(
    foreach ($root in $uninstallRoots) {
        if (Test-Path $root) {
            Get-ChildItem $root | ForEach-Object { Get-ItemProperty $_.PSPath }
        }
    }
)
$entry = $entries | Where-Object { $_.DisplayName -eq 'Aegis Agent' } | Select-Object -First 1
if (-not $entry) { Write-Output 'Aegis Agent is not installed'; exit 0 }
if ($entry.UninstallString -match '\{[0-9A-Fa-f-]{36}\}') {
    $code = $Matches[0]
    $process = Start-Process msiexec.exe -ArgumentList @('/x', $code, '/qn', '/norestart') -Wait -PassThru
    if ($process.ExitCode -notin @(0, 1605, 3010, 1641)) {
        throw "msiexec uninstall failed with exit code $($process.ExitCode)"
    }
} else {
    throw 'Aegis Agent uninstall entry has no MSI product code'
}
if (Get-Service -Name AegisAgent -ErrorAction SilentlyContinue) {
    throw 'AegisAgent service survived uninstall'
}
Write-Output 'Aegis Agent removed (ProgramData state retained)'
exit 0
