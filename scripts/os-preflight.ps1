#Requires -Version 5.1
<#
.SYNOPSIS
  Preflight validazione OS per Aegis (Windows 11 / Server 2022).
.DESCRIPTION
  Controlli read-only pre-installazione: versione OS, Docker, Python,
  porte libere, disco e RAM. Exit 0 = tutti i check passati,
  exit 1 = almeno un check fallito (dettagli su stdout).
  Non modifica il sistema.
#>
$ErrorActionPreference = 'Continue'
$failed = 0

function Check($name, [scriptblock]$test, $hint) {
    try { $ok = & $test } catch { $ok = $false }
    if ($ok) { Write-Output "[PASS] $name" }
    else { Write-Output "[FAIL] $name -- $hint"; $script:failed++ }
}

Check 'OS Windows 10.0.22000+ (11) o Server 2022 (20348+)' {
    $v = [Environment]::OSVersion.Version
    ($v.Major -eq 10 -and $v.Build -ge 22000) -or ($v.Major -gt 10)
} 'richiesti Windows 11 / Server 2022'

Check 'Docker disponibile' { (Get-Command docker -ErrorAction Stop) -ne $null } 'installare Docker Desktop 4.x+'

Check 'Docker daemon raggiungibile' { docker info 2>$null | Select-String 'Server Version' -Quiet } 'avviare Docker Desktop'

Check 'Python 3.10+ disponibile' {
    $p = Get-Command python -ErrorAction Stop; $v = & python --version 2>&1
    $v -match 'Python 3\.(1[0-9]|[2-9][0-9])'
} 'installare Python 3.10+ e aggiungerlo al PATH'

Check 'Porte 5444/6388/8000/3000 libere o gia'' Aegis' {
    $busy = @(5444, 6388, 8000, 3000 | Where-Object {
        Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue
    })
    $busy.Count -eq 0
} 'porte occupate da altri servizi'

Check 'Disco libero >= 20 GB su C:' {
    (Get-PSDrive C).Free -gt 20GB
} 'liberare spazio su disco'

Check 'RAM >= 4 GB' {
    (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory -gt 4GB
} 'host sotto i requisiti minimi pilot'

if ($failed -gt 0) { Write-Output "PREFLIGHT: $failed check falliti"; exit 1 }
Write-Output 'PREFLIGHT: tutti i check passati'
exit 0
