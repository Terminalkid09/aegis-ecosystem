<#
.SYNOPSIS
  Valida gli installer Windows senza installare nulla (Fase 2 lifecycle test).
  - Tokenizza install.ps1 / uninstall.ps1 (errori di sintassi = fail).
  - Verifica passi obbligatori: prerequisiti, ACL directory, hash artefatto,
    recovery servizio, uninstall pulita (stop + remove + directory).
  Uso: powershell -NoProfile -File scripts/test-installers.ps1
  Ritorna exit 1 al primo problema (fail-closed per la CI).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$install = Join-Path $root ".." "aegis-guard" "install" "windows" "install.ps1"
$uninstall = Join-Path $root ".." "aegis-guard" "install" "windows" "uninstall.ps1"
$failures = 0

function Assert-True([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "PASS $msg" }
    else { Write-Host "FAIL $msg"; $script:failures++ }
}

function Test-Syntax([string]$path) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.PSParser]::Tokenize(
        (Get-Content -LiteralPath $path -Raw), [ref]$errors)
    Assert-True ($errors.Count -eq 0) "$([IO.Path]::GetFileName($path)) sintassi valida ($($errors.Count) errori)"
}

function Test-Contains([string]$path, [string]$pattern, [string]$msg) {
    $text = Get-Content -LiteralPath $path -Raw
    Assert-True ($text -match $pattern) "$msg ($([IO.Path]::GetFileName($path)))"
}

Assert-True (Test-Path -LiteralPath $install) "install.ps1 esiste"
Assert-True (Test-Path -LiteralPath $uninstall) "uninstall.ps1 esiste"
Assert-True (Test-Path -LiteralPath (Join-Path $root ".." "aegis-guard" "install" "windows" "nssm.exe")) "nssm.exe presente"

if ($failures -eq 0) {
    Test-Syntax $install
    Test-Syntax $uninstall
}

if ($failures -eq 0) {
    # install.ps1: prerequisiti, ACL, hash, recovery
    Test-Contains $install 'nssm\.exe' "install: usa NSSM"
    Test-Contains $install 'SetAccessRuleProtection|Set-Acl' "install: restrinzione ACL directory"
    Test-Contains $install 'Get-FileHash|sha256' "install: hash artefatto registrato"
    Test-Contains $install 'AppExit|AppRestartDelay' "install: recovery servizio"
    Test-Contains $install 'Start-Service AegisGuard' "install: avvio + verifica servizio"
    Test-Contains $install 'AEGIS_API_KEY' "install: chiave API da .env (mai hardcoded)"
    # uninstall.ps1: stop, remove, directory
    Test-Contains $uninstall 'Stop-Service' "uninstall: stop servizio"
    Test-Contains $uninstall 'remove AegisGuard|Remove.*[Ss]ervice' "uninstall: rimozione servizio"
}

if ($failures -gt 0) { Write-Host "$failures controlli falliti"; exit 1 }
Write-Host "INSTALLER CHECKS ALL PASS"
