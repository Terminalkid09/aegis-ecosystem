# ak - operator CLI for the Aegis server on Windows.
#
# This is installed by aegis-server-<version>-x64.msi under
# C:\Program Files\Aegis Server\bin. It manages the same Compose stack as the
# Linux package, but there is no systemd: Docker Desktop supplies the daemon and
# `ak start` is the bring-up command. It does not claim pre-login availability.

$ErrorActionPreference = "Stop"
$AkVersion = "__VERSION__"
$Edition = "__EDITION__"
$RegistryName = "__REGISTRY_NAME__"
$RegistryKey = "HKLM:\Software\Aegis\$RegistryName"
$HasAegis = ($Edition -ne "kraken")
$HasKraken = ($Edition -ne "aegis")

$ServerRoot = if ($env:AEGIS_SERVER_ROOT) { $env:AEGIS_SERVER_ROOT } else {
    Split-Path -Parent $PSScriptRoot
}
$DataDir = if ($env:AEGIS_DATA_DIR) { $env:AEGIS_DATA_DIR } else {
    Join-Path $env:ProgramData "Aegis"
}
$AegisDir = Join-Path $ServerRoot "aegis"
$KrakenDir = Join-Path $ServerRoot "kraken"
$ComposeFile = if ($Edition -eq "kraken") {
    Join-Path $KrakenDir "docker-compose.yml"
} else {
    Join-Path $AegisDir "docker-compose.yml"
}
$EnvFile = Join-Path $DataDir $(if ($Edition -eq "kraken") { "kraken.env" } else { "server.env" })
$ConfigScript = Join-Path $PSScriptRoot "configure-server.ps1"
$ProjectName = if ($Edition -eq "kraken") { "aegis-kraken" } else { "aegis" }
$UpdateRepo = "Terminalkid09/aegis-ecosystem"
$UpdateBaseUrl = if ($env:AEGIS_UPDATE_BASE_URL) { $env:AEGIS_UPDATE_BASE_URL } else {
    "https://github.com/$UpdateRepo/releases/download"
}

$AegisServices = @(
    "aegis-postgres", "aegis-redis", "aegis-brain", "aegis-link",
    "aegis-frontend", "aegis-caddy"
)
$KrakenServices = @(
    "aegis-kraken-db", "aegis-kraken-redis", "aegis-kraken-init",
    "aegis-kraken-broker", "aegis-kraken-sandbox-image", "aegis-kraken",
    "aegis-kraken-rdp", "aegis-kraken-sensors"
)

function Usage {
    @'
ak - manage the installed Aegis server on Windows

Usage:
  ak <command> [component] [options]
  ak <component> [command] [options]
  ak help [command]

Components:
  aegis       Aegis server: Brain, Link, dashboard, PostgreSQL, Redis, Caddy
  kraken      Kraken deception stack: app, sensors, broker, RDP, databases
  all         both stacks (default)

Commands:
  start       Build missing images and start the selected stack; --wait is
              the default, --no-wait returns immediately.
  stop        Stop the selected stack; data volumes and secrets are kept.
  restart     Stop and start the selected stack.
  status      Show the running containers for the selected stack.
  ps          Show Docker Compose containers and health.
  logs        Show container logs; use -f to follow and --tail N for a limit.
  doctor      Check Docker Desktop, Compose, files, port and memory use.
  url         Print the public and local dashboard URLs.
  configure   Set the public hostname, ACME email, dashboard port or URL.
  update      Install a release MSI, update the CLI and restart the stack.
  version     Print the CLI, edition and installed server version.
  help        Show this help, or detailed help for one command.

Examples:
  ak start
  ak start --wait --timeout 600
  ak start --no-wait
  ak start kraken
  ak kraken restart
  ak status
  ak logs aegis --tail 200
  ak logs aegis -f
  ak configure --domain soc.example.com --email ops@example.com
  ak configure --port 3005
  ak update --check
  ak update --version 4.2.1 --allow-downgrade --yes
  ak url

Privileges:
  configure and update require an elevated PowerShell because they write
  C:\ProgramData\Aegis\server.env and install the MSI. start/stop/restart need
  access to Docker Desktop; they do not need a Windows service account.

Dashboard URL and port:
  The dashboard binds to 127.0.0.1:3000 by default. At install/first
  start, a busy 3000 is replaced with the first free port in 3000-3099 and the
  selected value is written to server.env. A public URL is configured with
  AEGIS_DOMAIN, ACME_EMAIL and PUBLIC_BASE_URL.

Exit status:
  0  success
  1  a container, port, Docker or file operation failed
  2  invalid command, component or option

Files:
  C:\Program Files\Aegis Server\aegis        Compose project and source
  C:\Program Files\Aegis Server\bin          ak and configuration scripts
  C:\ProgramData\Aegis\server.env            secrets and public URL settings
  C:\ProgramData\Aegis\secrets               optional secret files

Windows boundary:
  Docker Desktop is per-user. This package installs the server files and the
  global `ak` command, but it does not create a pre-login Windows service. Run
  `ak start` after logging in, or use a scheduled task at logon. A true
  pre-login server requires a per-machine container runtime or native services.
'@
}

function CommandUsage([string]$Command) {
    switch ($Command) {
        "start" {
            @'
Usage: ak start [aegis|kraken|all] [--wait] [--no-wait] [--timeout SECONDS]

Build missing images with Docker Compose and start the selected stack. The first
start needs network access to the base-image registries and can take several
minutes. `ak start kraken` starts only the Kraken services; `ak start` starts
both stacks.

By default the command polls the project until at least one container is running
and none is starting or unhealthy; --wait makes that explicit for scripts shared
with Linux. Stopped one-shot services (database init, sandbox image loader) do
not count as failures. --no-wait returns as soon as Compose created the
containers. --timeout defaults to 300 seconds.
'@
        }
        "stop" {
            @'
Usage: ak stop [aegis|kraken|all]

Stop the selected containers. The named volumes and C:\ProgramData\Aegis are
kept. Use `ak start` to bring the stack back.
'@
        }
        "restart" {
            @'
Usage: ak restart [aegis|kraken|all]

Stop and start the selected stack. Use this after `ak configure`.
'@
        }
        "status" {
            @'
Usage: ak status [aegis|kraken|all]

Show the Docker containers for the selected stack. There is no systemd unit on
Windows; Docker Desktop must be running for the containers to be visible.
'@
        }
        "ps" {
            @'
Usage: ak ps [aegis|kraken|all]

Show Docker Compose containers, health and published ports.
'@
        }
        "logs" {
            @'
Usage: ak logs [aegis|kraken|all] [--tail N] [-f|--follow]

Show container logs. The default tail is 100 lines. -f follows until Ctrl-C.
'@
        }
        "doctor" {
            @'
Usage: ak doctor

Check the Docker CLI, Compose v2, Docker Desktop daemon, installed files and
server.env. It does not start or change anything. A failed check returns 1.
'@
        }
        "url" {
            @'
Usage: ak url [aegis|kraken|all]

Print the public dashboard URL and local dashboard URL from server.env, plus the
Kraken endpoint and suite path.
'@
        }
        "configure" {
            @'
Usage: ak configure [options]

Set the public hostname and local dashboard endpoint. With no options it prints
the current values without changing anything.

Options:
  --domain FQDN       Public DNS name, for example soc.example.com.
  --email ADDRESS     ACME account email; required for a public FQDN.
  --public-url URL    Public origin, for example https://soc.example.com.
  --port PORT         Local 127.0.0.1 dashboard port (1-65535).
  --restart           Restart the stack after writing the configuration.
  -h, --help          Show this help.

The command preserves existing secrets and unrelated ALLOWED_ORIGINS entries.
A busy port is a hard error unless the start-time fallback changes it.
'@
        }
        "update" {
            @'
Usage: ak update [options]

Install a release MSI for this edition, update the CLI and, unless disabled,
restart the stack. The MSI must match the installed edition (Aegis Server,
Kraken Server or Aegis Suite). The updater verifies the SHA-256 sidecar before
running msiexec and preserves the current FQDN/email/port properties.

Options:
  --version VERSION   Install an explicit version, for example 4.2.1.
  --latest            Use the latest non-prerelease GitHub release.
  --from PATH|URL     Local directory, local MSI, or release base URL.
  --sha256 HEX        Expected SHA-256 when the sidecar is unavailable.
  --check             Show current and target versions; change nothing.
  --allow-downgrade   Permit an older version after a verified DB backup.
  --no-restart        Update files but do not restart the stack.
  --yes               Do not ask for confirmation.
  --dry-run           Print the resolved artifact and checksum only.
  -h, --help          Show this help.

The release policy is in docs/RELEASE_POLICY.md. Older versions may remain
installable while their assets exist, but only the current and previous minor
lines receive fixes. A downgrade can require a database restore; it is never
silently assumed safe.
'@
        }
        "version" {
            "Usage: ak version`n`nPrint the CLI, edition and installed server version."
        }
        default {
            "ak: unknown command: $Command"
            return 2
        }
    }
}

function Fail([string]$Message) {
    Write-Host "ak: $Message" -ForegroundColor Red
    exit 1
}

function UsageError([string]$Message) {
    Write-Host "ak: $Message" -ForegroundColor Red
    exit 2
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin([string]$Action) {
    if (-not (Test-Admin)) {
        Fail "$Action requires an elevated PowerShell (Run as Administrator)"
    }
}

function Read-Env {
    $values = [ordered]@{}
    if (-not (Test-Path -LiteralPath $EnvFile)) { return $values }
    try {
        foreach ($line in [IO.File]::ReadAllLines($EnvFile)) {
            if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
                $values[$matches[1]] = $matches[2]
            }
        }
    } catch [UnauthorizedAccessException] {
        # server.env is intentionally Administrators/SYSTEM-only. Read-only
        # commands fall back to the public values stored in HKLM.
        return ([ordered]@{})
    }
    return $values
}

function EnvValue([string]$Key, [string]$Default = "") {
    $values = Read-Env
    if ($values.Contains($Key) -and "$($values[$Key])" -ne "") { return "$($values[$Key])" }
    return $Default
}

function RegistryValue([string]$Name, [string]$Default = "") {
    if (-not (Test-Path $RegistryKey)) { return $Default }
    $item = Get-ItemProperty -Path $RegistryKey -Name $Name -ErrorAction SilentlyContinue
    if ($item -and "$($item.$Name)" -ne "") { return "$($item.$Name)" }
    return $Default
}

function Write-Env([System.Collections.Specialized.OrderedDictionary]$Values) {
    $lines = foreach ($key in $Values.Keys) { "$key=$($Values[$key])" }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($EnvFile, (($lines -join "`n") + "`n"), $utf8)
}

function Set-Env([string]$Key, [string]$Value) {
    $values = Read-Env
    $values[$Key] = $Value
    Write-Env $values
}

function Add-Origin([string]$Origin) {
    $origins = EnvValue "ALLOWED_ORIGINS" ""
    $parts = @($origins -split ',' | Where-Object { $_ -ne "" })
    if ($parts -notcontains $Origin) { $parts += $Origin }
    Set-Env "ALLOWED_ORIGINS" ($parts -join ",")
}

function Test-PortInUse([int]$Port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $false
    } catch {
        return $true
    } finally {
        if ($listener) { try { $listener.Stop() } catch { } }
    }
}

function Find-FreePort([int]$Preferred) {
    if (-not (Test-PortInUse $Preferred)) { return $Preferred }
    for ($candidate = 3000; $candidate -le 3099; $candidate++) {
        if (-not (Test-PortInUse $candidate)) { return $candidate }
    }
    Fail "dashboard port $Preferred is busy and no free port exists in 3000-3099"
}

function Test-DockerCli {
    return [bool](Get-Command docker.exe -ErrorAction SilentlyContinue)
}

function Test-Compose {
    if (-not (Test-DockerCli)) { return $false }
    $output = & docker compose version 2>$null
    return ($LASTEXITCODE -eq 0 -and "$output" -match "Docker Compose version")
}

function Test-Daemon {
    if (-not (Test-DockerCli)) { return $false }
    $output = & docker info --format '{{.ServerVersion}}' 2>$null
    return ($LASTEXITCODE -eq 0 -and "$output" -ne "")
}

function Require-Docker {
    if (-not (Test-DockerCli)) {
        Fail "docker.exe not found; install Docker Desktop and enable WSL 2 integration"
    }
    if (-not (Test-Compose)) {
        Fail "docker compose v2 not available; update Docker Desktop"
    }
    if (-not (Test-Daemon)) {
        Fail "Docker Desktop is not running; start it and wait for 'Docker Desktop is running'"
    }
}

function Invoke-Compose {
    param(
        [string[]]$ComposeArgs,
        [switch]$KrakenProfile
    )
    if (-not (Test-Path -LiteralPath $ComposeFile)) {
        Fail "Compose file is missing: $ComposeFile"
    }
    $all = @("compose", "--env-file", $EnvFile, "-f", $ComposeFile)
    if ($KrakenProfile) { $all += @("--profile", "kraken") }
    $all += $ComposeArgs
    & docker @all
    if ($LASTEXITCODE -ne 0) {
        Fail "docker compose failed with exit code $LASTEXITCODE"
    }
}

function Initialize-Env {
    if (Test-Path -LiteralPath $EnvFile) { return }
    if (-not (Test-Path -LiteralPath $ConfigScript)) {
        Fail "configuration script is missing: $ConfigScript"
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ConfigScript `
        -InstallRoot $ServerRoot -DataDir $DataDir -Edition $Edition -AllowPortFallback
    if ($LASTEXITCODE -ne 0) {
        Fail "initial $([IO.Path]::GetFileName($EnvFile)) generation failed; run ak configure as Administrator"
    }
}

function Port-InUseByOther([int]$Port) {
    $own = & docker ps --filter "name=aegis-frontend" --format "{{.Names}}" 2>$null
    if ($LASTEXITCODE -eq 0 -and "$own" -match "aegis-frontend") {
        return $false
    }
    return Test-PortInUse $Port
}

function Guard-UiPort {
    $current = EnvValue "AEGIS_UI_PORT" "3000"
    if ($current -notmatch '^\d+$') { return }
    if (-not (Port-InUseByOther ([int]$current))) { return }
    $replacement = Find-FreePort ([int]$current)
    Set-Env "AEGIS_UI_PORT" ([string]$replacement)
    Add-Origin "http://localhost:$replacement"
    Write-Host "ak: dashboard port $current is busy; switched to $replacement" -ForegroundColor Yellow
}

function Assert-ComponentSupported([string]$Component) {
    if ($Component -eq "aegis" -and -not $HasAegis) {
        UsageError "this package is Kraken only; Aegis commands are unavailable"
    }
    if ($Component -eq "kraken" -and -not $HasKraken) {
        UsageError "this package is Aegis only; install aegis-suite for Kraken"
    }
    if ($Component -notin @("aegis", "kraken", "all")) {
        UsageError "unknown component: $Component (use aegis, kraken, or all)"
    }
}

function Build-IfNeeded([string]$Component) {
    $markers = @()
    switch ($Component) {
        "aegis" { $markers = @("aegis.images.ok") }
        "kraken" { $markers = @("kraken.images.ok") }
        "all" {
            if ($Edition -eq "aegis") { $markers = @("aegis.images.ok") }
            elseif ($Edition -eq "kraken") { $markers = @("kraken.images.ok") }
            else { $markers = @("aegis.images.ok", "kraken.images.ok") }
        }
    }
    $missing = @($markers | Where-Object { -not (Test-Path -LiteralPath (Join-Path $DataDir $_)) })
    if ($missing.Count -eq 0) { return }
    $profile = ($Edition -eq "suite" -and $Component -ne "aegis")
    Write-Host "Building $Component Docker images (first start can take several minutes)..." -ForegroundColor Cyan
    Invoke-Compose -ComposeArgs @("build") -KrakenProfile:$profile
    foreach ($marker in $markers) {
        New-Item -ItemType File -Path (Join-Path $DataDir $marker) -Force | Out-Null
    }
}

function Wait-Component([string]$Component, [int]$Timeout) {
    # Compose --wait treats a one-shot service that exits 0 (init, sandbox image
    # loader) as a failure, so poll the running containers instead: the same
    # contract as the Linux CLI, which ignores stopped one-shot services.
    $deadline = (Get-Date).AddSeconds($Timeout)
    while ($true) {
        $rows = @(& docker ps --filter "label=com.docker.compose.project=$ProjectName" `
            --filter "status=running" --format "{{.Names}}|{{.Status}}" 2>$null)
        $rows = @($rows | Where-Object { $_ })
        $bad = @($rows | Where-Object { $_ -match 'unhealthy|health: starting' })
        if ($rows.Count -gt 0 -and $bad.Count -eq 0) {
            Write-Host "Ready ${Component}: $($rows.Count) container(s) running" -ForegroundColor Green
            return
        }
        if ((Get-Date) -ge $deadline) {
            Fail "timed out after ${Timeout}s waiting for $Component; check: ak ps $Component and ak logs $Component"
        }
        Start-Sleep -Seconds 5
    }
}

function Start-Component([string]$Component, [int]$WaitTimeout = 300, [bool]$NoWait = $false) {
    Assert-ComponentSupported $Component
    $profile = ($Edition -eq "suite" -and $Component -ne "aegis")
    $upArgs = @("up", "-d", "--remove-orphans")
    switch ($Component) {
        "aegis" {
            Guard-UiPort
            Build-IfNeeded "aegis"
            Invoke-Compose -ComposeArgs $upArgs
        }
        "kraken" {
            if (-not (Test-Path -LiteralPath $EnvFile)) { Initialize-Env }
            Build-IfNeeded "kraken"
            Invoke-Compose -ComposeArgs $upArgs -KrakenProfile:$profile
        }
        "all" {
            if ($HasAegis) { Guard-UiPort }
            Build-IfNeeded "all"
            Invoke-Compose -ComposeArgs $upArgs -KrakenProfile:$profile
        }
    }
    if (-not $NoWait) { Wait-Component $Component $WaitTimeout }
}

function Stop-Component([string]$Component) {
    Assert-ComponentSupported $Component
    $profile = ($Edition -eq "suite" -and $Component -ne "aegis")
    switch ($Component) {
        "aegis" {
            Invoke-Compose -ComposeArgs (@("stop") + $AegisServices)
        }
        "kraken" {
            Invoke-Compose -ComposeArgs (@("stop") + $KrakenServices) -KrakenProfile:$profile
        }
        "all" {
            Invoke-Compose -ComposeArgs @("down") -KrakenProfile:$profile
        }
    }
}

function Cmd-Start([string]$Component, [string[]]$Options) {
    $timeout = 300
    $noWait = $false
    for ($i = 0; $i -lt $Options.Count; $i++) {
        switch ($Options[$i]) {
            "--wait" { }
            "--no-wait" { $noWait = $true }
            "--timeout" {
                if ($i + 1 -ge $Options.Count) { UsageError "--timeout requires seconds" }
                $timeout = $Options[$i + 1]
                $i++
            }
            default { UsageError "unknown start option: $($Options[$i])" }
        }
    }
    if ("$timeout" -notmatch '^\d+$') { UsageError "--timeout must be a number of seconds" }
    Assert-Admin "ak start"
    Initialize-Env
    Require-Docker
    Start-Component $Component -WaitTimeout ([int]$timeout) -NoWait:$noWait
    if ($noWait) {
        Write-Host "Started $Component; health checks may still be running. Check with: ak status" -ForegroundColor Green
    } else {
        Write-Host "Started $Component. Check with: ak status" -ForegroundColor Green
    }
}

function Cmd-Stop([string]$Component) {
    Assert-Admin "ak stop"
    Require-Docker
    Stop-Component $Component
    Write-Host "Stopped $Component." -ForegroundColor Green
}

function Cmd-Restart([string]$Component) {
    Assert-Admin "ak restart"
    Require-Docker
    Stop-Component $Component
    Start-Component $Component
    Write-Host "Restarted $Component." -ForegroundColor Green
}

function Cmd-Status([string]$Component) {
    Assert-ComponentSupported $Component
    if (-not (Test-DockerCli)) {
        Write-Host "docker.exe not found; install Docker Desktop" -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Daemon)) {
        Write-Host "Docker Desktop is not running" -ForegroundColor Red
        exit 1
    }
    Write-Host "== $Component =="
    $rows = @(& docker ps -a --filter "label=com.docker.compose.project=$ProjectName" `
        --format "{{.Names}}`t{{.Status}}`t{{.Ports}}" 2>$null)
    $rows = @($rows | Where-Object {
        if (-not $_) { return $false }
        if ($Component -eq "all") {
            if ($Edition -eq "aegis") { return ($_ -notmatch '^aegis-kraken') }
            if ($Edition -eq "kraken") { return ($_ -match '^aegis-kraken') }
            return $true
        }
        if ($Component -eq "kraken") { return ($_ -match '^aegis-kraken') }
        return ($_ -notmatch '^aegis-kraken')
    } | Sort-Object -Unique)
    if ($rows.Count -eq 0) {
        Write-Host "no containers"
    } else {
        $rows | ForEach-Object { Write-Host $_ }
    }
}

function Cmd-Ps([string]$Component) {
    Assert-ComponentSupported $Component
    Require-Docker
    $profile = ($Edition -eq "suite" -and $Component -ne "aegis")
    Invoke-Compose -ComposeArgs @("ps") -KrakenProfile:$profile
}

function Cmd-Logs([string]$Component, [string[]]$Options) {
    $follow = $false
    $tail = "100"
    for ($i = 0; $i -lt $Options.Count; $i++) {
        switch ($Options[$i]) {
            "-f" { $follow = $true }
            "--follow" { $follow = $true }
            "--tail" {
                if ($i + 1 -ge $Options.Count) { UsageError "--tail requires a number" }
                $tail = $Options[$i + 1]
                $i++
            }
            "-n" {
                if ($i + 1 -ge $Options.Count) { UsageError "-n requires a number" }
                $tail = $Options[$i + 1]
                $i++
            }
            default { UsageError "unknown logs option: $($Options[$i])" }
        }
    }
    if ($tail -notmatch '^\d+$') { UsageError "--tail must be a number" }
    Assert-ComponentSupported $Component
    Require-Docker
    $profile = ($Edition -eq "suite" -and $Component -ne "aegis")
    $composeArgs = @("logs", "--tail", $tail)
    if ($follow) { $composeArgs += "-f" }
    Invoke-Compose -ComposeArgs $composeArgs -KrakenProfile:$profile
}

function Cmd-Doctor {
    $rc = 0
    if (Test-DockerCli) {
        Write-Host "OK    docker CLI found"
    } else {
        Write-Host "FAIL  docker CLI not found"
        $rc = 1
    }
    if (Test-Compose) {
        Write-Host "OK    docker compose v2 found"
    } else {
        Write-Host "FAIL  docker compose v2 not found"
        $rc = 1
    }
    if (Test-Daemon) {
        Write-Host "OK    Docker Desktop daemon is reachable"
    } else {
        Write-Host "FAIL  Docker Desktop is not running or not reachable"
        $rc = 1
    }
    if (Test-Path -LiteralPath $ComposeFile) {
        Write-Host "OK    Compose project found: $ComposeFile"
    } else {
        Write-Host "FAIL  Compose project missing: $ComposeFile"
        $rc = 1
    }
    if (Test-Path -LiteralPath $EnvFile) {
        Write-Host "OK    environment found: $EnvFile"
        if ($HasAegis) {
            $port = EnvValue "AEGIS_UI_PORT" "3000"
            if ($port -match '^\d+$' -and (Test-PortInUse ([int]$port))) {
                Write-Host "WARN  dashboard port $port is already in use; ak start will use a free port"
            } else {
                Write-Host "OK    dashboard port $port is free"
            }
        }
    } else {
        Write-Host "FAIL  environment missing: $EnvFile; run ak start as Administrator"
        $rc = 1
    }
    Write-Host ""
    Write-Host "Resources:"
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        $free = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        Write-Host ("INFO  host memory: {0:N1} GiB total, {1:N1} GiB free" -f $total, $free)
    } catch {
        Write-Host "WARN  cannot read host memory"
    }
    $wslConfig = Join-Path $env:USERPROFILE ".wslconfig"
    if (Test-Path -LiteralPath $wslConfig) {
        $limit = @(Get-Content -LiteralPath $wslConfig -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^\s*memory\s*=' })
        if ($limit.Count -gt 0) {
            Write-Host "INFO  WSL ceiling $($limit[0].Trim()) (VM limit, includes Docker Desktop and page cache)"
        } else {
            Write-Host "WARN  .wslconfig has no memory= ceiling; Docker Desktop can grow to half the host RAM"
        }
    } else {
        Write-Host "WARN  no %USERPROFILE%\.wslconfig; Docker Desktop can grow to half the host RAM"
        Write-Host "      Set memory= and autoMemoryReclaim=gradual to bound it."
    }
    if (Test-Daemon) {
        $engineMem = & docker info --format "{{.MemTotal}}" 2>$null
        $engineCpu = & docker info --format "{{.NCPU}}" 2>$null
        if ("$engineMem" -match '^\d+$') {
            Write-Host ("INFO  Docker engine limit: {0:N1} GiB across {1} CPU" -f ([double]$engineMem / 1GB), $engineCpu)
        }
        & docker stats --no-stream --format "INFO  usage {{.Name}}: {{.MemUsage}} ({{.MemPerc}})" 2>$null |
            Select-Object -First 12 | ForEach-Object { Write-Host $_ }
    }

    if (Test-Admin) {
        Write-Host "OK    running elevated (configure available)"
    } else {
        Write-Host "WARN  not elevated; ak configure requires Administrator"
    }
    return $rc
}

function Cmd-Url([string]$Component) {
    Assert-ComponentSupported $Component
    if ($HasAegis -and ($Component -eq "aegis" -or $Component -eq "all")) {
        $domain = EnvValue "AEGIS_DOMAIN" (RegistryValue "Domain" "aegis.local")
        $port = EnvValue "AEGIS_UI_PORT" (RegistryValue "UiPort" "3000")
        $public = EnvValue "PUBLIC_BASE_URL" ""
        if (-not $public) { $public = "https://$domain" }
        $public = $public.TrimEnd('/')
        Write-Host "Aegis dashboard: $public/  (local: http://localhost:$port)"
    }
    if ($HasKraken -and ($Component -eq "kraken" -or $Component -eq "all")) {
        $krakenPort = EnvValue "KRAKEN_PORT_EXTERNAL" "8001"
        $base = EnvValue "KRAKEN_PUBLIC_BASE_PATH" ""
        Write-Host "Kraken: http://127.0.0.1:$krakenPort$($base.TrimEnd('/'))/  (suite: via Aegis Caddy)"
    }
}

function Cmd-Configure([string[]]$Options) {
    if (-not $HasAegis) {
        UsageError "ak configure is not available on the Kraken-only package; use ak url/update"
    }
    $domain = ""
    $email = ""
    $port = ""
    $publicUrl = ""
    $restart = $false

    for ($i = 0; $i -lt $Options.Count; $i++) {
        switch ($Options[$i]) {
            "--domain" {
                if ($i + 1 -ge $Options.Count) { UsageError "--domain requires a hostname" }
                $domain = $Options[$i + 1]; $i++
            }
            "--email" {
                if ($i + 1 -ge $Options.Count) { UsageError "--email requires an address" }
                $email = $Options[$i + 1]; $i++
            }
            "--port" {
                if ($i + 1 -ge $Options.Count) { UsageError "--port requires a number" }
                $port = $Options[$i + 1]; $i++
            }
            "--public-url" {
                if ($i + 1 -ge $Options.Count) { UsageError "--public-url requires an origin" }
                $publicUrl = $Options[$i + 1]; $i++
            }
            "--restart" { $restart = $true }
            "--no-restart" { $restart = $false }
            "-h" { CommandUsage "configure"; return }
            "--help" { CommandUsage "configure"; return }
            default { UsageError "unknown configure option: $($Options[$i])" }
        }
    }

    $changed = ($domain -or $email -or $port -or $publicUrl)
    if (-not $changed) {
        $values = Read-Env
        $currentDomain = if ($values.Contains("AEGIS_DOMAIN")) { $values["AEGIS_DOMAIN"] } else { RegistryValue "Domain" "aegis.local" }
        $currentEmail = if ($values.Contains("ACME_EMAIL")) { $values["ACME_EMAIL"] } else { RegistryValue "Email" "internal" }
        $currentPort = if ($values.Contains("AEGIS_UI_PORT")) { $values["AEGIS_UI_PORT"] } else { RegistryValue "UiPort" "3000" }
        $currentPublic = if ($values.Contains("PUBLIC_BASE_URL")) { $values["PUBLIC_BASE_URL"] } else { "https://$currentDomain" }
        Write-Host "Aegis domain:  $currentDomain"
        Write-Host "ACME email:   $currentEmail"
        Write-Host "Public URL:   $($currentPublic.TrimEnd('/'))"
        Write-Host "Local URL:    http://localhost:$currentPort"
        return
    }

    Assert-Admin "ak configure"
    $psArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ConfigScript,
        "-InstallRoot", $ServerRoot, "-DataDir", $DataDir, "-Edition", $Edition, "-Update"
    )
    if ($domain) { $psArgs += @("-Domain", $domain) }
    if ($email) { $psArgs += @("-Email", $email) }
    if ($port) { $psArgs += @("-UiPort", $port) }
    if ($publicUrl) { $psArgs += @("-PublicUrl", $publicUrl) }
    & powershell.exe @psArgs
    if ($LASTEXITCODE -ne 0) { Fail "configuration was not written" }

    if ($restart) {
        Require-Docker
        Start-Component "all"
        Write-Host "Restarted Aegis and Kraken." -ForegroundColor Green
    } else {
        Write-Host "Apply with: ak restart"
    }
}

function Get-NormalizedVersion([string]$Value) {
    $normalized = $Value.Trim()
    if ($normalized.StartsWith("v")) { $normalized = $normalized.Substring(1) }
    if ($normalized -notmatch '^\d+\.\d+\.\d+$') {
        UsageError "invalid version: $Value (expected MAJOR.MINOR.PATCH)"
    }
    return $normalized
}

function Get-LatestVersion {
    $headers = @{ "User-Agent" = "aegis-ak"; "Accept" = "application/vnd.github+json" }
    try {
        $release = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$UpdateRepo/releases/latest" `
            -Headers $headers -ErrorAction Stop
    } catch {
        Fail "cannot resolve the latest release: $($_.Exception.Message)"
    }
    if (-not $release -or $release.draft -or $release.prerelease) {
        Fail "the latest release is not a stable published release"
    }
    return (Get-NormalizedVersion ([string]$release.tag_name))
}

function Get-EditionAsset([string]$Version) {
    switch ($Edition) {
        "aegis" { return "aegis-server-$Version-x64.msi" }
        "kraken" { return "kraken-server-$Version-x64.msi" }
        "suite" { return "aegis-suite-$Version-x64.msi" }
    }
}

function Save-UpdateFile([string]$Uri, [string]$Path) {
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        Fail "download failed: $Uri ($($_.Exception.Message))"
    }
}

function Get-SidecarHash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    $first = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue |
        Where-Object { $_.Trim() -ne "" } | Select-Object -First 1)[0]
    if ($first -match '^([0-9A-Fa-f]{64})\s') { return $matches[1].ToLowerInvariant() }
    return ""
}

function Cmd-Update([string[]]$Options) {
    $version = ""
    $from = ""
    $expectedHash = ""
    $check = $false
    $latest = $false
    $allowDowngrade = $false
    $restart = $true
    $yes = $false
    $dryRun = $false

    for ($i = 0; $i -lt $Options.Count; $i++) {
        switch ($Options[$i]) {
            "--version" {
                if ($i + 1 -ge $Options.Count) { UsageError "--version requires a version" }
                $version = $Options[$i + 1]; $i++
            }
            "--from" {
                if ($i + 1 -ge $Options.Count) { UsageError "--from requires a directory, MSI or URL" }
                $from = $Options[$i + 1]; $i++
            }
            "--sha256" {
                if ($i + 1 -ge $Options.Count) { UsageError "--sha256 requires a hash" }
                $expectedHash = $Options[$i + 1]; $i++
            }
            "--check" { $check = $true }
            "--latest" { $latest = $true }
            "--allow-downgrade" { $allowDowngrade = $true }
            "--no-restart" { $restart = $false }
            "--yes" { $yes = $true }
            "--dry-run" { $dryRun = $true }
            "-h" { CommandUsage "update"; return }
            "--help" { CommandUsage "update"; return }
            default { UsageError "unknown update option: $($Options[$i])" }
        }
    }

    if ($version -and $latest) { UsageError "use --version or --latest, not both" }
    if (-not $version) {
        if ($latest) {
            $version = Get-LatestVersion
        } elseif ($from -and (Test-Path -LiteralPath $from) -and -not (Get-Item -LiteralPath $from).PSIsContainer) {
            if ((Split-Path -Leaf $from) -match '-(\d+\.\d+\.\d+)-x64\.msi$') {
                $version = $matches[1]
            }
        } elseif ($from -and $from -match '^https?://.*-(\d+\.\d+\.\d+)-x64\.msi$') {
            $version = $matches[1]
        } elseif ($check) {
            $version = Get-LatestVersion
        }
        if (-not $version) {
            UsageError "specify --version, --latest, or a versioned local MSI with --from"
        }
    }
    $version = Get-NormalizedVersion $version
    $current = Get-NormalizedVersion $AkVersion
    $comparison = ([version]$version).CompareTo([version]$current)

    if ($check) {
        Write-Host "Installed: $Edition $current"
        Write-Host "Target:    $Edition $version"
        if ($comparison -lt 0) { Write-Host "Target is older; use --allow-downgrade and a verified database backup." }
        return
    }
    if ($comparison -lt 0 -and -not $allowDowngrade) {
        Fail "refusing to downgrade from $current to $version without --allow-downgrade and a verified database backup"
    }

    Assert-Admin "ak update"
    $asset = Get-EditionAsset $version
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("aegis-update-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $artifact = Join-Path $tempRoot $asset
    $sidecar = "$artifact.sha256"
    $fromIsLocal = $false
    $fromUri = ""

    try {
        if ($from) {
            if (Test-Path -LiteralPath $from) {
                $fromIsLocal = $true
                $item = Get-Item -LiteralPath $from
                if ($item.PSIsContainer) {
                    $artifact = Join-Path $item.FullName $asset
                    $sidecar = "$artifact.sha256"
                } else {
                    $artifact = $item.FullName
                    $sidecar = "$artifact.sha256"
                }
                if (-not (Test-Path -LiteralPath $artifact)) {
                    Fail "release asset not found: $artifact"
                }
            } elseif ($from -match '^https?://') {
                if ($from -match '\.msi$') {
                    $fromUri = $from
                    $asset = Split-Path -Leaf ([uri]$from).AbsolutePath
                    $artifact = Join-Path $tempRoot $asset
                    $sidecar = "$artifact.sha256"
                } else {
                    $fromUri = "$($from.TrimEnd('/'))/$asset"
                }
            } else {
                Fail "--from is neither an existing path nor an http(s) URL: $from"
            }
        } else {
            $fromUri = "$($UpdateBaseUrl.TrimEnd('/'))/v$version/$asset"
        }

        if (-not $fromIsLocal) {
            Save-UpdateFile $fromUri $artifact
            Save-UpdateFile "$fromUri.sha256" $sidecar
        }

        $sidecarHash = Get-SidecarHash $sidecar
        if ($expectedHash) {
            if ($expectedHash -notmatch '^[0-9A-Fa-f]{64}$') { UsageError "--sha256 must be 64 hexadecimal characters" }
            $sidecarHash = $expectedHash.ToLowerInvariant()
        }
        if (-not $sidecarHash) {
            Fail "no SHA-256 sidecar found for $asset; pass --sha256 with the published digest"
        }
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
        if ($actualHash -ne $sidecarHash) {
            Fail "SHA-256 mismatch for $asset (expected $sidecarHash, got $actualHash)"
        }

        Write-Host "Update: $Edition $current -> $version"
        Write-Host "Asset:  $artifact"
        Write-Host "SHA256: $actualHash"
        if ($dryRun) {
            Write-Host "Dry run: no files changed."
            return
        }
        if (-not $yes) {
            $answer = Read-Host "Install this MSI and restart the stack? [y/N]"
            if ($answer -notmatch '^(?i)y(es)?$') {
                Write-Host "Update cancelled."
                return
            }
        }

        $msiArgs = @("/i", "`"$artifact`"", "/qn", "/norestart")
        if ($HasAegis) {
            $domain = EnvValue "AEGIS_DOMAIN" (RegistryValue "Domain" "aegis.local")
            $email = EnvValue "ACME_EMAIL" (RegistryValue "Email" "internal")
            $port = EnvValue "AEGIS_UI_PORT" (RegistryValue "UiPort" "3000")
            $msiArgs += @("AEGIS_DOMAIN=$domain", "ACME_EMAIL=$email", "AEGIS_UI_PORT=$port")
        }
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            Fail "MSI update failed (msiexec exit $($process.ExitCode)); previous files remain"
        }
        if ($restart) {
            $newAk = Join-Path $ServerRoot "bin\ak.ps1"
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $newAk restart
            if ($LASTEXITCODE -ne 0) { Fail "update installed, but restart failed; run ak restart" }
        } else {
            Write-Host "Update installed. Apply with: ak restart"
        }
        Write-Host "Updated $Edition to $version." -ForegroundColor Green
    } finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Cmd-Version {
    Write-Host "ak $AkVersion"
    Write-Host "server package: $Edition $AkVersion (Windows)"
    if (Test-Path -LiteralPath $EnvFile) {
        Write-Host "configuration: $EnvFile"
    }
}

function Main([string[]]$Arguments) {
    $argv = @($Arguments)
    if ($argv.Count -eq 0) { Usage; return }

    $command = $argv[0]
    $argv = @($argv | Select-Object -Skip 1)
    $component = "all"

    if ($command -in @("aegis", "kraken", "all")) {
        $component = $command
        if ($argv.Count -gt 0) {
            $command = $argv[0]
            $argv = @($argv | Select-Object -Skip 1)
        } else {
            $command = "status"
        }
    }

    if ($command -in @("start", "stop", "restart", "status", "ps", "url")) {
        if ($argv.Count -gt 0) {
            if ($argv[0] -in @("aegis", "kraken", "all")) {
                $component = $argv[0]
                $argv = @($argv | Select-Object -Skip 1)
            } elseif ($argv[0] -in @("-h", "--help")) {
                CommandUsage $command
                return
            } elseif ($argv[0] -like "--*" -and $command -eq "start") {
                # start parses --wait/--no-wait/--timeout itself.
            } else {
                UsageError "unknown component: $($argv[0]) (use aegis, kraken, or all)"
            }
        }
    }

    if ($command -eq "update") {
        if ($component -ne "all") {
            UsageError "ak update updates the installed edition; do not pass a component"
        }
        Cmd-Update $argv
        return
    }

    if ($command -eq "logs") {
        if ($argv.Count -gt 0 -and $argv[0] -in @("aegis", "kraken", "all")) {
            $component = $argv[0]
            $argv = @($argv | Select-Object -Skip 1)
        } elseif ($argv.Count -gt 0 -and $argv[0] -in @("-h", "--help")) {
            CommandUsage logs
            return
        }
        Cmd-Logs $component $argv
        return
    }

    switch ($command) {
        "help" {
            if ($argv.Count -gt 0) { CommandUsage $argv[0] } else { Usage }
        }
        "-h" { Usage }
        "--help" { Usage }
        "version" { Cmd-Version }
        "--version" { Cmd-Version }
        "start" { Cmd-Start $component @($argv) }
        "stop" { Cmd-Stop $component }
        "restart" { Cmd-Restart $component }
        "status" { Cmd-Status $component }
        "ps" { Cmd-Ps $component }
        "url" { Cmd-Url $component }
        "doctor" { exit (Cmd-Doctor) }
        "configure" { Cmd-Configure $argv }
        "config" { Cmd-Configure $argv }
        "setup" { Cmd-Configure $argv }
        default {
            UsageError "unknown command: $command"
        }
    }
}

try {
    Main -Arguments $args
} catch {
    Write-Host "ak: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
