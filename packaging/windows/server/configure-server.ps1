<#
.SYNOPSIS
  Generate or update the Aegis/Kraken server environment on Windows.

.DESCRIPTION
  The MSI stores the operator's public FQDN, ACME email and dashboard port in
  HKLM. The first `ak start` calls this script to generate the environment with
  random secrets. `ak configure` calls it again with -Update, which changes only
  the requested public settings and never rotates existing secrets.

  Editions:
    aegis  - Aegis server; server.env with Aegis and shared Kraken settings
    kraken - standalone Kraken; kraken.env with private database/Redis secrets
    suite  - both stacks; server.env with the shared SSO/ingest settings

  The script deliberately does not print secret values. The environment file is
  restricted to Administrators and SYSTEM.
#>
[CmdletBinding()]
param(
    [string]$Domain = "",
    [string]$Email = "",
    [string]$PublicUrl = "",
    [string]$UiPort = "",
    [string]$InstallRoot = "",
    [string]$DataDir = "",
    [ValidateSet("aegis", "kraken", "suite")]
    [string]$Edition = "suite",
    [switch]$Update,
    [switch]$AllowPortFallback,
    [switch]$PrintOnly
)

$ErrorActionPreference = "Stop"
$isKraken = ($Edition -eq "kraken")

if (-not $InstallRoot) {
    $InstallRoot = Split-Path -Parent $PSScriptRoot
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)

if (-not $DataDir) {
    $DataDir = if ($env:AEGIS_DATA_DIR) { $env:AEGIS_DATA_DIR } else {
        Join-Path $env:ProgramData "Aegis"
    }
}
$DataDir = [IO.Path]::GetFullPath($DataDir)
$envFileName = if ($isKraken) { "kraken.env" } else { "server.env" }
$envFile = Join-Path $DataDir $envFileName
$secretsDir = Join-Path $DataDir "secrets"
$registryName = switch ($Edition) {
    "kraken" { "Kraken" }
    "suite" { "Suite" }
    default { "Server" }
}
$registryKey = "HKLM:\Software\Aegis\$registryName"

function New-Hex([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

function New-Base64([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Read-EnvFile([string]$Path) {
    $values = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $values }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $values[$matches[1]] = $matches[2]
        }
    }
    return $values
}

function Get-EnvValue($Values, [string]$Key, [string]$Default = "") {
    if ($Values.Contains($Key) -and $Values[$Key] -ne $null -and "$($Values[$Key])" -ne "") {
        return "$($Values[$Key])"
    }
    return $Default
}

function Test-PortInUse([int]$Port) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $false
    } catch {
        return $true
    } finally {
        if ($listener) {
            try { $listener.Stop() } catch { }
        }
    }
}

function Find-FreePort([int]$Preferred) {
    if (-not (Test-PortInUse $Preferred)) { return $Preferred }
    for ($candidate = 3000; $candidate -le 3099; $candidate++) {
        if (-not (Test-PortInUse $candidate)) { return $candidate }
    }
    throw "no free dashboard port in 3000-3099; choose a free port explicitly"
}

function Assert-Domain([string]$Value) {
    if ($Value -notmatch '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
        throw "invalid public hostname: $Value"
    }
    if ($Value -match '^\d{1,3}(\.\d{1,3}){3}$') {
        throw "the public hostname must be a DNS name, not an IP address: $Value"
    }
}

function Assert-Email([string]$Value) {
    if ($Value -eq "internal") { return }
    if ($Value -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        throw "invalid ACME email: $Value"
    }
}

function Set-PrivateAcl([string]$Path) {
    $icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
    & $icacls $Path /inheritance:r /grant:r "*S-1-5-32-544:(F)" "*S-1-5-18:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "could not restrict permissions on $Path"
    }
}

function Add-Origin([string]$Origins, [string]$Origin) {
    if (-not $Origin) { return $Origins }
    $parts = @($Origins -split ',' | Where-Object { $_ -ne "" })
    if ($parts -notcontains $Origin) { $parts += $Origin }
    return ($parts -join ",")
}

if ($env:AEGIS_DOMAIN) { $Domain = $env:AEGIS_DOMAIN }
if ($env:ACME_EMAIL) { $Email = $env:ACME_EMAIL }
if ($env:AEGIS_PUBLIC_URL) { $PublicUrl = $env:AEGIS_PUBLIC_URL }
if ($env:AEGIS_UI_PORT -and -not $UiPort) { $UiPort = $env:AEGIS_UI_PORT }

# The MSI writes these values before the first start. Read them only when the
# caller did not provide a value; explicit command-line values always win.
if (-not $Domain -and (Test-Path $registryKey)) {
    $Domain = (Get-ItemProperty -Path $registryKey -Name Domain -ErrorAction SilentlyContinue).Domain
}
if (-not $Email -and (Test-Path $registryKey)) {
    $Email = (Get-ItemProperty -Path $registryKey -Name Email -ErrorAction SilentlyContinue).Email
}
if (-not $UiPort -and (Test-Path $registryKey)) {
    $UiPort = (Get-ItemProperty -Path $registryKey -Name UiPort -ErrorAction SilentlyContinue).UiPort
}

$values = Read-EnvFile $envFile
$exists = ($values.Count -gt 0)

if ($isKraken) {
    if ($PrintOnly) {
        $port = Get-EnvValue $values "KRAKEN_PORT_EXTERNAL" "8001"
        Write-Host "Kraken URL:  http://127.0.0.1:$port$(Get-EnvValue $values 'KRAKEN_PUBLIC_BASE_PATH' '')/"
        Write-Host "Environment: $envFile"
        exit 0
    }

    $krakenDbPassword = Get-EnvValue $values "KRAKEN_DB_PASSWORD" (New-Hex 16)
    $krakenRedisPassword = Get-EnvValue $values "KRAKEN_REDIS_PASSWORD" (New-Hex 16)
    $krakenSecret = Get-EnvValue $values "KRAKEN_SECRET_KEY" (New-Hex 32)
    $krakenApiKey = Get-EnvValue $values "KRAKEN_INTERNAL_API_KEY" (New-Hex 32)
    $brokerToken = Get-EnvValue $values "SANDBOX_BROKER_TOKEN" (New-Hex 32)
    $ssoSecret = Get-EnvValue $values "KRAKEN_SSO_SECRET" (New-Hex 32)
    $ingestSecret = Get-EnvValue $values "KRAKEN_INGEST_SECRET" (New-Hex 32)
    $port = Get-EnvValue $values "KRAKEN_PORT_EXTERNAL" "8001"
    if ($port -notmatch '^\d+$' -or [int]$port -lt 1 -or [int]$port -gt 65535) {
        throw "KRAKEN_PORT_EXTERNAL must be a TCP port (1-65535)"
    }

    $env = [ordered]@{
        COMPOSE_PROJECT_NAME = "aegis-kraken"
        KRAKEN_DB_PASSWORD = $krakenDbPassword
        KRAKEN_REDIS_PASSWORD = $krakenRedisPassword
        KRAKEN_SECRET_KEY = $krakenSecret
        KRAKEN_INTERNAL_API_KEY = $krakenApiKey
        SANDBOX_BROKER_TOKEN = $brokerToken
        KRAKEN_SSO_SECRET = $ssoSecret
        KRAKEN_SSO_ENABLED = "false"
        KRAKEN_INGEST_ENABLED = "false"
        KRAKEN_INGEST_KEY = ""
        KRAKEN_INGEST_SECRET = $ingestSecret
        KRAKEN_INGEST_URL = ""
        KRAKEN_PUBLIC_BASE_PATH = Get-EnvValue $values "KRAKEN_PUBLIC_BASE_PATH" ""
        KRAKEN_PORT_EXTERNAL = $port
        CORS_ORIGINS = Get-EnvValue $values "CORS_ORIGINS" "http://localhost:$port"
        DOCKER_GID = Get-EnvValue $values "DOCKER_GID" "0"
        KRAKEN_HONEYPOT_BIND_IP = Get-EnvValue $values "KRAKEN_HONEYPOT_BIND_IP" "127.0.0.1"
        KRAKEN_SENSOR_PROTOCOLS = Get-EnvValue $values "KRAKEN_SENSOR_PROTOCOLS" "ssh,http,ftp,telnet,smb,rdp"
        KRAKEN_FILE_ANALYSIS_ENABLED = Get-EnvValue $values "KRAKEN_FILE_ANALYSIS_ENABLED" "true"
        KRAKEN_OBJECT_STORE_BACKEND = Get-EnvValue $values "KRAKEN_OBJECT_STORE_BACKEND" "local"
        KRAKEN_DETONATION_ENABLED = Get-EnvValue $values "KRAKEN_DETONATION_ENABLED" "false"
        MALWARE_RETENTION_DAYS = Get-EnvValue $values "MALWARE_RETENTION_DAYS" "30"
        MALWARE_MAX_TOTAL_BYTES = Get-EnvValue $values "MALWARE_MAX_TOTAL_BYTES" "5368709120"
    }
    foreach ($key in @("KRAKEN_SENSOR_CONFIG_SIGNING_KEY", "KRAKEN_SMB_ENGINE",
                       "KRAKEN_SMB_SHARE", "KRAKEN_SMB_SERVER_NAME",
                       "KRAKEN_FTP_PASV_ADVERTISE_HOST", "KRAKEN_RDP_INGEST_ENABLED")) {
        if ($values.Contains($key) -and "$($values[$key])" -ne "") { $env[$key] = $values[$key] }
    }
} else {
    if (-not $Domain) { $Domain = Get-EnvValue $values "AEGIS_DOMAIN" "aegis.local" }
    if (-not $Email) { $Email = Get-EnvValue $values "ACME_EMAIL" "internal" }
    if (-not $UiPort) { $UiPort = Get-EnvValue $values "AEGIS_UI_PORT" "3000" }

    $currentDomain = Get-EnvValue $values "AEGIS_DOMAIN" $Domain
    $currentEmail = Get-EnvValue $values "ACME_EMAIL" $Email
    $currentPort = Get-EnvValue $values "AEGIS_UI_PORT" $UiPort
    $currentPublic = Get-EnvValue $values "PUBLIC_BASE_URL" "https://$currentDomain"
    $currentPublic = $currentPublic.TrimEnd('/')

    if ($PrintOnly) {
        Write-Host "Aegis domain:  $currentDomain"
        Write-Host "ACME email:   $currentEmail"
        Write-Host "Public URL:   $currentPublic"
        Write-Host "Local URL:    http://localhost:$currentPort"
        exit 0
    }

    Assert-Domain $Domain
    Assert-Email $Email

    if ($UiPort -notmatch '^\d+$') { throw "dashboard port must be a number" }
    $requestedPort = [int]$UiPort
    if ($requestedPort -lt 1 -or $requestedPort -gt 65535) {
        throw "dashboard port must be between 1 and 65535"
    }

    $publicUrlBound = $PSBoundParameters.ContainsKey("PublicUrl") -and $PublicUrl
    $domainBound = $PSBoundParameters.ContainsKey("Domain") -and $Domain
    if ($publicUrlBound) {
        if ($PublicUrl -notmatch '^https?://') {
            throw "public URL must start with http:// or https://"
        }
        $PublicUrl = $PublicUrl.TrimEnd('/')
        $uri = [Uri]$PublicUrl
        if ($domainBound -and $uri.Host -ne $Domain) {
            throw "public URL host $($uri.Host) does not match AEGIS_DOMAIN $Domain"
        }
        if (-not $domainBound) {
            if (-not $uri.Host) { throw "cannot derive a hostname from $PublicUrl" }
            $Domain = $uri.Host
            Assert-Domain $Domain
        }
    } elseif ($domainBound -or -not $exists) {
        $PublicUrl = "https://$Domain"
    } else {
        $PublicUrl = Get-EnvValue $values "PUBLIC_BASE_URL" "https://$Domain"
        $PublicUrl = $PublicUrl.TrimEnd('/')
    }

    if ($Domain -notmatch '\.local$' -and $Domain -ne "localhost" -and $Email -eq "internal") {
        throw "ACME email is required for a public FQDN; set -Email ops@example.com"
    }

    if ($requestedPort -ne [int]$currentPort) {
        if (Test-PortInUse $requestedPort) {
            if (-not $AllowPortFallback) {
                throw "port $requestedPort is already in use; stop the other process or choose another port"
            }
            $requestedPort = Find-FreePort $requestedPort
            Write-Host "dashboard port is busy; using $requestedPort" -ForegroundColor Yellow
        }
    }

    $uiPort = [string]$requestedPort

    # A first install generates every secret. An update preserves all existing
    # secrets and only replaces the public settings requested by the operator.
    $postgresPassword = Get-EnvValue $values "POSTGRES_PASSWORD" (New-Hex 16)
    $redisPassword = Get-EnvValue $values "REDIS_PASSWORD" (New-Hex 16)
    $apiKey = Get-EnvValue $values "AEGIS_API_KEY" (New-Hex 32)
    $enrollKey = Get-EnvValue $values "AGENT_ENROLL_KEY" (New-Hex 16)
    $jwtSecret = Get-EnvValue $values "JWT_SECRET" (New-Hex 32)
    $masterKey = Get-EnvValue $values "MASTER_KEY_B64" (New-Base64 32)
    $backupPassphrase = Get-EnvValue $values "BACKUP_PASSPHRASE" (New-Hex 16)
    $ssoSecret = Get-EnvValue $values "KRAKEN_SSO_SECRET" (New-Hex 32)
    $ingestSecret = Get-EnvValue $values "KRAKEN_INGEST_SECRET" (New-Hex 32)
    $krakenSecret = Get-EnvValue $values "KRAKEN_SECRET_KEY" (New-Hex 32)
    $krakenApiKey = Get-EnvValue $values "KRAKEN_INTERNAL_API_KEY" (New-Hex 32)
    $krakenDbPassword = Get-EnvValue $values "KRAKEN_DB_PASSWORD" (New-Hex 16)
    $krakenRedisPassword = Get-EnvValue $values "KRAKEN_REDIS_PASSWORD" (New-Hex 16)
    $brokerToken = Get-EnvValue $values "SANDBOX_BROKER_TOKEN" (New-Hex 32)

    $origins = Get-EnvValue $values "ALLOWED_ORIGINS" ""
    foreach ($origin in @("https://$Domain", "http://localhost:$uiPort", "http://localhost:5173", $PublicUrl)) {
        $origins = Add-Origin $origins $origin
    }

    $cookieSecure = "true"
    if ($PublicUrl -match '^http://') { $cookieSecure = "false" }
    $suite = ($Edition -eq "suite")

    $env = [ordered]@{
        COMPOSE_PROJECT_NAME = "aegis"
        POSTGRES_USER = "aegis_user"
        POSTGRES_PASSWORD = $postgresPassword
        POSTGRES_DB = "aegis_db"
        DATABASE_URL = "postgresql+asyncpg://aegis_user:$postgresPassword@aegis-postgres:5432/aegis_db"
        REDIS_PASSWORD = $redisPassword
        REDIS_URL = "redis://:$redisPassword@aegis-redis:6379"
        REDIS_HOST = "aegis-redis"
        REDIS_PORT = "6379"
        POSTGRES_PORT = "5444"
        BRAIN_PORT_EXTERNAL = "8000"
        LINK_PORT_EXTERNAL = "8088"
        OLLAMA_PORT_EXTERNAL = "11435"
        AEGIS_API_KEY = $apiKey
        AGENT_ENROLL_KEY = $enrollKey
        JWT_SECRET = $jwtSecret
        MASTER_KEY_B64 = $masterKey
        JWT_ALGORITHM = "HS256"
        JWT_EXPIRE_MINUTES = "60"
        AEGIS_DEBUG = "false"
        AEGIS_ALLOW_OPEN_REGISTRATION = "false"
        AEGIS_COOKIE_SECURE = $cookieSecure
        AEGIS_DOMAIN = $Domain
        ACME_EMAIL = $Email
        ALLOWED_ORIGINS = $origins
        PUBLIC_BASE_URL = $PublicUrl
        AEGIS_UI_PORT = $uiPort
        VITE_API_URL = "/api/v1"
        BACKUP_PASSPHRASE = $backupPassphrase
        SHODAN_API_KEY = ""
        ABUSEIPDB_API_KEY = ""
        KRAKEN_SSO_ENABLED = if ($suite) { "true" } else { "false" }
        KRAKEN_SSO_SECRET = $ssoSecret
        KRAKEN_SSO_TTL_SECONDS = "60"
        KRAKEN_INGEST_ENABLED = if ($suite) { "true" } else { "false" }
        KRAKEN_INGEST_KEY = if ($suite) { $apiKey } else { "" }
        KRAKEN_INGEST_SECRET = $ingestSecret
        KRAKEN_INGEST_URL = if ($suite) { "http://aegis-brain:8000" } else { "" }
        KRAKEN_PUBLIC_BASE_PATH = if ($suite) { "/kraken" } else { "" }
        KRAKEN_SECRET_KEY = $krakenSecret
        KRAKEN_INTERNAL_API_KEY = $krakenApiKey
        KRAKEN_DB_PASSWORD = $krakenDbPassword
        KRAKEN_REDIS_PASSWORD = $krakenRedisPassword
        SANDBOX_BROKER_TOKEN = $brokerToken
        KRAKEN_PORT_EXTERNAL = "8001"
        DOCKER_GID = "0"
        KRAKEN_HONEYPOT_BIND_IP = "127.0.0.1"
        KRAKEN_SENSOR_PROTOCOLS = "ssh,http,ftp,telnet,smb,rdp"
        KRAKEN_FILE_ANALYSIS_ENABLED = "true"
        KRAKEN_OBJECT_STORE_BACKEND = "local"
        KRAKEN_DETONATION_ENABLED = "false"
        MALWARE_RETENTION_DAYS = "30"
        MALWARE_MAX_TOTAL_BYTES = "5368709120"
        SIEM_ENABLED = "true"
        SYSLOG_ENABLED = "false"
    }
}

# Preserve operator-managed optional settings that are not part of the wizard.
foreach ($key in @(
    "AI_PROVIDER", "AI_MODEL", "AI_AUTOMATIC_ENRICH", "AI_RATE_LIMIT_PER_MIN",
    "GEMINI_API_KEY", "GEMINI_MODEL", "OPENAI_API_KEY", "OPENAI_BASE_URL",
    "OPENAI_MODEL", "OLLAMA_URL", "OLLAMA_DEFAULT_MODEL", "OLLAMA_ALLOWED_MODELS",
    "OIDC_ENABLED", "OIDC_ISSUER", "OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI", "OIDC_SCOPES", "OIDC_BUTTON_LABEL",
    "OIDC_GROUPS_CLAIM", "OIDC_GROUP_ROLE_MAP", "OIDC_DEFAULT_ROLE",
    "OIDC_AUTO_CREATE_USERS", "OIDC_LINK_BY_EMAIL", "OIDC_SYNC_ROLE",
    "OIDC_REQUIRE_VERIFIED_EMAIL", "OIDC_ALLOW_LOCAL_LOGIN",
    "MTLS_MODE", "ENTERPRISE_STRICT", "PLAYBOOK_SCRIPT_ENABLED",
    "SYSLOG_BIND", "SYSLOG_PORT", "SIEM_RETENTION_DAYS"
)) {
    if ($values.Contains($key) -and $values[$key] -ne "") {
        $env[$key] = $values[$key]
    }
}

if (-not (Test-Path -LiteralPath $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $secretsDir)) {
    New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
}

$lines = foreach ($key in $env.Keys) { "$key=$($env[$key])" }
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), $utf8)
Set-PrivateAcl $envFile

if ($isKraken) {
    Write-Host "Kraken environment written: $envFile"
    Write-Host "Local URL: http://127.0.0.1:$($env['KRAKEN_PORT_EXTERNAL'])/"
} else {
    Write-Host "Aegis server environment written: $envFile"
    Write-Host "Public URL: $PublicUrl"
    Write-Host "Local URL:  http://localhost:$uiPort"
}
if (-not $exists -and -not $Update) {
    Write-Host "Secrets generated. Run 'ak start' to build and start the stack." -ForegroundColor Green
}
