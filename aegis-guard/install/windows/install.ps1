# Aegis-Guard Native Installation (Windows)
# Prerequisites: Java 21+, Maven (in PATH), NSSM (nssm.cc)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$nssmPath = Join-Path $scriptPath "nssm.exe"
$installDir = "C:\Program Files\Aegis\Guard"
$jarPath = Join-Path $installDir "aegis-guard.jar"
$envFile = Join-Path $scriptPath "..\..\.env"
$pomPath = Join-Path $scriptPath "..\..\pom.xml"

Write-Host "â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—" -ForegroundColor Cyan
Write-Host "â•‘ Aegis-Guard Windows Installation       â•‘" -ForegroundColor Cyan
Write-Host "â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Cyan

# === PREREQUISITES CHECK ===
Write-Host "`n[1/6] Checking prerequisites..." -ForegroundColor Cyan

if (-not (Test-Path $nssmPath)) {
    Write-Error "âœ— nssm.exe not found at $nssmPath. Please copy nssm.exe here."
    exit 1
}
Write-Host "  âœ“ nssm.exe found" -ForegroundColor Green

# Automated JRE check/download
$jrePath = Join-Path $scriptPath "jre\bin\java.exe"
if ($null -eq (Get-Command java -ErrorAction SilentlyContinue) -and -not (Test-Path $jrePath)) {
    Write-Host "  âš  Java not found. Downloading portable JRE..." -ForegroundColor Yellow
    $jreZip = Join-Path $scriptPath "jre.zip"
    Invoke-WebRequest -Uri "https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.zip" -OutFile $jreZip # Example URL
    Expand-Archive -Path $jreZip -DestinationPath (Join-Path $scriptPath "jre_temp")
    Move-Item (Join-Path $scriptPath "jre_temp\*\bin") (Join-Path $scriptPath "jre\bin") -Force
    Remove-Item $jreZip
    Remove-Item (Join-Path $scriptPath "jre_temp") -Recurse
    $javaExe = $jrePath
} elseif (Test-Path $jrePath) {
    $javaExe = $jrePath
} else {
    $javaExe = "java"
}
Write-Host "  âœ“ Using Java: $javaExe" -ForegroundColor Green

if ($null -eq (Get-Command mvn -ErrorAction SilentlyContinue)) {
    Write-Error "âœ— Maven not found in PATH. Please install Maven 3.8+ and add to PATH."
    exit 1
}
Write-Host "  âœ“ Maven found" -ForegroundColor Green

if (-not (Test-Path $pomPath)) {
    Write-Error "âœ— pom.xml not found at $pomPath"
    exit 1
}
Write-Host "  âœ“ pom.xml found" -ForegroundColor Green

# === ENVIRONMENT LOADING ===
Write-Host "`n[2/6] Loading environment from .env..." -ForegroundColor Cyan

if (-not (Test-Path $envFile)) {
    Write-Error "âœ— .env file not found at $envFile"
    exit 1
}

$envVars = @{}
Get-Content $envFile | Where-Object { $_ -match '=' -and -not $_.StartsWith('#') } | ForEach-Object {
    $key, $value = $_.Split('=', 2)
    $key = $key.Trim()
    $value = $value.Trim('"').Trim("'")
    if ($key -and $value) {
        $envVars[$key] = $value
        [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
}

# Validate required variables
if (-not $envVars['AEGIS_API_KEY']) {
    Write-Error "âœ— AEGIS_API_KEY not found in .env"
    exit 1
}
Write-Host "  âœ“ AEGIS_API_KEY configured" -ForegroundColor Green
Write-Host "  âœ“ Environment loaded" -ForegroundColor Green

# === BUILD / ARTIFACT CHECK ===
Write-Host "`n[3/6] Verifying artifact..." -ForegroundColor Cyan

$jarSource = Join-Path $scriptPath "..\target\aegis-guard.jar"
if (-not (Test-Path $jarSource)) {
    Write-Error "âœ— aegis-guard.jar not found at $jarSource`nPlease ensure the project is built or copy the pre-compiled JAR to the 'target' folder."
    exit 1
}
Write-Host "  âœ“ Artifact found: aegis-guard.jar" -ForegroundColor Green

# === INSTALLATION DIRECTORY ===
Write-Host "`n[4/6] Creating installation directory..." -ForegroundColor Cyan

New-Item -Path $installDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

# Secure directory permissions (Administrators only)
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($adminRule)
Set-Acl $installDir $acl

Write-Host "  âœ“ Directory created at $installDir" -ForegroundColor Green

# Copy JAR
$jarSource = Join-Path $scriptPath "..\target\aegis-guard.jar"
if (-not (Test-Path $jarSource)) {
    Write-Error "âœ— JAR file not found at $jarSource"
    exit 1
}

Copy-Item $jarSource -Destination $jarPath -Force
Write-Host "  âœ“ JAR deployed" -ForegroundColor Green

# === CONFIGURATION ===
Write-Host "`n[5/6] Configuring service..." -ForegroundColor Cyan

$machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid').MachineGuid
$agentId = $envVars['AEGIS_AGENT_ID']
if (-not $agentId) {
    $agentId = $machineGuid
}

$gatewayUrl = $envVars['AEGIS_GATEWAY_URL']
if (-not $gatewayUrl) {
    $gatewayUrl = "http://localhost:8088/api/v1/events"
}

# Rewrite Docker internal URL to localhost for host execution
if ($gatewayUrl -match "aegis-link:8080") {
    $externalPort = $envVars['LINK_PORT_EXTERNAL']
    if (-not $externalPort) { $externalPort = "8088" }
    $gatewayUrl = $gatewayUrl -replace "aegis-link:8080", "localhost:$externalPort"
}

Write-Host "  Agent ID: $agentId" -ForegroundColor Gray
Write-Host "  Gateway:  $gatewayUrl" -ForegroundColor Gray

# Compute file hash
$hash = Get-FileHash $jarPath -Algorithm SHA256
$hash | Out-File "$installDir\aegis-guard.sha256" -Force
Write-Host "  âœ“ File integrity: $(($hash.Hash).Substring(0, 16))..." -ForegroundColor Green

# Check if service already exists
if (Get-Service "AegisGuard" -ErrorAction SilentlyContinue) {
    Write-Host "  â„¹ Service already exists, updating configuration..." -ForegroundColor Yellow
    Stop-Service AegisGuard -Force -ErrorAction SilentlyContinue
    & $nssmPath remove AegisGuard confirm
}

# Install service
& $nssmPath install AegisGuard "java" "-jar `"$jarPath`""
if ($LASTEXITCODE -ne 0) {
    Write-Error "âœ— Failed to install service via NSSM"
    exit 1
}

# Set environment variables for service
$apiKey = $envVars['AEGIS_API_KEY']
if ($envVars['AEGIS_SCAN_INTERVAL_MS']) {
    $scanInterval = $envVars['AEGIS_SCAN_INTERVAL_MS']
} else {
    $scanInterval = '1000'
}

& $nssmPath set AegisGuard AppEnvironmentExtra `
    "AEGIS_GATEWAY_URL=$gatewayUrl`nAEGIS_GUARD_API_KEY=$apiKey`nAEGIS_AGENT_ID=$agentId`nAEGIS_SCAN_INTERVAL_MS=$scanInterval"

# Set service recovery
& $nssmPath set AegisGuard AppExit Default Restart
& $nssmPath set AegisGuard AppRestartDelay 5000
& $nssmPath set AegisGuard AppStopMethodSkip 0

Write-Host "  âœ“ Service configured" -ForegroundColor Green

# === START SERVICE ===
Write-Host "`n[6/6] Starting service..." -ForegroundColor Cyan

Start-Service AegisGuard
Start-Sleep -Seconds 3

$svc = Get-Service AegisGuard -ErrorAction SilentlyContinue
if ($svc.Status -eq "Running") {
    Write-Host "  âœ“ Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host "  âœ— Service failed to start (Status: $($svc.Status))" -ForegroundColor Red
    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    - Check Event Viewer: Applications and Services Logs > Windows > NSSM"
    Write-Host "    - Check Java version: java -version"
    Write-Host "    - Check JAR exists: Test-Path '$jarPath'"
    Write-Host "    - Try manual start: java -jar '$jarPath'"
    exit 1
}

# === SUCCESS ===
Write-Host "`nâ•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—" -ForegroundColor Green
Write-Host "â•‘ âœ“ Installation Successful              â•‘" -ForegroundColor Green
Write-Host "â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Green

Write-Host @"

Service Details:
  Name:        AegisGuard
  Path:        $jarPath
  Agent ID:    $agentId
  Gateway:     $gatewayUrl
  
Management:
  View logs:   Get-EventLog -LogName Application -Source AegisGuard -Newest 20
  Stop:        Stop-Service AegisGuard
  Start:       Start-Service AegisGuard
  Status:      Get-Service AegisGuard
  Uninstall:   .\uninstall.ps1

For issues, check:
  - Windows Event Viewer (Application logs)
  - .env configuration
  - Firewall rules for port 8088
  - Network connectivity to gateway
"@ -ForegroundColor Green
