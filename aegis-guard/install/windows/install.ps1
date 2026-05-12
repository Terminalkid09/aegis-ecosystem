# Aegis-Guard Native Installation (Windows)
# Prerequisites: Java 21+, Maven (in PATH), NSSM (nssm.cc)

$nssmPath = "nssm.exe"
$installDir = "C:\Program Files\Aegis\Guard"
$jarPath = "$installDir\aegis-guard.jar"
$envFile = "..\..\..\.env"

Write-Host "--- Aegis-Guard Hardened Setup ---" -ForegroundColor Cyan

# 1. Load .env
if (-not (Test-Path $envFile)) { Write-Error "No .env file found."; exit 1 }
Get-Content $envFile | Where-Object { $_ -match '=' } | ForEach-Object {
    $key, $value = $_.Split('=', 2)
    [Environment]::SetEnvironmentVariable($key, $value, "Process")
}

# 2. Build
mvn clean package -DskipTests -f ..\..\pom.xml

# 3. Create secure directory and restrict access
New-Item -Path $installDir -ItemType Directory -Force
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($adminRule)
Set-Acl $installDir $acl

Copy-Item "..\target\aegis-guard.jar" -Destination $jarPath

# 4. Register as Service
$machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid').MachineGuid
.\$nssmPath install AegisGuard "java" "-jar $jarPath"
.\$nssmPath set AegisGuard AppEnvironmentExtra "AEGIS_GATEWAY_URL=$env:AEGIS_GATEWAY_URL`nAEGIS_GUARD_API_KEY=$env:AEGIS_API_KEY`nAEGIS_AGENT_ID=$machineGuid"

# 5. Integrity Check (Simple hash)
Get-FileHash $jarPath -Algorithm SHA256 | Out-File "$installDir\aegis-guard.sha256"

Start-Service AegisGuard
Write-Host "Service AegisGuard started securely." -ForegroundColor Green
