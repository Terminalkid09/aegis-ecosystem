@echo off
setlocal enabledelayedexpansion
title Aegis-Guard Automated Installer
color 0B

set ROOT_DIR=%~dp0
set JAR_DEST=%ROOT_DIR%aegis-guard.jar
set TARGET_JAR=%ROOT_DIR%target\aegis-guard.jar
set NSSM_PATH=%ROOT_DIR%install\windows\nssm.exe
set JRE_DIR=%ROOT_DIR%jre
set MVN_DIR=%ROOT_DIR%mvn_temp

echo =======================================================
echo           AEGIS-GUARD AUTONOMOUS INSTALLER
echo =======================================================

:: 1. JRE Setup (Self-Healing) - MUST BE FIRST
echo [1/4] Preparing runtime...
if not exist "%JRE_DIR%\bin\java.exe" (
    echo [INFO] Java not found. Downloading Microsoft JDK 21...
    powershell -Command "if (Test-Path 'jre_temp') { Remove-Item 'jre_temp' -Recurse -Force }; if (Test-Path 'jre') { Remove-Item 'jre' -Recurse -Force }; Invoke-WebRequest -Uri 'https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.zip' -OutFile 'jre.zip'; Expand-Archive -Path 'jre.zip' -DestinationPath 'jre_temp'; $topDir = Get-ChildItem 'jre_temp' | Select-Object -First 1; Move-Item $topDir.FullName 'jre'; Remove-Item 'jre.zip'; Remove-Item 'jre_temp' -Recurse"
    if errorlevel 1 (
        echo [ERROR] Failed to download or extract JRE.
        pause & exit /b 1
    )
    echo [SUCCESS] JRE configured.
)
set "JAVA_HOME=%JRE_DIR%"
set "PATH=%JRE_DIR%\bin;%PATH%"

:: 2. Build Logic
if not exist "%TARGET_JAR%" (
    echo [INFO] Artifact missing. Building from source...
    
    :: Download Maven Portable if missing or empty
    set "NEED_MVN=yes"
    if exist "%MVN_DIR%" (
        for /d %%d in ("%MVN_DIR%\apache-maven-*") do (
            if exist "%%d\bin\mvn.cmd" set "NEED_MVN=no"
        )
    )
    
    if "!NEED_MVN!"=="yes" (
        echo [INFO] Downloading Maven...
        if exist "%MVN_DIR%" rd /s /q "%MVN_DIR%"
        powershell -Command "Invoke-WebRequest -Uri 'https://archive.apache.org/dist/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.zip' -OutFile 'maven.zip'; Expand-Archive -Path 'maven.zip' -DestinationPath 'mvn_temp'; Remove-Item 'maven.zip' -Force"
        if errorlevel 1 (
            echo [ERROR] Failed to download Maven.
            pause & exit /b 1
        )
    )
    
    :: Find maven bin
    set "MVN_FOUND=no"
    for /d %%d in ("%MVN_DIR%\apache-maven-*") do (
        set "MVN_FOUND=yes"
        echo [INFO] Building with %%d...
        call "%%d\bin\mvn.cmd" clean package -DskipTests -f "%ROOT_DIR%pom.xml"
    )

    if "!MVN_FOUND!"=="no" (
        echo [ERROR] Maven not found in %MVN_DIR%.
        pause & exit /b 1
    )

    if not exist "%TARGET_JAR%" (
        echo [ERROR] Build failed. Please check the logs above.
        pause & exit /b 1
    )
)
copy "%TARGET_JAR%" "%JAR_DEST%" /Y

:: 3. Registration
echo [2/4] Privilege check...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARN] Not running as Administrator. Skipping Windows Service registration.
    echo [INFO] You can still run the agent manually using the start scripts.
    goto :finalize
)

echo [INFO] Registering service...
if not exist "%NSSM_PATH%" (
    echo [ERROR] nssm.exe not found at %NSSM_PATH%
    pause & exit /b 1
)

"%NSSM_PATH%" stop AegisGuard >nul 2>&1
"%NSSM_PATH%" remove AegisGuard confirm >nul 2>&1
"%NSSM_PATH%" install AegisGuard "%JRE_DIR%\bin\java.exe" "-jar \"%JAR_DEST%\""
"%NSSM_PATH%" set AegisGuard Start SERVICE_AUTO_START

:: 4. Start
echo [3/4] Starting service...
sc start AegisGuard

:finalize
echo [4/4] Finalizing...
echo =======================================================
echo          INSTALLATION COMPLETE
echo =======================================================
echo [INFO] AegisGuard service has been registered and started.
echo [INFO] If it fails to stay running, check the Brain API connectivity.
pause
