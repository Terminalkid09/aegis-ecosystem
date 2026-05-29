@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo [INFO] Starting Aegis Guard on host...

:: Path configuration
set "BASE_DIR=%~dp0aegis-guard"
set "JRE_BIN=%BASE_DIR%\jre\bin\java.exe"
set "JAR_FILE=%BASE_DIR%\aegis-guard.jar"
set "TARGET_JAR=%BASE_DIR%\target\aegis-guard.jar"

:: 1. Check for Java
set "JAVA_CMD=java"
if exist "%JRE_BIN%" (
    set "JAVA_CMD=%JRE_BIN%"
    echo [INFO] Using internal JRE: !JAVA_CMD!
) else (
    where java >nul 2>nul
    if errorlevel 1 (
        echo [INFO] Java not found. Running installer...
        cd /d "%BASE_DIR%"
        call install_agent.bat
        cd /d "%~dp0"
        if not exist "%JRE_BIN%" (
            echo [ERROR] Installation failed to provide JRE.
            pause & exit /b 1
        )
        set "JAVA_CMD=%JRE_BIN%"
    ) else (
        echo [INFO] Using system Java.
    )
)

:: 2. Check for JAR (prefer the one in root, then target)
set "RUN_JAR="
if exist "%JAR_FILE%" (
    set "RUN_JAR=%JAR_FILE%"
) else if exist "%TARGET_JAR%" (
    set "RUN_JAR=%TARGET_JAR%"
)

if "!RUN_JAR!"=="" (
    echo [INFO] Aegis Guard JAR not found. Running installer...
    cd /d "%BASE_DIR%"
    call install_agent.bat
    cd /d "%~dp0"
    
    if exist "%JAR_FILE%" (
        set "RUN_JAR=%JAR_FILE%"
    ) else if exist "%TARGET_JAR%" (
        set "RUN_JAR=%TARGET_JAR%"
    )

    if "!RUN_JAR!"=="" (
        echo [ERROR] Installation failed to produce JAR.
        pause & exit /b 1
    )
)

echo [INFO] Executing: "!JAVA_CMD!" -jar "!RUN_JAR!"
"!JAVA_CMD!" -jar "!RUN_JAR!"
pause
