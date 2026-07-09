@echo off
setlocal EnableDelayedExpansion
title Aegis Agent Builder

set "ROOT=%~dp0"

echo ====== Building Aegis Agents ======
echo.

:: ---- Step 1: NodeTrace (PyInstaller) ----
echo [*] Step 1/3: Building NodeTrace Agent (PyInstaller)...
cd /d "%ROOT%NodeTrace\agents\python"

where pip >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] pip not found. Install Python 3 + pip first.
    exit /b 1
)

pip install pyinstaller -q 2>&1 | findstr /V "already satisfied"
pyinstaller --onedir --name nodetrace-agent --add-data "config.json;." agent.py >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] PyInstaller build failed.
    exit /b 1
)

copy /y config.json dist\nodetrace-agent\config.json >nul 2>&1
echo     Telemetry interval set to 10s for real-time updates
rmdir /s /q build 2>nul
del /q nodetrace-agent.spec 2>nul

set "NODE_SIZE="
for /f %%s in ('dir /s /-c dist\nodetrace-agent ^| findstr /B /C:"  File(s)"') do set "NODE_SIZE=%%s"
echo [+] NodeTrace Agent built: dist\nodetrace-agent\nodetrace-agent.exe (!NODE_SIZE!)
echo.

:: ---- Step 2: Guard (Maven) ----
echo [*] Step 2/3: Building Aegis-Guard (Maven)...

cd /d "%ROOT%aegis-guard"

where mvn >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Maven not found. Install Maven 3 and set PATH.
    exit /b 1
)

call mvn clean package -DskipTests -q
if !errorlevel! neq 0 (
    echo [!] Maven build failed.
    exit /b 1
)

for %%f in ("%ROOT%aegis-guard\target\aegis-guard.jar") do set "JAR_SIZE=%%~zf"
echo [+] Aegis-Guard built: target\aegis-guard.jar (!JAR_SIZE! bytes)
echo.

:: ---- Step 3: Minimal JRE (jlink) ----
echo [*] Step 3/3: Creating minimal JRE via jlink...

set "JLINK="
set "JMODS="

:: Find JDK with jmods (needed for jlink)
if exist "!JAVA_HOME!\bin\jlink.exe" if exist "!JAVA_HOME!\jmods" (
    set "JLINK=!JAVA_HOME!\bin\jlink.exe"
    set "JMODS=!JAVA_HOME!\jmods"
)
if not defined JLINK (
    for /d %%d in ("%ProgramFiles%\Eclipse Adoptium\*") do (
        if exist "%%d\bin\jlink.exe" if exist "%%d\jmods" (
            set "JLINK=%%d\bin\jlink.exe"
            set "JMODS=%%d\jmods"
        )
    )
)
if not defined JLINK (
    for /d %%d in ("%ProgramFiles%\Java\*") do (
        if exist "%%d\bin\jlink.exe" if exist "%%d\jmods" (
            set "JLINK=%%d\bin\jlink.exe"
            set "JMODS=%%d\jmods"
        )
    )
)
if not defined JLINK (
    for /d %%d in ("%ProgramFiles%\Microsoft*\*") do (
        if exist "%%d\bin\jlink.exe" if exist "%%d\jmods" (
            set "JLINK=%%d\bin\jlink.exe"
            set "JMODS=%%d\jmods"
        )
    )
)

if not defined JLINK (
    echo [!] No JDK with jmods found. Install JDK 21+ or set JAVA_HOME.
    echo     Skipping JRE minimization. Using system java instead.
    goto :skip_jlink
)

echo     Using: !JLINK!

:: Remove old JRE if exists
if exist "%ROOT%aegis-guard\jre" (
    takeown /f "%ROOT%aegis-guard\jre" /r /d y >nul 2>&1
    icacls "%ROOT%aegis-guard\jre" /grant "%USERNAME%":F /t /q >nul 2>&1
    rmdir /s /q "%ROOT%aegis-guard\jre" >nul 2>&1
)
if exist "%ROOT%aegis-guard\jre" (
    :: If still exists (locked), use jre-new instead
    rmdir /s /q "%ROOT%aegis-guard\jre-new" >nul 2>&1
    set "JRE_OUT=%ROOT%aegis-guard\jre-new"
) else (
    set "JRE_OUT=%ROOT%aegis-guard\jre"
)

"!JLINK!" --module-path "!JMODS!" ^
    --add-modules java.base,java.datatransfer,java.desktop,java.logging,java.naming,java.security.jgss,java.sql,java.xml,jdk.crypto.ec ^
    --output "!JRE_OUT!" ^
    --strip-debug --compress zip-6 --no-header-files --no-man-pages
if !errorlevel! neq 0 (
    echo [!] jlink failed.
    exit /b 1
)

for /f %%s in ('dir /s /-c "!JRE_OUT!" ^| findstr /B /C:"  File(s)"') do set "JRE_SIZE=%%s"
echo [+] Minimal JRE created: !JRE_OUT! (!JRE_SIZE!)

:skip_jlink
echo.
echo ====== Build Complete ======
echo.
echo Summary:
echo   NodeTrace: %ROOT%NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe
if exist "%ROOT%aegis-guard\jre"        echo   Guard JRE:  %ROOT%aegis-guard\jre\bin\java.exe
if exist "%ROOT%aegis-guard\jre-new"    echo   Guard JRE:  %ROOT%aegis-guard\jre-new\bin\java.exe
echo   Guard JAR:  %ROOT%aegis-guard\target\aegis-guard.jar
echo.
echo Run 'aegis.bat' to start the platform and agents.
pause
