@echo off
setlocal EnableDelayedExpansion
title Aegis Agent Builder

set "ROOT=%~dp0"

echo ====== Building Aegis Agents ======
echo.

:: ---- Step 0: trova un JDK (javac) PRIMA di Maven ----
:: Il `java` di PATH e' spesso un JRE (Adoptium installa entrambi): Maven
:: morirebbe con "No compiler is provided". Il JDK che serve a Maven e'
:: lo stesso che serve a jlink (Step 3): lo cerco qui e lo riuso.
set "JDK_HOME="
if exist "!JAVA_HOME!\bin\javac.exe" set "JDK_HOME=!JAVA_HOME!"
if not defined JDK_HOME (
    for /d %%d in ("%ProgramFiles%\Eclipse Adoptium\*") do (
        if exist "%%d\bin\javac.exe" set "JDK_HOME=%%d"
    )
)
if not defined JDK_HOME (
    for /d %%d in ("%ProgramFiles%\Java\*") do (
        if exist "%%d\bin\javac.exe" set "JDK_HOME=%%d"
    )
)
if not defined JDK_HOME (
    for /d %%d in ("%ProgramFiles%\Microsoft*") do (
        if exist "%%d\bin\javac.exe" set "JDK_HOME=%%d"
    )
)
if not defined JDK_HOME (
    echo [!] No JDK found: install JDK 21+ or set JAVA_HOME to a JDK.
    exit /b 1
)
echo [+] JDK found: !JDK_HOME!
set "JAVA_HOME=!JDK_HOME!"
set "PATH=!JDK_HOME!\bin;!PATH!"
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
:: -y: senza, il secondo build fallisce perche' dist/ esiste gia' (non idempotente)
pyinstaller --onedir -y --noconfirm --name nodetrace-agent --add-data "config.json;." agent.py
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
echo [*] Step 3/4: Creating minimal JRE via jlink...

:: JDK_HOME e' stato individuato allo Step 0 (javac): un JDK con javac ha
:: sempre jmods, quindi niente seconda ricerca.
set "JLINK="
set "JMODS="
if defined JDK_HOME if exist "!JDK_HOME!\bin\jlink.exe" if exist "!JDK_HOME!\jmods" (
    set "JLINK=!JDK_HOME!\bin\jlink.exe"
    set "JMODS=!JDK_HOME!\jmods"
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

:: jdk.net e' obbligatorio: Apache HttpClient 5 usa jdk.net.Sockets
:: (DefaultHttpClientConnectionOperator). jlink non analizza le dipendenze del
:: codice non modulare sul classpath, quindi il JRE si costruisce "bene" e
:: l'agente poi muore con NoClassDefFoundError: jdk/net/Sockets.
"!JLINK!" --module-path "!JMODS!" ^
    --add-modules java.base,java.datatransfer,java.desktop,java.logging,java.naming,java.security.jgss,java.sql,java.xml,jdk.crypto.ec,jdk.net ^
    --output "!JRE_OUT!" ^
    --strip-debug --compress zip-6 --no-header-files --no-man-pages
if !errorlevel! neq 0 (
    echo [!] jlink failed.
    exit /b 1
)

for /f %%s in ('dir /s /-c "!JRE_OUT!" ^| findstr /B /C:"  File(s)"') do set "JRE_SIZE=%%s"
echo [+] Minimal JRE created: !JRE_OUT! (!JRE_SIZE!)

:: ---- Step 4: ETW kernel collector (MinGW, best-effort) ----
:: Telemetria kernel Windows (Kernel-Process / Kernel-Network). Nessun driver:
:: consumer ETW user-mode, zero firme. Se il compilatore manca, la build NON
:: fallisce: Guard degrada da solo (EtwPipeSource) e resta il polling Toolhelp32.
echo [*] Step 4/4: Building ETW collector (aegis-etw.exe)...
set "GCC_EXE="
for /d %%d in ("%USERPROFILE%\Downloads\x86_64-*-mingw64" "%ProgramFiles%\mingw64" "C:\mingw64" "C:\msys64\mingw64") do (
    if exist "%%d\bin\gcc.exe" set "GCC_EXE=%%d\bin\gcc.exe"
)
where gcc >nul 2>&1 && set "GCC_EXE=gcc"
if defined GCC_EXE (
    cd /d "%ROOT%aegis-ebpf"
    "!GCC_EXE!" -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh -lws2_32
    if !errorlevel! neq 0 (
        echo [!] ETW collector build failed (non bloccante: Guard resta operativo).
    ) else (
        echo [+] ETW collector built: aegis-ebpf\aegis-etw.exe
    )
    cd /d "%ROOT%"
) else (
    echo [!] gcc (MinGW-w64) non trovato: ETW collector non compilato.
    echo     Guard funzionera' senza telemetria kernel ETW (degrada a polling).
    echo     Installa MinGW-w64 per abilitarla.
)

:skip_jlink
echo.
echo ====== Build Complete ======
echo.
echo Summary:
echo   NodeTrace: %ROOT%NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe
if exist "%ROOT%aegis-ebpf\aegis-etw.exe" echo   ETW:        %ROOT%aegis-ebpf\aegis-etw.exe
if exist "%ROOT%aegis-guard\jre"        echo   Guard JRE:  %ROOT%aegis-guard\jre\bin\java.exe
if exist "%ROOT%aegis-guard\jre-new"    echo   Guard JRE:  %ROOT%aegis-guard\jre-new\bin\java.exe
echo   Guard JAR:  %ROOT%aegis-guard\target\aegis-guard.jar
echo.
echo Run 'aegis.bat' to start the platform and agents.
pause
