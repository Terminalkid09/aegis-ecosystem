[Setup]
AppName=Aegis Guard Agent
AppVerName=Aegis Guard Agent 1.0.0
DefaultDirName={commonpf}\Aegis\Guard
DefaultGroupName=Aegis
OutputDir=dist
OutputBaseFilename=AegisGuardSetup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Files]
Source: "target\aegis-guard.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "jre\*"; DestDir: "{app}\jre"; Flags: recursesubdirs
Source: "install\windows\nssm.exe"; DestDir: "{app}"

[Run]
Filename: "{app}\nssm.exe"; Parameters: "stop AegisGuard"; Flags: runhidden; StatusMsg: "Stopping existing service..."
Filename: "{app}\nssm.exe"; Parameters: "remove AegisGuard confirm"; Flags: runhidden; StatusMsg: "Removing existing service..."
Filename: "{app}\nssm.exe"; Parameters: "install AegisGuard ""{app}\jre\bin\java.exe"" ""-jar {app}\aegis-guard.jar"""; Flags: runhidden; StatusMsg: "Registering AegisGuard service..."
Filename: "{app}\nssm.exe"; Parameters: "set AegisGuard Start SERVICE_AUTO_START"; Flags: runhidden
Filename: "sc"; Parameters: "start AegisGuard"; Flags: runhidden; StatusMsg: "Starting AegisGuard..."

[UninstallRun]
Filename: "{app}\nssm.exe"; Parameters: "stop AegisGuard"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "remove AegisGuard confirm"; Flags: runhidden
