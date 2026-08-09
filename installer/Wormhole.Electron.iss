; Wormhole installer — Electron build (Inno Setup 6)
;
; RUNTIME: scripts/Build-ElectronInstaller.ps1 stages the Electron runtime + renderer + Go
; backend into a directory (PublishDir) whose root is the app folder: Wormhole.exe (the renamed
; Electron runtime binary) with resources\app\ holding package.json, dist\, dist-electron\ (Go
; backend + sidecars + RDP host + credential reader), and Assets\. No Node.js runtime is needed
; on the target machine.
;
; Keep the established Electron AppId so upgrades remain compatible with existing installs.

#define MyAppName       "Wormhole"
#define MyAppPublisher  "Wormhole project"
#define MyAppExeName    "Wormhole.exe"

#ifndef MyAppVersion
  #error MyAppVersion must be defined by the build script.
#endif

#ifndef AppArchitecture
  #define AppArchitecture "x64"
#endif

#ifndef PublishDir
  #define PublishDir "..\artifacts\electron-app\" + AppArchitecture + "\Wormhole"
#endif

[Setup]
AppId={{CC26892F-C6E1-4C7A-8D3D-6621619F5ADD}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\Assets\Wormhole.ico
OutputBaseFilename=Wormhole-{#MyAppVersion}-win-{#AppArchitecture}-setup
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#AppArchitecture}
ArchitecturesInstallIn64BitMode={#AppArchitecture}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\{#MyAppExeName}"; ValueType: expandsz; ValueName: "DumpFolder"; ValueData: "%LOCALAPPDATA%\Wormhole\crashdumps"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\{#MyAppExeName}"; ValueType: dword; ValueName: "DumpCount"; ValueData: "10"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\{#MyAppExeName}"; ValueType: dword; ValueName: "DumpType"; ValueData: "1"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\{#MyAppExeName}"; Flags: nowait runasoriginaluser; Check: ShouldRestartApp

[Code]
function CmdLineParamExists(const Value: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Value) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function ShouldRestartApp: Boolean;
begin
  Result := CmdLineParamExists('/RESTARTAPP');
end;
