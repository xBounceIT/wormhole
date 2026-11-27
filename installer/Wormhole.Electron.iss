; Wormhole installer — Electron build (Inno Setup 6)
;
; RUNTIME: scripts/Build-ElectronInstaller.ps1 stages the Electron runtime + renderer + Go
; backend into a directory (PublishDir) whose root is the app folder: Wormhole.exe (the renamed
; Electron runtime binary) with resources\app\ holding package.json, dist\, dist-electron\ (Go
; backend + sidecars + RDP host + credential reader), node_modules\ (main-process dependencies),
; and Assets\. No standalone Node.js runtime is needed
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
CloseApplications=force
RestartApplications=no
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

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\{#MyAppExeName}"; Flags: nowait runasoriginaluser; Check: ShouldRestartApp

[Code]
const
  LegacyLocalDumps = 'Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\{#MyAppExeName}';
  WerExclusions = 'Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications';
  InstallerState = 'Software\Wormhole\Installer';
  WerExclusionOwner = 'OwnsWerExclusion';

procedure RemoveLegacyLocalDumps;
var
  Names, Subkeys: TArrayOfString;
  Folder: String;
  Count, DumpType: Cardinal;
begin
  { WER LocalDumps operate independently of in-process crash handling.
    Remove the previous installer's exact defaults and leave customized policies alone. }
  if not RegGetValueNames(HKLM, LegacyLocalDumps, Names) then Exit;
  if GetArrayLength(Names) <> 3 then Exit;
  if not RegGetSubkeyNames(HKLM, LegacyLocalDumps, Subkeys) then Exit;
  if GetArrayLength(Subkeys) <> 0 then Exit;
  if not RegQueryStringValue(HKLM, LegacyLocalDumps, 'DumpFolder', Folder) then Exit;
  if not RegQueryDWordValue(HKLM, LegacyLocalDumps, 'DumpCount', Count) then Exit;
  if not RegQueryDWordValue(HKLM, LegacyLocalDumps, 'DumpType', DumpType) then Exit;
  if (CompareText(Folder, '%LOCALAPPDATA%\Wormhole\crashdumps') <> 0) or
    (Count <> 10) or (DumpType <> 1) then Exit;
  RegDeleteValue(HKLM, LegacyLocalDumps, 'DumpFolder');
  RegDeleteValue(HKLM, LegacyLocalDumps, 'DumpCount');
  RegDeleteValue(HKLM, LegacyLocalDumps, 'DumpType');
  RegDeleteKeyIfEmpty(HKLM, LegacyLocalDumps);
end;

procedure InstallWerExclusion;
begin
  { Use the native view for x64 and ARM64, including when Setup runs as a
    32-bit process. DWORD 1 is the entry emitted by WerAddExcludedApplication. }
  if RegValueExists(HKLM64, WerExclusions, '{#MyAppExeName}') then Exit;
  if not RegWriteDWordValue(HKLM64, InstallerState, WerExclusionOwner, 1) then
  begin
    Log('Could not record ownership of the Wormhole WER exclusion.');
    Exit;
  end;
  if not RegWriteDWordValue(HKLM64, WerExclusions, '{#MyAppExeName}', 1) then
  begin
    RegDeleteValue(HKLM64, InstallerState, WerExclusionOwner);
    RegDeleteKeyIfEmpty(HKLM64, InstallerState);
    Log('Could not register the Wormhole WER exclusion.');
  end;
end;

procedure RemoveOwnedWerExclusion;
var
  Owner, Value: Cardinal;
begin
  if not RegQueryDWordValue(HKLM64, InstallerState, WerExclusionOwner, Owner) then Exit;
  if Owner <> 1 then Exit;
  if RegQueryDWordValue(HKLM64, WerExclusions, '{#MyAppExeName}', Value) and
    (Value = 1) then
  begin
    if not RegDeleteValue(HKLM64, WerExclusions, '{#MyAppExeName}') then
    begin
      Log('Could not remove the installer-owned Wormhole WER exclusion.');
      Exit;
    end;
  end;
  RegDeleteValue(HKLM64, InstallerState, WerExclusionOwner);
  RegDeleteKeyIfEmpty(HKLM64, InstallerState);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RemoveLegacyLocalDumps;
    InstallWerExclusion;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then RemoveOwnedWerExclusion;
end;

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

function CanReplaceAppImage(const AppPath: String): Boolean;
var
  Probe: TFileStream;
begin
  { Open the existing image without changing it. Windows denies write access
    while it is mapped by any process in this installation. }
  try
    Probe := TFileStream.Create(AppPath, fmOpenWrite or fmShareDenyNone);
    Probe.Free;
    Result := True;
  except
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  AppPath: String;
  Attempt: Integer;
  Progress: TOutputMarqueeProgressWizardPage;
begin
  Result := '';
  AppPath := ExpandConstant('{app}\{#MyAppExeName}');
  if not ShouldRestartApp then Exit;
  if not FileExists(AppPath) or CanReplaceAppImage(AppPath) then Exit;

  { The in-app updater starts Setup before flushing browser storage and stopping
    sessions. This also works for older versions that pass only /RESTARTAPP. }
  Log('Waiting for the installed Wormhole executable to be released.');
  Progress := CreateOutputMarqueeProgressPage('Preparing to install', 'Waiting for Wormhole to close...');
  try
    Progress.Show;
    for Attempt := 1 to 240 do
    begin
      Progress.Animate;
      Sleep(250);
      if CanReplaceAppImage(AppPath) then Exit;
    end;
    Log('Shutdown grace period expired. Checking remaining locks with Restart Manager.');
  finally
    Progress.Hide;
  end;
end;
