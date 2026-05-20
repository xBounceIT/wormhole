; Wormhole installer (Inno Setup 6)
; Scaffold — wire up signing, custom pages, and per-architecture artifacts before shipping.

#define MyAppName       "Wormhole"
#define MyAppPublisher  "Wormhole project"
#define MyAppExeName    "Wormhole.exe"
#define MyAppVersion    "0.1.0"

#ifndef AppArchitecture
  #define AppArchitecture "x64"
#endif

#ifndef PublishDir
  #define PublishDir "..\artifacts\publish\win-" + AppArchitecture
#endif

[Setup]
AppId={{6E3A0D9E-2A1F-4F4C-9C9F-2F8F8E1A0A11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
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

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
