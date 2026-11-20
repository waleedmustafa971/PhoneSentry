; Inno Setup script: builds PhoneSentry-Setup.exe from dist\PhoneSentry.exe
; Install Inno Setup (https://jrsoftware.org/isdl.php), then: iscc installer.iss
#define AppName "PhoneSentry"
#define AppVersion "1.0.0"

[Setup]
AppId={{6E0B7C51-3B7E-4C2C-9E43-5A1D2F7C9B10}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=dist
OutputBaseFilename=PhoneSentry-Setup-{#AppVersion}
SetupIconFile=assets\logo.ico
UninstallDisplayIcon={app}\PhoneSentry.exe
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "dist\PhoneSentry.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\PhoneSentry.exe"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\PhoneSentry.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\PhoneSentry.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{localappdata}\PhoneSentry\platform-tools\adb.exe"; Parameters: "kill-server"; Flags: runhidden skipifdoesntexist; RunOnceId: "KillAdb"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\PhoneSentry"
