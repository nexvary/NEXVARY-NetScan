#define MyAppName "NEXVARY NetScan"
#define MyAppVersion "0.2.7"
#define MyAppPublisher "NEXVARY"
#define MyAppExeName "NEXVARY-NetScan.exe"

[Setup]
AppId={{A6521DA2-54C8-4A3F-9EB5-69A97F8B7422}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\NEXVARY NetScan
DefaultGroupName=NEXVARY NetScan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\artifacts\installer
OutputBaseFilename=NEXVARY-NetScan-Setup-v{#MyAppVersion}
SetupIconFile=..\src\NEXVARY.NetScan\Assets\AppIcon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
AppComments=IPv4 discovery, offline IEEE vendor lookup, network details, history and CSV export.
AppPublisherURL=https://nexvary.com
UninstallDisplayName=NEXVARY NetScan
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
MinVersion=10.0.17763
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NEXVARY NetScan Installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "..\artifacts\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NEXVARY NetScan"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\NEXVARY NetScan"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch NEXVARY NetScan"; Flags: nowait postinstall skipifsilent

