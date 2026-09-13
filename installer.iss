; Script de Inno Setup para KILLVirus
[Setup]
AppId={{E1B92C34-89C1-4D52-B42E-89C41C8F9A22}
AppName=KILLVirus
AppVersion=1.0
AppPublisher=KILLVirus Security
DefaultDirName={autopf}\KILLVirus
DefaultGroupName=KILLVirus
OutputDir=dist_installer
OutputBaseFilename=KILLVirus_Setup
SetupIconFile=assets\icon.ico
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Binario compilado
Source: "dist\KILLVirus.exe"; DestDir: "{app}"; Flags: ignoreversion
; Carpetas de soporte
Source: "data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\KILLVirus"; Filename: "{app}\KILLVirus.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar KILLVirus"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KILLVirus"; Filename: "{app}\KILLVirus.exe"; Tasks: desktopicon; IconFilename: "{app}\assets\icon.ico"

[Run]
Filename: "{app}\KILLVirus.exe"; Description: "{cm:LaunchProgram,KILLVirus}"; Flags: nowait postinstall skipifsilent