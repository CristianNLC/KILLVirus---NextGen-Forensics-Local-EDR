; Script de Inno Setup para KILLVirus v2.0
[Setup]
AppId={{E1B92C34-89C1-4D52-B42E-89C41C8F9A22}
AppName=KILLVirus PRO
AppVersion=2.0
AppPublisher=KILLVirus Security
AppPublisherURL=https://github.com/
DefaultDirName={autopf}\KILLVirus
DefaultGroupName=KILLVirus
OutputDir=dist_installer
OutputBaseFilename=KILLVirus_v2_Setup
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
; Binario compilado con PyInstaller
Source: "dist\KILLVirus_v2.exe"; DestDir: "{app}"; Flags: ignoreversion
; Carpetas de soporte requeridas en ejecución
Source: "data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\KILLVirus PRO"; Filename: "{app}\KILLVirus_v2.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar KILLVirus"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KILLVirus PRO"; Filename: "{app}\KILLVirus_v2.exe"; Tasks: desktopicon; IconFilename: "{app}\assets\icon.ico"

[Run]
Filename: "{app}\KILLVirus_v2.exe"; Description: "{cm:LaunchProgram,KILLVirus PRO}"; Flags: nowait postinstall skipifsilent