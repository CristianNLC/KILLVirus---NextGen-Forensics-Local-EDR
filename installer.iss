; Script de Inno Setup para KILLVirus 2.3.0
; Requiere Inno Setup 6.3+ (probado con Inno Setup 7).
; Compilar con scripts\build_installer.ps1 (o ISCC.exe installer.iss).

[Setup]
AppId={{E1B92C34-89C1-4D52-B42E-89C41C8F9A22}
AppName=KILLVirus
AppVersion=2.3.0
AppVerName=KILLVirus 2.3.0
AppPublisher=KILLVirus Security
AppPublisherURL=https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR
AppSupportURL=https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR/issues
AppUpdatesURL=https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR/releases
DefaultDirName={autopf}\KILLVirus
DefaultGroupName=KILLVirus
UninstallDisplayIcon={app}\KILLVirus_v2.exe
LicenseFile=LICENSE
OutputDir=dist_installer
OutputBaseFilename=KILLVirus_v2_Setup
SetupIconFile=assets\icon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
CloseApplications=yes
RestartApplications=no
AllowNoIcons=yes
SetupLogging=yes
VersionInfoVersion=2.3.0.0
VersionInfoCompany=KILLVirus Security
VersionInfoDescription=Instalador de KILLVirus 2.3.0
VersionInfoCopyright=MIT License

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "service"; Description: "Instalar agente de proteccion en segundo plano (servicio de Windows)"; GroupDescription: "Componentes adicionales:"

[Files]
; Binario compilado con PyInstaller (lo genera scripts\build_release.ps1).
Source: "dist\KILLVirus_v2.exe"; DestDir: "{app}"; Flags: ignoreversion
; Datos semilla que la app copia a %LOCALAPPDATA%\KILLVirus en el primer
; arranque. No se incluyen config.json, agent_status.json ni integrity.json:
; son estado local del desarrollador y no deben viajar en el instalador.
Source: "data\signatures.json"; DestDir: "{app}\data"; Flags: ignoreversion
Source: "data\rules.yar"; DestDir: "{app}\data"; Flags: ignoreversion
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Restos de la extinta capa PRO: sus accesos apuntaban a este mismo ejecutable
; y solo generaban duplicados confusos tras actualizar.
Type: files; Name: "{group}\KILLVirus PRO.lnk"
Type: files; Name: "{autodesktop}\KILLVirus PRO.lnk"

[Icons]
Name: "{group}\KILLVirus"; Filename: "{app}\KILLVirus_v2.exe"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar KILLVirus"; Filename: "{uninstallexe}"
Name: "{autodesktop}\KILLVirus"; Filename: "{app}\KILLVirus_v2.exe"; Tasks: desktopicon; IconFilename: "{app}\assets\icon.ico"

[Run]
; El servicio se instala antes de abrir la interfaz para que ambos usen el
; mismo directorio de datos (%LOCALAPPDATA%\KILLVirus del usuario que instala).
Filename: "{app}\KILLVirus_v2.exe"; Parameters: "--install-service"; StatusMsg: "Instalando servicio de proteccion..."; Flags: runhidden waituntilterminated; Tasks: service
; La app se abre como el usuario original, no elevada (el instalador sí lo está).
Filename: "{app}\KILLVirus_v2.exe"; Description: "{cm:LaunchProgram,KILLVirus}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\KILLVirus_v2.exe"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveKILLVirusAgent"

[UninstallDelete]
; Restos que el runtime pudiera haber dejado dentro de {app}; los datos de
; usuario (cuarentena, reportes, logs) viven en %LOCALAPPDATA% y no se tocan.
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\assets"

[Code]
const
  AgentService = 'KILLVirusAgent';

function RunHidden(const CommandLine: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{cmd}'), '/c ' + CommandLine, '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Result := ResultCode;
end;

function ServiceInstalled(): Boolean;
begin
  Result := RunHidden('sc.exe query ' + AgentService + ' >nul 2>&1') = 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  I: Integer;
begin
  Result := '';
  if not ServiceInstalled() then
    Exit;

  { En una actualización el servicio mantiene abierto el .exe y Windows no
    deja sobrescribirlo. Se detiene y elimina antes de copiar los archivos;
    la tarea "service" lo vuelve a instalar al final. }
  RunHidden('sc.exe stop ' + AgentService + ' >nul 2>&1');
  for I := 1 to 20 do
  begin
    Sleep(500);
    if RunHidden('sc.exe query ' + AgentService + ' | findstr /i "STOPPED" >nul 2>&1') = 0 then
      Break;
  end;
  RunHidden('sc.exe delete ' + AgentService + ' >nul 2>&1');
  Sleep(1500);
end;
