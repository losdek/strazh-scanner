#define AppVersion "3.3.0"
[Setup]
AppId={{C284E01B-C9AB-41D4-9CCD-59BE5D6D4268}
AppName=Страж
AppVersion={#AppVersion}
AppPublisher=Strazh Project
DefaultDirName={localappdata}\Programs\Strazh
DefaultGroupName=Страж
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=Strazh-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\Strazh.exe
CloseApplications=yes
RestartApplications=no
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"
[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; Flags: unchecked
[Files]
Source: "..\publish\*"; DestDir: "{app}"; Excludes: "clamav\*"; Flags: ignoreversion recursesubdirs createallsubdirs
; Bundled ClamAV for Windows (Cisco Talos, GPL-2.0) and its signature database.
Source: "..\dependencies\clamav\*"; DestDir: "{app}\clamav"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\clamav\db\*"; DestDir: "{app}\clamav\db"; Flags: onlyifdoesntexist
Source: "..\dependencies\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; Flags: dontcopy
[Icons]
Name: "{group}\Страж"; Filename: "{app}\Strazh.exe"
Name: "{autodesktop}\Страж"; Filename: "{app}\Strazh.exe"; Tasks: desktopicon
[UninstallDelete]
Type: filesandordirs; Name: "{app}\clamav"
[Run]
Filename: "{app}\Strazh.exe"; Description: "Открыть Страж"; Flags: nowait postinstall skipifsilent
[Code]
function HasWebView: Boolean;
var Version: String;
begin
  Result := (RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0'));
  if not Result then
    Result := (RegQueryStringValue(HKLM32, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0'));
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  Result := '';
  if not HasWebView then begin
    ExtractTemporaryFile('MicrosoftEdgeWebView2RuntimeInstallerX64.exe');
    if not Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe'), '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code) then
      Result := 'Не удалось запустить установку Microsoft WebView2.'
    else if not HasWebView then
      Result := 'Microsoft WebView2 не установлен. Код: ' + IntToStr(Code) + '. Перезапустите установку после устранения ошибки.';
  end;
end;
