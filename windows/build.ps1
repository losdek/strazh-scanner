param([switch]$SkipInstaller)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$publish = Join-Path $PSScriptRoot 'publish'
$deps = Join-Path $PSScriptRoot 'dependencies'
New-Item -ItemType Directory -Force $publish,$deps | Out-Null
Push-Location $root
try {
  if (-not $IsWindows) { throw 'Build this package on Windows x64 with PowerShell 7.' }
  $env:RUSTFLAGS = '-C target-feature=+crt-static'
  cargo test --manifest-path app/Cargo.toml -p scan-engine --locked
  if ($LASTEXITCODE) { throw 'Rust engine tests failed' }
  cargo test --manifest-path app/Cargo.toml -p virustotal-local --lib --locked
  if ($LASTEXITCODE) { throw 'Rust pipeline tests failed' }
  cargo build --manifest-path app/Cargo.toml --release --bin vt-scan --locked
  if ($LASTEXITCODE) { throw 'Rust build failed' }
  dotnet publish windows/Strazh/Strazh.csproj -c Release -r win-x64 --self-contained true -o $publish
  if ($LASTEXITCODE) { throw 'Windows UI build failed' }
  Copy-Item app/target/release/vt-scan.exe $publish -Force
  Copy-Item windows/README.md $publish -Force
  Copy-Item app/engine/data/loki-sha256.txt $publish -Force
  # Bundled ClamAV for Windows (official Cisco Talos build), verified by SHA-256.
  $clamZip = Join-Path $deps 'clamav-1.5.4.win.x64.zip'
  if (-not (Test-Path (Join-Path $deps 'clamav/clamd.exe'))) {
    Invoke-WebRequest 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip' -OutFile $clamZip
    if ((Get-FileHash $clamZip -Algorithm SHA256).Hash -ne '0D9E0228B2674137EA1A2853566C98A0278AD52AB2582C3D6DBD75373848C395') { throw 'ClamAV download hash mismatch' }
    Expand-Archive $clamZip (Join-Path $deps 'clamav-full') -Force
    $src = Join-Path $deps 'clamav-full/clamav-1.5.4.win.x64'
    New-Item -ItemType Directory -Force (Join-Path $deps 'clamav') | Out-Null
    Copy-Item "$src/*.dll","$src/clamd.exe","$src/freshclam.exe","$src/COPYING.txt" (Join-Path $deps 'clamav') -Force
    Copy-Item "$src/certs","$src/COPYING" (Join-Path $deps 'clamav') -Recurse -Force
  }
  # A source checkout has no signature database. Bootstrap it before packaging.
  $database = Join-Path $root 'clamav/db'
  New-Item -ItemType Directory -Force $database | Out-Null
  if (-not (Get-ChildItem $database -File | Where-Object { $_.Extension -in '.cvd','.cld' })) {
    $freshConfig = Join-Path $deps 'freshclam-build.conf'
    @"
DatabaseDirectory "$database"
DatabaseMirror database.clamav.net
ConnectTimeout 20
ReceiveTimeout 120
"@ | Set-Content $freshConfig -Encoding utf8NoBOM
    & (Join-Path $deps 'clamav/freshclam.exe') --config-file $freshConfig
    if ($LASTEXITCODE -ne 0) { throw 'ClamAV database download failed; retry later or provide clamav/db/*.cvd.' }
  }
  # The portable output must contain the same engine and database as the installer.
  Copy-Item (Join-Path $deps 'clamav') $publish -Recurse -Force
  Copy-Item $database (Join-Path $publish 'clamav') -Recurse -Force
  & "$publish/vt-scan.exe" --mode hashes --quiet app/Cargo.toml
  if ($LASTEXITCODE) { throw 'Packaged scanner smoke test failed' }
  & ./windows/test-scanner.ps1 -Scanner "$publish/vt-scan.exe"
  if ($SkipInstaller) { return }
  $runtime = Join-Path $deps 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
  Invoke-WebRequest 'https://go.microsoft.com/fwlink/?linkid=2124701' -OutFile $runtime
  $signature = Get-AuthenticodeSignature $runtime
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'WebView2 installer signature validation failed' }
  $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  $iscc = if ($compiler) { $compiler.Source } else { "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" }
  if (-not (Test-Path $iscc)) { throw 'Install Inno Setup 6 on the build machine.' }
  & $iscc windows/installer/Strazh.iss
  if ($LASTEXITCODE) { throw 'Installer compilation failed' }
  Get-FileHash windows/dist/Strazh-Setup-x64.exe -Algorithm SHA256 | Format-List
} finally { Pop-Location }
