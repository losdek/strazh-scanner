#!/usr/bin/env bash
# Builds windows/dist/Strazh-Setup-x64.exe on Linux with Inno Setup running under wine,
# then copies it to the STRAZH USB stick if that is mounted.
# Needs: wine, and a finished windows/publish folder (Strazh.exe, vt-scan.exe, clamav/).
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
inno="${INNO_INSTALLER:-}"
inno_sha=a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c
export WINEPREFIX="$HOME/.wine-strazh" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml="

for f in Strazh.exe vt-scan.exe clamav/clamd.exe clamav/db/daily.cvd; do
  [[ -f "$root/windows/publish/$f" ]] || { echo "Нет windows/publish/$f — сначала соберите пакет." >&2; exit 1; }
done
[[ -f "$root/windows/dependencies/MicrosoftEdgeWebView2RuntimeInstallerX64.exe" ]] || { echo "Нет установщика WebView2 в windows/dependencies." >&2; exit 1; }

iscc="$(find "$WINEPREFIX/drive_c" -iname ISCC.exe 2>/dev/null | head -1 || true)"
if [[ -z "$iscc" ]]; then
  if [[ -z "$inno" || ! -f "$inno" ]]; then
    inno="$(mktemp -d)/innosetup-6.7.4.exe"
    curl -fL -o "$inno" https://github.com/jrsoftware/issrc/releases/download/is-6_7_4/innosetup-6.7.4.exe
  fi
  echo "$inno_sha  $inno" | sha256sum -c - || { echo 'Хеш Inno Setup не совпал.' >&2; exit 1; }
  wineboot -i >/dev/null 2>&1 || true
  wine "$inno" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER
  iscc="$(find "$WINEPREFIX/drive_c" -iname ISCC.exe | head -1)"
fi
echo "Компилятор: $iscc"
mkdir -p "$root/windows/dist"
wine "$iscc" /Q "$(winepath -w "$root/windows/installer/Strazh.iss")"
setup="$root/windows/dist/Strazh-Setup-x64.exe"
ls -la "$setup"
sha256sum "$setup"
usb=/run/media/$USER/STRAZH
if mountpoint -q "$usb"; then
  cp "$setup" "$usb/Windows/" && sync
  (cd "$usb" && sha256sum Windows/Strazh-Setup-x64.exe)
  echo "Скопировано на флешку: $usb/Windows/Strazh-Setup-x64.exe"
fi
