#!/usr/bin/env bash
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="$HOME/.local/share/strazh"
if [[ ! -x "$source_dir/app/strazh" ]]; then
  echo 'Готовая сборка app/strazh не найдена.' >&2
  exit 1
fi
if ldd "$source_dir/app/strazh" | grep -q 'not found'; then
  echo 'Не хватает системных библиотек GTK/WebKit. На CachyOS нужны gtk3 и webkit2gtk-4.1.' >&2
  exit 1
fi
mkdir -p "$install_dir/bin" "$HOME/.local/bin" "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/scalable/apps"
install -m 755 "$source_dir/app/strazh" "$install_dir/bin/strazh.new"
mv -f "$install_dir/bin/strazh.new" "$install_dir/bin/strazh"
install -m 755 "$source_dir/app/vt-scan" "$install_dir/bin/vt-scan"
if [[ -d "$source_dir/clamav" ]]; then
  rm -rf "$install_dir/clamav.new"
  cp -a "$source_dir/clamav" "$install_dir/clamav.new"
  # Keep a newer database that the app already downloaded.
  if [[ -d "$install_dir/clamav/db" ]]; then cp -a -u "$install_dir/clamav/db/." "$install_dir/clamav.new/db/"; fi
  rm -rf "$install_dir/clamav"
  mv "$install_dir/clamav.new" "$install_dir/clamav"
fi
# Optional: `./install.sh --clamav-service` keeps ClamAV loaded from login, so the
# ClamAV mode is ready instantly (costs ~700 MB RAM). Remove: systemctl --user disable --now strazh-clamd
if [[ "${1:-}" == "--clamav-service" && -x "$install_dir/clamav/bin/clamd" ]]; then
  mkdir -p "$HOME/.config/strazh" "$HOME/.cache/strazh/clamd-tmp" "$HOME/.config/systemd/user"
  cat > "$HOME/.config/strazh/clamd.conf" <<CONF
DatabaseDirectory $install_dir/clamav/db
LocalSocket /run/user/$(id -u)/strazh-clamd.sock
LocalSocketMode 600
Foreground yes
TemporaryDirectory $HOME/.cache/strazh/clamd-tmp
StreamMaxLength 4G
MaxFileSize 0
MaxScanSize 0
MaxRecursion 64
MaxFiles 0
MaxThreads 4
SelfCheck 3600
CONF
  cat > "$HOME/.config/systemd/user/strazh-clamd.service" <<UNIT
[Unit]
Description=Страж: ClamAV для проверки файлов

[Service]
Environment=LD_LIBRARY_PATH=$install_dir/clamav/lib
ExecStart=$install_dir/clamav/bin/clamd --config-file $HOME/.config/strazh/clamd.conf
Nice=10
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now strazh-clamd.service
  echo 'ClamAV будет готов сразу после входа в систему.'
fi
install -m 644 "$source_dir/app/assets/strazh.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/strazh.svg"
install -m 644 "$source_dir/README.md" "$install_dir/README.md"
ln -sfn "$install_dir/bin/strazh" "$HOME/.local/bin/strazh"
cat > "$HOME/.local/share/applications/strazh.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Страж
Name[en]=Strazh
Comment=Локальная проверка файлов с встроенным ClamAV
Exec="$install_dir/bin/strazh"
Icon=strazh
Terminal=false
Categories=Utility;Security;
Keywords=антивирус;проверка;файлы;scanner;
StartupWMClass=strazh
DESKTOP
if command -v update-desktop-database >/dev/null; then update-desktop-database "$HOME/.local/share/applications"; fi
echo 'Страж установлен. Откройте его из меню приложений.'
