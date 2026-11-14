#!/usr/bin/env bash
# Встановлення LibSentinel на Ubuntu 22.04 / 24.04 (також Kali Linux, ParrotOS).
# Запуск із каталогу проєкту:  bash install.sh
set -euo pipefail

cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
VENV_DIR="$PROJECT_DIR/.venv"

echo "==> 1/5 Системні пакети (python3-venv, git, docker)"
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip git ca-certificates curl
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get install -y docker.io
fi
sudo systemctl enable --now docker || true
if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  echo "    Користувача $USER додано до групи docker."
  echo "    ВАЖЛИВО: вийдіть із системи й увійдіть знову (або виконайте 'newgrp docker'),"
  echo "    після чого повторно запустіть install.sh, щоб зібрати пісочницю."
fi

echo "==> 2/5 Віртуальне середовище Python"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -e "$PROJECT_DIR[dev]"

echo "==> 3/5 Команда libsentinel у ~/.local/bin"
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV_DIR/bin/libsentinel" "$HOME/.local/bin/libsentinel"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
     export PATH="$HOME/.local/bin:$PATH"
     echo "    ~/.local/bin додано до PATH у ~/.bashrc" ;;
esac

echo "==> 4/5 Образ пісочниці для динамічного аналізу"
if docker info >/dev/null 2>&1; then
  "$VENV_DIR/bin/libsentinel" sandbox-build
else
  echo "    Docker поки недоступний для користувача — пропущено (див. повідомлення вище)"
fi

echo "==> 5/5 Бази даних (популярні бібліотеки, OpenSSF Malicious Packages)"
"$VENV_DIR/bin/libsentinel" update-data || echo "    Не вдалося оновити бази — можна повторити пізніше: libsentinel update-data"

echo
"$VENV_DIR/bin/libsentinel" doctor || true
echo
echo "Готово. Приклад запуску:  libsentinel analyze requests --from 2.31.0 --to 2.32.3"
