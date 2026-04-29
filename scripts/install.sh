#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_USER="$(id -un)"
SERVICE_NAME="nespi-watcher.service"

cd "$PROJECT_DIR"

echo "[1/6] Installation dépendances système..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap

echo "[2/6] Création environnement virtuel..."
python3 -m venv .venv
source .venv/bin/activate

echo "[3/6] Installation dépendances Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[4/6] Préparation configuration locale (.env) si absent..."
if [ ! -f .env ]; then
  cat > .env << 'ENVEOF'
NETWORK_RANGE=192.168.1.0/24
APP_HOST=0.0.0.0
APP_PORT=8080
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_MODE=summary
ALERT_MIN_NEW_DEVICES=1
ALERT_COOLDOWN_SECONDS=300
ALERT_UNKNOWN_ONLY=false
SCAN_TIMEOUT=60
AUTO_SCAN_ENABLED=true
SCAN_INTERVAL_SECONDS=600
STARTUP_SCAN_ENABLED=false
OFFLINE_AFTER_SECONDS=1800
SCAN_API_KEY=
IGNORE_IPS=
IGNORE_MACS=
MAX_SCAN_HISTORY_ROWS=5000
LOG_LEVEL=INFO
ENVEOF
  echo "Fichier .env créé."
fi

echo "[5/6] Installation service systemd..."
sed -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" -e "s|__RUN_USER__|$RUN_USER|g" systemd/nespi-watcher.service > /tmp/nespi-watcher.service
sudo cp /tmp/nespi-watcher.service /etc/systemd/system/"$SERVICE_NAME"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

echo "[6/6] Démarrage service..."
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl status "$SERVICE_NAME" --no-pager || true

echo "Installation terminée. Dashboard: http://IP_DU_RASPBERRY:8080"
