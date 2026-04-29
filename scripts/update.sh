#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_NAME="nespi-watcher.service"

cd "$PROJECT_DIR"

echo "[1/4] Mise à jour du code..."
git pull --ff-only

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/4] Mise à jour dépendances Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[3/4] Réinstallation du service (chemin robuste)..."
sed "s|__PROJECT_DIR__|$PROJECT_DIR|g" systemd/nespi-watcher.service > /tmp/nespi-watcher.service
sudo cp /tmp/nespi-watcher.service /etc/systemd/system/"$SERVICE_NAME"
sudo systemctl daemon-reload


echo "[4/4] Redémarrage + statut..."
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl status "$SERVICE_NAME" --no-pager || true

echo "Mise à jour terminée."
