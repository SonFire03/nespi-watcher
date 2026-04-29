#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/soso/nespi-watcher"
SERVICE_NAME="nespi-watcher.service"

cd "$PROJECT_DIR"

echo "[1/4] Mise à jour du code..."
git pull --ff-only

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/4] Mise à jour dépendances Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[3/4] Redémarrage service..."
sudo systemctl restart "$SERVICE_NAME"

echo "[4/4] Statut du service..."
sudo systemctl status "$SERVICE_NAME" --no-pager || true

echo "Mise à jour terminée."
