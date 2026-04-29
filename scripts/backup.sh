#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR="$PROJECT_DIR/backups"
TS="$(date +%Y%m%d_%H%M%S)"

mkdir -p "$BACKUP_DIR"

if [ ! -f "$PROJECT_DIR/devices.db" ]; then
  echo "Aucune base devices.db trouvée"
  exit 1
fi

cp "$PROJECT_DIR/devices.db" "$BACKUP_DIR/devices_${TS}.db"
gzip -f "$BACKUP_DIR/devices_${TS}.db"

echo "Backup créé: $BACKUP_DIR/devices_${TS}.db.gz"
