#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/soso/nespi-watcher"

cd "$PROJECT_DIR"

# shellcheck disable=SC1091
source .venv/bin/activate

python - << 'PYEOF'
from app import db, process_scan, setup_logging

setup_logging()
db.init_db()
result = process_scan()
print(result)
PYEOF
