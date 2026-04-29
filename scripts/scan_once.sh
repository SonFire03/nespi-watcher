#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# shellcheck disable=SC1091
source .venv/bin/activate

python - << 'PYEOF'
from app import db, process_scan, setup_logging

setup_logging()
db.init_db()
result = process_scan(source="manual-script")
print(result)
PYEOF
