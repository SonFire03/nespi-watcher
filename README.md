# NESPi Watcher

Dashboard local de surveillance réseau optimisé Raspberry Pi (léger, sans dépendances lourdes).

## Présentation

### Vue globale du projet

![NESPi Watcher - Vue globale](docs/images/cdf5d0e5-fe06-43c4-adbc-a226bb83d53b.png)

### Bot Telegram (alertes)

![NESPi Watcher - Bot Telegram](docs/images/53217cb3-4005-40b8-bbf9-dd3fa21633c6.png)

## Améliorations incluses

- UI V3 cyber (tabs, métriques, historique scans, filtres)
- Scan auto périodique configurable
- Anti-chevauchement des scans
- Historique scans avec rétention automatique (anti-usure SD)
- Détection online/offline réelle (basée sur `last_seen`)
- API devices avec pagination/recherche/filtre statut
- API events (`/api/events`) pour les événements appareil
- Événements appareils : nouveau, hostname changé, IP changée (même MAC)
- Alertes Telegram intelligentes (mode, seuil, cooldown, inconnus uniquement)
- Hardening systemd (`NoNewPrivileges`, `ProtectSystem`, etc.)
- Ignore list IP/MAC
- Clé API optionnelle pour lancer les scans manuels
- Backup SQLite via script dédié
- Tests unitaires + CI GitHub Actions

## Endpoints

- `GET /health`
- `GET /api/status`
- `GET /api/scans?limit=50`
- `GET /api/events?limit=50`
- `GET /api/devices?limit=200&offset=0&search=&status=all|online|offline`
- `GET|POST /api/scan` (clé API optionnelle)
- `GET /scan` (clé API optionnelle)

## Installation

```bash
git clone <URL_DU_REPO_GIT> <DOSSIER_LOCAL>
cd <DOSSIER_LOCAL>
chmod +x scripts/*.sh
./scripts/install.sh
```

## Variables `.env`

```env
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
```

## Scripts

- `scripts/install.sh`: install complet + service
- `scripts/update.sh`: update code/deps + refresh service + restart
- `scripts/scan_once.sh`: scan manuel en CLI
- `scripts/backup.sh`: backup compressé de `devices.db` dans `backups/`

## Tests locaux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

## Vérification

```bash
sudo systemctl status nespi-watcher.service --no-pager
curl -s http://127.0.0.1:8080/api/status
curl -s "http://127.0.0.1:8080/api/devices?limit=50&status=online"
curl -s "http://127.0.0.1:8080/api/events?limit=20"
```
