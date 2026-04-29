# NESPi Watcher

Dashboard local de surveillance réseau optimisé Raspberry Pi (léger, sans dépendances lourdes).

## Présentation

### Vue globale du projet

<img width="1536" height="1024" alt="53217cb3-4005-40b8-bbf9-dd3fa21633c6" src="https://github.com/user-attachments/assets/392b9b62-191e-483c-bb90-64903cfbb180" />


### Bot Telegram (alertes)

<img width="1536" height="1024" alt="f88a1c53-cf1b-44a5-b811-3d3cada76afe" src="https://github.com/user-attachments/assets/db92f799-730c-4dfc-b191-5ecb6bd1391b" />


## Améliorations incluses

- UI V3 cyber (tabs, métriques, historique scans, filtres)
- Scan auto périodique configurable
- Anti-chevauchement des scans
- Historique scans avec rétention automatique (anti-usure SD)
- Détection online/offline réelle (basée sur `last_seen`)
- API devices avec pagination/recherche/filtre statut
- Événements appareils (nouveau + changement hostname)
- Alertes Telegram intelligentes :
  - mode `summary` ou `each`
  - seuil minimum (`ALERT_MIN_NEW_DEVICES`)
  - cooldown anti-spam (`ALERT_COOLDOWN_SECONDS`)
  - option inconnus uniquement (`ALERT_UNKNOWN_ONLY`)
- Hardening systemd (`NoNewPrivileges`, `ProtectSystem`, etc.)
- Ignore list IP/MAC
- Clé API optionnelle pour lancer les scans manuels

## Endpoints

- `GET /health`
- `GET /api/status`
- `GET /api/scans?limit=50`
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

## Vérification

```bash
sudo systemctl status nespi-watcher.service --no-pager
curl -s http://127.0.0.1:8080/api/status
curl -s "http://127.0.0.1:8080/api/devices?limit=50&status=online"
```

## Assets README

- `docs/images/nespi-watcher-overview.png`: image de présentation générale
- `docs/images/nespi-watcher-telegram-bot.png`: image dédiée au bot Telegram
