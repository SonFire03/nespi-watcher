# NESPi Watcher

NESPi Watcher est un dashboard web local de surveillance réseau, pensé pour Raspberry Pi 2 Model B (Raspberry Pi OS Legacy 32-bit), léger et stable.

## Nouveautés V2

- Scan automatique périodique (configurable)
- Historique des scans en base SQLite
- Endpoint statut enrichi (`/api/status`)
- Endpoint historique scans (`/api/scans`)
- Anti-chevauchement des scans (verrou)
- Telegram en mode résumé (moins de spam) ou mode détaillé
- Scripts robustes sans chemin codé en dur

## Fonctionnalités

- Scan réseau local via `nmap` (`-sn`)
- Détection d'appareils (IP, MAC, hostname)
- Stockage historique dans SQLite
- Détection de nouveaux appareils
- Alerte Telegram optionnelle
- Dashboard web Flask
- Endpoints API JSON :
  - `GET /health`
  - `GET /scan`
  - `GET /api/devices`
  - `GET /api/scan`
  - `GET /api/status`
  - `GET /api/scans`
- Logs légers avec rotation

## Structure du projet

```text
nespi-watcher/
├── app.py
├── scanner.py
├── database.py
├── alerts.py
├── config.py
├── requirements.txt
├── README.md
├── systemd/
│   └── nespi-watcher.service
├── scripts/
│   ├── install.sh
│   ├── update.sh
│   └── scan_once.sh
└── templates/
    └── index.html
```

## Installation sur Raspberry

```bash
git clone https://github.com/SonFire03/nespi-watcher.git /home/soso/nespi-watcher
cd /home/soso/nespi-watcher
chmod +x scripts/*.sh
./scripts/install.sh
```

## Variables d'environnement

```env
NETWORK_RANGE=192.168.1.0/24
APP_HOST=0.0.0.0
APP_PORT=8080
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_MODE=summary
SCAN_TIMEOUT=60
AUTO_SCAN_ENABLED=true
SCAN_INTERVAL_SECONDS=600
STARTUP_SCAN_ENABLED=false
DB_PATH=devices.db
LOG_LEVEL=INFO
```

### Telegram

- `TELEGRAM_MODE=summary` : 1 message récapitulatif par scan
- `TELEGRAM_MODE=each` : 1 message par nouvel appareil

## Utilisation

- Dashboard : `http://IP_DU_RASPBERRY:8080`
- Healthcheck : `http://IP_DU_RASPBERRY:8080/health`
- Scan manuel API : `http://IP_DU_RASPBERRY:8080/api/scan`
- Liste appareils API : `http://IP_DU_RASPBERRY:8080/api/devices`
- Statut service/API : `http://IP_DU_RASPBERRY:8080/api/status`
- Historique scans : `http://IP_DU_RASPBERRY:8080/api/scans`

## Scripts utiles

- `scripts/install.sh`
  - installe dépendances système
  - crée venv et installe requirements
  - installe service systemd avec le bon chemin réel du projet

- `scripts/update.sh`
  - `git pull --ff-only`
  - met à jour dépendances
  - réinstalle le fichier service pour garder le bon chemin
  - redémarre le service

- `scripts/scan_once.sh`
  - lance un scan manuel en CLI

## Logs

- Dossier : `logs/`
- Fichier : `logs/nespi-watcher.log`
- Rotation : 512 KB x 3 backups

## Commandes utiles

```bash
sudo systemctl status nespi-watcher.service
sudo systemctl restart nespi-watcher.service
sudo journalctl -u nespi-watcher.service -f
```
