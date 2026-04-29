# NESPi Watcher

NESPi Watcher est un dashboard web local de surveillance réseau, pensé pour Raspberry Pi 2 Model B (Raspberry Pi OS Legacy 32-bit), léger et stable.

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

## Pré-requis

- Raspberry Pi OS Legacy 32-bit
- Python 3
- `sudo` disponible
- Connexion réseau locale

## Installation sur Raspberry

```bash
git clone <mon_repo_github> /home/soso/nespi-watcher
cd /home/soso/nespi-watcher
chmod +x scripts/*.sh
./scripts/install.sh
```

Le script `install.sh` :

1. installe dépendances système (`python3`, `python3-venv`, `python3-pip`, `nmap`)
2. crée `.venv`
3. installe `requirements.txt`
4. crée un fichier `.env` minimal si absent
5. installe et active le service systemd
6. démarre le service

## Configuration

Le projet lit les variables d'environnement suivantes (valeurs par défaut) :

```env
NETWORK_RANGE=192.168.1.0/24
APP_HOST=0.0.0.0
APP_PORT=8080
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SCAN_TIMEOUT=60
```

### Option 1 (simple)

Éditer `.env` puis exporter au shell avant lancement manuel.

### Option 2 (service systemd)

Pour rendre les variables persistantes pour le service, créer un override :

```bash
sudo systemctl edit nespi-watcher.service
```

Puis ajouter :

```ini
[Service]
Environment=NETWORK_RANGE=192.168.1.0/24
Environment=APP_HOST=0.0.0.0
Environment=APP_PORT=8080
Environment=TELEGRAM_BOT_TOKEN=
Environment=TELEGRAM_CHAT_ID=
Environment=SCAN_TIMEOUT=60
```

Ensuite :

```bash
sudo systemctl daemon-reload
sudo systemctl restart nespi-watcher.service
```

## Utilisation

- Dashboard : `http://IP_DU_RASPBERRY:8080`
- Healthcheck : `http://IP_DU_RASPBERRY:8080/health`
- Scan manuel API : `http://IP_DU_RASPBERRY:8080/api/scan`
- Liste appareils API : `http://IP_DU_RASPBERRY:8080/api/devices`

## Scripts utiles

- `scripts/update.sh` :
  - `git pull --ff-only`
  - mise à jour dépendances Python
  - redémarrage service

- `scripts/scan_once.sh` : lance un scan ponctuel depuis le shell

## Logs

- Dossier : `logs/`
- Fichier : `logs/nespi-watcher.log`
- Rotation : 512 KB x 3 backups

Ce comportement limite l'usure SD et évite les logs volumineux.

## Commandes systemd

```bash
sudo systemctl status nespi-watcher.service
sudo systemctl restart nespi-watcher.service
sudo journalctl -u nespi-watcher.service -f
```

## Notes robustesse

- Si MAC absente : valeur `Inconnue`
- Si hostname absent : valeur `Inconnu`
- Si sortie nmap partielle/invalide : erreur loggée, application continue
- Si Telegram non configuré : aucune erreur bloquante
