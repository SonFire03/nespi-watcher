# NESPi Watcher

## Options supplémentaires implémentées

- Boot/heartbeat: `NOTIFY_ON_FIRST_BOOT`, `HEARTBEAT_ENABLED`, `HEARTBEAT_INTERVAL_MIN`
- Scheduling: `SCAN_JITTER_SECONDS`, `RANDOMIZE_NETWORK_ORDER`, `SCAN_WINDOW`
- Purge auto: `DEVICE_INACTIVE_DAYS_PURGE`, `EVENT_RETENTION_DAYS`, `SCAN_RETENTION_DAYS`
- Upgrade safety: `DB_BACKUP_BEFORE_UPGRADE`
- Safety modes: `DRY_RUN_SCAN`, `SAFE_MODE`, `MAINTENANCE_MODE`, `READ_ONLY_API`
- Time/format: `TZ_OVERRIDE`, `TIMESTAMP_FORMAT`
- Export privacy: `EXPORT_REDACT`, `EXPORT_TOKEN`
- Audit chain: `API_AUDIT_LOG`, `AUDIT_HASH_CHAIN`
- Anti-spam device events: `MAX_EVENT_PER_DEVICE_PER_HOUR`
- Identity/network: `REMOTE_IP_TRUST_HEADER`, `SERVICE_BANNER`, `UI_COMPACT_MODE`
- Existing advanced options conservées: webhook, auth basic, cors, risk score, backup, metrics, scan profiles

## Endpoints clés

- `GET /health`
- `GET /metrics`
- `GET|POST /api/scan?profile=quick|deep`
- `GET /api/devices`
- `POST /api/device/meta`
- `GET /api/device/timeline?ip=<IP>&mac=<MAC>`
- `GET /api/scans`
- `GET /api/events`
- `GET /api/status`
- `GET /api/export/devices?format=json|csv&token=<EXPORT_TOKEN>`
