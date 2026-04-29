import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, render_template, request

from alerts import send_telegram_alert
from config import Config
from database import DeviceDatabase
from scanner import scan_network

app = Flask(__name__)
config = Config()
db = DeviceDatabase(config.DB_PATH)

_scan_lock = threading.Lock()
_auto_scan_thread = None
_last_alert_ts = 0


def setup_logging() -> None:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / "nespi-watcher.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    if root_logger.handlers:
        return

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=512 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def _parse_iso_z(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _with_online_status(devices: List[Dict]) -> List[Dict]:
    now = datetime.now(timezone.utc)
    threshold = timedelta(seconds=config.OFFLINE_AFTER_SECONDS)
    out = []
    for d in devices:
        item = dict(d)
        last_seen_dt = _parse_iso_z(item.get("last_seen", ""))
        online = (now - last_seen_dt) <= threshold
        item["online"] = online
        item["status"] = "online" if online else "offline"
        out.append(item)
    return out


def _check_scan_api_key() -> bool:
    if not config.SCAN_API_KEY:
        return True
    provided = request.headers.get("X-API-Key", "") or request.args.get("key", "")
    return provided == config.SCAN_API_KEY


def _should_ignore(dev: Dict) -> bool:
    ip = (dev.get("ip") or "").strip()
    mac = (dev.get("mac") or "").strip().upper()
    if ip and ip in config.IGNORE_IPS:
        return True
    if mac and mac in config.IGNORE_MACS:
        return True
    return False


def _send_scan_telegram(new_devices: List[Dict], scanned_count: int) -> None:
    global _last_alert_ts

    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return

    filtered = new_devices
    if config.ALERT_UNKNOWN_ONLY:
        filtered = [d for d in filtered if d.get("hostname") == "Inconnu" or d.get("mac") == "Inconnue"]

    if len(filtered) < config.ALERT_MIN_NEW_DEVICES:
        return

    now_ts = int(time.time())
    if config.ALERT_COOLDOWN_SECONDS > 0 and (now_ts - _last_alert_ts) < config.ALERT_COOLDOWN_SECONDS:
        logging.info("Alerte Telegram ignorée (cooldown actif)")
        return

    mode = config.TELEGRAM_MODE if config.TELEGRAM_MODE in {"summary", "each"} else "summary"

    if mode == "each":
        for dev in filtered:
            msg = (
                "[NESPi Watcher] Nouvel appareil détecté\n"
                f"IP: {dev['ip']}\n"
                f"MAC: {dev['mac']}\n"
                f"Hostname: {dev['hostname']}"
            )
            send_telegram_alert(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, msg)
        _last_alert_ts = now_ts
        return

    lines = [
        "[NESPi Watcher] Nouveaux appareils détectés",
        f"Réseau: {config.NETWORK_RANGE}",
        f"Appareils scannés: {scanned_count}",
        f"Nouveaux: {len(filtered)}",
        "",
    ]
    for dev in filtered[:20]:
        lines.append(f"- {dev['ip']} | {dev['mac']} | {dev['hostname']}")
    if len(filtered) > 20:
        lines.append(f"... et {len(filtered) - 20} autres")

    send_telegram_alert(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, "\n".join(lines))
    _last_alert_ts = now_ts


def process_scan(source: str = "manual") -> Dict:
    if not _scan_lock.acquire(blocking=False):
        return {"status": "busy", "message": "Un scan est déjà en cours"}

    start_time = time.monotonic()
    try:
        logging.info("Lancement scan réseau [%s]: %s", source, config.NETWORK_RANGE)
        scanned_devices = scan_network(config.NETWORK_RANGE, timeout=config.SCAN_TIMEOUT)

        seen_at = db.now_iso()
        new_devices = []

        for dev in scanned_devices:
            ip = dev.get("ip", "")
            mac = dev.get("mac", "Inconnue") or "Inconnue"
            hostname = dev.get("hostname", "Inconnu") or "Inconnu"

            normalized = {"ip": ip, "mac": mac, "hostname": hostname}
            if not ip or _should_ignore(normalized):
                continue

            prev = db.get_device(ip, mac)
            is_new, hostname_changed = db.upsert_device(ip=ip, mac=mac, hostname=hostname, seen_at=seen_at)

            if is_new:
                new_devices.append(normalized)
                db.log_device_event(
                    happened_at=seen_at,
                    ip=ip,
                    mac=mac,
                    event_type="new_device",
                    old_value="",
                    new_value=hostname,
                )

                if mac != "Inconnue":
                    recent_for_mac = db.get_recent_devices_by_mac(mac, limit=2)
                    if len(recent_for_mac) >= 2:
                        current = recent_for_mac[0]
                        previous = recent_for_mac[1]
                        old_ip = previous.get("ip", "")
                        new_ip = current.get("ip", "")
                        if old_ip and new_ip and old_ip != new_ip:
                            db.log_device_event(
                                happened_at=seen_at,
                                ip=new_ip,
                                mac=mac,
                                event_type="ip_changed",
                                old_value=old_ip,
                                new_value=new_ip,
                            )
            elif hostname_changed and prev:
                db.log_device_event(
                    happened_at=seen_at,
                    ip=ip,
                    mac=mac,
                    event_type="hostname_changed",
                    old_value=prev.get("hostname", ""),
                    new_value=hostname,
                )

        _send_scan_telegram(new_devices, scanned_count=len(scanned_devices))

        duration_ms = int((time.monotonic() - start_time) * 1000)
        db.log_scan(
            scanned_at=seen_at,
            source=source,
            scanned_count=len(scanned_devices),
            new_count=len(new_devices),
            duration_ms=duration_ms,
            status="ok",
            message="",
        )
        db.prune_scan_history(config.MAX_SCAN_HISTORY_ROWS)

        logging.info(
            "Scan terminé [%s]. %s appareils, %s nouveaux, %sms.",
            source,
            len(scanned_devices),
            len(new_devices),
            duration_ms,
        )

        return {
            "status": "ok",
            "network_range": config.NETWORK_RANGE,
            "source": source,
            "scanned_count": len(scanned_devices),
            "new_count": len(new_devices),
            "new_devices": new_devices,
            "duration_ms": duration_ms,
            "scanned_at": seen_at,
        }
    except Exception as exc:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        scanned_at = db.now_iso()
        db.log_scan(
            scanned_at=scanned_at,
            source=source,
            scanned_count=0,
            new_count=0,
            duration_ms=duration_ms,
            status="error",
            message=str(exc),
        )
        logging.exception("Erreur scan [%s]: %s", source, exc)
        return {"status": "error", "message": "Erreur interne pendant le scan"}
    finally:
        _scan_lock.release()


def auto_scan_loop() -> None:
    interval = max(30, config.SCAN_INTERVAL_SECONDS)
    logging.info("Auto-scan activé toutes les %s secondes", interval)

    if config.STARTUP_SCAN_ENABLED:
        process_scan(source="startup")

    while True:
        time.sleep(interval)
        process_scan(source="auto")


def start_auto_scan_if_enabled() -> None:
    global _auto_scan_thread
    if not config.AUTO_SCAN_ENABLED:
        logging.info("Auto-scan désactivé")
        return

    _auto_scan_thread = threading.Thread(target=auto_scan_loop, name="auto-scan", daemon=True)
    _auto_scan_thread.start()


def get_runtime_status() -> Dict:
    last_scan = db.get_last_scan()
    stats = db.get_db_stats()
    return {
        "status": "ok",
        "network_range": config.NETWORK_RANGE,
        "total_devices": db.count_devices(),
        "last_scan": last_scan,
        "auto_scan_enabled": config.AUTO_SCAN_ENABLED,
        "scan_interval_seconds": max(30, config.SCAN_INTERVAL_SECONDS),
        "offline_after_seconds": config.OFFLINE_AFTER_SECONDS,
        "telegram_enabled": bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID),
        "telegram_mode": config.TELEGRAM_MODE,
        "scan_api_key_enabled": bool(config.SCAN_API_KEY),
        "history_retention_rows": config.MAX_SCAN_HISTORY_ROWS,
        "db_stats": stats,
    }


@app.route("/")
def index():
    devices = _with_online_status(db.get_devices(limit=200, offset=0, search=""))
    runtime = get_runtime_status()
    return render_template("index.html", devices=devices, config=config, runtime=runtime)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/scan")
def scan_page():
    if not _check_scan_api_key():
        return jsonify({"status": "error", "message": "API key invalide"}), 401
    result = process_scan(source="manual")
    return jsonify(result)


@app.route("/api/devices")
def api_devices():
    limit = request.args.get("limit", default=200, type=int)
    offset = request.args.get("offset", default=0, type=int)
    search = request.args.get("search", default="", type=str)
    status_filter = request.args.get("status", default="all", type=str).lower()

    devices = _with_online_status(db.get_devices(limit=limit, offset=offset, search=search))
    if status_filter in {"online", "offline"}:
        devices = [d for d in devices if d.get("status") == status_filter]

    total = db.count_devices(search=search)
    return jsonify(
        {
            "status": "ok",
            "count": len(devices),
            "total": total,
            "limit": max(1, min(int(limit), 1000)),
            "offset": max(0, int(offset)),
            "devices": devices,
        }
    )


@app.route("/api/scan", methods=["GET", "POST"])
def api_scan():
    if not _check_scan_api_key():
        return jsonify({"status": "error", "message": "API key invalide"}), 401
    result = process_scan(source="manual")
    return jsonify(result)


@app.route("/api/status")
def api_status():
    return jsonify(get_runtime_status())


@app.route("/api/scans")
def api_scans():
    limit = request.args.get("limit", default=20, type=int)
    return jsonify({"status": "ok", "scans": db.get_recent_scans(limit=limit)})


@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", default=50, type=int)
    return jsonify({"status": "ok", "events": db.get_recent_events(limit=limit)})


def main() -> None:
    setup_logging()
    db.init_db()
    start_auto_scan_if_enabled()
    app.run(host=config.APP_HOST, port=config.APP_PORT)


if __name__ == "__main__":
    main()
