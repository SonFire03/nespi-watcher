import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict

from flask import Flask, jsonify, render_template

from alerts import send_telegram_alert
from config import Config
from database import DeviceDatabase
from scanner import scan_network

app = Flask(__name__)
config = Config()
db = DeviceDatabase(config.DB_PATH)

_scan_lock = threading.Lock()
_auto_scan_thread = None


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


def _send_scan_telegram(new_devices: list, scanned_count: int) -> None:
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return
    if not new_devices:
        return

    mode = config.TELEGRAM_MODE if config.TELEGRAM_MODE in {"summary", "each"} else "summary"

    if mode == "each":
        for dev in new_devices:
            msg = (
                "[NESPi Watcher] Nouvel appareil détecté\n"
                f"IP: {dev['ip']}\n"
                f"MAC: {dev['mac']}\n"
                f"Hostname: {dev['hostname']}"
            )
            send_telegram_alert(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, msg)
        return

    lines = [
        "[NESPi Watcher] Nouveaux appareils détectés",
        f"Réseau: {config.NETWORK_RANGE}",
        f"Appareils scannés: {scanned_count}",
        f"Nouveaux: {len(new_devices)}",
        "",
    ]
    for dev in new_devices[:15]:
        lines.append(f"- {dev['ip']} | {dev['mac']} | {dev['hostname']}")

    if len(new_devices) > 15:
        lines.append(f"... et {len(new_devices) - 15} autres")

    send_telegram_alert(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, "\n".join(lines))


def process_scan(source: str = "manual") -> Dict:
    if not _scan_lock.acquire(blocking=False):
        return {
            "status": "busy",
            "message": "Un scan est déjà en cours",
        }

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

            if not ip:
                continue

            is_new = db.upsert_device(ip=ip, mac=mac, hostname=hostname, seen_at=seen_at)
            if is_new:
                new_devices.append({"ip": ip, "mac": mac, "hostname": hostname})

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
    return {
        "status": "ok",
        "network_range": config.NETWORK_RANGE,
        "total_devices": db.count_devices(),
        "last_scan": last_scan,
        "auto_scan_enabled": config.AUTO_SCAN_ENABLED,
        "scan_interval_seconds": max(30, config.SCAN_INTERVAL_SECONDS),
        "telegram_enabled": bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID),
        "telegram_mode": config.TELEGRAM_MODE,
    }


@app.route("/")
def index():
    devices = db.get_all_devices()
    runtime = get_runtime_status()
    return render_template("index.html", devices=devices, config=config, runtime=runtime)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/scan")
def scan_page():
    result = process_scan(source="manual")
    return jsonify(result)


@app.route("/api/devices")
def api_devices():
    devices = db.get_all_devices()
    return jsonify({"status": "ok", "count": len(devices), "devices": devices})


@app.route("/api/scan")
def api_scan():
    result = process_scan(source="manual")
    return jsonify(result)


@app.route("/api/status")
def api_status():
    return jsonify(get_runtime_status())


@app.route("/api/scans")
def api_scans():
    return jsonify({"status": "ok", "scans": db.get_recent_scans(limit=20)})


def main() -> None:
    setup_logging()
    db.init_db()
    start_auto_scan_if_enabled()
    app.run(host=config.APP_HOST, port=config.APP_PORT)


if __name__ == "__main__":
    main()
