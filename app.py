import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template

from alerts import send_telegram_alert
from config import Config
from database import DeviceDatabase
from scanner import scan_network

app = Flask(__name__)
config = Config()
db = DeviceDatabase(config.DB_PATH)


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


def process_scan() -> dict:
    logging.info("Lancement scan réseau: %s", config.NETWORK_RANGE)
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
            new_devices.append(dev)
            msg = (
                "[NESPi Watcher] Nouvel appareil détecté\n"
                f"IP: {ip}\n"
                f"MAC: {mac}\n"
                f"Hostname: {hostname}"
            )
            send_telegram_alert(
                config.TELEGRAM_BOT_TOKEN,
                config.TELEGRAM_CHAT_ID,
                msg,
            )

    logging.info("Scan terminé. %s appareils, %s nouveaux.", len(scanned_devices), len(new_devices))

    return {
        "status": "ok",
        "network_range": config.NETWORK_RANGE,
        "scanned_count": len(scanned_devices),
        "new_count": len(new_devices),
        "new_devices": new_devices,
    }


@app.route("/")
def index():
    devices = db.get_all_devices()
    return render_template("index.html", devices=devices, config=config)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/scan")
def scan_page():
    result = process_scan()
    return jsonify(result)


@app.route("/api/devices")
def api_devices():
    devices = db.get_all_devices()
    return jsonify({"status": "ok", "count": len(devices), "devices": devices})


@app.route("/api/scan")
def api_scan():
    result = process_scan()
    return jsonify(result)


def main() -> None:
    setup_logging()
    db.init_db()

    app.run(host=config.APP_HOST, port=config.APP_PORT)


if __name__ == "__main__":
    main()
