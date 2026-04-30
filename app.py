import csv
import io
import json
import logging
import socket
import hmac
import hashlib
import threading
import time
import random
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List

import requests
from flask import Flask, Response, jsonify, render_template, request

from alerts import send_telegram_alert
from config import Config
from database import DeviceDatabase
from scanner import scan_network, scan_open_ports
from cowrie_reader import get_clean_events, get_cowrie_stats

app = Flask(__name__)
config = Config()
db = DeviceDatabase(config.DB_PATH)

_scan_lock = threading.Lock()
_auto_scan_thread = None
_backup_thread = None
_last_alert_ts = 0
_scan_request_window = []
_known_aliases = {}
_nmap_slots = threading.Semaphore(max(1, config.MAX_CONCURRENT_NMAP))
_status_cache = {"ts": 0.0, "value": None}
_audit_prev_hash = ""


def _load_known_aliases() -> Dict[str, str]:
    aliases = {}
    path = config.KNOWN_DEVICES_FILE
    if not path:
        return aliases
    try:
        p = Path(path)
        if not p.exists():
            return aliases
        if p.suffix.lower() == ".json":
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k, v in data.items():
                    aliases[str(k).strip().upper()] = str(v).strip()
            return aliases
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split(",", 1)]
            if len(parts) == 2:
                aliases[parts[0].upper()] = parts[1]
    except Exception as exc:
        logging.warning("Impossible de charger KNOWN_DEVICES_FILE: %s", exc)
    return aliases


def _is_quiet_hours() -> bool:
    if not config.QUIET_HOURS or "-" not in config.QUIET_HOURS:
        return False
    try:
        start_s, end_s = [x.strip() for x in config.QUIET_HOURS.split("-", 1)]
        now = datetime.now().time()
        sh, sm = [int(x) for x in start_s.split(":", 1)]
        eh, em = [int(x) for x in end_s.split(":", 1)]
        start_t = datetime.now().replace(hour=sh, minute=sm, second=0, microsecond=0).time()
        end_t = datetime.now().replace(hour=eh, minute=em, second=0, microsecond=0).time()
        if start_t <= end_t:
            return start_t <= now <= end_t
        return now >= start_t or now <= end_t
    except Exception:
        return False


def _is_scan_window_open() -> bool:
    mode = config.SCAN_WINDOW
    hour = datetime.now().hour
    if mode == "day":
        return 7 <= hour < 22
    if mode == "night":
        return hour >= 22 or hour < 7
    return True


def _send_webhook(event_type: str, payload: Dict) -> None:
    if not config.WEBHOOK_URL:
        return
    body = {"event_type": event_type, "payload": payload, "ts": int(time.time())}
    headers = {"Content-Type": "application/json"}
    if config.WEBHOOK_SECRET:
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        sig = hmac.new(config.WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        headers["X-Nespi-Signature"] = sig
    try:
        requests.post(config.WEBHOOK_URL, json=body, headers=headers, timeout=5)
    except Exception:
        pass


def _api_audit() -> None:
    if not config.API_AUDIT_LOG:
        return
    if not request.path.startswith("/api") and request.path not in {"/scan", "/health", "/metrics"}:
        return
    Path("logs").mkdir(exist_ok=True)
    remote = request.headers.get(config.REMOTE_IP_TRUST_HEADER, "").split(",")[0].strip() if config.REMOTE_IP_TRUST_HEADER else request.remote_addr
    line = f"{datetime.now(timezone.utc).isoformat()} {remote} {request.method} {request.path} {request.query_string.decode('utf-8','ignore')}"
    global _audit_prev_hash
    if config.AUDIT_HASH_CHAIN:
        h = hashlib.sha256((line + "|" + _audit_prev_hash).encode("utf-8")).hexdigest()
        _audit_prev_hash = h
        line += f" hash={h}"
    line += "\n"
    with open("logs/api_audit.log", "a", encoding="utf-8") as fh:
        fh.write(line)


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

    file_handler = RotatingFileHandler(log_path, maxBytes=512 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    cutoff = time.time() - (config.LOG_RETENTION_DAYS * 86400)
    for f in log_dir.glob("*.log*"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
        except Exception:
            pass


@app.before_request
def _before_request_hooks():
    if request.method == "OPTIONS":
        return Response(status=204)
    _api_audit()
    if config.AUTH_BASIC_ENABLED:
        auth = request.authorization
        if not auth or auth.username != config.AUTH_USER:
            return Response("Unauthorized", status=401, headers={"WWW-Authenticate": "Basic realm='NESPi Watcher'"})
        expected = config.AUTH_PASS_HASH.strip().lower()
        provided = hashlib.sha256((auth.password or "").encode("utf-8")).hexdigest()
        if not expected or provided != expected:
            return Response("Unauthorized", status=401, headers={"WWW-Authenticate": "Basic realm='NESPi Watcher'"})


@app.after_request
def _after_request_cors(resp):
    if config.CORS_ALLOWED_ORIGINS:
        origin = request.headers.get("Origin", "")
        if origin and origin in config.CORS_ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-Export-Token"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def _parse_iso_z(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _now_utc() -> datetime:
    if config.TZ_OVERRIDE:
        try:
            from zoneinfo import ZoneInfo
            return datetime.now(ZoneInfo(config.TZ_OVERRIDE)).astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _fmt_ts(iso_z: str) -> str:
    if config.TIMESTAMP_FORMAT == "human":
        dt = _parse_iso_z(iso_z)
        if config.TZ_OVERRIDE:
            try:
                from zoneinfo import ZoneInfo
                dt = dt.astimezone(ZoneInfo(config.TZ_OVERRIDE))
            except Exception:
                pass
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return iso_z


def _mask_ip(ip: str) -> str:
    if config.SHOW_PRIVATE_INFO:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "***"


def _mask_mac(mac: str) -> str:
    if config.SHOW_PRIVATE_INFO:
        return mac
    if len(mac) >= 8:
        return mac[:8] + ":**:**:**"
    return "**:**:**:**:**:**"


def _with_online_status(devices: List[Dict]) -> List[Dict]:
    now = _now_utc()
    threshold = timedelta(seconds=config.OFFLINE_AFTER_SECONDS)
    out = []
    for d in devices:
        item = dict(d)
        last_seen = _parse_iso_z(item.get("last_seen", ""))
        item["online"] = (now - last_seen) <= (threshold + timedelta(seconds=config.OFFLINE_GRACE_PERIOD_SECONDS))
        item["status"] = "online" if item["online"] else "offline"
        if config.DEVICE_ALIAS_ENABLED:
            item["alias"] = _known_aliases.get((item.get("mac") or "").upper(), "")
        if not config.SHOW_PRIVATE_INFO:
            item["ip"] = _mask_ip(item.get("ip", ""))
            item["mac"] = _mask_mac(item.get("mac", ""))
        out.append(item)
    return out


def _is_safe_mode() -> bool:
    return config.SAFE_MODE


def _check_scan_api_key() -> bool:
    if not config.SCAN_API_KEY:
        return True
    provided = request.headers.get("X-API-Key", "") or request.args.get("key", "")
    return provided == config.SCAN_API_KEY


def _check_export_token() -> bool:
    if not config.EXPORT_TOKEN:
        return True
    provided = request.headers.get("X-Export-Token", "") or request.args.get("token", "")
    return provided == config.EXPORT_TOKEN


def _scan_rate_allowed() -> bool:
    now = time.time()
    window_start = now - 60
    while _scan_request_window and _scan_request_window[0] < window_start:
        _scan_request_window.pop(0)
    if len(_scan_request_window) >= config.API_RATE_LIMIT_SCAN_PER_MIN:
        return False
    _scan_request_window.append(now)
    return True


def _should_ignore(dev: Dict) -> bool:
    ip = (dev.get("ip") or "").strip()
    mac = (dev.get("mac") or "").strip().upper()
    return (ip and ip in config.IGNORE_IPS) or (mac and mac in config.IGNORE_MACS)


def _tg_send(msg: str) -> None:
    if _is_quiet_hours():
        return
    if config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID:
        send_telegram_alert(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, msg)


def _send_scan_telegram(new_devices: List[Dict], scanned_count: int) -> None:
    global _last_alert_ts
    filtered = new_devices
    if config.ALERT_UNKNOWN_ONLY:
        filtered = [d for d in filtered if d.get("hostname") == "Inconnu" or d.get("mac") == "Inconnue"]
    if len(filtered) < config.ALERT_MIN_NEW_DEVICES:
        return
    now_ts = int(time.time())
    min_gap = max(config.ALERT_COOLDOWN_SECONDS, config.ALERT_BATCH_WINDOW_SECONDS)
    if min_gap > 0 and (now_ts - _last_alert_ts) < min_gap:
        return
    lines = [
        "[NESPi Watcher] Nouveaux appareils détectés",
        f"Réseaux: {', '.join(config.NETWORK_RANGES)}",
        f"Appareils scannés: {scanned_count}",
        f"Nouveaux: {len(filtered)}",
        "",
    ]
    for d in filtered[:20]:
        lines.append(f"- {d['ip']} | {d['mac']} | {d['hostname']}")
    _tg_send("\n".join(lines))
    _last_alert_ts = now_ts


def _run_one_scan(network: str, profile: str) -> List[Dict]:
    with _nmap_slots:
        return scan_network(network, timeout=config.SCAN_TIMEOUT, profile=profile, deep_ports=config.NMAP_DEEP_PORTS)


def _fingerprint_for_device(hostname: str, ports: List[int]) -> str:
    return f"{hostname}|{','.join(str(p) for p in sorted(set(ports)))}"


def process_scan(source: str = "manual", profile: str = "") -> Dict:
    if config.MAINTENANCE_MODE:
        return {"status": "error", "message": "maintenance_mode"}
    if source in {"auto", "startup", "auto-retry"} and not _is_scan_window_open():
        return {"status": "skipped", "message": "scan_window_closed"}
    if not _scan_lock.acquire(blocking=False):
        return {"status": "busy", "message": "Un scan est déjà en cours"}

    profile = (profile or config.DEFAULT_SCAN_PROFILE or "quick").lower()
    if _is_safe_mode():
        profile = "quick"
    if profile not in {"quick", "deep"}:
        profile = "quick"

    start = time.monotonic()
    try:
        all_devices = []
        networks = list(config.NETWORK_RANGES)
        if config.RANDOMIZE_NETWORK_ORDER:
            random.shuffle(networks)
        for network in networks:
            all_devices.extend(_run_one_scan(network, profile=profile))

        unique = []
        seen = set()
        for d in all_devices:
            key = (d.get("ip", ""), d.get("mac", ""))
            if key in seen:
                continue
            seen.add(key)
            unique.append(d)

        now_iso = db.now_iso()
        new_devices = []
        for dev in unique:
            ip = dev.get("ip", "")
            mac = dev.get("mac", "Inconnue") or "Inconnue"
            hostname = dev.get("hostname", "Inconnu") or "Inconnu"
            if config.DNS_REVERSE_LOOKUP and (hostname == "Inconnu" or not hostname):
                try:
                    hostname = socket.gethostbyaddr(ip)[0] or "Inconnu"
                except Exception:
                    hostname = "Inconnu"
            n = {"ip": ip, "mac": mac, "hostname": hostname}
            if not ip or _should_ignore(n):
                continue
            if config.ALLOWLIST_ONLY and mac not in _known_aliases:
                continue
            is_blocked = ip in config.BLOCKLIST_IPS or mac in config.BLOCKLIST_MACS
            prev = db.get_device(ip, mac)
            is_new, hostname_changed = db.upsert_device(ip, mac, hostname, now_iso)
            if is_new:
                new_devices.append(n)
                db.log_device_event(now_iso, ip, mac, "new_device", "", hostname)
                _send_webhook("new_device", n)
                if mac != "Inconnue":
                    rec = db.get_recent_devices_by_mac(mac, limit=2)
                    if len(rec) >= 2 and rec[1].get("ip") != rec[0].get("ip"):
                        db.log_device_event(now_iso, rec[0].get("ip", ""), mac, "ip_changed", rec[1].get("ip", ""), rec[0].get("ip", ""))
                        if config.ALERT_IP_CHANGED:
                            _tg_send(f"[NESPi Watcher] IP changée\nMAC: {mac}\nAncienne IP: {rec[1].get('ip','')}\nNouvelle IP: {rec[0].get('ip','')}")
                        _send_webhook("ip_changed", {"mac": mac, "old_ip": rec[1].get("ip", ""), "new_ip": rec[0].get("ip", "")})
            ports = []
            if config.PORT_SCAN_ON_NEW_DEVICE and is_new and not _is_safe_mode():
                with _nmap_slots:
                    ports = scan_open_ports(ip, top_ports=config.PORT_SCAN_TOP_PORTS, timeout=config.PORT_SCAN_TIMEOUT)
                if ports:
                    db.log_device_event(now_iso, ip, mac, "open_ports", "", ",".join(str(p) for p in ports))
                    if config.ALERT_OPEN_PORTS and any(p in config.SENSITIVE_PORTS for p in ports):
                        _tg_send(f"[NESPi Watcher] Port sensible détecté\nIP: {ip}\nMAC: {mac}\nPorts: {','.join(str(p) for p in ports)}")
                    _send_webhook("open_ports", {"ip": ip, "mac": mac, "ports": ports})

            if config.DEVICE_FINGERPRINT_ENABLED:
                prev_state = db.get_device_state(ip, mac)
                new_fp = _fingerprint_for_device(hostname, ports)
                old_fp = prev_state.get("fingerprint", "")
                db.set_device_state(ip, mac, new_fp, ",".join(str(p) for p in ports), now_iso)
                if old_fp and old_fp != new_fp:
                    db.log_device_event(now_iso, ip, mac, "fingerprint_changed", old_fp, new_fp)
                    if config.ALERT_FINGERPRINT_CHANGED:
                        _tg_send(f"[NESPi Watcher] Fingerprint changé\nIP: {ip}\nMAC: {mac}")
                    _send_webhook("fingerprint_changed", {"ip": ip, "mac": mac})

            if hostname_changed and prev:
                db.log_device_event(now_iso, ip, mac, "hostname_changed", prev.get("hostname", ""), hostname)
                _send_webhook("hostname_changed", {"ip": ip, "mac": mac, "old": prev.get("hostname", ""), "new": hostname})

            if is_blocked:
                db.set_device_meta(ip, mac, config.SUSPECT_DEVICE_TAG, "blocked by policy", now_iso)
                db.log_device_event(now_iso, ip, mac, "blocked_device", "", "policy_match")
            elif config.AUTO_TAG_BY_VENDOR:
                h = hostname.lower()
                auto_tag = ""
                if "android" in h or "iphone" in h:
                    auto_tag = "mobile"
                elif "tv" in h or "chromecast" in h:
                    auto_tag = "media"
                elif "router" in h or "livebox" in h:
                    auto_tag = "network"
                if auto_tag:
                    db.set_device_meta(ip, mac, auto_tag, "", now_iso)

            if config.DEVICE_RISK_SCORE_ENABLED:
                score = 0
                if is_blocked:
                    score += 80
                if hostname == "Inconnu":
                    score += 20
                if mac == "Inconnue":
                    score += 20
                if ports and any(p in config.SENSITIVE_PORTS for p in ports):
                    score += 30
                if score >= config.RISK_ALERT_THRESHOLD:
                    cutoff = (_now_utc() - timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    if db.count_events_for_device_since(ip, mac, cutoff) < config.MAX_EVENT_PER_DEVICE_PER_HOUR:
                        db.log_device_event(now_iso, ip, mac, "risk_alert", "", str(score))
                        _tg_send(f"[NESPi Watcher] Risque élevé\nIP: {ip}\nMAC: {mac}\nScore: {score}")
                        _send_webhook("risk_alert", {"ip": ip, "mac": mac, "score": score})

            if config.MAX_SCAN_DURATION_SECONDS and (time.monotonic() - start) > config.MAX_SCAN_DURATION_SECONDS:
                break

        duration_ms = int((time.monotonic() - start) * 1000)
        if not config.DRY_RUN_SCAN:
            db.log_scan(now_iso, source, len(unique), len(new_devices), duration_ms, "ok", f"profile={profile}")
        db.prune_scan_history(config.MAX_SCAN_HISTORY_ROWS)
        _send_scan_telegram(new_devices, scanned_count=len(unique))
        _send_webhook("scan_finished", {"source": source, "scanned_count": len(unique), "new_count": len(new_devices)})
        if config.CHANGELOG_ENABLED and new_devices:
            Path("logs").mkdir(exist_ok=True)
            with open("logs/changelog.log", "a", encoding="utf-8") as fh:
                for d in new_devices:
                    fh.write(f"{now_iso} NEW {d.get('ip')} {d.get('mac')} {d.get('hostname')}\n")

        return {"status": "ok", "profile": profile, "network_ranges": config.NETWORK_RANGES, "scanned_count": len(unique), "new_count": len(new_devices), "new_devices": new_devices, "duration_ms": duration_ms, "scanned_at": now_iso}
    except Exception as exc:
        now_iso = db.now_iso()
        duration_ms = int((time.monotonic() - start) * 1000)
        if not config.DRY_RUN_SCAN:
            db.log_scan(now_iso, source, 0, 0, duration_ms, "error", str(exc))
        if config.ALERT_SCAN_ERRORS:
            _tg_send(f"[NESPi Watcher] Erreur scan\n{exc}")
        _send_webhook("scan_error", {"source": source, "error": str(exc)})
        if config.AUTO_RESCAN_AFTER_ERROR:
            time.sleep(max(1, config.RESCAN_DELAY_SECONDS))
            try:
                process_scan(source="auto-retry", profile="quick")
            except Exception:
                pass
        logging.exception("Erreur scan: %s", exc)
        return {"status": "error", "message": "Erreur interne pendant le scan"}
    finally:
        _scan_lock.release()


def auto_scan_loop() -> None:
    if config.STARTUP_SCAN_ENABLED:
        process_scan(source="startup")
    if config.NOTIFY_ON_FIRST_BOOT:
        marker = Path(".first_boot_done")
        if not marker.exists():
            _tg_send("[NESPi Watcher] Service démarré (first boot)")
            marker.write_text("ok", encoding="utf-8")
    while True:
        if config.SCAN_JITTER_SECONDS > 0:
            time.sleep(random.randint(0, config.SCAN_JITTER_SECONDS))
        time.sleep(max(30, config.SCAN_INTERVAL_SECONDS))
        process_scan(source="auto")


def _backup_db_once() -> None:
    db_path = Path(config.DB_PATH)
    if not db_path.exists():
        return
    bdir = Path("backups")
    bdir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = bdir / f"devices_{ts}.db"
    target.write_bytes(db_path.read_bytes())
    cutoff = time.time() - (config.BACKUP_RETENTION_DAYS * 86400)
    for f in bdir.glob("devices_*.db"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
        except Exception:
            pass


def auto_backup_loop() -> None:
    while True:
        _backup_db_once()
        time.sleep(86400)


def heartbeat_loop() -> None:
    while True:
        time.sleep(max(1, config.HEARTBEAT_INTERVAL_MIN) * 60)
        _tg_send("[NESPi Watcher] Heartbeat: service actif")


def housekeeping_loop() -> None:
    while True:
        now = _now_utc()
        if config.DEVICE_INACTIVE_DAYS_PURGE > 0:
            cutoff = (now - timedelta(days=config.DEVICE_INACTIVE_DAYS_PURGE)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            db.purge_inactive_devices(cutoff)
        if config.EVENT_RETENTION_DAYS > 0:
            cutoff = (now - timedelta(days=config.EVENT_RETENTION_DAYS)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            db.purge_old_events(cutoff)
        if config.SCAN_RETENTION_DAYS > 0:
            cutoff = (now - timedelta(days=config.SCAN_RETENTION_DAYS)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            db.purge_old_scans(cutoff)
        time.sleep(3600)


def auto_vacuum_loop() -> None:
    while True:
        mode = config.DB_VACUUM_SCHEDULE
        if mode == "daily":
            time.sleep(86400)
        elif mode == "weekly":
            time.sleep(86400 * 7)
        else:
            return
        try:
            db.run_vacuum()
        except Exception:
            pass


def start_background_workers() -> None:
    global _auto_scan_thread, _backup_thread, _known_aliases
    _known_aliases = _load_known_aliases()
    if not config.WAL_MODE:
        try:
            with db._connect() as conn:
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.commit()
        except Exception:
            pass
    if config.AUTO_SCAN_ENABLED:
        _auto_scan_thread = threading.Thread(target=auto_scan_loop, daemon=True, name="auto-scan")
        _auto_scan_thread.start()
    if config.AUTO_BACKUP_ENABLED:
        _backup_thread = threading.Thread(target=auto_backup_loop, daemon=True, name="auto-backup")
        _backup_thread.start()
    if config.DB_VACUUM_SCHEDULE in {"daily", "weekly"}:
        threading.Thread(target=auto_vacuum_loop, daemon=True, name="auto-vacuum").start()
    if config.HEARTBEAT_ENABLED:
        threading.Thread(target=heartbeat_loop, daemon=True, name="heartbeat").start()
    threading.Thread(target=housekeeping_loop, daemon=True, name="housekeeping").start()


def get_runtime_status() -> Dict:
    now = time.time()
    if _status_cache["value"] is not None and (now - _status_cache["ts"]) < config.CACHE_STATUS_SECONDS:
        return dict(_status_cache["value"])
    value = {
        "status": "ok",
        "network_ranges": config.NETWORK_RANGES,
        "scan_profiles": config.SCAN_PROFILES,
        "default_scan_profile": config.DEFAULT_SCAN_PROFILE,
        "total_devices": db.count_devices(),
        "last_scan": db.get_last_scan(),
        "auto_scan_enabled": config.AUTO_SCAN_ENABLED,
        "scan_interval_seconds": config.SCAN_INTERVAL_SECONDS,
        "offline_after_seconds": config.OFFLINE_AFTER_SECONDS,
        "scan_api_key_enabled": bool(config.SCAN_API_KEY),
        "export_token_enabled": bool(config.EXPORT_TOKEN),
        "read_only_api": config.READ_ONLY_API,
        "ui_theme": config.UI_THEME,
        "ui_auto_refresh_seconds": config.UI_AUTO_REFRESH_SECONDS,
        "ui_page_size_default": config.UI_PAGE_SIZE_DEFAULT,
        "timezone_display": config.TIMEZONE_DISPLAY,
        "maintenance_mode": config.MAINTENANCE_MODE,
        "auto_update_check": config.AUTO_UPDATE_CHECK,
        "service_banner": config.SERVICE_BANNER,
        "ui_compact_mode": config.UI_COMPACT_MODE,
        "dry_run_scan": config.DRY_RUN_SCAN,
        "safe_mode": config.SAFE_MODE,
        "db_stats": db.get_db_stats(),
    }
    _status_cache["ts"] = now
    _status_cache["value"] = dict(value)
    return value


def _health_payload() -> Dict:
    if config.MAINTENANCE_MODE:
        return {"status": "error", "message": "maintenance_mode"}
    payload = {"status": "ok"}
    if config.HEALTH_REQUIRE_RECENT_SCAN:
        last = db.get_last_scan()
        if not last:
            payload = {"status": "error", "message": "no_scan"}
        else:
            age = (datetime.now(timezone.utc) - _parse_iso_z(last.get("scanned_at", ""))).total_seconds()
            if age > config.HEALTH_MAX_SCAN_AGE_SECONDS:
                payload = {"status": "error", "message": "scan_too_old", "scan_age_seconds": int(age)}
    return payload


@app.route("/")
def index():
    devices = _with_online_status(db.get_devices(limit=200, offset=0, search=""))
    return render_template("index.html", devices=devices, config=config, runtime=get_runtime_status())


@app.route("/health")
def health():
    payload = _health_payload()
    return jsonify(payload), (200 if payload.get("status") == "ok" else 503)


@app.route("/scan")
def scan_page():
    if config.MAINTENANCE_MODE:
        return jsonify({"status": "error", "message": "maintenance_mode"}), 503
    if config.READ_ONLY_API:
        return jsonify({"status": "error", "message": "read_only_api"}), 403
    if not _check_scan_api_key():
        return jsonify({"status": "error", "message": "API key invalide"}), 401
    if not _scan_rate_allowed():
        return jsonify({"status": "error", "message": "rate_limited"}), 429
    profile = request.args.get("profile", default=config.DEFAULT_SCAN_PROFILE, type=str)
    return jsonify(process_scan(source="manual", profile=profile))


@app.route("/api/devices")
def api_devices():
    limit = request.args.get("limit", default=config.UI_PAGE_SIZE_DEFAULT, type=int)
    offset = request.args.get("offset", default=0, type=int)
    search = request.args.get("search", default="", type=str)
    status_filter = request.args.get("status", default="all", type=str).lower()
    devices = _with_online_status(db.get_devices(limit=limit, offset=offset, search=search))
    if status_filter in {"online", "offline"}:
        devices = [d for d in devices if d.get("status") == status_filter]
    for d in devices:
        d["first_seen"] = _fmt_ts(d.get("first_seen", ""))
        d["last_seen"] = _fmt_ts(d.get("last_seen", ""))
    return jsonify({"status": "ok", "count": len(devices), "total": db.count_devices(search=search), "limit": max(1, min(int(limit), 1000)), "offset": max(0, int(offset)), "devices": devices})


@app.route("/api/device/meta", methods=["POST"])
def api_device_meta():
    if config.MAINTENANCE_MODE:
        return jsonify({"status": "error", "message": "maintenance_mode"}), 503
    if config.READ_ONLY_API:
        return jsonify({"status": "error", "message": "read_only_api"}), 403
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    mac = (data.get("mac") or "").strip()
    if not ip or not mac:
        return jsonify({"status": "error", "message": "ip et mac requis"}), 400
    db.set_device_meta(ip, mac, (data.get("tag") or "").strip(), (data.get("note") or "").strip(), db.now_iso())
    return jsonify({"status": "ok"})


@app.route("/api/device/timeline")
def api_device_timeline():
    ip = request.args.get("ip", default="", type=str).strip()
    mac = request.args.get("mac", default="", type=str).strip()
    if not ip and not mac:
        return jsonify({"status": "error", "message": "ip ou mac requis"}), 400
    events = db.get_recent_events(limit=request.args.get("limit", default=100, type=int), ip=ip, mac=mac)
    if config.EVENT_TYPES_FILTER:
        events = [e for e in events if e.get("event_type") in config.EVENT_TYPES_FILTER]
    for e in events:
        e["happened_at"] = _fmt_ts(e.get("happened_at", ""))
    return jsonify({"status": "ok", "events": events})


@app.route("/api/scan", methods=["GET", "POST"])
def api_scan():
    if config.MAINTENANCE_MODE:
        return jsonify({"status": "error", "message": "maintenance_mode"}), 503
    if config.READ_ONLY_API:
        return jsonify({"status": "error", "message": "read_only_api"}), 403
    if not _check_scan_api_key():
        return jsonify({"status": "error", "message": "API key invalide"}), 401
    if not _scan_rate_allowed():
        return jsonify({"status": "error", "message": "rate_limited"}), 429
    payload = request.get_json(silent=True) or {}
    profile = payload.get("profile") or request.args.get("profile", config.DEFAULT_SCAN_PROFILE)
    return jsonify(process_scan(source="manual", profile=str(profile)))


@app.route("/api/status")
def api_status():
    return jsonify(get_runtime_status())


@app.route("/api/scans")
def api_scans():
    scans = db.get_recent_scans(limit=request.args.get("limit", default=20, type=int))
    for s in scans:
        s["scanned_at"] = _fmt_ts(s.get("scanned_at", ""))
    return jsonify({"status": "ok", "scans": scans})


@app.route("/api/cowrie")
def api_cowrie():
    limit = request.args.get("limit", default=80, type=int)
    events = get_clean_events(limit=max(1, min(limit, 300)))
    return jsonify({"status": "ok", "events": events})


@app.route("/api/cowrie/stats")
def api_cowrie_stats():
    limit = request.args.get("limit", default=300, type=int)
    return jsonify(get_cowrie_stats(limit=max(1, min(limit, 1000))))


@app.route("/api/events")
def api_events():
    events = db.get_recent_events(limit=request.args.get("limit", default=50, type=int))
    if config.EVENT_TYPES_FILTER:
        events = [e for e in events if e.get("event_type") in config.EVENT_TYPES_FILTER]
    for e in events:
        e["happened_at"] = _fmt_ts(e.get("happened_at", ""))
    return jsonify({"status": "ok", "events": events})


@app.route("/api/export/devices")
def api_export_devices():
    if not _check_export_token():
        return jsonify({"status": "error", "message": "token export invalide"}), 401
    fmt = request.args.get("format", default="json", type=str).lower()
    rows = _with_online_status(db.get_devices(limit=config.EXPORT_MAX_ROWS, offset=0, search=""))
    if config.EXPORT_REDACT:
        for r in rows:
            r["ip"] = _mask_ip(r.get("ip", ""))
            r["mac"] = _mask_mac(r.get("mac", ""))
    if fmt == "csv":
        out = io.StringIO()
        fields = ["ip", "mac", "hostname", "alias", "first_seen", "last_seen", "status", "tag"]
        if config.EXPORT_INCLUDE_NOTES:
            fields.append("note")
        writer = csv.DictWriter(out, fieldnames=fields, delimiter=config.CSV_SEPARATOR)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fields})
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=devices.csv"})
    return jsonify({"status": "ok", "devices": rows})


@app.route("/metrics")
def metrics():
    if not config.METRICS_ENABLED:
        return Response("metrics_disabled 1\n", mimetype="text/plain")
    s = get_runtime_status()
    dbs = s.get("db_stats", {})
    lines = [
        f"nespi_total_devices {int(s.get('total_devices', 0))}",
        f"nespi_auto_scan_enabled {1 if s.get('auto_scan_enabled') else 0}",
        f"nespi_scan_api_key_enabled {1 if s.get('scan_api_key_enabled') else 0}",
        f"nespi_db_size_bytes {int(dbs.get('db_size_bytes', 0))}",
        f"nespi_event_count {int(dbs.get('event_count', 0))}",
    ]
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


def main() -> None:
    setup_logging()
    db.init_db()
    start_background_workers()
    app.run(host=config.APP_HOST, port=config.APP_PORT)


if __name__ == "__main__":
    main()
