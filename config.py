import os


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


_load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int, min_value: int = 0) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except Exception:
        value = default
    return max(min_value, value)


def _get_csv_set(name: str) -> set:
    raw = os.getenv(name, "")
    if not raw.strip():
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


class Config:
    NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = _get_int("APP_PORT", 8080, min_value=1)

    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    TELEGRAM_MODE = os.getenv("TELEGRAM_MODE", "summary").strip().lower()
    ALERT_MIN_NEW_DEVICES = _get_int("ALERT_MIN_NEW_DEVICES", 1, min_value=1)
    ALERT_COOLDOWN_SECONDS = _get_int("ALERT_COOLDOWN_SECONDS", 300, min_value=0)
    ALERT_UNKNOWN_ONLY = _get_bool("ALERT_UNKNOWN_ONLY", False)

    SCAN_TIMEOUT = _get_int("SCAN_TIMEOUT", 60, min_value=5)
    SCAN_INTERVAL_SECONDS = _get_int("SCAN_INTERVAL_SECONDS", 600, min_value=30)
    AUTO_SCAN_ENABLED = _get_bool("AUTO_SCAN_ENABLED", True)
    STARTUP_SCAN_ENABLED = _get_bool("STARTUP_SCAN_ENABLED", False)
    OFFLINE_AFTER_SECONDS = _get_int("OFFLINE_AFTER_SECONDS", 1800, min_value=60)

    SCAN_API_KEY = os.getenv("SCAN_API_KEY", "").strip()
    IGNORE_IPS = _get_csv_set("IGNORE_IPS")
    IGNORE_MACS = {m.upper() for m in _get_csv_set("IGNORE_MACS")}

    DB_PATH = os.getenv("DB_PATH", "devices.db")
    MAX_SCAN_HISTORY_ROWS = _get_int("MAX_SCAN_HISTORY_ROWS", 5000, min_value=100)
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
