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


def _get_csv_list(name: str, default: str = "") -> list:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


class Config:
    NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
    NETWORK_RANGES = _get_csv_list("NETWORK_RANGES", NETWORK_RANGE)
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = _get_int("APP_PORT", 8080, min_value=1)

    SCAN_PROFILES = _get_csv_list("SCAN_PROFILES", "quick,deep")
    DEFAULT_SCAN_PROFILE = os.getenv("DEFAULT_SCAN_PROFILE", "quick").strip().lower()
    NMAP_DEEP_PORTS = _get_int("NMAP_DEEP_PORTS", 100, min_value=1)
    MAX_CONCURRENT_NMAP = _get_int("MAX_CONCURRENT_NMAP", 1, min_value=1)

    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip()
    WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
    TELEGRAM_MODE = os.getenv("TELEGRAM_MODE", "summary").strip().lower()
    ALERT_MIN_NEW_DEVICES = _get_int("ALERT_MIN_NEW_DEVICES", 1, min_value=1)
    ALERT_COOLDOWN_SECONDS = _get_int("ALERT_COOLDOWN_SECONDS", 300, min_value=0)
    ALERT_UNKNOWN_ONLY = _get_bool("ALERT_UNKNOWN_ONLY", False)
    ALERT_SCAN_ERRORS = _get_bool("ALERT_SCAN_ERRORS", False)
    ALERT_OFFLINE_DEVICES = _get_bool("ALERT_OFFLINE_DEVICES", False)
    ALERT_IP_CHANGED = _get_bool("ALERT_IP_CHANGED", False)
    ALERT_OPEN_PORTS = _get_bool("ALERT_OPEN_PORTS", False)
    ALERT_FINGERPRINT_CHANGED = _get_bool("ALERT_FINGERPRINT_CHANGED", False)
    ALERT_BATCH_WINDOW_SECONDS = _get_int("ALERT_BATCH_WINDOW_SECONDS", 60, min_value=0)
    QUIET_HOURS = os.getenv("QUIET_HOURS", "").strip()

    SENSITIVE_PORTS = {_get_int("_tmp", 0)}
    SENSITIVE_PORTS = {int(x) for x in _get_csv_set("SENSITIVE_PORTS")} if _get_csv_set("SENSITIVE_PORTS") else {22, 23, 445, 3389}

    SCAN_TIMEOUT = _get_int("SCAN_TIMEOUT", 60, min_value=5)
    MAX_SCAN_DURATION_SECONDS = _get_int("MAX_SCAN_DURATION_SECONDS", 300, min_value=10)
    AUTO_SCAN_ENABLED = _get_bool("AUTO_SCAN_ENABLED", True)
    SCAN_INTERVAL_SECONDS = _get_int("SCAN_INTERVAL_SECONDS", 600, min_value=30)
    STARTUP_SCAN_ENABLED = _get_bool("STARTUP_SCAN_ENABLED", False)
    OFFLINE_AFTER_SECONDS = _get_int("OFFLINE_AFTER_SECONDS", 1800, min_value=60)
    OFFLINE_GRACE_PERIOD_SECONDS = _get_int("OFFLINE_GRACE_PERIOD_SECONDS", 300, min_value=0)
    NEW_DEVICE_GRACE_PERIOD_SECONDS = _get_int("NEW_DEVICE_GRACE_PERIOD_SECONDS", 120, min_value=0)

    SCAN_API_KEY = os.getenv("SCAN_API_KEY", "").strip()
    EXPORT_TOKEN = os.getenv("EXPORT_TOKEN", "").strip()
    IGNORE_IPS = _get_csv_set("IGNORE_IPS")
    IGNORE_MACS = {m.upper() for m in _get_csv_set("IGNORE_MACS")}
    ALLOWLIST_ONLY = _get_bool("ALLOWLIST_ONLY", False)
    BLOCKLIST_MACS = {m.upper() for m in _get_csv_set("BLOCKLIST_MACS")}
    BLOCKLIST_IPS = _get_csv_set("BLOCKLIST_IPS")
    SUSPECT_DEVICE_TAG = os.getenv("SUSPECT_DEVICE_TAG", "suspect").strip()
    AUTO_TAG_BY_VENDOR = _get_bool("AUTO_TAG_BY_VENDOR", False)

    KNOWN_DEVICES_FILE = os.getenv("KNOWN_DEVICES_FILE", "").strip()
    DEVICE_ALIAS_ENABLED = _get_bool("DEVICE_ALIAS_ENABLED", True)
    EVENT_TYPES_FILTER = _get_csv_set("EVENT_TYPES_FILTER")
    DEVICE_RISK_SCORE_ENABLED = _get_bool("DEVICE_RISK_SCORE_ENABLED", False)
    RISK_ALERT_THRESHOLD = _get_int("RISK_ALERT_THRESHOLD", 70, min_value=1)
    SCAN_WINDOW = os.getenv("SCAN_WINDOW", "always").strip().lower()

    AUTO_BACKUP_ENABLED = _get_bool("AUTO_BACKUP_ENABLED", False)
    BACKUP_RETENTION_DAYS = _get_int("BACKUP_RETENTION_DAYS", 14, min_value=1)
    DB_VACUUM_SCHEDULE = os.getenv("DB_VACUUM_SCHEDULE", "off").strip().lower()
    WAL_MODE = _get_bool("WAL_MODE", True)

    API_RATE_LIMIT_SCAN_PER_MIN = _get_int("API_RATE_LIMIT_SCAN_PER_MIN", 3, min_value=1)
    READ_ONLY_API = _get_bool("READ_ONLY_API", False)
    MAINTENANCE_MODE = _get_bool("MAINTENANCE_MODE", False)
    AUTH_BASIC_ENABLED = _get_bool("AUTH_BASIC_ENABLED", False)
    AUTH_USER = os.getenv("AUTH_USER", "").strip()
    AUTH_PASS_HASH = os.getenv("AUTH_PASS_HASH", "").strip()
    CORS_ALLOWED_ORIGINS = _get_csv_list("CORS_ALLOWED_ORIGINS", "")
    API_AUDIT_LOG = _get_bool("API_AUDIT_LOG", False)
    CHANGELOG_ENABLED = _get_bool("CHANGELOG_ENABLED", False)
    AUTO_UPDATE_CHECK = _get_bool("AUTO_UPDATE_CHECK", False)

    UI_THEME = os.getenv("UI_THEME", "cyber").strip().lower()
    SHOW_PRIVATE_INFO = _get_bool("SHOW_PRIVATE_INFO", True)
    UI_PAGE_SIZE_DEFAULT = _get_int("UI_PAGE_SIZE_DEFAULT", 100, min_value=10)
    UI_AUTO_REFRESH_SECONDS = _get_int("UI_AUTO_REFRESH_SECONDS", 15, min_value=5)
    TIMEZONE_DISPLAY = os.getenv("TIMEZONE_DISPLAY", "utc").strip().lower()

    HEALTH_REQUIRE_RECENT_SCAN = _get_bool("HEALTH_REQUIRE_RECENT_SCAN", False)
    HEALTH_MAX_SCAN_AGE_SECONDS = _get_int("HEALTH_MAX_SCAN_AGE_SECONDS", 1800, min_value=30)

    EXPORT_MAX_ROWS = _get_int("EXPORT_MAX_ROWS", 5000, min_value=100)
    EXPORT_INCLUDE_NOTES = _get_bool("EXPORT_INCLUDE_NOTES", True)
    CSV_SEPARATOR = os.getenv("CSV_SEPARATOR", ",") if os.getenv("CSV_SEPARATOR", ",") in {",", ";", "\t"} else ","

    DB_PATH = os.getenv("DB_PATH", "devices.db")
    MAX_SCAN_HISTORY_ROWS = _get_int("MAX_SCAN_HISTORY_ROWS", 5000, min_value=100)
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_RETENTION_DAYS = _get_int("LOG_RETENTION_DAYS", 7, min_value=1)
    CACHE_STATUS_SECONDS = _get_int("CACHE_STATUS_SECONDS", 5, min_value=1)

    PORT_SCAN_ON_NEW_DEVICE = _get_bool("PORT_SCAN_ON_NEW_DEVICE", False)
    PORT_SCAN_TOP_PORTS = _get_int("PORT_SCAN_TOP_PORTS", 20, min_value=1)
    PORT_SCAN_TIMEOUT = _get_int("PORT_SCAN_TIMEOUT", 15, min_value=3)
    DNS_REVERSE_LOOKUP = _get_bool("DNS_REVERSE_LOOKUP", False)
    VENDOR_LOOKUP_LOCAL = _get_bool("VENDOR_LOOKUP_LOCAL", False)
    DEVICE_FINGERPRINT_ENABLED = _get_bool("DEVICE_FINGERPRINT_ENABLED", True)

    AUTO_RESCAN_AFTER_ERROR = _get_bool("AUTO_RESCAN_AFTER_ERROR", False)
    RESCAN_DELAY_SECONDS = _get_int("RESCAN_DELAY_SECONDS", 30, min_value=1)
    METRICS_ENABLED = _get_bool("METRICS_ENABLED", True)
    NOTIFY_ON_FIRST_BOOT = _get_bool("NOTIFY_ON_FIRST_BOOT", False)
    HEARTBEAT_ENABLED = _get_bool("HEARTBEAT_ENABLED", False)
    HEARTBEAT_INTERVAL_MIN = _get_int("HEARTBEAT_INTERVAL_MIN", 60, min_value=1)
    SCAN_JITTER_SECONDS = _get_int("SCAN_JITTER_SECONDS", 0, min_value=0)
    RANDOMIZE_NETWORK_ORDER = _get_bool("RANDOMIZE_NETWORK_ORDER", False)
    DEVICE_INACTIVE_DAYS_PURGE = _get_int("DEVICE_INACTIVE_DAYS_PURGE", 0, min_value=0)
    EVENT_RETENTION_DAYS = _get_int("EVENT_RETENTION_DAYS", 0, min_value=0)
    SCAN_RETENTION_DAYS = _get_int("SCAN_RETENTION_DAYS", 0, min_value=0)
    DB_BACKUP_BEFORE_UPGRADE = _get_bool("DB_BACKUP_BEFORE_UPGRADE", True)
    DRY_RUN_SCAN = _get_bool("DRY_RUN_SCAN", False)
    SAFE_MODE = _get_bool("SAFE_MODE", False)
    TZ_OVERRIDE = os.getenv("TZ_OVERRIDE", "").strip()
    TIMESTAMP_FORMAT = os.getenv("TIMESTAMP_FORMAT", "iso").strip().lower()
    EXPORT_REDACT = _get_bool("EXPORT_REDACT", False)
    AUDIT_HASH_CHAIN = _get_bool("AUDIT_HASH_CHAIN", False)
    MAX_EVENT_PER_DEVICE_PER_HOUR = _get_int("MAX_EVENT_PER_DEVICE_PER_HOUR", 20, min_value=1)
    BLOCKLIST_AUTO_EXPIRE_DAYS = _get_int("BLOCKLIST_AUTO_EXPIRE_DAYS", 0, min_value=0)
    REMOTE_IP_TRUST_HEADER = os.getenv("REMOTE_IP_TRUST_HEADER", "").strip()
    SERVICE_BANNER = os.getenv("SERVICE_BANNER", "NESPi Watcher").strip()
    UI_COMPACT_MODE = _get_bool("UI_COMPACT_MODE", False)
