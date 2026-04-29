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
        # Le chargement .env ne doit jamais bloquer l'application.
        pass


_load_dotenv()


class Config:
    NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.getenv("APP_PORT", "8080"))
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "60"))
    DB_PATH = os.getenv("DB_PATH", "devices.db")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
