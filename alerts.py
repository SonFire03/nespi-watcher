import logging
from typing import Optional

import requests


logger = logging.getLogger(__name__)


def send_telegram_alert(bot_token: str, chat_id: str, message: str, timeout: int = 8) -> bool:
    if not bot_token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
    }

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        if response.ok:
            return True
        logger.warning("Telegram API a répondu avec un code non-OK: %s", response.status_code)
        return False
    except Exception as exc:
        logger.warning("Erreur envoi Telegram: %s", exc)
        return False
