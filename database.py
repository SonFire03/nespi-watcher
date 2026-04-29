import sqlite3
from datetime import datetime
from typing import Dict, List


class DeviceDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (ip, mac)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                ON devices (last_seen)
                """
            )
            conn.commit()

    def upsert_device(self, ip: str, mac: str, hostname: str, seen_at: str) -> bool:
        """
        Retourne True si l'appareil est nouveau, sinon False.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT ip, mac FROM devices WHERE ip = ? AND mac = ?", (ip, mac)
            )
            existing = cur.fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE devices
                    SET hostname = ?, last_seen = ?
                    WHERE ip = ? AND mac = ?
                    """,
                    (hostname, seen_at, ip, mac),
                )
                conn.commit()
                return False

            conn.execute(
                """
                INSERT INTO devices (ip, mac, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ip, mac, hostname, seen_at, seen_at),
            )
            conn.commit()
            return True

    def get_all_devices(self) -> List[Dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT ip, mac, hostname, first_seen, last_seen
                FROM devices
                ORDER BY last_seen DESC
                """
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def now_iso() -> str:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
