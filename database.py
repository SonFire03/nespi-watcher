import sqlite3
from datetime import datetime
from typing import Dict, List, Optional


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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    scanned_count INTEGER NOT NULL,
                    new_count INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at
                ON scan_history (scanned_at DESC)
                """
            )
            conn.commit()

    def upsert_device(self, ip: str, mac: str, hostname: str, seen_at: str) -> bool:
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

    def count_devices(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) AS c FROM devices")
            row = cur.fetchone()
            return int(row["c"]) if row else 0

    def log_scan(
        self,
        scanned_at: str,
        source: str,
        scanned_count: int,
        new_count: int,
        duration_ms: int,
        status: str,
        message: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_history (
                    scanned_at, source, scanned_count, new_count, duration_ms, status, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scanned_at, source, scanned_count, new_count, duration_ms, status, message),
            )
            conn.commit()

    def get_last_scan(self) -> Optional[Dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT scanned_at, source, scanned_count, new_count, duration_ms, status, message
                FROM scan_history
                ORDER BY id DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_recent_scans(self, limit: int = 20) -> List[Dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT scanned_at, source, scanned_count, new_count, duration_ms, status, message
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def now_iso() -> str:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
