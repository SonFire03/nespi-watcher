import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple


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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices (ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices (mac)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices (hostname)")

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
                "CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at DESC)"
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    happened_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_device_events_happened_at ON device_events (happened_at DESC)"
            )
            conn.commit()

    def get_device(self, ip: str, mac: str) -> Optional[Dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT ip, mac, hostname, first_seen, last_seen FROM devices WHERE ip = ? AND mac = ?",
                (ip, mac),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def upsert_device(self, ip: str, mac: str, hostname: str, seen_at: str) -> Tuple[bool, bool]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT ip, mac, hostname FROM devices WHERE ip = ? AND mac = ?", (ip, mac)
            )
            existing = cur.fetchone()

            if existing:
                hostname_changed = existing["hostname"] != hostname
                conn.execute(
                    "UPDATE devices SET hostname = ?, last_seen = ? WHERE ip = ? AND mac = ?",
                    (hostname, seen_at, ip, mac),
                )
                conn.commit()
                return False, hostname_changed

            conn.execute(
                """
                INSERT INTO devices (ip, mac, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ip, mac, hostname, seen_at, seen_at),
            )
            conn.commit()
            return True, False

    def log_device_event(
        self,
        happened_at: str,
        ip: str,
        mac: str,
        event_type: str,
        old_value: str = "",
        new_value: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO device_events (happened_at, ip, mac, event_type, old_value, new_value)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (happened_at, ip, mac, event_type, old_value, new_value),
            )
            conn.commit()

    def get_devices(self, limit: int = 200, offset: int = 0, search: str = "") -> List[Dict]:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        search = (search or "").strip()

        query = "SELECT ip, mac, hostname, first_seen, last_seen FROM devices"
        params: List = []

        if search:
            query += " WHERE ip LIKE ? OR mac LIKE ? OR hostname LIKE ?"
            token = f"%{search}%"
            params.extend([token, token, token])

        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._connect() as conn:
            cur = conn.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    def count_devices(self, search: str = "") -> int:
        search = (search or "").strip()
        query = "SELECT COUNT(*) AS c FROM devices"
        params: List = []

        if search:
            query += " WHERE ip LIKE ? OR mac LIKE ? OR hostname LIKE ?"
            token = f"%{search}%"
            params.extend([token, token, token])

        with self._connect() as conn:
            cur = conn.execute(query, params)
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

    def prune_scan_history(self, max_rows: int) -> None:
        max_rows = max(100, int(max_rows))
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM scan_history
                WHERE id NOT IN (
                    SELECT id FROM scan_history ORDER BY id DESC LIMIT ?
                )
                """,
                (max_rows,),
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
                (max(1, min(int(limit), 200)),),
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def now_iso() -> str:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
