import os
import sqlite3
from datetime import datetime, timezone
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
            conn.execute("PRAGMA journal_mode=WAL")
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

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_meta (
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    tag TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (ip, mac)
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_state (
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    fingerprint TEXT NOT NULL DEFAULT '',
                    open_ports TEXT NOT NULL DEFAULT '',
                    last_port_scan TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (ip, mac)
                )
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history (scanned_at DESC)")

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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_device_events_happened_at ON device_events (happened_at DESC)")
            conn.commit()

    def run_vacuum(self) -> None:
        with self._connect() as conn:
            conn.execute("VACUUM")
            conn.commit()

    def get_device(self, ip: str, mac: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ip, mac, hostname, first_seen, last_seen FROM devices WHERE ip = ? AND mac = ?",
                (ip, mac),
            ).fetchone()
            return dict(row) if row else None

    def get_recent_devices_by_mac(self, mac: str, limit: int = 2) -> List[Dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT ip, mac, hostname, first_seen, last_seen FROM devices WHERE mac = ? ORDER BY last_seen DESC LIMIT ?",
                (mac, max(1, int(limit))),
            )
            return [dict(row) for row in cur.fetchall()]

    def upsert_device(self, ip: str, mac: str, hostname: str, seen_at: str) -> Tuple[bool, bool]:
        with self._connect() as conn:
            existing = conn.execute("SELECT hostname FROM devices WHERE ip = ? AND mac = ?", (ip, mac)).fetchone()
            if existing:
                changed = existing["hostname"] != hostname
                conn.execute("UPDATE devices SET hostname = ?, last_seen = ? WHERE ip = ? AND mac = ?", (hostname, seen_at, ip, mac))
                conn.commit()
                return False, changed
            conn.execute("INSERT INTO devices (ip, mac, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)", (ip, mac, hostname, seen_at, seen_at))
            conn.commit()
            return True, False

    def set_device_meta(self, ip: str, mac: str, tag: str, note: str, updated_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO device_meta (ip, mac, tag, note, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip, mac)
                DO UPDATE SET tag=excluded.tag, note=excluded.note, updated_at=excluded.updated_at
                """,
                (ip, mac, tag[:64], note[:500], updated_at),
            )
            conn.commit()

    def get_device_state(self, ip: str, mac: str) -> Dict:
        with self._connect() as conn:
            row = conn.execute("SELECT fingerprint, open_ports, last_port_scan FROM device_state WHERE ip = ? AND mac = ?", (ip, mac)).fetchone()
            return dict(row) if row else {"fingerprint": "", "open_ports": "", "last_port_scan": ""}

    def set_device_state(self, ip: str, mac: str, fingerprint: str, open_ports: str, last_port_scan: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO device_state (ip, mac, fingerprint, open_ports, last_port_scan)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip, mac)
                DO UPDATE SET fingerprint=excluded.fingerprint, open_ports=excluded.open_ports, last_port_scan=excluded.last_port_scan
                """,
                (ip, mac, fingerprint[:256], open_ports[:1000], last_port_scan),
            )
            conn.commit()

    def log_device_event(self, happened_at: str, ip: str, mac: str, event_type: str, old_value: str = "", new_value: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO device_events (happened_at, ip, mac, event_type, old_value, new_value) VALUES (?, ?, ?, ?, ?, ?)",
                (happened_at, ip, mac, event_type, old_value, new_value),
            )
            conn.commit()

    def get_recent_events(self, limit: int = 50, ip: str = "", mac: str = "") -> List[Dict]:
        query = "SELECT id, happened_at, ip, mac, event_type, old_value, new_value FROM device_events"
        params: List = []
        conds = []
        if ip:
            conds.append("ip = ?")
            params.append(ip)
        if mac:
            conds.append("mac = ?")
            params.append(mac)
        if conds:
            query += " WHERE " + " AND ".join(conds)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def count_events_for_device_since(self, ip: str, mac: str, since_iso: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM device_events WHERE ip = ? AND mac = ? AND happened_at >= ?",
                (ip, mac, since_iso),
            ).fetchone()
            return int(row["c"]) if row else 0

    def get_devices(self, limit: int = 200, offset: int = 0, search: str = "") -> List[Dict]:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        search = (search or "").strip()
        query = (
            "SELECT d.ip, d.mac, d.hostname, d.first_seen, d.last_seen, "
            "COALESCE(m.tag, '') AS tag, COALESCE(m.note, '') AS note "
            "FROM devices d LEFT JOIN device_meta m ON d.ip = m.ip AND d.mac = m.mac"
        )
        params: List = []
        if search:
            query += " WHERE d.ip LIKE ? OR d.mac LIKE ? OR d.hostname LIKE ? OR m.tag LIKE ? OR m.note LIKE ?"
            token = f"%{search}%"
            params.extend([token, token, token, token, token])
        query += " ORDER BY d.last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def count_devices(self, search: str = "") -> int:
        search = (search or "").strip()
        query = "SELECT COUNT(*) AS c FROM devices d LEFT JOIN device_meta m ON d.ip = m.ip AND d.mac = m.mac"
        params: List = []
        if search:
            query += " WHERE d.ip LIKE ? OR d.mac LIKE ? OR d.hostname LIKE ? OR m.tag LIKE ? OR m.note LIKE ?"
            token = f"%{search}%"
            params.extend([token, token, token, token, token])
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
            return int(row["c"]) if row else 0

    def log_scan(self, scanned_at: str, source: str, scanned_count: int, new_count: int, duration_ms: int, status: str, message: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_history (scanned_at, source, scanned_count, new_count, duration_ms, status, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scanned_at, source, scanned_count, new_count, duration_ms, status, message),
            )
            conn.commit()

    def prune_scan_history(self, max_rows: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history WHERE id NOT IN (SELECT id FROM scan_history ORDER BY id DESC LIMIT ?)", (max(100, int(max_rows)),))
            conn.commit()

    def get_last_scan(self) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT scanned_at, source, scanned_count, new_count, duration_ms, status, message FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def get_recent_scans(self, limit: int = 20) -> List[Dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT scanned_at, source, scanned_count, new_count, duration_ms, status, message FROM scan_history ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 200)),)).fetchall()]

    def get_db_stats(self) -> Dict:
        with self._connect() as conn:
            device_count = int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
            scan_count = int(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0])
            event_count = int(conn.execute("SELECT COUNT(*) FROM device_events").fetchone()[0])
        size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {"db_size_bytes": size, "devices_count": device_count, "scan_history_count": scan_count, "event_count": event_count}

    def purge_inactive_devices(self, cutoff_iso: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff_iso,))
            conn.execute("DELETE FROM device_meta WHERE (ip, mac) NOT IN (SELECT ip, mac FROM devices)")
            conn.execute("DELETE FROM device_state WHERE (ip, mac) NOT IN (SELECT ip, mac FROM devices)")
            conn.commit()

    def purge_old_events(self, cutoff_iso: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM device_events WHERE happened_at < ?", (cutoff_iso,))
            conn.commit()

    def purge_old_scans(self, cutoff_iso: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history WHERE scanned_at < ?", (cutoff_iso,))
            conn.commit()

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
