from database import DeviceDatabase


def test_upsert_and_events(tmp_path):
    db = DeviceDatabase(str(tmp_path / "test.db"))
    db.init_db()

    ts1 = db.now_iso()
    is_new, hostname_changed = db.upsert_device("192.168.1.2", "AA:BB:CC:DD:EE:01", "host-1", ts1)
    assert is_new is True
    assert hostname_changed is False

    ts2 = db.now_iso()
    is_new, hostname_changed = db.upsert_device("192.168.1.2", "AA:BB:CC:DD:EE:01", "host-2", ts2)
    assert is_new is False
    assert hostname_changed is True

    db.log_device_event(ts2, "192.168.1.2", "AA:BB:CC:DD:EE:01", "hostname_changed", "host-1", "host-2")
    events = db.get_recent_events(limit=10)
    assert len(events) >= 1


def test_scan_history_retention(tmp_path):
    db = DeviceDatabase(str(tmp_path / "test.db"))
    db.init_db()

    for i in range(120):
      db.log_scan(db.now_iso(), "test", i, 0, 100, "ok", "")

    db.prune_scan_history(100)
    scans = db.get_recent_scans(limit=200)
    assert len(scans) == 100
