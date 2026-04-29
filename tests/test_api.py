import os

os.environ["DB_PATH"] = "/tmp/nespi_watcher_test_api.db"
os.environ["AUTO_SCAN_ENABLED"] = "false"
os.environ["SCAN_API_KEY"] = "secret"

from app import app, db  # noqa: E402


def setup_module(module):
    db.init_db()


def test_api_scan_requires_key():
    client = app.test_client()
    resp = client.get("/api/scan")
    assert resp.status_code == 401


def test_api_status_ok():
    client = app.test_client()
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
