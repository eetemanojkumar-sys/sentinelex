import os
import tempfile

_db_file = tempfile.NamedTemporaryFile(prefix="sentinelx-test-", suffix=".db", delete=False)
_db_file.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _db_file.name
os.environ["SENTINELX_AGENT_TOKEN"] = "test-bootstrap-token"
os.environ["SENTINELX_ADMIN_TOKEN"] = "test-admin-token"
os.environ["SENTINELX_HISTORY_INTERVAL_SECONDS"] = "300"

from fastapi.testclient import TestClient
from server.main import app, SessionLocal, Telemetry

client = TestClient(app)


def test_enroll_telemetry_pagination_and_revoke():
    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-Agent-Token": "test-bootstrap-token"},
        json={
            "hostname": "test-linux-01",
            "os_name": "Linux",
            "machine_id": "12345678-test-machine",
        },
    )
    assert enrollment.status_code == 201
    identity = enrollment.json()
    assert identity["agent_id"]
    assert identity["host_id"]
    assert identity["agent_token"]

    payload = {
        "host_id": identity["host_id"],
        "metrics": {
            "hostname": "test-linux-01",
            "cpu_percent": 7.5,
            "memory": {"percent": 40.0},
            "disk": {"/": {"percent": 50.0}},
            "processes": [{"pid": 1}],
        },
        "events": [],
    }
    headers = {"X-Agent-Token": identity["agent_token"]}
    first = client.post("/api/v1/telemetry", headers=headers, json=payload)
    second = client.post("/api/v1/telemetry", headers=headers, json=payload)
    assert first.status_code == 202
    assert second.status_code == 202

    hosts = client.get("/api/v1/hosts?limit=10&offset=0")
    assert hosts.status_code == 200
    assert hosts.headers["X-Total-Count"] == "1"
    assert hosts.json()[0]["host_id"] == identity["host_id"]

    with SessionLocal() as db:
        history_rows = db.query(Telemetry).filter_by(host_id=identity["host_id"]).count()
        assert history_rows == 1

    wrong_host = dict(payload, host_id="spoofed-host")
    assert client.post("/api/v1/telemetry", headers=headers, json=wrong_host).status_code == 403

    revoke = client.post(
        f"/api/v1/admin/agents/{identity['agent_id']}/revoke",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert revoke.status_code == 200
    assert client.post("/api/v1/telemetry", headers=headers, json=payload).status_code == 401
