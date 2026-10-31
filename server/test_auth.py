"""Administrator authentication and per-agent enrollment integration tests."""
import os
import tempfile
import unittest
from pathlib import Path

_DB = tempfile.TemporaryDirectory()
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_DB.name) / "sentinelx-auth.db")
os.environ["SENTINELX_ADMIN_USERNAME"] = "admin"
os.environ["SENTINELX_ADMIN_PASSWORD"] = "Test-Admin-Password-123!"
os.environ["SENTINELX_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


class SecurityApiTests(unittest.TestCase):
    def setUp(self):
        client.cookies.clear()

    def login(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "admin", "password": "Test-Admin-Password-123!"
        })
        self.assertEqual(response.status_code, 200, response.text)

    def test_monitoring_api_requires_admin_session(self):
        self.assertEqual(client.get("/api/v1/hosts").status_code, 401)
        self.login()
        self.assertEqual(client.get("/api/v1/hosts").status_code, 200)

    def test_dashboard_redirects_to_login(self):
        response = client.get("/dashboard/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_agent_enrollment_is_single_use_and_revoke_works(self):
        self.login()
        token_response = client.post("/api/v1/admin/agents/enrollment-tokens", json={"expires_minutes": 30})
        self.assertEqual(token_response.status_code, 200, token_response.text)
        enrollment_token = token_response.json()["enrollment_token"]
        enrolled = client.post("/api/v1/agents/enroll", json={
            "enrollment_token": enrollment_token, "host_id": "host-01"
        })
        self.assertEqual(enrolled.status_code, 200, enrolled.text)
        agent_token = enrolled.json()["agent_token"]
        replay = client.post("/api/v1/agents/enroll", json={
            "enrollment_token": enrollment_token, "host_id": "host-02"
        })
        self.assertEqual(replay.status_code, 401)
        payload = {"host_id": "host-01", "metrics": {"cpu_percent": 2}}
        accepted = client.post("/api/v1/telemetry", json=payload,
                               headers={"X-Agent-Token": agent_token})
        self.assertEqual(accepted.status_code, 202, accepted.text)
        wrong_host = client.post("/api/v1/telemetry",
                                 json={"host_id": "host-02", "metrics": {}},
                                 headers={"X-Agent-Token": agent_token})
        self.assertEqual(wrong_host.status_code, 401)
        agents = client.get("/api/v1/admin/agents").json()
        credential_id = next(item["id"] for item in agents if item["host_id"] == "host-01")
        revoked = client.post(f"/api/v1/admin/agents/{credential_id}/revoke")
        self.assertEqual(revoked.status_code, 200)
        denied = client.post("/api/v1/telemetry", json=payload,
                             headers={"X-Agent-Token": agent_token})
        self.assertEqual(denied.status_code, 401)

    def test_invalid_admin_password_is_rejected(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "admin", "password": "wrong"
        })
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
