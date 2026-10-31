"""Regression tests for the self-hosted API entry points."""
import os
import tempfile
import unittest
from pathlib import Path

_DB = tempfile.TemporaryDirectory()
os.environ.setdefault("SENTINELX_AGENT_TOKEN", "sentinelx-selfhosted-test-token")
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_DB.name) / "selfhosted-test.db")

from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


class SelfHostedApiTests(unittest.TestCase):
    def test_health_is_available(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "ok")

    def test_root_redirects_to_dashboard(self):
        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/dashboard/")

    def test_monitoring_routes_are_enabled(self):
        for path in ("/api/v1/hosts", "/api/v1/events", "/api/v1/summary"):
            response = client.get(path)
            self.assertEqual(response.status_code, 200, f"{path}: {response.text}")

    def test_telemetry_requires_agent_token(self):
        payload = {"host_id":"test-host","metrics":{"cpu_percent":12.5}}
        response = client.post("/api/v1/telemetry", json=payload)
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
