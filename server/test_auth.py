"""Authentication and fail-closed tenant-data API tests."""
import os
import tempfile
import unittest
from pathlib import Path

_DB = tempfile.TemporaryDirectory()
os.environ["SENTINELX_AGENT_TOKEN"] = "sentinelx-auth-test-token"
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_DB.name) / "auth-test.db")
os.environ["SENTINELX_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient
from server import main

# The ingestion test module may import the app first with production defaults.
# Force insecure cookies only inside this isolated HTTP test process.
main.COOKIE_SECURE = False
client = TestClient(main.app)


class AuthApiTests(unittest.TestCase):
    def setUp(self):
        # A fresh email per test avoids order-dependent account state.
        import uuid
        self.email = "user-" + uuid.uuid4().hex[:12] + "@example.test"
        self.password = "Correct-Horse-Battery-42!"

    def test_register_me_logout_and_reject_revoked_session(self):
        response = client.post("/api/v1/auth/register", json={
            "email": self.email, "password": self.password,
            "organization_name": "Example Customer",
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIn("sentinelx_session", response.cookies)
        me = client.get("/api/v1/auth/me")
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["user"]["email"], self.email)
        self.assertEqual(me.json()["organizations"][0]["role"], "owner")
        logout = client.post("/api/v1/auth/logout")
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(client.get("/api/v1/auth/me").status_code, 401)

    def test_login_rejects_bad_password(self):
        client.post("/api/v1/auth/register", json={
            "email": self.email, "password": self.password,
            "organization_name": "Example Customer",
        })
        response = client.post("/api/v1/auth/login", json={
            "email": self.email, "password": "wrong-password",
        })
        self.assertEqual(response.status_code, 401)

    def test_unscoped_legacy_data_routes_fail_closed(self):
        response = client.get("/api/v1/hosts")
        self.assertEqual(response.status_code, 503)
        self.assertIn("tenant isolation", response.text.lower())


if __name__ == "__main__":
    unittest.main()
