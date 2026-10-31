"""Regression test for idempotent ingestion using a per-agent credential."""
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DB = tempfile.TemporaryDirectory()
os.environ["SENTINELX_ADMIN_PASSWORD"] = "Test-Admin-Password-123!"
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_TEST_DB.name) / "ingestion-test.db")

from server import main


class TelemetryIngestionTests(unittest.TestCase):
    def test_replayed_batch_is_acknowledged_without_duplicate_writes(self):
        token = main.generate_secret() if hasattr(main, "generate_secret") else "test-agent-token"
        with main.SessionLocal() as db:
            db.add(main.AgentCredential(id="test-credential", host_id="test-host-01",
                                        token_hash=main.hash_secret(token)))
            db.commit()
            payload = main.TelemetryIn(
                host_id="test-host-01", batch_id="test-batch-0001", sequence=1,
                agent=main.AgentInfo(version="test", platform="Linux", architecture="x86_64"),
                metrics={"hostname": "test-host", "cpu_percent": 12.5},
                events=[main.EventIn(event_type="test_event", severity="low", message="Test event")],
            )
            first = main.ingest(payload, token, db)
            duplicate = main.ingest(payload, token, db)
            self.assertTrue(first["accepted"])
            self.assertFalse(first.get("duplicate", False))
            self.assertTrue(duplicate["accepted"])
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(db.query(main.Telemetry).filter_by(host_id="test-host-01").count(), 1)
            self.assertEqual(db.query(main.SecurityEvent).filter_by(host_id="test-host-01").count(), 1)
            self.assertEqual(db.query(main.IngestedBatch).filter_by(host_id="test-host-01").count(), 1)


if __name__ == "__main__":
    unittest.main()
