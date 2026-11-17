"""Integration test for authenticated, idempotent telemetry ingestion."""
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DB = tempfile.TemporaryDirectory()
os.environ["SENTINELX_AGENT_TOKEN"] = "sentinelx-test-token"
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(_TEST_DB.name) / "ingestion-test.db")

from server import main


class TelemetryIngestionTests(unittest.TestCase):
    def test_bootstrap_token_cannot_ingest_without_explicit_legacy_override(self):
        from fastapi import HTTPException
        with main.SessionLocal() as db:
            with self.assertRaises(HTTPException):
                main.authenticate_agent("sentinelx-test-token", db)

    def test_replayed_batch_is_acknowledged_without_duplicate_writes(self):
        payload = main.TelemetryIn(
            host_id="test-host-01",
            batch_id="test-batch-0001",
            sequence=1,
            agent={
                "version": "test",
                "platform": "Linux",
                "architecture": "x86_64",
            },
            metrics={"hostname": "test-host", "cpu_percent": 12.5, "services": {"available": True, "items": [{"name": "nginx.service", "status": "active"}]}, "processes": [{"pid": 1, "name": "systemd"}]},
            events=[
                main.EventIn(
                    event_type="test_event",
                    severity="low",
                    message="Test event",
                )
            ],
        )

        with main.SessionLocal() as db:
            db.add(main.AgentCredential(agent_id="test-agent", host_id="test-host-01", hostname="test-host", os_name="Linux", token_hash=main.token_digest("sentinelx-test-token"), revoked=False))
            db.commit()
            first = main.ingest(payload, "sentinelx-test-token", db)
            duplicate = main.ingest(payload, "sentinelx-test-token", db)

            self.assertTrue(first["accepted"])
            self.assertFalse(first.get("duplicate", False))
            self.assertTrue(duplicate["accepted"])
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(db.query(main.Telemetry).filter_by(host_id="test-host-01").count(), 1)
            self.assertEqual(db.query(main.SecurityEvent).filter_by(host_id="test-host-01").count(), 1)
            self.assertEqual(db.query(main.IngestedBatch).filter_by(host_id="test-host-01").count(), 1)
            self.assertEqual(db.query(main.ServiceStateHistory).filter_by(host_id="test-host-01").count(), 1)
            changed = main.TelemetryIn(host_id="test-host-01", batch_id="test-batch-0002", sequence=2, collected_at=main.utcnow(), metrics={"services": {"items": [{"name": "nginx.service", "status": "failed"}]}}, events=[])
            main.ingest(changed, "sentinelx-test-token", db)
            self.assertEqual(db.query(main.ServiceStateHistory).filter_by(host_id="test-host-01").count(), 2)
            history = main.service_history("test-host-01", None, None, 500, True, db)
            processes = main.process_history("test-host-01", None, None, 100, True, db)
            self.assertEqual(processes["count"], 1)
            self.assertEqual([item["state"] for item in history["items"]], ["active", "failed"])


if __name__ == "__main__":
    unittest.main()
