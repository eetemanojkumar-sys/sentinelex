"""Tests for the durable telemetry outbox."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from outbox import acknowledge_batch, enqueue_batch, get_pending_batch, reject_batch


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "queue.sqlite3")
        self.env = patch.dict(os.environ, {"SENTINELX_QUEUE_PATH": self.db_path})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def test_batch_survives_reopen_and_is_acknowledged(self):
        payload = {
            "batch_id": "batch-001",
            "host_id": "host-a",
            "metrics": {"cpu_percent": 12.5},
            "events": [{"event_type": "test"}],
        }
        enqueue_batch(payload)
        self.assertEqual(get_pending_batch(), payload)
        acknowledge_batch("batch-001")
        self.assertIsNone(get_pending_batch())

    def test_log_records_remain_immutable_until_batch_acknowledgement(self):
        payload = {
            "batch_id": "batch-with-logs",
            "host_id": "host-a",
            "metrics": {"cpu_percent": 91.0},
            "events": [],
            "logs": [
                {
                    "source": "systemd",
                    "channel": "journal",
                    "severity": "high",
                    "message": "service failed",
                    "record_id": "cursor-123",
                }
            ],
        }
        expected = {
            "batch_id": "batch-with-logs",
            "host_id": "host-a",
            "metrics": {"cpu_percent": 91.0},
            "events": [],
            "logs": [
                {
                    "source": "systemd",
                    "channel": "journal",
                    "severity": "high",
                    "message": "service failed",
                    "record_id": "cursor-123",
                }
            ],
        }
        enqueue_batch(payload)
        payload["logs"].clear()
        payload["metrics"]["cpu_percent"] = 0

        # Repeated reads model retry attempts after a lost acknowledgement.
        self.assertEqual(get_pending_batch(), expected)
        self.assertEqual(get_pending_batch(), expected)

        acknowledge_batch("batch-with-logs")
        self.assertIsNone(get_pending_batch())

    def test_permanent_failure_moves_batch_to_dead_letter(self):
        payload = {"batch_id": "dead-letter-1", "events": [{"message": "bad"}]}
        enqueue_batch(payload)
        reject_batch("dead-letter-1", "HTTP 422")
        self.assertIsNone(get_pending_batch())
        import sqlite3
        connection = sqlite3.connect(self.db_path)
        try:
            row = connection.execute(
                "SELECT reason FROM dead_letter_batches WHERE batch_id = ?",
                ("dead-letter-1",),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row[0], "HTTP 422")

    def test_duplicate_enqueue_does_not_replace_original_payload(self):
        original = {"batch_id": "batch-002", "value": 1}
        enqueue_batch(original)
        enqueue_batch({"batch_id": "batch-002", "value": 2})
        self.assertEqual(get_pending_batch(), original)


if __name__ == "__main__":
    unittest.main()
