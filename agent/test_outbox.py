"""Tests for the durable telemetry outbox."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from outbox import acknowledge_batch, enqueue_batch, get_pending_batch


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

    def test_duplicate_enqueue_does_not_replace_original_payload(self):
        original = {"batch_id": "batch-002", "value": 1}
        enqueue_batch(original)
        enqueue_batch({"batch_id": "batch-002", "value": 2})
        self.assertEqual(get_pending_batch(), original)


if __name__ == "__main__":
    unittest.main()
