"""Unit tests for bounded cross-platform log collection and redaction."""
import json
import subprocess
import unittest
from unittest.mock import patch

from collectors.common import redact_log_message
from collectors.linux import collect_logs as collect_linux_logs
from collectors.windows import collect_logs as collect_windows_logs


class LogCollectorTests(unittest.TestCase):
    def test_redacts_common_credentials(self):
        message = "password=hunter2 token:abc Bearer xyz AKIA1234567890ABCDEF"
        cleaned = redact_log_message(message)
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("abc", cleaned)
        self.assertNotIn("xyz", cleaned)
        self.assertIn("[REDACTED_AWS_ACCESS_KEY]", cleaned)

    @patch("collectors.linux.subprocess.run")
    def test_linux_journal_records_are_normalized(self, run):
        item = {
            "__REALTIME_TIMESTAMP": "1794931200000000",
            "__CURSOR": "s=cursor-123",
            "PRIORITY": "3",
            "SYSLOG_IDENTIFIER": "sshd",
            "_SYSTEMD_UNIT": "ssh.service",
            "_PID": "123",
            "MESSAGE": "authentication failed password=topsecret",
        }
        run.return_value = subprocess.CompletedProcess(
            args=["journalctl"], returncode=0,
            stdout=json.dumps(item) + "\n", stderr="",
        )
        records = collect_linux_logs()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source"], "sshd")
        self.assertEqual(records[0]["severity"], "high")
        self.assertEqual(records[0]["record_id"], "s=cursor-123")
        self.assertNotIn("topsecret", records[0]["message"])

    @patch("collectors.windows.subprocess.run")
    def test_windows_event_records_are_normalized(self, run):
        item = {
            "source": "Service Control Manager",
            "channel": "System",
            "severity": 2,
            "event_id": 7000,
            "record_id": 456,
            "message": "Service failed token=secret-value",
            "timestamp": "2026-11-17T10:00:00Z",
            "details": {"level": "Error"},
        }
        run.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"], returncode=0,
            stdout=json.dumps([item]), stderr="",
        )
        records = collect_windows_logs()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["channel"], "System")
        self.assertEqual(records[0]["severity"], "high")
        self.assertEqual(records[0]["event_id"], "7000")
        self.assertNotIn("secret-value", records[0]["message"])


if __name__ == "__main__":
    unittest.main()
