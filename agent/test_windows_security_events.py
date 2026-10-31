"""Windows Security Event Log collector tests."""
import unittest
from unittest.mock import patch

from collectors import windows


class WindowsSecurityEventTests(unittest.TestCase):
    def setUp(self):
        with windows._seen_lock:
            windows._seen_security_record_ids.clear()

    @patch("collectors.windows.subprocess.run")
    def test_parses_single_security_event(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = (
            '{"record_id":77,"event_id":4625,'
            '"time_created":"2026-10-31T10:00:00Z",'
            '"message":"An account failed to log on"}'
        )
        result = windows.collect_security_events()
        self.assertTrue(result["available"])
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["event_id"], 4625)

    def test_emits_failed_and_successful_logons_once(self):
        queued = []
        result = {
            "available": True,
            "items": [
                {"record_id": 100, "event_id": 4624, "message": "login ok"},
                {"record_id": 101, "event_id": 4625, "message": "login failed"},
            ],
        }
        count = windows.emit_security_events(
            lambda *args: queued.append(args), result
        )
        again = windows.emit_security_events(
            lambda *args: queued.append(args), result
        )
        self.assertEqual(count, 2)
        self.assertEqual(again, 0)
        self.assertEqual(len(queued), 2)
        self.assertEqual(queued[0][0], "windows_login_success")
        self.assertEqual(queued[1][0], "windows_login_failed")
        self.assertEqual(queued[1][1], "high")

    def test_permission_error_is_reported_as_unavailable(self):
        with patch("collectors.windows.subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = "Access is denied"
            result = windows.collect_security_events()
        self.assertFalse(result["available"])
        self.assertIn("Access is denied", result["reason"])


if __name__ == "__main__":
    unittest.main()
