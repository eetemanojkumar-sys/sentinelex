"""Windows collector contract tests; safe to run on non-Windows CI too."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psutil
from collectors import windows


class WindowsCollectorTests(unittest.TestCase):
    def test_service_inventory_reports_unavailable_off_windows(self):
        if not hasattr(psutil, "win_service_iter"):
            result = windows.windows_services()
            self.assertFalse(result["available"])
            self.assertEqual(result["items"], [])

    def test_service_inventory_maps_windows_service_fields(self):
        service = SimpleNamespace(as_dict=lambda: {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "status": "running",
            "start_type": "automatic",
            "username": "LocalSystem",
            "pid": 123,
        })
        with patch.object(psutil, "win_service_iter", return_value=[service], create=True):
            result = windows.windows_services()
        self.assertTrue(result["available"])
        self.assertEqual(result["items"][0]["name"], "Spooler")
        self.assertEqual(result["items"][0]["status"], "running")

    @patch("collectors.windows.subprocess.run")
    def test_defender_status_parses_powershell_json(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = (
            '{"AntivirusEnabled":true,'
            '"RealTimeProtectionEnabled":true,'
            '"AntivirusSignatureLastUpdated":"2026-10-31T10:00:00Z"}'
        )
        result = windows.defender_status()
        self.assertTrue(result["available"])
        self.assertTrue(result["antivirus_enabled"])
        self.assertTrue(result["real_time_protection_enabled"])

    @patch("collectors.windows.subprocess.run")
    def test_defender_status_does_not_claim_false_when_unavailable(self, run):
        run.side_effect = FileNotFoundError("powershell.exe not found")
        result = windows.defender_status()
        self.assertFalse(result["available"])


if __name__ == "__main__":
    unittest.main()
