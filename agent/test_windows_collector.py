"""Windows collector contract tests; safe to run on non-Windows CI too."""
import unittest
from unittest.mock import patch

from collectors import windows


class WindowsCollectorTests(unittest.TestCase):
    def test_service_inventory_reports_unavailable_off_windows(self):
        result = windows.windows_services()
        self.assertIn("available", result)
        self.assertIn("items", result)

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
