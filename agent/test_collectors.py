"""Linux collector rule tests; platform-independent and safe on Windows CI."""
import unittest
from unittest.mock import patch

from collectors import linux


class LinuxCollectorTests(unittest.TestCase):
    def test_preserves_shared_metric_schema_and_adds_antivirus(self):
        base = {
            "hostname": "test-host",
            "platform": "test-platform",
            "os": {"system": "Linux"},
            "boot_time": 1000.0,
            "uptime_seconds": 100.0,
            "cpu_percent": 3.5,
            "cpu_count_logical": 2,
            "memory": {"total_bytes": 1024, "available_bytes": 512, "percent": 50.0},
            "swap": {"total_bytes": 0, "used_bytes": 0, "free_bytes": 0, "percent": 0.0},
            "disk": {},
            "network_interfaces": {},
            "temperatures": {},
            "process_count": 0,
            "processes": [],
            "listening_ports": [],
        }
        with patch.object(linux, "collect_base_metrics", return_value=base), \
             patch.object(linux, "antivirus_status", return_value={"clamd": False}):
            metrics = linux.collect_metrics(lambda *args, **kwargs: None, {})

        self.assertEqual(metrics["cpu_percent"], 3.5)
        self.assertEqual(metrics["memory"]["percent"], 50.0)
        self.assertEqual(metrics["process_count"], 0)
        self.assertEqual(metrics["antivirus"], {"clamd": False})

    def test_disk_alert_thresholds_are_transition_based(self):
        base = {
            "disk": {
                "/data": {"percent": 85.0, "filesystem": "ext4"},
                "/snap": {"percent": 99.0, "filesystem": "squashfs"},
            }
        }
        events = []
        state = {}
        with patch.object(linux, "collect_base_metrics", return_value=base), \
             patch.object(linux, "antivirus_status", return_value={}):
            linux.collect_metrics(lambda *args: events.append(args), state)
            linux.collect_metrics(lambda *args: events.append(args), state)

        self.assertEqual(state["/data"], "warning")
        self.assertNotIn("/snap", state)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "disk_warning")


if __name__ == "__main__":
    unittest.main()
