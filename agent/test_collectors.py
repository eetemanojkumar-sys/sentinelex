"""Unit tests for the Linux telemetry collector.

Run from the repository root with:
    cd agent && python -m unittest -v test_collectors
"""
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from collectors import common, linux


class LinuxCollectorTests(unittest.TestCase):
    @patch.object(linux, "antivirus_status", return_value={"clamd": False})
    @patch.object(common.psutil, "cpu_percent", return_value=3.5)
    @patch.object(common.psutil, "boot_time", return_value=1000.0)
    @patch.object(common.psutil, "virtual_memory")
    @patch.object(common.psutil, "disk_partitions", return_value=[])
    @patch.object(common.psutil, "process_iter", return_value=[])
    @patch.object(common.psutil, "net_connections", return_value=[])
    @patch.object(common.psutil, "sensors_temperatures", return_value={}, create=True)
    def test_preserves_legacy_metric_schema(
        self, _temps, _connections, _processes, _partitions, virtual_memory,
        _boot, _cpu, _antivirus
    ):
        virtual_memory.return_value = SimpleNamespace(
            total=1024, available=512, percent=50.0
        )
        metrics = linux.collect_metrics(lambda *args, **kwargs: None, {})
        expected = {
            "hostname", "platform", "os", "boot_time", "uptime_seconds",
            "cpu_percent", "cpu_count_logical", "memory", "swap", "disk",
            "network_interfaces", "temperatures", "process_count",
            "processes", "listening_ports", "antivirus",
        }
        self.assertEqual(set(metrics), expected)
        self.assertEqual(metrics["cpu_percent"], 3.5)
        self.assertEqual(metrics["memory"]["percent"], 50.0)
        self.assertEqual(metrics["process_count"], 0)

    def test_disk_alert_thresholds_are_transition_based(self):
        disk_state = {}
        events = []
        fake_partition = SimpleNamespace(mountpoint="/data", fstype="ext4")
        fake_usage = SimpleNamespace(
            total=100, used=85, free=15, percent=85.0
        )
        with patch.object(common.psutil, "disk_partitions", return_value=[fake_partition]), \
             patch.object(common.psutil, "disk_usage", return_value=fake_usage), \
             patch.object(common.psutil, "process_iter", return_value=[]), \
             patch.object(common.psutil, "net_connections", return_value=[]), \
             patch.object(common.psutil, "sensors_temperatures", return_value={}, create=True), \
             patch.object(common.psutil, "virtual_memory",
                          return_value=SimpleNamespace(total=100, available=50, percent=50)), \
             patch.object(common.psutil, "boot_time", return_value=1000.0), \
             patch.object(common.psutil, "cpu_percent", return_value=1.0), \
             patch.object(linux, "antivirus_status", return_value={}):
            linux.collect_metrics(lambda *args: events.append(args), disk_state)
            linux.collect_metrics(lambda *args: events.append(args), disk_state)

        self.assertEqual(disk_state["/data"], "warning")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "disk_warning")


if __name__ == "__main__":
    unittest.main()
