"""Shared collector contract tests (run: python -m unittest -v)."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from collectors import common


class CommonCollectorContractTests(unittest.TestCase):
    def test_collector_returns_expected_keys(self):
        with patch.object(common.psutil, "disk_partitions", return_value=[]), \
             patch.object(common.psutil, "process_iter", return_value=[]), \
             patch.object(common.psutil, "net_connections", return_value=[]), \
             patch.object(common.psutil, "net_io_counters", return_value={}), \
             patch.object(common.psutil, "net_if_addrs", return_value={}), \
             patch.object(common.psutil, "sensors_temperatures", return_value={}), \
             patch.object(common.psutil, "virtual_memory",
                          return_value=SimpleNamespace(total=100, available=50, percent=50)), \
             patch.object(common.psutil, "swap_memory",
                          return_value=SimpleNamespace(total=0, used=0, free=0, percent=0)), \
             patch.object(common.psutil, "boot_time", return_value=1000.0), \
             patch.object(common.psutil, "cpu_percent", return_value=2.0), \
             patch.object(common.psutil, "cpu_count", return_value=2):
            metrics = common.collect_base_metrics()

        expected = {
            "hostname", "platform", "os", "boot_time", "uptime_seconds",
            "cpu_percent", "cpu_count_logical", "memory", "swap", "disk",
            "network_interfaces", "temperatures", "process_count",
            "processes", "listening_ports",
        }
        self.assertEqual(set(metrics), expected)
        self.assertEqual(metrics["memory"]["percent"], 50)
        self.assertEqual(metrics["cpu_count_logical"], 2)


if __name__ == "__main__":
    unittest.main()
