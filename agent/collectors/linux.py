"""Linux-specific metric collection for SentinelX.

The returned dictionary intentionally preserves the existing telemetry schema so
this refactor remains compatible with the current central API and dashboard.
"""
import platform
import shutil
import socket
import subprocess
import time

import psutil


def antivirus_status():
    status = {
        binary: shutil.which(binary) is not None
        for binary in ("clamd", "clamscan", "freshclam")
    }
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "clamav-daemon"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        status["clamav_daemon_active"] = result.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        status["clamav_daemon_active"] = None
    return status


def collect_metrics(queue_event, disk_alert_states):
    """Collect Linux telemetry using the legacy SentinelX metric names."""
    disk = {}
    for partition in psutil.disk_partitions(all=False):
        mountpoint = partition.mountpoint
        # Snap loopback images are read-only package mounts, not useful capacity alerts.
        if (
            partition.fstype.lower() == "squashfs"
            or mountpoint == "/snap"
            or mountpoint.startswith("/snap/")
        ):
            continue
        try:
            usage = psutil.disk_usage(mountpoint)
        except OSError:
            continue
        disk[mountpoint] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": usage.percent,
        }
        state = (
            "critical" if usage.percent >= 90
            else "warning" if usage.percent >= 80
            else "healthy"
        )
        previous_state = disk_alert_states.get(mountpoint, "healthy")
        if state != previous_state:
            if state == "critical":
                queue_event(
                    "disk_critical",
                    "critical",
                    f"Disk usage is {usage.percent}% on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": usage.percent},
                )
            elif state == "warning":
                queue_event(
                    "disk_warning",
                    "medium",
                    f"Disk usage is {usage.percent}% on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": usage.percent},
                )
            elif previous_state != "healthy":
                queue_event(
                    "disk_recovered",
                    "info",
                    f"Disk usage returned to the healthy range on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": usage.percent},
                )
            disk_alert_states[mountpoint] = state

    processes = []
    for proc in psutil.process_iter(
        ["pid", "name", "username", "memory_info", "exe"]
    ):
        try:
            info = proc.info
            memory_info = info.get("memory_info")
            processes.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "exe": info.get("exe"),
                "memory_rss_bytes": memory_info.rss if memory_info else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    listening_ports = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN:
                address = None
                if conn.laddr:
                    address = f"{conn.laddr.ip}:{conn.laddr.port}"
                listening_ports.append({
                    "local_address": address,
                    "pid": conn.pid,
                    "family": str(conn.family),
                    "type": str(conn.type),
                })
    except (psutil.AccessDenied, OSError):
        pass

    temperatures = {}
    try:
        sensor_data = psutil.sensors_temperatures() or {}
        for name, entries in sensor_data.items():
            temperatures[name] = [
                {"label": entry.label, "current": entry.current}
                for entry in entries
            ]
    except (AttributeError, OSError):
        pass

    memory = psutil.virtual_memory()
    boot_time = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "boot_time": boot_time,
        "uptime_seconds": time.time() - boot_time,
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory": {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "percent": memory.percent,
        },
        "disk": disk,
        "temperatures": temperatures,
        "process_count": len(processes),
        "processes": processes[:200],
        "listening_ports": listening_ports,
        "antivirus": antivirus_status(),
    }
