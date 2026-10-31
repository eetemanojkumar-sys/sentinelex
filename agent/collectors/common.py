"""Operating-system-independent SentinelX telemetry collectors."""
import platform
import socket
import time

import psutil


def collect_base_metrics():
    """Collect metrics available through psutil on supported operating systems."""
    disk = {}
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, PermissionError):
            continue
        disk[partition.mountpoint] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": usage.percent,
            "filesystem": partition.fstype or None,
        }

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

    network = {}
    try:
        counters = psutil.net_io_counters(pernic=True)
        addresses = psutil.net_if_addrs()
        for name, stats in counters.items():
            network[name] = {
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
                "dropin": stats.dropin,
                "dropout": stats.dropout,
                "addresses": [
                    {
                        "family": str(item.family),
                        "address": item.address,
                        "netmask": item.netmask,
                    }
                    for item in addresses.get(name, [])
                ],
            }
    except (AttributeError, OSError):
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
    swap = psutil.swap_memory()
    boot_time = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "boot_time": boot_time,
        "uptime_seconds": max(0, time.time() - boot_time),
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "memory": {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "percent": memory.percent,
        },
        "swap": {
            "total_bytes": swap.total,
            "used_bytes": swap.used,
            "free_bytes": swap.free,
            "percent": swap.percent,
        },
        "disk": disk,
        "network_interfaces": network,
        "temperatures": temperatures,
        "process_count": len(processes),
        "processes": processes[:200],
        "listening_ports": listening_ports,
    }
