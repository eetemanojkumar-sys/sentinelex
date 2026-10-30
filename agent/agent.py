"""SentinelX Linux endpoint collector (rule-based; no AI/ML)."""
import hashlib
import os
import platform
import shutil
import socket
import subprocess
import time
from pathlib import Path
from threading import Lock

import psutil
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

CENTRAL_URL = os.getenv("SENTINELX_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
HOST_ID = os.getenv("SENTINELX_HOST_ID", socket.gethostname())
INTERVAL = max(5, int(os.getenv("SENTINELX_INTERVAL", "30")))
WATCH_PATHS = [
    Path(item.strip()).resolve()
    for item in os.getenv("SENTINELX_WATCH_PATHS", "/etc,/opt,/var/www,/home").split(",")
    if item.strip()
]
MODEL_EXTENSIONS = {
    ".pkl", ".pickle", ".joblib", ".h5", ".keras",
    ".pt", ".pth", ".onnx", ".safetensors", ".model",
}
events = []
event_lock = Lock()


def queue_event(event_type, severity, message, details=None):
    item = {
        "event_type": event_type,
        "severity": severity,
        "message": message[:1000],
        "details": details or {},
    }
    with event_lock:
        events.append(item)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_hash(path):
    try:
        return sha256_file(path)
    except OSError:
        return None


class ChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in MODEL_EXTENSIONS:
            queue_event(
                "new_model_file", "medium", f"New model file detected: {path}",
                {"path": str(path), "sha256": safe_hash(path)},
            )
        else:
            queue_event("new_file", "info", f"New file detected: {path}", {"path": str(path)})

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() in MODEL_EXTENSIONS:
            queue_event(
                "model_file_modified", "high", f"Model file modified: {path}",
                {"path": str(path), "sha256": safe_hash(path)},
            )
        else:
            queue_event("file_modified", "info", f"File modified: {path}", {"path": str(path)})

    def on_deleted(self, event):
        if not event.is_directory:
            queue_event("file_deleted", "low", f"File deleted: {event.src_path}",
                        {"path": event.src_path})


def antivirus_status():
    status = {binary: shutil.which(binary) is not None
              for binary in ("clamd", "clamscan", "freshclam")}
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "clamav-daemon"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        status["clamav_daemon_active"] = result.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        status["clamav_daemon_active"] = None
    return status


def collect_metrics():
    disk = {}
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except OSError:
            continue
        disk[partition.mountpoint] = {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": usage.percent,
        }
        if usage.percent >= 90:
            queue_event("disk_critical", "critical",
                        f"Disk usage is {usage.percent}% on {partition.mountpoint}",
                        {"mountpoint": partition.mountpoint, "percent": usage.percent})
        elif usage.percent >= 80:
            queue_event("disk_warning", "medium",
                        f"Disk usage is {usage.percent}% on {partition.mountpoint}",
                        {"mountpoint": partition.mountpoint, "percent": usage.percent})

    processes = []
    for proc in psutil.process_iter(
        ["pid", "name", "username", "memory_info", "exe"]
    ):
        try:
            info = proc.info
            memory = info.get("memory_info")
            processes.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "exe": info.get("exe"),
                "memory_rss_bytes": memory.rss if memory else None,
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


def start_watchers():
    observer = Observer()
    handler = ChangeHandler()
    for path in WATCH_PATHS:
        if path.is_dir():
            try:
                observer.schedule(handler, str(path), recursive=True)
                print(f"Watching {path}", flush=True)
            except OSError as exc:
                print(f"Cannot watch {path}: {exc}", flush=True)
    observer.start()
    return observer


def send_payload(metrics):
    with event_lock:
        batch = events[:]
        del events[:]
    payload = {"host_id": HOST_ID, "metrics": metrics, "events": batch}
    try:
        response = requests.post(
            f"{CENTRAL_URL}/api/v1/telemetry",
            json=payload,
            headers={"X-Agent-Token": AGENT_TOKEN},
            timeout=10,
        )
        response.raise_for_status()
        print(f"Telemetry sent; events={len(batch)}", flush=True)
    except requests.RequestException as exc:
        with event_lock:
            events[:0] = batch
        print(f"Telemetry delivery failed: {exc}", flush=True)


def main():
    if not AGENT_TOKEN:
        raise SystemExit("SENTINELX_AGENT_TOKEN is required")
    observer = start_watchers()
    try:
        while True:
            try:
                send_payload(collect_metrics())
            except Exception as exc:  # keep the service alive; log collection errors
                print(f"Collection error: {exc}", flush=True)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
