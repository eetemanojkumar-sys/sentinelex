"""SentinelX cross-platform endpoint agent service and telemetry transport."""
import hashlib
import os
import platform
import socket
import tempfile
import time
import uuid
from pathlib import Path
from threading import Lock

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

CENTRAL_URL = os.getenv("SENTINELX_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
HOST_ID = os.getenv("SENTINELX_HOST_ID", socket.gethostname())
INTERVAL = max(5, int(os.getenv("SENTINELX_INTERVAL", "30")))
AGENT_VERSION = "0.2.0"
sequence = 0
pending_payload = None

if platform.system() == "Windows":
    DEFAULT_WATCH_PATHS = r"C:\Windows\System32\drivers\etc"
    INSTALL_DIR = Path(os.getenv("SENTINELX_INSTALL_DIR", r"C:\Program Files\SentinelX"))
else:
    DEFAULT_WATCH_PATHS = "/etc,/opt,/var/www,/home"
    INSTALL_DIR = Path(os.getenv("SENTINELX_INSTALL_DIR", "/opt/sentinelx"))

WATCH_PATHS = [
    Path(item.strip()).resolve()
    for item in os.getenv("SENTINELX_WATCH_PATHS", DEFAULT_WATCH_PATHS).split(",")
    if item.strip()
]
MODEL_EXTENSIONS = {
    ".pkl", ".pickle", ".joblib", ".h5", ".keras",
    ".pt", ".pth", ".onnx", ".safetensors", ".model",
}
events = []
event_lock = Lock()
disk_alert_states = {}

# Keep one collector per host identity. The OS releases this lock automatically
# if the process exits or crashes, so stale lock files are harmless.
_agent_lock_handle = None


def acquire_single_instance_lock():
    global _agent_lock_handle
    lock_name = hashlib.sha256(HOST_ID.encode("utf-8")).hexdigest()[:16]
    lock_path = Path(tempfile.gettempdir()) / f"sentinelx-agent-{lock_name}.lock"
    handle = None
    try:
        handle = open(lock_path, "a+")
        if os.name == "nt":
            import msvcrt
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write("0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        if handle is not None:
            handle.close()
        return False
    _agent_lock_handle = handle
    return True


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
    EXCLUDED_PATHS = [INSTALL_DIR.resolve()]

    def is_excluded(self, path):
        try:
            resolved = Path(path).resolve()
            return any(
                resolved == excluded or excluded in resolved.parents
                for excluded in self.EXCLUDED_PATHS
            )
        except (OSError, ValueError):
            return False

    def on_created(self, event):
        if event.is_directory or self.is_excluded(event.src_path):
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
        if event.is_directory or self.is_excluded(event.src_path):
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
        if not event.is_directory and not self.is_excluded(event.src_path):
            queue_event(
                "file_deleted", "low", f"File deleted: {event.src_path}",
                {"path": event.src_path},
            )


if platform.system() == "Windows":
    from collectors.windows import collect_metrics
elif platform.system() == "Linux":
    from collectors.linux import collect_metrics
else:
    raise SystemExit(f"Unsupported SentinelX platform: {platform.system()}")


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
    """Send one immutable batch until it is acknowledged by the central API."""
    global sequence, pending_payload
    if pending_payload is None:
        sequence += 1
        with event_lock:
            batch = events[:]
            del events[:]
        pending_payload = {
            "schema_version": 1,
            "host_id": HOST_ID,
            "batch_id": uuid.uuid4().hex,
            "agent": {
                "version": AGENT_VERSION,
                "platform": platform.system(),
                "architecture": platform.machine(),
            },
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sequence": sequence,
            "metrics": metrics,
            "events": batch,
        }
    batch_size = len(pending_payload["events"])
    try:
        response = requests.post(
            f"{CENTRAL_URL}/api/v1/telemetry",
            json=pending_payload,
            headers={"X-Agent-Token": AGENT_TOKEN},
            timeout=10,
        )
        response.raise_for_status()
        print(f"Telemetry acknowledged; events={batch_size}", flush=True)
        pending_payload = None
    except requests.RequestException as exc:
        # Retain the exact payload and batch ID. If the server committed it but
        # the response was lost, retrying is safe because ingestion is idempotent.
        print(f"Telemetry delivery pending acknowledgement: {exc}", flush=True)


def main():
    if not AGENT_TOKEN:
        raise SystemExit("SENTINELX_AGENT_TOKEN is required")
    if not acquire_single_instance_lock():
        print(f"Another SentinelX agent is already running for host {HOST_ID}; exiting.", flush=True)
        raise SystemExit(0)
    observer = start_watchers()
    try:
        while True:
            try:
                send_payload(collect_metrics(queue_event, disk_alert_states))
            except Exception as exc:
                print(f"Collection error: {exc}", flush=True)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
