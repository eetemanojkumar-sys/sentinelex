"""SentinelX cross-platform endpoint agent service and telemetry transport."""
import hashlib
import os
import platform
import socket
import time
import json
import uuid
import stat
from pathlib import Path
from threading import Lock

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

CENTRAL_URL = os.getenv("SENTINELX_URL", "http://127.0.0.1:8000").rstrip("/")
BOOTSTRAP_TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
AGENT_TOKEN = BOOTSTRAP_TOKEN
HOST_ID = os.getenv("SENTINELX_HOST_ID", "")
INTERVAL = max(5, int(os.getenv("SENTINELX_INTERVAL", "30")))
STATE_FILE = Path(os.getenv("SENTINELX_STATE_FILE", str(Path(os.getenv("PROGRAMDATA", "/var/lib")) / "SentinelX" / "agent.json")))

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


def initialize_identity():
    """Load a persisted per-agent credential or enroll this endpoint once."""
    global AGENT_TOKEN, HOST_ID

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if state.get("agent_token") and state.get("host_id") and state.get("agent_id"):
                AGENT_TOKEN = state["agent_token"]
                HOST_ID = state["host_id"]
                return
        except (OSError, ValueError, TypeError):
            print("Saved SentinelX identity could not be read; enrolling again.", flush=True)

    if not BOOTSTRAP_TOKEN:
        raise SystemExit("SENTINELX_AGENT_TOKEN bootstrap token is required for first enrollment")

    machine_id = str(uuid.uuid4())
    payload = {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "machine_id": machine_id,
    }
    response = requests.post(
        f"{CENTRAL_URL}/api/v1/agents/enroll",
        json=payload,
        headers={"X-Agent-Token": BOOTSTRAP_TOKEN},
        timeout=15,
    )
    response.raise_for_status()
    registration = response.json()
    required = ("agent_id", "host_id", "agent_token")
    if not all(registration.get(key) for key in required):
        raise RuntimeError("Central API returned an incomplete enrollment response")

    state = {
        "agent_id": registration["agent_id"],
        "host_id": registration["host_id"],
        "agent_token": registration["agent_token"],
        "machine_id": machine_id,
    }
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    try:
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    temporary.replace(STATE_FILE)
    AGENT_TOKEN = state["agent_token"]
    HOST_ID = state["host_id"]
    print(f"Enrolled with SentinelX central; host_id={HOST_ID}", flush=True)


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
    initialize_identity()
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
