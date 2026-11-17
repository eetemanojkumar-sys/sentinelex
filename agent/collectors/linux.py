"""Linux-specific metric collection for SentinelX."""
import json
import shutil
import subprocess
from datetime import datetime, timezone


def linux_services(limit=250):
    """Return a bounded systemd service snapshot on Linux hosts."""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 0:
            return {"available": False, "items": [], "reason": (result.stderr or "systemctl unavailable")[:300]}
        items = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4 or not parts[0].endswith(".service"):
                continue
            items.append({
                "name": parts[0], "display_name": parts[4] if len(parts) > 4 else parts[0],
                "load_state": parts[1], "status": parts[2], "sub_state": parts[3],
            })
            if len(items) >= max(1, min(int(limit), 500)):
                break
        return {"available": True, "items": items}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "items": [], "reason": str(exc)[:300]}

from collectors.common import collect_base_metrics, redact_log_message


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


def collect_logs(limit=100, window_minutes=3):
    """Collect a bounded, overlapping window of journal records for central deduplication."""
    safe_limit = max(1, min(int(limit), 250))
    safe_window = max(1, min(int(window_minutes), 15))
    try:
        result = subprocess.run(
            [
                "journalctl", f"--since=-{safe_window}min", "-n", str(safe_limit),
                "--output=json", "--no-pager",
            ],
            capture_output=True, text=True, timeout=8, check=False,
        )
        if result.returncode != 0:
            return []
    except (OSError, subprocess.TimeoutExpired):
        return []

    severity_map = {
        0: "critical", 1: "critical", 2: "critical", 3: "high",
        4: "warning", 5: "info", 6: "info", 7: "debug",
    }
    records = []
    for line in result.stdout.splitlines():
        if len(records) >= safe_limit:
            break
        try:
            item = json.loads(line)
            raw_time = item.get("__REALTIME_TIMESTAMP")
            timestamp = None
            if raw_time is not None:
                timestamp = datetime.fromtimestamp(
                    int(raw_time) / 1_000_000, tz=timezone.utc
                ).isoformat()
            priority = int(item.get("PRIORITY", 6))
            source = (
                item.get("SYSLOG_IDENTIFIER")
                or item.get("_COMM")
                or item.get("_SYSTEMD_UNIT")
                or "system"
            )
            message = redact_log_message(item.get("MESSAGE", ""))
            if not message:
                continue
            records.append({
                "source": str(source)[:200],
                "channel": "journal",
                "severity": severity_map.get(priority, "info"),
                "event_id": None,
                "record_id": str(item.get("__CURSOR") or "")[:300] or None,
                "message": message,
                "timestamp": timestamp,
                "details": {
                    "unit": item.get("_SYSTEMD_UNIT"),
                    "pid": item.get("_PID"),
                    "priority": priority,
                },
            })
        except (TypeError, ValueError, OSError):
            continue
    return records


def collect_metrics(queue_event, disk_alert_states):
    """Collect shared metrics and apply Linux-specific disk and AV rules."""
    metrics = collect_base_metrics()
    disk = metrics["disk"]

    # Exclude snap loopback images, which are not useful capacity alerts.
    for mountpoint in list(disk):
        filesystem = (disk[mountpoint].get("filesystem") or "").lower()
        if (
            filesystem == "squashfs"
            or mountpoint == "/snap"
            or mountpoint.startswith("/snap/")
        ):
            disk.pop(mountpoint, None)

    for mountpoint, usage in disk.items():
        percent = usage["percent"]
        state = "critical" if percent >= 90 else "warning" if percent >= 80 else "healthy"
        previous_state = disk_alert_states.get(mountpoint, "healthy")
        if state != previous_state:
            if state == "critical":
                queue_event(
                    "disk_critical", "critical",
                    f"Disk usage is {percent}% on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": percent},
                )
            elif state == "warning":
                queue_event(
                    "disk_warning", "medium",
                    f"Disk usage is {percent}% on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": percent},
                )
            elif previous_state != "healthy":
                queue_event(
                    "disk_recovered", "info",
                    f"Disk usage returned to the healthy range on {mountpoint}",
                    {"mountpoint": mountpoint, "percent": percent},
                )
            disk_alert_states[mountpoint] = state

    metrics["services"] = linux_services()
    metrics["antivirus"] = antivirus_status()
    return metrics
