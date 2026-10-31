"""Linux-specific metric collection for SentinelX."""
import shutil
import subprocess

from collectors.common import collect_base_metrics


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

    metrics["antivirus"] = antivirus_status()
    return metrics
