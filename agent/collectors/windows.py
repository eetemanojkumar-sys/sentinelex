"""Windows-specific collectors for SentinelX."""
import json
import subprocess

import psutil

from collectors.common import collect_base_metrics


def defender_status():
    """Read Defender state through the supported PowerShell cmdlet when available."""
    script = (
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"available": False, "reason": "Defender status unavailable"}
        data = json.loads(result.stdout)
        return {
            "available": True,
            "antivirus_enabled": data.get("AntivirusEnabled"),
            "real_time_protection_enabled": data.get("RealTimeProtectionEnabled"),
            "signature_last_updated": data.get("AntivirusSignatureLastUpdated"),
        }
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"available": False, "reason": "Defender status unavailable"}


def windows_services(limit=250):
    """Return a bounded Windows service inventory; unavailable values stay explicit."""
    services = []
    iterator = getattr(psutil, "win_service_iter", None)
    if iterator is None:
        return {"available": False, "items": []}
    try:
        for service in iterator():
            if len(services) >= limit:
                break
            try:
                item = service.as_dict()
                services.append({
                    "name": item.get("name"),
                    "display_name": item.get("display_name"),
                    "status": item.get("status"),
                    "start_type": item.get("start_type"),
                    "username": item.get("username"),
                    "pid": item.get("pid"),
                })
            except (OSError, psutil.AccessDenied):
                continue
        return {"available": True, "items": services}
    except (OSError, __import__("psutil").AccessDenied):
        return {"available": False, "items": []}


def collect_metrics(queue_event, disk_alert_states):
    """Collect shared metrics plus Windows-specific service and Defender status."""
    metrics = collect_base_metrics()
    for mountpoint, usage in metrics["disk"].items():
        percent = usage["percent"]
        state = "critical" if percent >= 90 else "warning" if percent >= 80 else "healthy"
        previous_state = disk_alert_states.get(mountpoint, "healthy")
        if state != previous_state:
            if state in ("warning", "critical"):
                queue_event(
                    "disk_" + state,
                    "critical" if state == "critical" else "medium",
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
    metrics["services"] = windows_services()
    metrics["antivirus"] = {"microsoft_defender": defender_status()}
    return metrics
