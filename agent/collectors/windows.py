"""Windows-specific collectors for SentinelX."""
import json
import subprocess
import threading

import psutil

from collectors.common import collect_base_metrics

_seen_security_record_ids = set()
_seen_lock = threading.Lock()


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
    except (OSError, psutil.AccessDenied):
        return {"available": False, "items": []}



def collect_security_events(limit=25):
    """Read recent successful/failed logons from the Windows Security log."""
    safe_limit = max(1, min(int(limit), 100))
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "$items = Get-WinEvent -FilterHashtable @{LogName='Security'; "
        "Id=4624,4625} -MaxEvents " + str(safe_limit) + "; "
        "$items | ForEach-Object { "
        "[PSCustomObject]@{ "
        "record_id=$_.RecordId; event_id=$_.Id; "
        "time_created=$_.TimeCreated.ToUniversalTime().ToString('o'); "
        "message=$_.Message "
        "} } | ConvertTo-Json -Compress -Depth 3"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=12, check=False,
        )
        if result.returncode != 0:
            return {"available": False,
                    "reason": (result.stderr or "Security event log access unavailable")[:500],
                    "items": []}
        if not result.stdout.strip():
            return {"available": True, "reason": None, "items": []}
        data = json.loads(result.stdout)
        return {"available": True, "reason": None,
                "items": data if isinstance(data, list) else [data]}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"available": False, "reason": str(exc)[:500], "items": []}


def emit_security_events(queue_event, result):
    """Convert newly observed Windows logon records into SentinelX events."""
    if not result.get("available"):
        return 0
    emitted = 0
    for item in result.get("items", []):
        record_id = item.get("record_id")
        if record_id is None:
            continue
        key = str(record_id)
        with _seen_lock:
            if key in _seen_security_record_ids:
                continue
            _seen_security_record_ids.add(key)
            if len(_seen_security_record_ids) > 5000:
                _seen_security_record_ids.clear()
                _seen_security_record_ids.add(key)
        event_id = int(item.get("event_id") or 0)
        failed = event_id == 4625
        queue_event(
            "windows_login_failed" if failed else "windows_login_success",
            "high" if failed else "info",
            "Failed Windows logon detected" if failed else "Successful Windows logon detected",
            {
                "source": "Windows Security Event Log",
                "event_id": event_id,
                "record_id": record_id,
                "time_created": item.get("time_created"),
                "message": (item.get("message") or "")[:1500],
            },
        )
        emitted += 1
    return emitted

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
    security_result = collect_security_events()
    emitted = emit_security_events(queue_event, security_result)
    metrics["security_event_collection"] = {
        "available": security_result["available"],
        "reason": security_result.get("reason"),
        "new_events": emitted,
        "event_ids": [4624, 4625],
    }
    return metrics
