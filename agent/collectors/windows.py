"""Windows-specific collectors for SentinelX."""
import json
import subprocess
import threading

import psutil

from collectors.common import collect_base_metrics, redact_log_message

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
    """Read recent successful and failed Windows logons."""
    safe_limit = max(1, min(int(limit), 100))
    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624,4625
            StartTime = (Get-Date).AddMinutes(-5)
        } -MaxEvents LIMIT_PLACEHOLDER -ErrorAction Stop
    )
    $output = @(
        foreach ($event in $events) {
            [PSCustomObject]@{
                record_id = $event.RecordId
                event_id = $event.Id
                time_created = $event.TimeCreated.ToUniversalTime().ToString('o')
                message = $event.Message
            }
        }
    )
    ConvertTo-Json -InputObject $output -Compress -Depth 3
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        '[]'
    }
    else {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
""".replace("LIMIT_PLACEHOLDER", str(safe_limit))

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        if result.returncode != 0:
            return {
                "available": False,
                "reason": (result.stderr or "Security event log access unavailable")[:500],
                "items": [],
            }

        output = result.stdout.strip()
        data = json.loads(output) if output else []
        if isinstance(data, dict):
            data = [data]
        return {"available": True, "reason": None, "items": data}

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


def collect_logs(limit=100, window_minutes=3):
    """Collect bounded System, Application and Security event-log records."""
    safe_limit = max(1, min(int(limit), 250))
    safe_window = max(1, min(int(window_minutes), 15))
    per_channel = max(1, (safe_limit + 2) // 3)
    script = r"""
$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddMinutes(-WINDOW_PLACEHOLDER)
$records = @()
foreach ($channel in @('System', 'Application', 'Security')) {
    try {
        $found = Get-WinEvent -FilterHashtable @{
            LogName = $channel
            StartTime = $start
        } -MaxEvents PER_CHANNEL_PLACEHOLDER -ErrorAction Stop
        foreach ($event in $found) {
            $records += [PSCustomObject]@{
                source = $event.ProviderName
                channel = $channel
                severity = $event.Level
                event_id = $event.Id
                record_id = $event.RecordId
                message = $event.Message
                timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
                details = @{ level = $event.LevelDisplayName }
            }
        }
    }
    catch {
        # Empty, disabled, or inaccessible channels must not stop other channels.
        continue
    }
}
ConvertTo-Json -InputObject @($records) -Compress -Depth 4
""".replace("WINDOW_PLACEHOLDER", str(safe_window)).replace(
        "PER_CHANNEL_PLACEHOLDER", str(per_channel)
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []

    severity_map = {
        1: "critical", 2: "high", 3: "warning",
        4: "info", 0: "info",
    }
    records = []
    for item in data[:safe_limit]:
        message = redact_log_message(item.get("message", ""))
        if not message:
            continue
        try:
            raw_level = int(item.get("severity") or 0)
        except (TypeError, ValueError):
            raw_level = 0
        records.append({
            "source": str(item.get("source") or "Windows Event Log")[:200],
            "channel": str(item.get("channel") or "System")[:100],
            "severity": severity_map.get(raw_level, "info"),
            "event_id": str(item.get("event_id") or "") or None,
            "record_id": str(item.get("record_id") or "") or None,
            "message": message,
            "timestamp": item.get("timestamp"),
            "details": item.get("details") or {},
        })
    return records


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
