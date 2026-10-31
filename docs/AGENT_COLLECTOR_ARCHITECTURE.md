# SentinelX Agent Collector Architecture

## Platform selection

The endpoint agent selects its collector from the detected operating system:
- Linux uses `collectors.linux`.
- Windows uses `collectors.windows`.
- Other operating systems exit with an explicit unsupported-platform message.

## Shared telemetry

`collectors.common.collect_base_metrics()` collects hostname and OS identity, CPU, RAM, swap, disk volumes, network interface counters and addresses, process inventory, listening sockets, and temperatures where supported.

Optional capabilities that are unavailable due to OS support or permissions must not be fabricated as zero.

## Linux-specific telemetry

The Linux collector retains the existing disk alert transitions, excludes Snap squashfs mounts from capacity alerts, and checks ClamAV commands and daemon status where available.

## Windows-specific telemetry

The initial Windows collector adds a bounded Windows service inventory and Microsoft Defender status through `Get-MpComputerStatus`, in addition to the shared metrics.

Defender and service capabilities are marked unavailable when the relevant OS API or command cannot provide data.

## File monitoring

Linux retains the existing default watch paths. Windows uses a narrow default watch path under the Windows system drivers directory to avoid recursively scanning broad system folders. Operators can configure paths with `SENTINELX_WATCH_PATHS`.

## Development tests

Install dependencies with `python -m pip install -r agent/requirements.txt`, then run `cd agent && python -m unittest discover -v`.

GitHub Actions is configured to run collector tests on Ubuntu and Windows runners. A passing CI run is required before merge or production deployment.

## Current limitations

- Windows Security Event Log collection now reads recent successful logons (4624) and failed logons (4625), deduplicates records during the agent process lifetime, and reports unavailable access explicitly.
- Windows service installation and the one-click PowerShell installer are not implemented yet.
- Secure per-host enrollment is not implemented yet; the prototype still uses a shared token.
- Dashboard views for network interfaces and services are not implemented yet.