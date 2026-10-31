# SentinelX Cross-Platform v1 Release Plan

## Product goal

Turn SentinelX into a centrally managed, rule-based infrastructure monitoring platform with lightweight endpoint agents for Linux and Windows. Keep the existing FastAPI, PostgreSQL, and browser dashboard foundation. No Docker, Kubernetes, AI, or machine learning.

## Deployment model

- Central server: one Ubuntu LTS host (initially the existing EC2 instance) runs FastAPI, PostgreSQL, and the dashboard.
- Endpoint agents: Linux and Windows machines run only the SentinelX agent as a background service.
- Agents send telemetry to the central API over HTTPS.
- The dashboard displays all enrolled endpoints in one fleet view.

The central server must not be installed on every endpoint. Endpoint installers must never install PostgreSQL or the dashboard.

## Supported platforms

### First cross-platform release
- Ubuntu and Debian family
- RHEL-compatible Linux distributions where systemd is available
- Windows 10/11 and Windows Server versions supported by the selected Python runtime

### Later release
- macOS, after its launch daemon, permissions, and platform-specific security collectors are tested.

## Endpoint capabilities

Shared collectors:
- OS identity, hostname, boot time, uptime
- CPU utilization and logical core count
- RAM and swap utilization
- Disk/volume capacity and history
- Network interface addresses and byte counters
- Process inventory and resource usage
- Listening sockets where permissions allow

Linux-specific collectors:
- systemd service inventory/status
- Linux authentication and journal events
- ClamAV status where installed
- Linux file integrity watches

Windows-specific collectors:
- Windows service inventory/status
- Windows Event Log authentication and system events
- Microsoft Defender status using supported Windows interfaces
- Windows file integrity watches
- Drive/volume inventory

A metric that is unavailable or unsupported must be represented as unavailable, not as zero. Collection permissions and platform limitations must be visible in the dashboard.

## Installer experience

Provide separate native installers with the same guided workflow:
- Linux: install.sh, run with sudo
- Windows: Install-SentinelX.ps1, run from an elevated PowerShell session

Each endpoint installer:
1. Checks OS, architecture, privileges, disk space, and connectivity.
2. Installs or locates a supported Python runtime.
3. Downloads a pinned, versioned SentinelX agent release.
4. Creates an isolated installation directory and virtual environment.
5. Installs pinned dependencies.
6. Prompts for the central HTTPS URL and a short-lived enrollment token.
7. Requests a unique host identity or generates one.
8. Registers a persistent service (systemd on Linux; Windows Service on Windows).
9. Starts the service and performs a health/enrollment check.
10. Prints the service status and log location.

The scripts must be idempotent, support uninstall/upgrade, verify downloaded artifacts, avoid writing secrets into shell history or logs, and fail safely with actionable messages.

## Required security work before multi-host rollout

The current prototype uses one shared agent token. Replace this with:
- A short-lived enrollment token used only during onboarding.
- A unique credential per registered host, stored with restrictive OS permissions.
- Token rotation and host revocation.
- HTTPS with certificate verification; never disable TLS verification by default.
- Authenticated dashboard sessions and authorization for management actions.
- Authentication/authorization for telemetry and sensitive read APIs.
- Rate limits, input limits, and audit events for administrative operations.

Do not expose the current API publicly until authentication, TLS, firewall rules, and dashboard access controls are configured. Keep the current localhost/SSH-tunnel deployment until then.

## Dashboard modules

1. Fleet overview: online/offline hosts, health state, alerts, and trends.
2. Host details: OS, version, uptime, last seen, agent version, and collection health.
3. CPU and memory: current readings, history, and top consumers.
4. Disk: all volumes, capacity trends, thresholds, and history.
5. Network: interface traffic, throughput, errors, and listening ports.
6. Processes: sortable process inventory and resource consumption.
7. Services: Linux systemd and Windows services.
8. Security events: login events, file changes, service changes, and rule-based detections.
9. Alerts: severity, acknowledgement, resolution, assignment, and notes.
10. Reports: date-range summaries and CSV export.
11. Settings: thresholds, collection interval, retention, host groups, and agent enrollment.

All dashboard values must be based on actual telemetry. Missing capabilities must be shown as unavailable. No fabricated security verdicts or automatic process termination.

## Data model evolution

Keep time-series telemetry, but introduce normalized host registration and lifecycle data. Add explicit OS/agent metadata, per-host credential records, alert state, and administrative audit records. Add indexes and retention policies before large fleet use. Use migrations (Alembic) rather than relying on create_all for schema evolution.

## Delivery milestones

### Milestone 1 — Safe foundation
- Create a cross-platform development branch.
- Separate shared collection from OS-specific collection.
- Normalize telemetry fields and add OS/agent metadata.
- Add tests for Linux and Windows collectors.

### Milestone 2 — Secure enrollment
- Host registration and one-time enrollment tokens.
- Per-host credentials, revocation, and authenticated read APIs.
- TLS deployment configuration.

### Milestone 3 — Windows agent
- Windows collectors and Windows Event Log/Defender integration.
- Windows Service wrapper and elevated installer.
- Test install, restart, upgrade, uninstall, and recovery.

### Milestone 4 — Linux installer
- Distribution checks, systemd setup, upgrades, uninstall, and recovery.
- Test clean installs and upgrades on supported distributions.

### Milestone 5 — Dashboard
- Fleet overview and host detail pages.
- CPU, memory, disk, network, processes, services, security events, and alert workflows.
- Filters, sorting, date ranges, historical charts, and CSV reports.

### Milestone 6 — Release hardening
- Integration tests, permissions review, installer artifact checksums/signatures, backups, retention, logging, and documented recovery procedures.

## Rollout rule

Keep the currently running production branch and EC2 deployment unchanged while this work is developed on a separate branch. Merge and deploy only after tests pass and the existing Linux agent remains compatible.
