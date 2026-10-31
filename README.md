# SentinelX

SentinelX is a rule-based, cross-platform endpoint health and security telemetry system. Linux and Windows agents report to a central FastAPI service backed by PostgreSQL. The project does not use Docker, AI/ML, Kubernetes, or predictive analytics.

## Current capabilities

- Cross-platform CPU, memory, swap, disk, uptime, process and listening-port telemetry
- Linux file-change monitoring and ClamAV executable/daemon status
- Windows service inventory and Microsoft Defender status
- Windows Security log collection for successful and failed logons (event IDs 4624 and 4625)
- Central authenticated telemetry ingestion and PostgreSQL persistence
- Dark-mode web dashboard with fleet overview, host inventory, disk history, events, processes, ports, endpoint protection and Windows services
- 30-second default agent reporting interval; dashboard refreshes every 10 seconds
- Disk usage rules: warning at 80%, critical at 90%

These are monitoring indicators, not proof of compromise. SentinelX does not automatically terminate processes or remediate hosts.

## Architecture

```text
Linux endpoint agent ---------\
                               \ HTTPS + shared agent token
Windows endpoint agent --------> Nginx TLS proxy -> FastAPI -> PostgreSQL
                               /                    |
Additional Linux agents ------/                     +-> Dashboard
```

The central API is normally bound to `127.0.0.1:8000` behind a TLS reverse proxy. The dashboard is served at `/dashboard/`.

Update the dashboard on an existing central Ubuntu deployment with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/dashboard-single-command-install/installers/linux/update-dashboard.sh | sudo bash
```

## Dashboard

- Dashboard: `https://CENTRAL-HOST:8443/dashboard/` (adjust host/port for your deployment)
- Health: `https://CENTRAL-HOST:8443/health`
- API docs: `https://CENTRAL-HOST:8443/docs`

Dashboard views:
- Overview: connected endpoints, latest CPU/memory readings, host status and recent events
- Hosts: operating system, availability, resources, processes, ports, services and protection status
- Disk monitoring: host/volume selectors, searchable inventory, 80%/90% thresholds and stored history
- Security events: searchable event feed with severity filtering
- Processes and network ports: latest endpoint snapshots
- Endpoint protection: Microsoft Defender on Windows and ClamAV status on Linux
- Windows services: service state, startup type, account and PID

The dashboard uses the existing read-only API endpoints and requires no frontend build step.

## One-command Linux agent installation

Run on a Debian/Ubuntu endpoint with sudo access:

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/dashboard-single-command-install/installers/linux/install.sh | sudo bash
```

The installer prompts for:
1. Central API base URL, for example `https://172.31.41.98:8443`
2. Shared SentinelX agent token (input is hidden)
3. Optional CA/server certificate path for a private or self-signed TLS certificate

It installs Python and Git prerequisites, downloads the selected branch, creates a virtual environment, installs agent dependencies, writes a root-only environment file, registers/enables the `sentinelx-agent` systemd service and starts it.

Logs:

```bash
sudo journalctl -u sentinelx-agent -f
```

This installer deploys the endpoint agent only. It does not create or replace the central API, database, Nginx configuration, or TLS reverse proxy.

## One-command Windows agent installation

Open **PowerShell as Administrator** on Windows 10/11 or Windows Server with Python 3 installed:

```powershell
irm https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/dashboard-single-command-install/installers/windows/Install-SentinelX.ps1 | iex
```

The installer prompts for the central API URL, hidden agent token, and optional CA/server certificate path. It installs the agent and Python dependencies, uses machine-scope Windows DPAPI to protect the token at rest, applies restrictive ACLs, registers a SYSTEM startup task, and starts it.

Agent log:

```powershell
Get-Content "$env:ProgramData\SentinelX\agent.log" -Tail 30
```

Task status:

```powershell
Get-ScheduledTask -TaskName "SentinelX-Windows-Agent" | Select-Object TaskName,State
```

If the central API uses a self-signed certificate, provide the matching public certificate file when prompted. Never distribute the TLS private key.

## Central API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | API health |
| POST | `/api/v1/telemetry` | Authenticated agent telemetry ingestion |
| GET | `/api/v1/hosts` | Latest metrics per host |
| GET | `/api/v1/events` | Recent events |
| GET | `/api/v1/summary` | Fleet summary |
| GET | `/api/v1/disk-history` | Stored disk samples for a host and volume |

## Security notes

- Use a long, unique shared agent token. Rotate it immediately if it is exposed.
- Protect the central API with TLS and restrict inbound security-group rules to trusted endpoint networks.
- Keep the database and Uvicorn port private; expose only the TLS reverse-proxy port.
- Linux installer stores its agent environment file with root-only permissions.
- Windows installer protects the token using machine-scope DPAPI and restricts access to SYSTEM and local Administrators.
- The current shared-token model is suitable for controlled deployments; per-agent credentials and role-based dashboard/API access are future hardening work.
- The optional CA certificate supplied to installers must be the public certificate/CA chain only, never a private key.

## Development principles

Python, FastAPI, PostgreSQL, native system services and transparent rule-based detection. No Docker, AI/ML, Kubernetes or predictive analytics.
