# SentinelX

SentinelX is an independent, rule-based infrastructure health and security monitoring platform for Linux and Windows endpoints. Agents report to a central FastAPI API backed by PostgreSQL. SentinelX owns collection, transport, storage, alert processing, and visualization; Prometheus, Node Exporter, Windows Exporter, and Grafana are not runtime dependencies.

This integration work is isolated on `cross-platform-v1-conflict-resolution`. Production `main` remains untouched until release checks and explicit deployment approval. No Docker, Kubernetes, AI, or machine learning.

## Current capabilities

- CPU, memory, swap, disk, uptime, process, and listening-port telemetry on Linux and Windows.
- Linux file-change monitoring and ClamAV executable/daemon status.
- Windows service inventory, Microsoft Defender status, and Security logon events (4624/4625).
- Agent enrollment, per-agent credentials, revocation support, and administrator-protected read APIs.
- SQLite-backed durable outbox with stable batch IDs and server-side idempotency.
- Fleet dashboard with host inventory, resource/disk history, events, processes, ports, endpoint protection, and Windows services.
- Default 30-second agent reporting interval; dashboard refreshes every 10 seconds.
- Disk warning at 80% and critical at 90%.

These are monitoring indicators, not proof of compromise. SentinelX does not automatically terminate processes or remediate hosts.

## Architecture

```text
Linux agent ---------\
                      \ HTTPS + per-agent credential
Windows agent --------> TLS reverse proxy -> FastAPI -> PostgreSQL
                      /                     |
Additional agents ---/                      +-> Dashboard
```

Bind the central API to localhost behind a TLS reverse proxy. The dashboard is served at `/dashboard/`.

## Security configuration

Set a long bootstrap secret in `SENTINELX_AGENT_TOKEN` and a separate `SENTINELX_ADMIN_TOKEN` for dashboard/read API access. The dashboard asks for the administrator token and retains it only in the current browser session.

Keep PostgreSQL and Uvicorn private; expose only the TLS reverse proxy. Restrict ingress to trusted endpoint networks. The bootstrap token is a compatibility path for older agents; migrate endpoints to per-agent enrollment and rotate any exposed credentials.

The enrolled agent credential is stored in a local state file; restrict its permissions/ACLs. The SQLite outbox defaults to `~/.sentinelx/outbox.sqlite3`; configure `SENTINELX_QUEUE_PATH` to use another protected location. It retains telemetry until acknowledgement.

## Agent installation

Review the maintained installers under `installers/linux/` and `installers/windows/` before use. They configure endpoint agents; they do not provision the central API, database, reverse proxy, or TLS configuration.

For private TLS, configure the public CA/server certificate only. Never distribute a TLS private key.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | API and database health |
| POST | `/api/v1/agents/enroll` | Enroll endpoint with bootstrap token |
| POST | `/api/v1/telemetry` | Authenticated, idempotent telemetry ingestion |
| GET | `/api/v1/hosts` | Latest hosts (administrator auth, paginated) |
| GET | `/api/v1/events` | Recent events (administrator auth) |
| GET | `/api/v1/summary` | Fleet summary (administrator auth) |
| GET | `/api/v1/disk-history` | Disk samples (administrator auth) |
| GET | `/api/v1/metrics/history` | CPU, memory, and network history (administrator auth) |

## Operational notes

- `create_all` adds missing tables but does not migrate existing production tables. Plan and verify schema migrations before deploying.
- Run collectors with least privilege; some process/port data requires elevated permissions.
- File-event monitoring can miss changes during downtime or when OS watcher limits are reached. Complement it with periodic integrity baselines.
- Defender/ClamAV values are status checks, not proof a malware scan has completed.
- Historical metrics are persisted at a lower cadence to limit database writes.

## Development principles

Python, FastAPI, PostgreSQL, native OS services, and transparent rule-based logic. No Docker, AI/ML, Kubernetes, or predictive analytics.

See [Independent Monitoring Architecture](docs/INDEPENDENT_MONITORING_ARCHITECTURE.md) for component boundaries, data model, security design, scale strategy, and roadmap.


## Automated deployment

The deployment branch includes a safe installer for a fresh Ubuntu/Debian central server and a separate Windows endpoint installer.

### Ubuntu central server and local Linux agent

Review the script, then run it from the repository root:

```bash
sudo bash deploy/install.sh
```

The installer:
- Checks the OS and required tools.
- Creates a recovery archive before modifying an existing installation.
- Backs up PostgreSQL using `pg_dump` when a PostgreSQL URL is configured; it stops if that database backup fails.
- Preserves `/etc/sentinelx/sentinelx.env`, existing agent identity, outbox and database contents.
- Generates first-run agent/admin credentials only on a genuinely fresh installation.
- Installs pinned Python dependencies and systemd units.
- Installs and enables the daily PostgreSQL telemetry-retention timer (30-day telemetry / 180-day event defaults, configurable in the environment file).
- Starts the central API and (unless skipped) the Linux agent, then checks `/health`.

Modes:

```bash
sudo bash deploy/install.sh --mode backup
sudo bash deploy/install.sh --mode update
sudo bash deploy/install.sh --mode repair
sudo bash deploy/install.sh --mode install --skip-agent
```

Backups are written to `/var/backups/sentinelx`. The installer keeps the API bound to `127.0.0.1`; configure a TLS reverse proxy and restrictive security-group/firewall rules for remote access. It does not open public ports.

### Windows endpoint

Run PowerShell as Administrator on each Windows endpoint:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\install-windows-agent.ps1 -CentralUrl "https://YOUR-SENTINELX-HOST"
```

The script securely prompts for the bootstrap token if it is not supplied as a parameter, installs Python if required, installs the agent dependencies, protects its configuration under ProgramData, and registers a startup scheduled task running as SYSTEM. The first run enrolls the endpoint and stores its per-agent credential locally.

Use HTTPS for remote Windows endpoints. The bootstrap token is a provisioning secret; do not paste it into tickets, chat, or source control.

**Important:** This installer is a deployment foundation, not a claim that every future SentinelX capability is already implemented. It installs the current repository release and verifies the API/agent processes; it does not install Prometheus, Node Exporter, Windows Exporter, or Grafana.
