# SentinelX

SentinelX is a rule-based cross-platform monitoring and security telemetry platform for Linux and Windows servers. The initial scale target is **1,000 endpoints** reporting to a centralized FastAPI/PostgreSQL control plane.

## Capabilities

- CPU, memory, swap, disk, uptime, process, network-interface and listening-port telemetry
- Linux file-change monitoring and ClamAV availability
- Windows service inventory, Microsoft Defender status and Security log events 4624/4625
- Unique endpoint enrollment and per-agent credentials
- Central live host snapshots, sampled resource history and security event storage
- Fleet dashboard with 100-host pages, server-side hostname search, host drill-down and endpoint protection status
- Automatic agent startup on Linux (systemd) and Windows (Task Scheduler)
- Rule-based disk thresholds: warning at 80%, critical at 90%

SentinelX reports monitoring signals; it does not automatically kill processes, remediate systems or claim that a malware scan has been completed. It does not use AI/ML.

## 1,000-endpoint baseline

- 60-second heartbeat by default in the installers (~16.7 requests/second at 1,000 endpoints)
- Latest host state updated on every heartbeat
- Compact disk/resource history sampled every 5 minutes (~288,000 history rows/day at 1,000 endpoints)
- 30-day telemetry and 180-day event retention via daily systemd timer
- Two Uvicorn API workers and a conservative PostgreSQL pool baseline; measure and tune for the actual EC2/RDS instance
- Dashboard host inventory is fetched in 100-host pages with server-side search

This is an initial measured-capacity target, not a guarantee for every instance class or workload. Run the staging load test and inspect PostgreSQL CPU, IOPS, connections, storage growth and API p95/p99 latency before production sign-off.

Detailed design and operating assumptions: [docs/SCALING-1000.md](docs/SCALING-1000.md).

## Architecture

```text
Linux / Windows agents (N endpoints)
       | HTTPS, bootstrap enrollment, per-agent token
       v
Nginx TLS ingress -> FastAPI workers -> PostgreSQL
                            |              |
                      fleet APIs       agent credentials
                      paginated hosts  latest host snapshot
                      events            compact history
                                        security events
                            |
                            v
                      Web dashboard
```

The central API is normally bound to `127.0.0.1:8000` behind the existing TLS reverse proxy. Dashboard: `https://CENTRAL-HOST:8443/dashboard/`.

## Update existing central Ubuntu deployment

On the existing central host, expected paths are `/opt/sentinelx`, `/opt/sentinelx/venv` and `/etc/sentinelx/sentinelx.env`:

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/linux/update-central.sh | sudo bash
```

The updater backs up the API module and dashboard, installs the new API/dashboard, creates a protected admin token if absent, configures two API workers and DB connection pools, enables daily retention cleanup, restarts the API and checks its local health endpoint. It does not replace PostgreSQL, Nginx or TLS private keys.

The updater creates `SENTINELX_ADMIN_TOKEN` in `/etc/sentinelx/sentinelx.env`; it is not printed. The API service account needs read access to this environment file. Keep it protected and do not paste it into chat or logs.

## Install/enroll a Linux endpoint

On Debian/Ubuntu with sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/linux/install.sh | sudo bash
```

Enter the central API URL, the bootstrap/enrollment token from the central environment, and optionally the public CA/server certificate for a private TLS deployment. The installer installs Python/Git prerequisites, creates a virtual environment, stores its config root-only, registers a systemd service and starts the agent.

Logs:

```bash
sudo journalctl -u sentinelx-agent -f
```

## Install/enroll a Windows endpoint

Run PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/windows/Install-SentinelX.ps1 | iex
```

Enter the central API URL, bootstrap/enrollment token and optional public CA/server certificate. The installer registers a SYSTEM startup task and protects the bootstrap token at rest with machine-scope DPAPI. The agent stores its individual credential in `%ProgramData%\SentinelX\agent.json` with restricted ACLs.

Task status:

```powershell
Get-ScheduledTask -TaskName "SentinelX-Windows-Agent" | Select-Object TaskName,State
Get-Content "$env:ProgramData\SentinelX\agent.log" -Tail 30
```

## Enrollment and authentication

- Installer supplies a bootstrap/enrollment token.
- First agent start calls `POST /api/v1/agents/enroll` with hostname, OS and a persistent machine identifier.
- API creates a unique per-agent token and stores only its SHA-256 hash.
- Agent persists its token locally and sends it with every telemetry request.
- API binds the credential to the enrolled host ID; spoofed host IDs are rejected.
- Revocation invalidates that agent token.
- During rollout, legacy shared-token telemetry remains enabled for existing unupgraded agents. After every endpoint has enrolled, set `SENTINELX_ALLOW_LEGACY_TOKEN=false` in the central service environment and restart the API. Keep the bootstrap/enrollment token for future approved enrollments and rotate it through a controlled rollout.

Admin API endpoints require `X-Admin-Token` matching `SENTINELX_ADMIN_TOKEN`:
- `GET /api/v1/admin/agents`
- `POST /api/v1/admin/agents/{agent_id}/revoke`

Do not expose the admin token in a dashboard or frontend. Operator SSO/RBAC and authenticated dashboard read APIs remain additional production-hardening work before exposure to untrusted networks.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | API + database health |
| POST | `/api/v1/agents/enroll` | Bootstrap-authenticated enrollment |
| POST | `/api/v1/telemetry` | Authenticated telemetry ingest |
| GET | `/api/v1/hosts?limit=100&offset=0&search=...` | Paginated latest host snapshots; total in `X-Total-Count` |
| GET | `/api/v1/summary` | Fleet count and latest 20 hosts |
| GET | `/api/v1/events?limit=100&offset=0` | Bounded event query |
| GET | `/api/v1/disk-history` | Sampled disk history |
| GET | `/api/v1/admin/agents` | Enrolled agent inventory (admin token) |
| POST | `/api/v1/admin/agents/{agent_id}/revoke` | Revoke endpoint credential (admin token) |

## Staging load test

The script creates persistent synthetic enrollment records. Run it only against staging, never production:

```bash
python -m pip install requests
python scripts/load_test.py --url https://staging.example:8443 --token '<bootstrap-token>' --agents 1000 --concurrency 50 --ca /path/to/ca.crt
```

It reports successful enrollments, telemetry acceptance, elapsed time and per-agent latency. Revoke/remove test registrations and data from staging after testing.

## Security and operational notes

- Restrict inbound TLS ingress to trusted networks; keep PostgreSQL and Uvicorn private.
- Use a unique high-entropy bootstrap token and a separate admin token. Store both in a secret manager for larger deployments.
- Never distribute TLS private keys to endpoints; provide only the public CA/certificate chain.
- Protect endpoint state files and installer configuration.
- Back up PostgreSQL and test restore before production.
- Retention defaults: telemetry 30 days, security events 180 days.
- Consider Redis Streams/RabbitMQ/Kafka, time partitioning and additional API instances only after measured ingestion bursts, storage growth or p95 latency justify them. The 1k baseline writes directly to PostgreSQL; it does not claim a message-queue architecture.

## CI and tests

`requirements-dev.txt` includes pytest and httpx. GitHub Actions checks Python compilation, enrollment/authentication/history tests, dashboard JavaScript syntax and Linux shell-script syntax.
