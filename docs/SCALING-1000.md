# SentinelX scale target: 1,000 endpoints

## Scope and operating assumptions

This release targets an initial fleet of 1,000 Linux and Windows servers reporting to one central SentinelX control plane.

Recommended baseline:
- 1,000 enrolled endpoints
- 60-second agent heartbeat (configurable per endpoint)
- Approximately 16.7 telemetry requests/second at steady state
- 100-host dashboard pages; server-side search and pagination
- Live host snapshot updated on every accepted heartbeat
- Compact historical resource/disk sample no more than once every 5 minutes per host
- 30-day telemetry history and 180-day security-event retention
- Two Uvicorn workers as a conservative starting point on a 2-vCPU central host
- SQLAlchemy pool size 5 plus overflow 5 per worker (20 maximum pooled connections for two workers)

At these settings the history table receives about 288,000 samples/day (1,000 hosts × 12 samples/hour × 24 hours), rather than 1.44 million full telemetry snapshots/day. Actual capacity depends on JSON size, event volume, PostgreSQL/RDS storage, IOPS, network latency and dashboard usage. Load test the actual instance class before production sign-off.

## Architecture

```text
             Linux agent 001 ... Linux agent N
             Windows agent 001 ... Windows agent N
                        | HTTPS / TLS
                        v
                 Nginx / TLS ingress
                        |
                        v
               FastAPI API workers (2+)
                  |             |
          enrollment/auth    telemetry ingest
                  |             |
                  v             v
          Agent credentials  HostLatest (one row/host)
                             Telemetry history (5-min)
                             Security events
                                  |
                                  v
                            PostgreSQL
                                  |
                                  v
                  Dashboard (100-host pages)
```

The API is stateless across workers. Agent credentials, host snapshots, history and events are stored in PostgreSQL. Do not put per-host identity or queues in process-local memory.

## Per-agent identity lifecycle

1. The endpoint installer receives the central URL, TLS CA certificate (if private), and bootstrap/enrollment token.
2. First agent start posts hostname, OS and a machine-generated persistent ID to `POST /api/v1/agents/enroll`.
3. The central API stores only SHA-256 of a newly generated per-agent token and returns that token once.
4. The agent stores agent ID, host ID and token in a local protected state file:
   - Linux: `/var/lib/SentinelX/agent.json` (agent runs as root; file mode 0600)
   - Windows: `%ProgramData%\SentinelX\agent.json` (restrict directory ACL to SYSTEM and Administrators)
5. All subsequent telemetry uses that per-agent token. The API verifies the token and requires the submitted host ID to match the enrolled identity.
6. Operators can list/revoke enrolled credentials using the admin API and `X-Admin-Token`.

The bootstrap token is still used for new enrollment. During migration, legacy shared-token telemetry is allowed by default for existing agents. After every endpoint has enrolled, set `SENTINELX_ALLOW_LEGACY_TOKEN=false` in the central environment and restart the API. Keep the enrollment token in a protected secret store; rotate it after rollout and distribute the new enrollment token through your approved provisioning process.

## API and database behavior

- `agent_credentials`: unique agent ID, unique host ID, token hash, OS, last seen, revocation state.
- `host_latest`: one current snapshot per host, updated every heartbeat.
- `telemetry`: compact resource/disk history, sampled at a configurable interval.
- `security_events`: event records with host/time and severity/time indexes.
- `GET /api/v1/hosts?limit=100&offset=0&search=...`: server-side pagination; total is returned in `X-Total-Count`.
- `GET /api/v1/summary`: total fleet count plus 20 latest host snapshots.
- `GET /api/v1/events?limit=100&offset=0&host_id=...`: bounded event query.
- `POST /api/v1/agents/enroll`: bootstrap-authenticated endpoint enrollment.
- `POST /api/v1/admin/agents/{agent_id}/revoke`: requires `X-Admin-Token`.

Schema creation adds new tables on API startup. Existing telemetry rows are not automatically backfilled into `host_latest`; each upgraded endpoint creates its latest row on its next heartbeat.

## Retention

The central updater installs a daily systemd timer:
- Telemetry history: 30 days
- Security events: 180 days

Adjust `SENTINELX_TELEMETRY_RETENTION_DAYS` and `SENTINELX_EVENT_RETENTION_DAYS` in the retention service if policy requires it. Back up PostgreSQL before changing retention or upgrading the API.

## Deployment commands

### Update existing central Ubuntu deployment

Run on the existing central host (expected paths: `/opt/sentinelx`, `/opt/sentinelx/venv`, `/etc/sentinelx/sentinelx.env`):

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/linux/update-central.sh | sudo bash
```

The updater backs up the API module/dashboard, installs the new API and dashboard, creates a protected admin token if absent, configures two API workers, enables daily retention cleanup, restarts the API and checks `/health`. Review the backup and logs after upgrade.

### Enroll a Linux endpoint

```bash
curl -fsSL https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/linux/install.sh | sudo bash
```

### Enroll a Windows endpoint

Run in elevated PowerShell:

```powershell
irm https://raw.githubusercontent.com/eetemanojkumar-sys/sentinelex/scale-1000-servers/installers/windows/Install-SentinelX.ps1 | iex
```

Installers use a 60-second reporting interval and enroll each machine to receive a unique credential. Provide the same bootstrap/enrollment token from the central environment to each authorized installer.

## Load test

Run only against a staging deployment. This test creates persistent enrollment records and sends one telemetry report per synthetic host:

```bash
python -m pip install requests
python scripts/load_test.py --url https://staging.example:8443 --token '<enrollment-token>' --agents 1000 --concurrency 50 --ca /path/to/ca.crt
```

Do not run this against production: the test creates 1,000 synthetic agent registrations and latest-host records. Revoke/remove test data from staging after measuring.

## Production readiness checklist

- [ ] Load test 1,000 concurrent enrollments and 1,000 telemetry heartbeats on staging.
- [ ] Measure API p50/p95/p99 latency, PostgreSQL CPU/IOPS, active connections, disk growth and event write rate.
- [ ] Size PostgreSQL/RDS storage and backup/restore procedures based on measured row sizes.
- [ ] Configure Nginx request body limits, rate limits, TLS, access logs and trusted-source security groups.
- [ ] Put the bootstrap and admin tokens in a secret manager; rotate bootstrap after endpoint migration.
- [ ] Set `SENTINELX_ALLOW_LEGACY_TOKEN=false` after all agents have per-agent credentials.
- [ ] Add authenticated operator access / SSO to dashboard read APIs before exposing dashboard beyond a trusted network.
- [ ] Test API restart, database restart, endpoint offline/reconnect and controlled EC2 reboot.
- [ ] Consider Redis/RabbitMQ/Kafka only if measured bursts or downstream processing require durable decoupling. The current 1k baseline writes directly to PostgreSQL; it does not claim queue-based ingestion.

## Scale beyond 1,000

For several thousand endpoints, load-test and scale horizontally:
- Add API workers/instances behind Nginx or an AWS load balancer.
- Keep shared state in PostgreSQL or a durable queue; never rely on worker memory.
- Consider partitioning telemetry by time and archiving older partitions.
- Add a queue (Redis Streams, RabbitMQ or Kafka) if ingestion bursts or downstream consumers justify its operational cost.
- Separate dashboard read traffic from ingest traffic if measured load requires it.
- Tune heartbeat jitter so endpoints do not all report on the same clock boundary.
