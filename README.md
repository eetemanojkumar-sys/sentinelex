# SentinelX

SentinelX is an open-source, self-hosted infrastructure monitoring and security telemetry platform for Linux and Windows systems.

Each installation runs its own central API, database and dashboard. There is no hosted SaaS tenant, customer registration, vendor cloud account or mandatory external service.

## Features

- Linux and Windows endpoint collectors.
- Host inventory, CPU, memory, disk, network and process telemetry.
- Rule-based endpoint security events.
- Central dashboard, metrics history and event APIs.
- Local administrator authentication.
- One-time agent enrollment, unique per-host credentials and revocation.
- Local storage controlled by the operator.

## Architecture

```text
 Linux endpoints                   Windows endpoints
 SentinelX agent                   SentinelX agent
       |                                  |
       +---------- HTTPS ----------------+
                         |
                SentinelX Central API
                Admin auth + enrollment
                         |
                 Local database
                         |
                   Web dashboard
```

## Central server quick start

Requirements: Python 3.11+, a supported SQLAlchemy database, and a private Linux server recommended for the central API.

```bash
git clone https://github.com/eetemanojkumar-sys/sentinelex.git
cd sentinelex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL="sqlite:///./sentinelx.db"
export SENTINELX_ADMIN_USERNAME="admin"
export SENTINELX_ADMIN_PASSWORD="replace-with-a-long-unique-password"
export SENTINELX_COOKIE_SECURE="false"  # local HTTP testing only
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/login` and sign in with the local administrator credentials. For remote access, use HTTPS and set `SENTINELX_COOKIE_SECURE=true`.

## Enroll an agent

1. Sign in as administrator.
2. Create an enrollment token with `POST /api/v1/admin/agents/enrollment-tokens` (JSON body: `{"expires_minutes":30}`).
3. Configure the agent with `SENTINELX_URL`, `SENTINELX_HOST_ID`, and the one-time `SENTINELX_ENROLLMENT_TOKEN`.
4. Start the agent. It exchanges the enrollment token, stores its unique credential locally and uses it for telemetry.
5. Remove the enrollment token from the agent environment after successful enrollment.

Administrators can list credentials using `GET /api/v1/admin/agents` and revoke one using `POST /api/v1/admin/agents/{credential_id}/revoke`.

## Security

The shared legacy agent token is disabled by default. The central API requires administrator authentication for the dashboard and monitoring/admin APIs. See [Security](docs/SECURITY.md) and [Self-hosted installation](docs/SELF_HOSTED_INSTALLATION.md).

Do not expose the API directly to the public internet. Use a TLS reverse proxy, private networking and backups.

## Tests

```bash
python -m unittest server.test_ingestion server.test_auth -v
cd agent
python -m unittest discover -v
```

## Project status

SentinelX is under active development. Review CI and release notes before production use.

## License

SentinelX is distributed under the MIT License. See [LICENSE](LICENSE).
