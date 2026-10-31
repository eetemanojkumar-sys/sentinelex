# Self-hosted installation

SentinelX is installed and operated by the organization that owns the infrastructure. There is no central SentinelX cloud, customer registration, hosted tenant, or vendor-managed database.

## Deployment model

A deployment consists of:
1. One central SentinelX API and dashboard.
2. One database owned and backed up by the operator.
3. SentinelX agents installed on monitored Linux and Windows endpoints.
4. Private network connectivity from agents to the central API.

Each operator runs an independent installation. Separate installations do not share accounts, telemetry or storage.

## Central server

### Requirements

- Python 3.11 or later.
- Linux host recommended for the central API.
- SQLite for evaluation/small single-node installations, or PostgreSQL for larger installations.
- Network reachability from enrolled agents.
- A reverse proxy with TLS for remote dashboard/API access.

### Install

```bash
git clone https://github.com/eetemanojkumar-sys/sentinelex.git
cd sentinelex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SENTINELX_AGENT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DATABASE_URL="sqlite:///./sentinelx.db"
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

For PostgreSQL, set `DATABASE_URL` to a SQLAlchemy PostgreSQL URL and install/configure the database before starting the API.

### Verify

```bash
curl http://127.0.0.1:8000/health
```

Open the dashboard at `http://127.0.0.1:8000/dashboard/` from the server itself. For remote access, use a TLS reverse proxy and authentication/access-control layer. Do not bind the development API to a public interface without these controls.

## Agent deployment

Install the agent from the repository on each supported endpoint and configure:
- central API base URL,
- installation agent token,
- collection interval and local collection settings.

The current prototype authenticates ingestion with a single installation-level token in the `X-Agent-Token` header. Protect it as a secret. Per-agent enrollment, credential rotation and revocation are not yet implemented.

## Operations

- Run the central API under a dedicated unprivileged service account.
- Store environment variables in a root-readable environment file.
- Restrict inbound API traffic to known agent networks and administrators.
- Terminate TLS at a trusted reverse proxy.
- Back up the database and test restoration.
- Monitor disk usage and log rotation.
- Upgrade from a reviewed release/commit and keep a rollback copy.

## Current limitations

This is a development-stage self-hosted project. Built-in dashboard user authentication, per-agent credential management, automatic database migrations, alert delivery and production hardening are not yet complete. Use network-level access controls until application authentication is implemented.
