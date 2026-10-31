# SentinelX

SentinelX is an open-source, self-hosted infrastructure monitoring and security telemetry platform for Linux and Windows systems.

It is designed to run inside infrastructure that you control. Each installation has its own central API, database, dashboard, and enrolled agents. SentinelX is not a hosted SaaS service and does not require a cloud account, vendor registration, or organization signup.

## What it does

- Collects endpoint telemetry from Linux and Windows agents.
- Tracks host inventory, CPU, memory, disk, network and host availability.
- Receives rule-based security events from endpoint collectors.
- Provides a central API and web dashboard.
- Stores telemetry in the installation's own database.
- Supports independent deployment without requiring Prometheus, Grafana, Node Exporter or Windows Exporter.

## Architecture

```text
 Linux hosts                         Windows hosts
 +------------------+                +------------------+
 | SentinelX Agent  |                | SentinelX Agent  |
 | collectors       |                | collectors       |
 +--------+---------+                +---------+--------+
          | HTTPS / agent token                |
          +----------------+-------------------+
                           |
                   +-------v--------+
                   | SentinelX      |
                   | Central API    |
                   | FastAPI        |
                   +-------+--------+
                           |
                   +-------v--------+
                   | Local database |
                   | SQLite /       |
                   | PostgreSQL     |
                   +-------+--------+
                           |
                   +-------v--------+
                   | Dashboard      |
                   | /dashboard/    |
                   +----------------+
```

## Quick start (central server)

Requirements: Python 3.11+, a supported database, and a Linux server for the central service.

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

Open `http://127.0.0.1:8000/dashboard/` on the server or access it through a properly secured reverse proxy. The API health endpoint is `/health`.

## Agent configuration

Configure each agent with the central API URL and the installation's agent token using the supported agent configuration for your release. Keep the token secret and do not commit it to source control. The current prototype uses one installation-level token; per-agent enrollment, rotation and revocation are planned security work.

## Important security notes

- The dashboard and monitoring read APIs in this development branch do not yet have built-in user authentication. Bind the API to loopback or a trusted private interface and place it behind a TLS-enabled reverse proxy with access control before allowing remote access.
- Do not expose the dashboard or API directly to the public internet.
- Use a high-entropy agent token, protect environment files, restrict network access, and back up the database.
- The current shared agent token is a prototype, not a per-agent identity system.
- Review [Security](docs/SECURITY.md) and [Self-hosted installation](docs/SELF_HOSTED_INSTALLATION.md) before deploying.

## Project status

SentinelX is under active development. Linux and Windows collectors, central telemetry ingestion, host/event/history APIs and the dashboard are being developed. Check the repository's CI status and release notes before production use.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports, tests, documentation and platform-specific collector improvements are welcome.

## License

A repository license has not yet been selected. Until a license is added, do not assume the code is granted under an open-source license; maintainers should select and add an explicit license before announcing a public open-source release.
