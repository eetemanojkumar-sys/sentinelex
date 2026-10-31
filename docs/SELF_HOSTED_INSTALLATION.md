# Self-hosted installation

Each SentinelX installation is operated independently by the organization that owns the infrastructure. There is no vendor cloud, tenant registration or shared customer database.

## Central server requirements

- Python 3.11 or later.
- Linux host recommended.
- SQLite for evaluation/small single-node installs, or PostgreSQL for larger installations.
- Private network connectivity from agents.
- TLS reverse proxy for remote administrator access.

## Install and start

```bash
git clone https://github.com/eetemanojkumar-sys/sentinelex.git
cd sentinelex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL="sqlite:///./sentinelx.db"
export SENTINELX_ADMIN_USERNAME="admin"
export SENTINELX_ADMIN_PASSWORD="replace-with-a-long-unique-password"
export SENTINELX_COOKIE_SECURE="false" # local HTTP testing only
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

The administrator password must be at least 12 characters. The first startup creates the local administrator record using a salted PBKDF2-SHA256 hash. Sign in at `/login`. For HTTPS deployments set `SENTINELX_COOKIE_SECURE=true`.

## Enroll a Linux or Windows agent

1. Sign in to the central dashboard.
2. Create a one-time enrollment token:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/admin/agents/enrollment-tokens \
  -H "Content-Type: application/json" \
  -b admin-cookies.txt -c admin-cookies.txt \
  -d '{"expires_minutes":30}'
```

Use an authenticated administrator session; the command above illustrates the API request, not an unauthenticated bootstrap.

3. Configure the agent's environment:
   - `SENTINELX_URL`: central base URL (HTTPS recommended)
   - `SENTINELX_HOST_ID`: unique stable host identifier
   - `SENTINELX_ENROLLMENT_TOKEN`: one-time token
   - `SENTINELX_INTERVAL`: optional collection interval

4. Start the agent. It exchanges the one-time token, receives a unique host-bound credential and saves it under the agent user's `.sentinelx/agent-token` file. On POSIX systems the file is mode 0600. On Windows, protect the service account profile directory with a restrictive ACL.
5. Remove `SENTINELX_ENROLLMENT_TOKEN` from the environment after successful enrollment. The stored per-agent credential is used for subsequent telemetry.

## Agent credential administration

- List enrolled agents: `GET /api/v1/admin/agents`
- Revoke one agent: `POST /api/v1/admin/agents/{credential_id}/revoke`
- Create another enrollment token for replacement/re-enrollment.

Revocation is enforced by the central API on the next telemetry request. To re-enroll a revoked endpoint, remove its local credential file and configure a fresh one-time enrollment token.

## Operations and safety

- Run the central API under a dedicated unprivileged service account.
- Store secrets in a protected environment file (for example, mode 0600).
- Restrict inbound API traffic to known agent networks and administrators.
- Terminate TLS at a trusted reverse proxy.
- Back up the database and test restoration.
- Monitor disk usage and logs.
- Do not expose the development Uvicorn server directly to the public internet.

## Current limitations

The current release supports one local administrator account; multi-user RBAC, MFA, login throttling, automatic schema migrations and a dedicated Windows installer/ACL setup remain future work. Existing installations using the old shared token must enroll agents with new individual credentials before disabling the legacy token permanently. The shared-token compatibility mode is disabled by default.
