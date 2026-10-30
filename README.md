# SentinelX

SentinelX is a **rule-based Linux system health and security monitoring project** written in Python.

Initial target: **one Ubuntu EC2 instance**. The first version runs directly on Linux using Python virtual environments and systemd. It does not use Docker, AI, machine learning, Kubernetes, or predictive analytics.

## Initial features

- CPU, memory, disk utilization and uptime collection
- Disk usage warnings at 80% and critical alerts at 90%
- New, modified, and deleted file event monitoring in configured directories
- Detection and SHA-256 inventory of ML model file types (the files are identified only; they are never loaded or executed)
- Running-process and listening-port inventory
- Basic ClamAV executable and daemon status checks
- Central FastAPI ingestion API and PostgreSQL persistence
- Shared-token authentication for the initial single-host deployment

## Architecture

```text
Ubuntu EC2
  |-- Python monitoring agent (systemd)
  |     |-- psutil: CPU / RAM / disk / processes / ports
  |     |-- watchdog: file changes
  |     |-- hashlib: SHA-256
  |     |-- ClamAV status check
  |     |
  |     +---- HTTPS / authenticated request ----+
  |                                               |
  |-- FastAPI service (systemd) <-----------------+
        |
        +-- PostgreSQL
        +-- REST API for hosts, events and summary
        +-- Nginx reverse proxy (deployment step)
```

For phase 1, the agent and API can run on the same EC2 instance. The agent posts to localhost. Later, agents on more Linux servers can send telemetry to a dedicated central host.

## Repository layout

```text
sentinelex/
├── agent/
│   ├── agent.py
│   └── requirements.txt
├── server/
│   ├── __init__.py
│   └── main.py
├── deploy/
│   ├── sentinelx-api.service
│   └── sentinelx-agent.service
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Run on Ubuntu EC2 (without Docker)

### 1. Install operating-system packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql postgresql-contrib clamav clamav-daemon
```

ClamAV is optional for the first run. Its presence and daemon status are reported; SentinelX does not claim that a malware scan has taken place.

### 2. Create the application account and directories

```bash
sudo useradd --system --create-home --home-dir /opt/sentinelx --shell /usr/sbin/nologin sentinelx
sudo mkdir -p /opt/sentinelx
sudo chown -R sentinelx:sentinelx /opt/sentinelx
```

Clone or copy this repository into `/opt/sentinelx`, then:

```bash
cd /opt/sentinelx
sudo -u sentinelx python3 -m venv venv
sudo -u sentinelx ./venv/bin/pip install -r requirements.txt
sudo -u sentinelx ./venv/bin/pip install -r agent/requirements.txt
```

### 3. Configure environment

Create an environment file outside the Git repository, for example `/etc/sentinelx/sentinelx.env`:

```bash
sudo install -d -m 0750 -o root -g sentinelx /etc/sentinelx
sudo sh -c 'umask 027; cat > /etc/sentinelx/sentinelx.env' <<'EOF'
SENTINELX_AGENT_TOKEN=REPLACE_WITH_A_LONG_RANDOM_SECRET
DATABASE_URL=postgresql+psycopg://sentinelx:REPLACE_DB_PASSWORD@127.0.0.1:5432/sentinelx
SENTINELX_URL=http://127.0.0.1:8000
SENTINELX_HOST_ID=ec2-ubuntu
SENTINELX_INTERVAL=30
SENTINELX_WATCH_PATHS=/etc,/opt,/var/www,/home
EOF
sudo chown root:sentinelx /etc/sentinelx/sentinelx.env
sudo chmod 0640 /etc/sentinelx/sentinelx.env
```

Generate secrets yourself; never commit real credentials. Configure PostgreSQL role/database to match the DSN above. Example:

```bash
sudo -u postgres psql
```

Inside psql, replace the password placeholder with a strong password:

```sql
CREATE ROLE sentinelx LOGIN PASSWORD 'REPLACE_DB_PASSWORD';
CREATE DATABASE sentinelx OWNER sentinelx;
\q
```

### 4. Configure services

Review the service files in `deploy/`, then install them:

```bash
sudo cp deploy/sentinelx-api.service /etc/systemd/system/
sudo cp deploy/sentinelx-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelx-api sentinelx-agent
sudo systemctl status sentinelx-api sentinelx-agent
```

### 5. Verify

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/hosts
curl http://127.0.0.1:8000/api/v1/events
curl http://127.0.0.1:8000/api/v1/summary
```

API documentation is available at `http://127.0.0.1:8000/docs` locally.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | API health |
| POST | `/api/v1/telemetry` | Authenticated agent telemetry ingestion |
| GET | `/api/v1/hosts` | Latest metrics per host |
| GET | `/api/v1/events` | Recent events |
| GET | `/api/v1/summary` | Fleet summary |

## Detection rules

| Signal | Initial rule |
|---|---|
| Disk usage | Warning >= 80%; critical >= 90% |
| New file | Record event under watched paths |
| Modified model file | Record event and SHA-256 digest |
| ClamAV daemon | Report active/inactive/unknown |
| Process inventory | Report sampled process information |
| Listening ports | Report current listening sockets |

These are monitoring indicators, not proof of compromise. The first implementation has no automatic remediation or process termination.

## Security and limitations

- Keep the API bound to localhost until a TLS reverse proxy and firewall policy are configured.
- Use a long, unique agent token; rotate it if exposed. The first version uses one shared token, suitable only for controlled single-host testing.
- Avoid watching pseudo-filesystems such as `/proc`, `/sys`, and `/dev`; do not watch high-churn or huge trees without tuning.
- File events can be missed during downtime or when Linux inotify limits are reached. A later integrity-baseline scan can complement event watching.
- Some process, port, and system data require elevated permissions. Run with the least privileges that meet the monitoring requirements.
- The initial ClamAV check checks binary presence and daemon state; it does not inspect detection signatures, real-time protection configuration, or scan results.
- Login auditing, account/privilege change detection, package change monitoring, per-agent credentials, alert notifications, retention policies, and the web dashboard are planned work.

## Development principles

Python + Linux native services. No Docker. No AI/ML. No Kubernetes. Rules and transparent threshold/event logic only.
