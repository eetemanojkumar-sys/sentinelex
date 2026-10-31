#!/usr/bin/env bash
# SentinelX safe Ubuntu/Debian one-command installer.
set -Eeuo pipefail
IFS=$'\n\t'
REPO_URL="$(printenv SENTINELX_REPO_URL || true)"
BRANCH="$(printenv SENTINELX_BRANCH || true)"
APP_DIR="$(printenv SENTINELX_APP_DIR || true)"
[ -n "$REPO_URL" ] || REPO_URL="https://github.com/eetemanojkumar-sys/sentinelex.git"
[ -n "$BRANCH" ] || BRANCH="deployment-automation"
[ -n "$APP_DIR" ] || APP_DIR="/opt/sentinelx"
CONFIG_DIR=/etc/sentinelx
ENV_FILE="$CONFIG_DIR/sentinelx.env"
BACKUP_ROOT=/var/backups/sentinelx
STATE_DIR=/var/lib/SentinelX
MODE=install
SKIP_AGENT=0
SKIP_POSTGRES=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --skip-agent) SKIP_AGENT=1; shift ;;
    --skip-postgres) SKIP_POSTGRES=1; shift ;;
    -h|--help) echo "Usage: sudo ./install.sh [--mode install|update|backup|repair] [--skip-agent] [--skip-postgres]"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done
[ "$EUID" -eq 0 ] || { echo "Run with sudo/root."; exit 1; }
case "$MODE" in install|update|backup|repair) ;; *) echo "Invalid mode"; exit 2 ;; esac
command -v apt-get >/dev/null || { echo "Ubuntu/Debian required."; exit 1; }
command -v systemctl >/dev/null || { echo "systemd required."; exit 1; }
log(){ printf '\n[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
mkdir -p "$BACKUP_ROOT" "$CONFIG_DIR" "$STATE_DIR"
chmod 0750 "$CONFIG_DIR"; chmod 0700 "$STATE_DIR"

backup_existing() {
  STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
  ARCHIVE="$BACKUP_ROOT/sentinelx-files-$STAMP.tar.gz"
  tar -czf "$ARCHIVE" -C / \
    --exclude=opt/sentinelx/venv --exclude=opt/sentinelx/.git \
    opt/sentinelx etc/sentinelx var/lib/SentinelX 2>/dev/null || {
      rm -f "$ARCHIVE"
      die "File backup failed; stopping before changes."
    }
  chmod 0600 "$ARCHIVE"
  log "File/config/agent-state backup created: $ARCHIVE"
  if [ -f "$ENV_FILE" ]; then
    python3 - "$ENV_FILE" "$BACKUP_ROOT" "$STAMP" <<'PY'
import os, sys, subprocess, tempfile, shutil
from pathlib import Path
from urllib.parse import urlsplit, unquote
cfg, root, stamp = sys.argv[1:]
values = {}
for raw in Path(cfg).read_text().splitlines():
    line = raw.strip()
    if line and not line.startswith("#") and "=" in line:
        k,v = line.split("=",1); values[k.strip()] = v.strip().strip('"').strip("'")
url = values.get("DATABASE_URL","")
if not url.startswith(("postgresql://","postgres://","postgresql+psycopg://")):
    print("No PostgreSQL URL detected; database dump skipped.")
    raise SystemExit(0)
pg_dump = shutil.which("pg_dump")
if not pg_dump:
    print("pg_dump unavailable; cannot safely continue.", file=sys.stderr); raise SystemExit(3)
p = urlsplit(url.replace("postgresql+psycopg://","postgresql://",1))
host,port = p.hostname or "127.0.0.1", str(p.port or 5432)
db,user,password = unquote(p.path.lstrip("/")),unquote(p.username or ""),unquote(p.password or "")
if not db or not user:
    print("DATABASE_URL incomplete; database backup aborted.",file=sys.stderr); raise SystemExit(4)
def esc(x): return str(x).replace("\\","\\\\").replace(":","\\:")
fd,pf = tempfile.mkstemp(prefix="sentinelx-pgpass-"); os.fchmod(fd,0o600)
with os.fdopen(fd,"w") as f: f.write(":".join(map(esc,[host,port,db,user,password]))+"\n")
out = Path(root) / ("sentinelx-db-"+stamp+".dump")
env = os.environ.copy(); env["PGPASSFILE"] = pf
try: rc = subprocess.run([pg_dump,"-h",host,"-p",port,"-U",user,"-d",db,"-Fc","-f",str(out)],env=env).returncode
finally: Path(pf).unlink(missing_ok=True)
if rc:
    out.unlink(missing_ok=True); print("PostgreSQL dump failed; stopping.",file=sys.stderr); raise SystemExit(rc)
os.chmod(out,0o600); print("PostgreSQL database dump created: "+str(out))
PY
  fi
}
if [ "$MODE" = backup ]; then backup_existing; exit 0; fi
if [ -d "$APP_DIR" ] || [ -f "$ENV_FILE" ]; then
  log "Existing installation found; backing up before changes."
  backup_existing
fi
if [ "$MODE" = repair ] && [ ! -f "$ENV_FILE" ]; then die "No existing config; use install mode."; fi

log "Installing operating-system dependencies."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git rsync python3 python3-venv python3-pip openssl
if [ "$SKIP_POSTGRES" -eq 0 ]; then
  apt-get install -y postgresql postgresql-contrib
  systemctl enable --now postgresql
fi
mkdir -p "$APP_DIR" "$CONFIG_DIR" "$STATE_DIR"
if ! id sentinelx >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --no-create-home --shell /usr/sbin/nologin sentinelx
fi

if [ "$MODE" != repair ]; then
  STAGE="$(mktemp -d)"
  trap 'rm -rf "$STAGE"' EXIT
  log "Downloading SentinelX release branch: $BRANCH"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$STAGE/repo"
  rsync -a --exclude='.git/' --exclude='venv/' --exclude='*.db' --exclude='*.sqlite' --exclude='*.sqlite3' "$STAGE/repo/" "$APP_DIR/"
fi

if [ ! -f "$ENV_FILE" ]; then
  [ "$SKIP_POSTGRES" -eq 0 ] || die "Cannot create default config with --skip-postgres."
  log "Generating first-run credentials and PostgreSQL database."
  AGENT_TOKEN="$(openssl rand -hex 32)"
  ADMIN_TOKEN="$(openssl rand -hex 32)"
  DB_PASSWORD="$(openssl rand -hex 32)"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_password="$DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE sentinelx LOGIN PASSWORD %L', :'db_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='sentinelx') \gexec
SELECT format('CREATE DATABASE sentinelx OWNER sentinelx')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='sentinelx') \gexec
SQL
  umask 027
  cat > "$ENV_FILE" <<EOF
SENTINELX_AGENT_TOKEN=$AGENT_TOKEN
SENTINELX_ADMIN_TOKEN=$ADMIN_TOKEN
DATABASE_URL=postgresql+psycopg://sentinelx:$DB_PASSWORD@127.0.0.1:5432/sentinelx
SENTINELX_URL=http://127.0.0.1:8000
SENTINELX_INTERVAL=30
SENTINELX_WATCH_PATHS=/etc,/opt,/var/www,/home
SENTINELX_STATE_FILE=$STATE_DIR/agent.json
SENTINELX_QUEUE_PATH=$STATE_DIR/outbox.sqlite3
EOF
  unset AGENT_TOKEN ADMIN_TOKEN DB_PASSWORD
fi
ensure_setting() {
  KEY="$1"; VALUE="$2"
  if ! grep -q "^$KEY=" "$ENV_FILE"; then printf '%s=%s\n' "$KEY" "$VALUE" >> "$ENV_FILE"; fi
}
ensure_setting SENTINELX_AGENT_TOKEN "$(openssl rand -hex 32)"
ensure_setting SENTINELX_ADMIN_TOKEN "$(openssl rand -hex 32)"
ensure_setting SENTINELX_URL "http://127.0.0.1:8000"
ensure_setting SENTINELX_INTERVAL "30"
ensure_setting SENTINELX_WATCH_PATHS "/etc,/opt,/var/www,/home"
ensure_setting SENTINELX_STATE_FILE "$STATE_DIR/agent.json"
ensure_setting SENTINELX_QUEUE_PATH "$STATE_DIR/outbox.sqlite3"
chown root:sentinelx "$ENV_FILE"; chmod 0640 "$ENV_FILE"
chown -R sentinelx:sentinelx "$APP_DIR"; chmod 0750 "$APP_DIR"
chown root:root "$CONFIG_DIR"; chmod 0750 "$CONFIG_DIR"
chown root:root "$STATE_DIR"; chmod 0700 "$STATE_DIR"

log "Installing isolated Python dependencies."
if [ ! -x "$APP_DIR/venv/bin/python" ]; then sudo -u sentinelx python3 -m venv "$APP_DIR/venv"; fi
sudo -u sentinelx "$APP_DIR/venv/bin/python" -m pip install --upgrade pip
sudo -u sentinelx "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
if [ -f "$APP_DIR/agent/requirements.txt" ]; then
  sudo -u sentinelx "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/agent/requirements.txt"
fi

log "Installing systemd services."
install -m 0644 "$APP_DIR/deploy/sentinelx-api.service" /etc/systemd/system/sentinelx-api.service
if [ "$SKIP_AGENT" -eq 0 ]; then install -m 0644 "$APP_DIR/deploy/sentinelx-agent.service" /etc/systemd/system/sentinelx-agent.service; fi
systemctl daemon-reload
systemctl enable sentinelx-api
if [ "$SKIP_AGENT" -eq 0 ]; then systemctl enable sentinelx-agent; fi
systemctl restart sentinelx-api
if [ "$SKIP_AGENT" -eq 0 ]; then systemctl restart sentinelx-agent; fi

log "Waiting for API and database health."
HEALTHY=0
for attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:8000/health >/dev/null; then HEALTHY=1; break; fi
  sleep 2
done
if [ "$HEALTHY" -eq 0 ]; then
  systemctl --no-pager --full status sentinelx-api || true
  journalctl -u sentinelx-api -n 80 --no-pager || true
  die "Health check failed. Backups remain under $BACKUP_ROOT."
fi
systemctl is-active --quiet sentinelx-api || die "API is not active."
if [ "$SKIP_AGENT" -eq 0 ]; then systemctl is-active --quiet sentinelx-agent || die "Linux agent is not active."; fi
echo
echo "SentinelX deployment completed."
echo "API health: http://127.0.0.1:8000/health"
echo "Dashboard:  http://127.0.0.1:8000/dashboard/"
echo "Config:     $ENV_FILE (secrets are not printed)"
echo "Backups:    $BACKUP_ROOT"
echo "API bind:   127.0.0.1; use a TLS reverse proxy for remote access."
echo "Windows endpoints use deploy/install-windows-agent.ps1."
