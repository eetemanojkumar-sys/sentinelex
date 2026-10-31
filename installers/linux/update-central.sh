#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/eetemanojkumar-sys/sentinelex"
BRANCH="scale-1000-servers"
APP_DIR="${SENTINELX_APP_DIR:-/opt/sentinelx}"
ENV_FILE="/etc/sentinelx/sentinelx.env"
SERVICE="sentinelx-api"
TMP="$(mktemp -d)"
STAMP="$(date +%Y%m%d%H%M%S)"
BACKUP="$APP_DIR/.sentinelx-backup-$STAMP"

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

if [[ "$EUID" -ne 0 ]]; then
  echo "Run on the central Ubuntu server with sudo." >&2
  exit 1
fi
[[ -f "$APP_DIR/server/main.py" ]] || { echo "Central API not found at $APP_DIR/server/main.py" >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Environment file not found: $ENV_FILE" >&2; exit 1; }
[[ -x "$APP_DIR/venv/bin/uvicorn" ]] || { echo "Expected virtualenv not found at $APP_DIR/venv" >&2; exit 1; }

echo "Downloading SentinelX 1k-fleet release..."
curl -fsSL "$REPO/archive/refs/heads/$BRANCH.zip" -o "$TMP/release.zip"
unzip -q "$TMP/release.zip" -d "$TMP"
SRC="$TMP/sentinelex-$BRANCH"
[[ -f "$SRC/server/main.py" && -f "$SRC/dashboard/index.html" ]] || { echo "Release archive is incomplete." >&2; exit 1; }

mkdir -p "$BACKUP"
cp -a "$APP_DIR/server/main.py" "$BACKUP/main.py"
[[ ! -d "$APP_DIR/dashboard" ]] || cp -a "$APP_DIR/dashboard" "$BACKUP/dashboard"
mkdir -p "$APP_DIR/scripts"
cp -a "$SRC/server/main.py" "$APP_DIR/server/main.py"
rm -rf "$APP_DIR/dashboard.new"
cp -a "$SRC/dashboard" "$APP_DIR/dashboard.new"
rm -rf "$APP_DIR/dashboard"
mv "$APP_DIR/dashboard.new" "$APP_DIR/dashboard"
cp -a "$SRC/scripts/retention_cleanup.py" "$APP_DIR/scripts/retention_cleanup.py"

if id sentinelx >/dev/null 2>&1; then
  chown -R sentinelx:sentinelx "$APP_DIR/server" "$APP_DIR/dashboard" "$APP_DIR/scripts"
fi

# Create an admin credential once. It is stored only in the root-protected env file.
if ! grep -q '^SENTINELX_ADMIN_TOKEN=' "$ENV_FILE"; then
  printf '\nSENTINELX_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" >> "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
fi

# Two API workers are a conservative starting point for a 2-vCPU central EC2.
# Tune pool sizes and workers upward only after load testing the actual database.
DROPIN="/etc/systemd/system/$SERVICE.service.d"
mkdir -p "$DROPIN"
cat > "$DROPIN/scale.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/sentinelx/venv/bin/uvicorn server.main:app --host 127.0.0.1 --port 8000 --workers 2
Environment=SENTINELX_HISTORY_INTERVAL_SECONDS=300
Environment=DB_POOL_SIZE=5
Environment=DB_MAX_OVERFLOW=5
Environment=DB_POOL_TIMEOUT=30
EOF

cat > /etc/systemd/system/sentinelx-retention.service <<'EOF'
[Unit]
Description=SentinelX telemetry retention cleanup
After=postgresql.service
Wants=postgresql.service

[Service]
Type=oneshot
User=sentinelx
Group=sentinelx
WorkingDirectory=/opt/sentinelx
EnvironmentFile=/etc/sentinelx/sentinelx.env
Environment=SENTINELX_TELEMETRY_RETENTION_DAYS=30
Environment=SENTINELX_EVENT_RETENTION_DAYS=180
ExecStart=/opt/sentinelx/venv/bin/python /opt/sentinelx/scripts/retention_cleanup.py
NoNewPrivileges=true
PrivateTmp=true
EOF

cat > /etc/systemd/system/sentinelx-retention.timer <<'EOF'
[Unit]
Description=Daily SentinelX telemetry retention cleanup

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=900

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sentinelx-retention.timer
systemctl restart "$SERVICE"
sleep 4

if ! systemctl is-active --quiet "$SERVICE"; then
  echo "API restart failed; restoring previous API and dashboard." >&2
  cp -a "$BACKUP/main.py" "$APP_DIR/server/main.py"
  if [[ -d "$BACKUP/dashboard" ]]; then
    rm -rf "$APP_DIR/dashboard"
    cp -a "$BACKUP/dashboard" "$APP_DIR/dashboard"
  fi
  rm -f "$DROPIN/scale.conf"
  systemctl daemon-reload
  systemctl restart "$SERVICE" || true
  exit 1
fi

if ! curl -fsS http://127.0.0.1:8000/health; then
  echo "Health check failed. Inspect journalctl -u $SERVICE." >&2
  exit 1
fi

echo
echo "SentinelX 1k-fleet central update installed."
echo "API workers: 2; per-worker DB pool: 5 + 5 overflow"
echo "Latest host snapshot is updated every heartbeat; historical samples are stored at 5-minute intervals."
echo "Retention: 30 days telemetry, 180 days security events."
echo "Admin token is stored in $ENV_FILE; do not print or share it."
echo "Backup: $BACKUP"
echo "Check: sudo journalctl -u $SERVICE -n 50 --no-pager"
