#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/eetemanojkumar-sys/sentinelex.git"
BRANCH="scale-1000-servers"
INSTALL_DIR="/opt/sentinelx-agent"
CONFIG_DIR="/etc/sentinelx-agent"
SERVICE="sentinelx-agent"

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

echo "SentinelX Linux agent installer"
echo "This installs/updates the endpoint agent only; it does not replace the central API or database."

read -rp "Central API base URL [https://127.0.0.1:8443]: " CENTRAL_URL
CENTRAL_URL="${CENTRAL_URL:-https://127.0.0.1:8443}"
CENTRAL_URL="${CENTRAL_URL%/}"
read -rsp "SentinelX agent token: " AGENT_TOKEN
echo
if [[ -z "$AGENT_TOKEN" || "$AGENT_TOKEN" =~ [[:space:]] ]]; then
  echo "Token must be non-empty and contain no whitespace." >&2
  exit 1
fi
read -rp "CA certificate path (blank for system trust): " CA_SOURCE

command -v apt-get >/dev/null || { echo "This installer currently supports Debian/Ubuntu." >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git ca-certificates

if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch origin "$BRANCH"
  git -C "$INSTALL_DIR" checkout "$BRANCH"
  git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
elif [[ -e "$INSTALL_DIR" ]]; then
  echo "$INSTALL_DIR exists but is not a Git checkout; refusing to overwrite it." >&2
  exit 1
else
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/agent/requirements.txt"

install -d -m 0750 -o root -g root "$CONFIG_DIR"
CA_LINE=""
if [[ -n "$CA_SOURCE" ]]; then
  [[ -f "$CA_SOURCE" ]] || { echo "CA certificate not found: $CA_SOURCE" >&2; exit 1; }
  install -m 0644 "$CA_SOURCE" "$CONFIG_DIR/ca.crt"
  CA_LINE="REQUESTS_CA_BUNDLE=$CONFIG_DIR/ca.crt"
else
  rm -f "$CONFIG_DIR/ca.crt"
fi

umask 077
{
  printf 'SENTINELX_URL=%s\n' "$CENTRAL_URL"
  printf 'SENTINELX_AGENT_TOKEN=%s\n' "$AGENT_TOKEN"
  printf 'SENTINELX_HOST_ID=%s\n' "$(hostname)"
  printf 'SENTINELX_INTERVAL=60\n'
  [[ -z "$CA_LINE" ]] || printf '%s\n' "$CA_LINE"
} > "$CONFIG_DIR/agent.env"
unset AGENT_TOKEN

cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=SentinelX cross-platform endpoint agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR/agent
EnvironmentFile=$CONFIG_DIR/agent.env
ExecStart=$INSTALL_DIR/.venv/bin/python $INSTALL_DIR/agent/agent.py
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

chmod 0600 "$CONFIG_DIR/agent.env"
systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 3
systemctl --no-pager --full status "$SERVICE" || true

echo
echo "SentinelX agent installation completed."
echo "Logs: sudo journalctl -u $SERVICE -f"
