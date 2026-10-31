#!/usr/bin/env bash
set -Eeuo pipefail

REPO="https://github.com/eetemanojkumar-sys/sentinelex"
BRANCH="dashboard-single-command-install"
APP_DIR="${SENTINELX_APP_DIR:-/opt/sentinelx}"
SERVICE="sentinelx-api"
TMP_DIR="$(mktemp -d)"
BACKUP_DIR=""

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this updater with sudo." >&2
  exit 1
fi
if [[ ! -f "$APP_DIR/server/main.py" ]]; then
  echo "SentinelX central API not found at $APP_DIR; set SENTINELX_APP_DIR if installed elsewhere." >&2
  exit 1
fi
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }
command -v unzip >/dev/null || { apt-get update && apt-get install -y unzip; }

echo "Downloading SentinelX dashboard release..."
curl -fsSL "$REPO/archive/refs/heads/$BRANCH.zip" -o "$TMP_DIR/release.zip"
unzip -q "$TMP_DIR/release.zip" -d "$TMP_DIR"
SOURCE_DIR="$TMP_DIR/sentinelex-$BRANCH/dashboard"
[[ -f "$SOURCE_DIR/index.html" && -f "$SOURCE_DIR/app.js" ]] || {
  echo "Dashboard files missing from downloaded release." >&2
  exit 1
}

BACKUP_DIR="$APP_DIR/dashboard.backup.$(date +%Y%m%d%H%M%S)"
if [[ -d "$APP_DIR/dashboard" ]]; then
  cp -a "$APP_DIR/dashboard" "$BACKUP_DIR"
fi
rm -rf "$APP_DIR/dashboard.new"
cp -a "$SOURCE_DIR" "$APP_DIR/dashboard.new"
rm -rf "$APP_DIR/dashboard"
mv "$APP_DIR/dashboard.new" "$APP_DIR/dashboard"

if id sentinelx >/dev/null 2>&1; then
  chown -R sentinelx:sentinelx "$APP_DIR/dashboard"
fi

systemctl restart "$SERVICE"
sleep 2
if ! systemctl is-active --quiet "$SERVICE"; then
  echo "API did not remain active; restoring previous dashboard." >&2
  rm -rf "$APP_DIR/dashboard"
  if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
    mv "$BACKUP_DIR" "$APP_DIR/dashboard"
  fi
  systemctl restart "$SERVICE" || true
  exit 1
fi

echo "Dashboard updated successfully."
echo "Open: https://YOUR-CENTRAL-HOST:8443/dashboard/"
echo "API service: $(systemctl is-active "$SERVICE")"
if [[ -n "$BACKUP_DIR" ]]; then
  echo "Previous dashboard backup: $BACKUP_DIR"
fi
