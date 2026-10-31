#!/usr/bin/env bash
# Create a root-only backup of SentinelX production files and PostgreSQL.
# Run from the SentinelX repository checkout on the central Ubuntu host.
set -Eeuo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo bash deploy/backup-production.sh" >&2
  exit 1
fi

APP_DIR="${SENTINELX_APP_DIR:-/opt/sentinelx}"
CONFIG_DIR="${SENTINELX_CONFIG_DIR:-/etc/sentinelx}"
DB_NAME="${SENTINELX_DB_NAME:-sentinelx}"
BACKUP_ROOT="${SENTINELX_BACKUP_ROOT:-/var/backups/sentinelx}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/$STAMP"

command -v pg_dump >/dev/null || { echo "pg_dump is required." >&2; exit 1; }
command -v tar >/dev/null || { echo "tar is required." >&2; exit 1; }
[[ -d "$APP_DIR" ]] || { echo "Application directory not found: $APP_DIR" >&2; exit 1; }

install -d -m 0700 -o root -g root "$DEST"
trap 'echo "Backup incomplete. Inspect protected directory: $DEST" >&2' ERR

echo "Creating PostgreSQL backup..."
if id postgres >/dev/null 2>&1; then
  sudo -u postgres pg_dump --format=custom --no-owner --no-acl --dbname="$DB_NAME" > "$DEST/postgres.dump"
else
  echo "PostgreSQL OS account 'postgres' not found; refusing to guess DB credentials." >&2
  exit 1
fi
chmod 0600 "$DEST/postgres.dump"
pg_restore --list "$DEST/postgres.dump" >/dev/null

echo "Archiving application and configuration..."
PATHS=()
[[ -e "$APP_DIR" ]] && PATHS+=("${APP_DIR#/}")
[[ -e "$CONFIG_DIR" ]] && PATHS+=("${CONFIG_DIR#/}")
[[ -e /etc/nginx ]] && PATHS+=("etc/nginx")
[[ -e /etc/systemd/system/sentinelx-api.service ]] && PATHS+=("etc/systemd/system/sentinelx-api.service")
[[ -e /etc/systemd/system/sentinelx-agent.service ]] && PATHS+=("etc/systemd/system/sentinelx-agent.service")
tar --xattrs --acls -czf "$DEST/files.tar.gz" -C / "${PATHS[@]}"
chmod 0600 "$DEST/files.tar.gz"

{
  echo "backup_utc=$STAMP"
  echo "app_dir=$APP_DIR"
  echo "config_dir=$CONFIG_DIR"
  echo "database=$DB_NAME"
  echo "api_service=$(systemctl is-active sentinelx-api 2>/dev/null || true)"
  echo "nginx_service=$(systemctl is-active nginx 2>/dev/null || true)"
  echo "postgresql_service=$(systemctl is-active postgresql 2>/dev/null || true)"
} > "$DEST/backup-manifest.txt"
chmod 0600 "$DEST/backup-manifest.txt"

echo "Backup created: $DEST"
echo "Contents: postgres.dump, files.tar.gz, backup-manifest.txt"
echo "Copy this directory to encrypted off-instance storage and test a restore before production changes."
