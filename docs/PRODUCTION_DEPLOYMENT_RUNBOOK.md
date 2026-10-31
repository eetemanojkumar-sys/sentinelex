# SentinelX production deployment runbook

**Deployment strategy:** upgrade the existing central Ubuntu EC2 host in a controlled maintenance window. Do not replace the production instance or database as part of this release.

## 1. Current deployment layout

The documented live layout is:

- Application: `/opt/sentinelx`
- Python environment: `/opt/sentinelx/venv`
- API service: `sentinelx-api` (Uvicorn on `127.0.0.1:8000`)
- Agent service, if this host is also monitored: `sentinelx-agent`
- Environment file: `/etc/sentinelx/sentinelx.env`
- TLS material: `/etc/sentinelx/tls/`
- Nginx: HTTPS reverse proxy on port `8443`
- PostgreSQL database: `sentinelx`
- Health endpoint: `https://127.0.0.1:8443/health`
- Dashboard: `https://127.0.0.1:8443/dashboard/`

Confirm these values on the host before running any command. Do not overwrite the production environment file, TLS private key, Nginx configuration, or database.

## 2. Release gate — do not skip

The repository contains central API code, endpoint installers, and scaling changes, but a green agent unit-test workflow alone is not a production release qualification.

Before production:
1. Run the complete CI suite on the exact candidate commit (Linux and Windows).
2. Run API integration tests against a disposable PostgreSQL database.
3. Validate the candidate on a staging Ubuntu instance with a copy of the production schema and synthetic data. Never run the 1,000-agent load test against production.
4. Verify enrollment, telemetry ingestion, pagination, dashboard rendering, retention cleanup, and Linux/Windows agent compatibility.
5. Confirm the database schema change plan. The API currently uses SQLAlchemy `create_all`; that creates missing tables but is not a safe substitute for versioned migrations when changing existing schemas. Do not assume it upgrades existing columns.
6. Confirm authentication and network exposure. Dashboard/read endpoints must not be exposed to untrusted networks without authentication and authorization. Keep PostgreSQL and port 8000 private. Restrict port 8443 to trusted endpoint networks and administrative access.
7. Confirm the bootstrap/legacy-token policy and rotate any previously exposed credentials. Never place secrets in Git, command-line arguments, tickets, or deployment logs.

**Stop condition:** if any gate is not satisfied, keep the current production version running.

## 3. Pre-deployment checks

Run on the central host:

```bash
sudo systemctl status sentinelx-api --no-pager
sudo systemctl status nginx --no-pager
sudo systemctl status postgresql --no-pager
sudo ss -ltnp
curl -kfsS https://127.0.0.1:8443/health
```

Check disk space and recent errors:

```bash
df -h
sudo journalctl -u sentinelx-api -n 100 --no-pager
sudo nginx -t
```

Do not paste environment-file contents or private-key material into chat or logs.

## 4. Create a recoverable backup

Use the repository backup helper from the candidate checkout:

```bash
sudo bash deploy/backup-production.sh
```

The helper creates a root-only backup directory containing a PostgreSQL custom-format dump and copies of the application/configuration paths that exist. Store a second copy outside the EC2 instance (prefer encrypted, access-controlled storage). A backup is not verified until the PostgreSQL dump has been restored successfully to a separate test database.

Also create an EC2/EBS snapshot using the AWS console or your approved backup process before changing production.

## 5. Controlled deployment sequence

Only after staging validation and backup verification:

1. Announce a maintenance window and pause endpoint rollout.
2. Record the exact currently deployed Git commit and the candidate release tag/commit.
3. Confirm a recent, restorable PostgreSQL backup and an EC2/EBS snapshot.
4. Fetch the candidate release into a separate temporary directory. Do not run an unreviewed `git reset --hard` in the live application directory.
5. Review the full diff and configuration changes. Preserve `/etc/sentinelx/sentinelx.env`, TLS files, Nginx site configuration, and database contents.
6. Install dependencies in a tested virtual environment. Do not blindly upgrade packages on the live host.
7. Apply only reviewed, versioned database migrations. If no migration is supplied for a schema change, stop.
8. Switch the application code using a reversible release-directory/symlink approach, or a documented file-level deployment with a tested rollback.
9. Restart only the API service; do not restart PostgreSQL unless the release explicitly requires it.
10. Verify health, dashboard, API logs, DB connectivity, and a real endpoint's next telemetry heartbeat.
11. Keep the previous release and backup available until the observation period is complete.

Do not use the dashboard updater or endpoint installer as a central API deployment mechanism. They are not substitutes for this runbook.

## 6. Post-deployment smoke tests

```bash
curl -kfsS https://127.0.0.1:8443/health
sudo systemctl is-active sentinelx-api
sudo systemctl is-active nginx
sudo journalctl -u sentinelx-api --since "10 minutes ago" --no-pager
```

Then check from an authorized browser:
- `https://CENTRAL-HOST:8443/dashboard/`
- Host list and summary load without browser-console errors.
- Existing Linux endpoint continues reporting.
- A Windows endpoint continues reporting.
- New enrollment and token revocation work as expected in staging before enabling them in production.

## 7. Rollback

If health checks or telemetry fail:
1. Stop further endpoint rollout.
2. Switch the application back to the exact previous release/commit.
3. Restore the previous configuration only if it was changed and only from the protected backup.
4. Restart `sentinelx-api` and verify `/health`.
5. Restore the database only if a reviewed migration changed it and the rollback plan explicitly requires restoration. A database restore can discard telemetry written after the backup; coordinate and preserve that data where possible.
6. Keep Nginx, TLS, and PostgreSQL unchanged unless the incident specifically involves them.

Do not delete the failed release or backup until the incident is understood.

## 8. Endpoint rollout

After central API acceptance:
- Pilot one Linux endpoint and one Windows endpoint.
- Confirm certificate verification is enabled; install the public CA/certificate on endpoints where needed. Never distribute the TLS private key.
- Confirm each endpoint has a unique identity and credential.
- Check service restart behavior, logs, host identity persistence, and token revocation.
- Expand in small batches (for example 10, 50, 100) while watching API latency, PostgreSQL connections, CPU, memory, disk I/O, and error rates.
- Run the 1,000-agent load test only against isolated staging infrastructure.

## 9. Production status

This runbook is a safe deployment procedure, not evidence that production has been upgraded. No production host, database, security group, or service is changed by this document.