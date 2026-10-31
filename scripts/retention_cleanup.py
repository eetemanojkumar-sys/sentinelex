#!/usr/bin/env python3
"""Bounded-retention cleanup for SentinelX PostgreSQL telemetry."""
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text

database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise SystemExit("DATABASE_URL must be provided by the SentinelX environment file")

engine = create_engine(database_url, pool_pre_ping=True)
now = datetime.now(timezone.utc)
telemetry_days = max(1, int(os.getenv("SENTINELX_TELEMETRY_RETENTION_DAYS", "30")))
event_days = max(1, int(os.getenv("SENTINELX_EVENT_RETENTION_DAYS", "180")))

with engine.begin() as connection:
    telemetry_result = connection.execute(
        text("DELETE FROM telemetry WHERE received_at < :cutoff"),
        {"cutoff": now - timedelta(days=telemetry_days)},
    )
    event_result = connection.execute(
        text("DELETE FROM security_events WHERE created_at < :cutoff"),
        {"cutoff": now - timedelta(days=event_days)},
    )

print(
    f"Retention cleanup complete: telemetry_rows={telemetry_result.rowcount}, "
    f"event_rows={event_result.rowcount}, telemetry_days={telemetry_days}, "
    f"event_days={event_days}"
)
engine.dispose()
