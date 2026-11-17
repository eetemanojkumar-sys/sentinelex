"""Backfill service state transitions from service snapshots in retained telemetry.

Run after deploying the code on a staging copy first:
  DATABASE_URL=... SENTINELX_AGENT_TOKEN=... python scripts/backfill_service_history.py
The script is idempotent and never modifies existing telemetry or event rows.
"""
from sqlalchemy import select

from server.main import SessionLocal, ServiceStateHistory, Telemetry, utcnow


def backfill():
    inserted = 0
    last_state = {}
    with SessionLocal() as db:
        rows = db.execute(
            select(Telemetry).order_by(Telemetry.host_id, Telemetry.received_at)
        ).scalars().yield_per(500)
        for row in rows:
            items = ((row.metrics or {}).get("services") or {}).get("items") or []
            if not isinstance(items, list):
                continue
            for item in items[:500]:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("service_name") or "")[:255].strip()
                state = str(item.get("status") or item.get("state") or "unknown")[:80].lower()
                if not name:
                    continue
                key = (row.host_id, name)
                if last_state.get(key) == state:
                    continue
                last_state[key] = state
                exists = db.scalar(select(ServiceStateHistory.id).where(
                    ServiceStateHistory.host_id == row.host_id,
                    ServiceStateHistory.service_name == name,
                    ServiceStateHistory.collected_at == row.received_at,
                ))
                if exists:
                    continue
                db.add(ServiceStateHistory(
                    host_id=row.host_id, service_name=name,
                    display_name=(str(item.get("display_name") or "")[:255] or None),
                    state=state, sub_state=(str(item.get("sub_state") or "")[:80] or None),
                    collected_at=row.received_at, received_at=utcnow(),
                    details={"source": "historical_telemetry_backfill"},
                ))
                inserted += 1
            if inserted and inserted % 500 == 0:
                db.commit()
        db.commit()
    return inserted


if __name__ == "__main__":
    print(f"Inserted {backfill()} historical service transitions.")
