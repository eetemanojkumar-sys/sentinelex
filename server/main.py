"""SentinelX central telemetry API (rule-based; no AI/ML)."""
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, Integer, JSON, String, create_engine, desc, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
if not TOKEN:
    raise RuntimeError("SENTINELX_AGENT_TOKEN must be configured")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(String(1000))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )


Base.metadata.create_all(bind=engine)
app = FastAPI(
    title="SentinelX Central API",
    version="0.1.0",
    description="Rule-based Linux health and security telemetry collector",
)


class EventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="info",
                           pattern="^(info|low|medium|high|critical)$")
    message: str = Field(min_length=1, max_length=1000)
    details: dict[str, Any] = Field(default_factory=dict)


class TelemetryIn(BaseModel):
    host_id: str = Field(min_length=1, max_length=255)
    metrics: dict[str, Any]
    events: list[EventIn] = Field(default_factory=list, max_length=500)


def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def verify_agent(token: str | None):
    if not token or token != TOKEN:
        raise HTTPException(status_code=401, detail="Invalid agent token")


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelx-central", "version": "0.1.0"}


@app.post("/api/v1/telemetry", status_code=202)
def ingest(payload: TelemetryIn, x_agent_token: str | None = Header(default=None),
           db: Session = Depends(db_session)):
    verify_agent(x_agent_token)
    db.add(Telemetry(host_id=payload.host_id, metrics=payload.metrics))
    for event in payload.events:
        db.add(SecurityEvent(
            host_id=payload.host_id,
            event_type=event.event_type,
            severity=event.severity,
            message=event.message,
            details=event.details,
        ))
    db.commit()
    return {"accepted": True, "host_id": payload.host_id,
            "events_received": len(payload.events)}


@app.get("/api/v1/hosts")
def hosts(db: Session = Depends(db_session)):
    rows = db.scalars(select(Telemetry).order_by(desc(Telemetry.received_at))).all()
    latest = {}
    for row in rows:
        if row.host_id not in latest:
            latest[row.host_id] = {
                "host_id": row.host_id,
                "last_seen": row.received_at,
                "metrics": row.metrics,
            }
    return list(latest.values())


@app.get("/api/v1/events")
def events(limit: int = 100, db: Session = Depends(db_session)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
    ).all()
    return [{
        "id": row.id,
        "host_id": row.host_id,
        "event_type": row.event_type,
        "severity": row.severity,
        "message": row.message,
        "details": row.details,
        "created_at": row.created_at,
    } for row in rows]


@app.get("/api/v1/summary")
def summary(db: Session = Depends(db_session)):
    host_rows = db.scalars(select(Telemetry).order_by(desc(Telemetry.received_at))).all()
    seen = set()
    latest_hosts = []
    for row in host_rows:
        if row.host_id not in seen:
            seen.add(row.host_id)
            latest_hosts.append({
                "host_id": row.host_id,
                "metrics": row.metrics,
                "last_seen": row.received_at,
            })
    recent = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(10)
    ).all()
    return {
        "monitored_hosts": len(latest_hosts),
        "latest_hosts": latest_hosts,
        "recent_events": [{
            "host_id": event.host_id,
            "severity": event.severity,
            "event_type": event.event_type,
            "message": event.message,
            "created_at": event.created_at,
        } for event in recent],
    }
