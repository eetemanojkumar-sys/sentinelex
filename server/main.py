"""SentinelX scalable central API for multi-host telemetry."""
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean, DateTime, Index, Integer, JSON, String, create_engine, desc,
    func, select, text
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.sql import over

BOOTSTRAP_TOKEN = os.getenv("SENTINELX_ENROLLMENT_TOKEN") or os.getenv("SENTINELX_AGENT_TOKEN", "")
ALLOW_LEGACY_TOKEN = os.getenv("SENTINELX_ALLOW_LEGACY_TOKEN", "true").lower() in {"1", "true", "yes"}\nADMIN_TOKEN = os.getenv("SENTINELX_ADMIN_TOKEN", "")\nHISTORY_INTERVAL_SECONDS = max(60, int(os.getenv("SENTINELX_HISTORY_INTERVAL_SECONDS", "300")))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")
if not BOOTSTRAP_TOKEN:
    raise RuntimeError("SENTINELX_AGENT_TOKEN must be configured")

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}
engine_options = {
    "pool_pre_ping": True,
    "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
}
if not is_sqlite:
    engine_options.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "20")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "30")),
        "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT", "30")),
    })
engine = create_engine(DATABASE_URL, connect_args=connect_args, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    host_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class Telemetry(Base):
    __tablename__ = "telemetry"
    __table_args__ = (
        Index("ix_telemetry_host_received", "host_id", "received_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_host_created", "host_id", "created_at"),
        Index("ix_security_events_severity_created", "severity", "created_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(String(1000))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


if is_sqlite:
    Base.metadata.create_all(bind=engine)
else:
    # Prevent concurrent Uvicorn workers racing during first-start schema creation.
    with engine.connect() as schema_connection:
        schema_connection.execute(text("SELECT pg_advisory_lock(731904211)"))
        schema_connection.commit()
        try:
            Base.metadata.create_all(bind=schema_connection)
        finally:
            schema_connection.execute(text("SELECT pg_advisory_unlock(731904211)"))
            schema_connection.commit()

app = FastAPI(
    title="SentinelX Central API",
    version="0.2.0",
    description="Scalable rule-based telemetry control plane for Linux and Windows fleets.",
)
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def dashboard_home():
    return RedirectResponse(url="/dashboard/")


class EventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="info", pattern="^(info|low|medium|high|critical)$")
    message: str = Field(min_length=1, max_length=1000)
    details: dict[str, Any] = Field(default_factory=dict)


class TelemetryIn(BaseModel):
    host_id: str = Field(min_length=1, max_length=255)
    metrics: dict[str, Any]
    events: list[EventIn] = Field(default_factory=list, max_length=500)


class EnrollmentIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=80)
    machine_id: str = Field(min_length=8, max_length=128)


def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticate_agent(token: str | None, db: Session):
    if not token:
        raise HTTPException(status_code=401, detail="Agent token required")
    credential = db.scalar(
        select(AgentCredential).where(AgentCredential.token_hash == token_digest(token))
    )
    if credential:
        if credential.revoked:
            raise HTTPException(status_code=401, detail="Agent credential revoked")
        return credential
    # Temporary compatibility for agents not yet upgraded to per-agent enrollment.
    if ALLOW_LEGACY_TOKEN and secrets.compare_digest(token, BOOTSTRAP_TOKEN):
        return None
    raise HTTPException(status_code=401, detail="Invalid agent token")


@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        database = "unavailable"
    if database != "ok":
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ok", "service": "sentinelx-central", "version": "0.3.0", "database": database}


@app.post("/api/v1/agents/enroll", status_code=201)
def enroll(payload: EnrollmentIn, x_agent_token: str | None = Header(default=None),
           db: Session = Depends(db_session)):
    if not x_agent_token or not secrets.compare_digest(x_agent_token, BOOTSTRAP_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid enrollment token")

    # A machine ID is stable on that endpoint. Re-enrollment rotates its token.
    safe_hostname = payload.hostname[:240]
    host_id = f"{safe_hostname}-{hashlib.sha256(payload.machine_id.encode()).hexdigest()[:12]}"
    existing = db.scalar(select(AgentCredential).where(AgentCredential.host_id == host_id))
    raw_token = secrets.token_urlsafe(48)
    if existing:
        existing.token_hash = token_digest(raw_token)
        existing.hostname = payload.hostname
        existing.os_name = payload.os_name
        existing.revoked = False
        existing.last_seen = utcnow()
        credential = existing
    else:
        credential = AgentCredential(
            agent_id=str(uuid.uuid4()),
            host_id=host_id,
            hostname=payload.hostname,
            os_name=payload.os_name,
            token_hash=token_digest(raw_token),
            last_seen=utcnow(),
            revoked=False,
        )
        db.add(credential)
    db.commit()
    db.refresh(credential)
    return {
        "agent_id": credential.agent_id,
        "host_id": credential.host_id,
        "agent_token": raw_token,
        "token_type": "Bearer",
        "message": "Store this credential securely; it is returned only during enrollment.",
    }


@app.post("/api/v1/telemetry", status_code=202)
def ingest(payload: TelemetryIn, x_agent_token: str | None = Header(default=None),
           db: Session = Depends(db_session)):
    credential = authenticate_agent(x_agent_token, db)
    if credential and payload.host_id != credential.host_id:
        raise HTTPException(status_code=403, detail="Host identity does not match enrolled agent")

    now = utcnow()
    latest_row = db.get(HostLatest, payload.host_id)
    if latest_row:
        latest_row.received_at = now
        latest_row.metrics = payload.metrics
    else:
        db.add(HostLatest(host_id=payload.host_id, received_at=now, metrics=payload.metrics))

    # Keep a lower-frequency historical sample while updating the live snapshot
    # on every heartbeat. This limits write amplification for large fleets.
    last_history = db.scalar(
        select(func.max(Telemetry.received_at)).where(Telemetry.host_id == payload.host_id)
    )
    if last_history is not None and last_history.tzinfo is None:\n        last_history = last_history.replace(tzinfo=timezone.utc)\n    if last_history is None or (now - last_history).total_seconds() >= HISTORY_INTERVAL_SECONDS:
        history_metrics = {
            key: payload.metrics[key]
            for key in ("hostname", "platform", "os", "uptime_seconds", "boot_time",
                        "cpu_percent", "cpu_count_logical", "memory", "swap", "disk")
            if key in payload.metrics
        }
        db.add(Telemetry(host_id=payload.host_id, received_at=now, metrics=history_metrics))

    if payload.events:
        db.add_all([
            SecurityEvent(
                host_id=payload.host_id,
                event_type=event.event_type,
                severity=event.severity,
                message=event.message,
                details=event.details,
                created_at=now,
            )
            for event in payload.events
        ])
    if credential:
        credential.last_seen = now
    db.commit()
    return {"accepted": True, "host_id": payload.host_id, "events_received": len(payload.events)}


@app.get("/api/v1/hosts")
def hosts(response: Response, limit: int = Query(default=100, ge=1, le=250),
          offset: int = Query(default=0, ge=0), search: str | None = None,
          db: Session = Depends(db_session)):
    query = select(HostLatest)
    if search:
        query = query.where(HostLatest.host_id.ilike(f"%{search[:100]}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(HostLatest.host_id).offset(offset).limit(limit)
    ).all()
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Limit"] = str(limit)
    response.headers["X-Offset"] = str(offset)
    return [{
        "host_id": row.host_id,
        "last_seen": row.received_at,
        "metrics": row.metrics,
    } for row in rows]@app.get("/api/v1/summary")
def summary(db: Session = Depends(db_session)):
    host_count = db.scalar(select(func.count()).select_from(HostLatest)) or 0
    latest_hosts = db.scalars(
        select(HostLatest).order_by(desc(HostLatest.received_at)).limit(20)
    ).all()
    recent = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(10)
    ).all()
    return {
        "monitored_hosts": host_count,
        "latest_hosts": [{
            "host_id": row.host_id, "metrics": row.metrics, "last_seen": row.received_at
        } for row in latest_hosts],
        "recent_events": [{
            "host_id": event.host_id, "severity": event.severity,
            "event_type": event.event_type, "message": event.message,
            "created_at": event.created_at,
        } for event in recent],
    }
