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
    Boolean, DateTime, Index, Integer, JSON, String, UniqueConstraint, create_engine, desc,
    func, select, text
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.sql import over

BOOTSTRAP_TOKEN = os.getenv("SENTINELX_AGENT_TOKEN", "")
ALLOW_LEGACY_BOOTSTRAP_INGEST = os.getenv("SENTINELX_ALLOW_LEGACY_BOOTSTRAP_INGEST", "false").lower() in {"1", "true", "yes"}
ADMIN_TOKEN = os.getenv("SENTINELX_ADMIN_TOKEN", "")
HISTORY_INTERVAL_SECONDS = max(60, int(os.getenv("SENTINELX_HISTORY_INTERVAL_SECONDS", "300")))
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


class IngestedBatch(Base):
    """Idempotency ledger preventing duplicate writes for retried batches."""
    __tablename__ = "ingested_batches"
    __table_args__ = (
        UniqueConstraint("host_id", "batch_id", name="uq_ingested_batch_host_batch"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    batch_id: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


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



class HostLatest(Base):
    """Most recent telemetry snapshot for each endpoint."""
    __tablename__ = "host_latest"
    host_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON)


class ServiceStateHistory(Base):
    """Persist service state transitions instead of storing every repeated poll."""
    __tablename__ = "service_state_history"
    __table_args__ = (
        UniqueConstraint("host_id", "service_name", "collected_at",
                         name="uq_service_transition_time"),
        Index("ix_service_history_host_time", "host_id", "collected_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    service_name: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(80))
    sub_state: Mapped[str | None] = mapped_column(String(80), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class LogRecord(Base):
    """Normalized, searchable endpoint log records with overlap-safe deduplication."""
    __tablename__ = "log_records"
    __table_args__ = (
        UniqueConstraint("host_id", "fingerprint", name="uq_log_host_fingerprint"),
        Index("ix_logs_host_time", "host_id", "occurred_at"),
        Index("ix_logs_severity_time", "severity", "occurred_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(128), index=True)
    channel: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    event_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    record_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message: Mapped[str] = mapped_column(String(4000))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    """Persistent rule-based incident lifecycle and correlated evidence."""
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("host_id", "incident_key", name="uq_incident_host_key"),
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_host_last_seen", "host_id", "last_seen"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[str] = mapped_column(String(255), index=True)
    incident_key: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    summary: Mapped[str] = mapped_column(String(2000))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


Base.metadata.create_all(bind=engine)

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


class LogIn(BaseModel):
    source: str = Field(min_length=1, max_length=128)
    channel: str | None = Field(default=None, max_length=64)
    severity: str = Field(default="info", pattern="^(info|low|medium|warning|high|critical|error)$")
    event_id: str | None = Field(default=None, max_length=80)
    record_id: str | None = Field(default=None, max_length=128)
    message: str = Field(min_length=1, max_length=4000)
    timestamp: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TelemetryIn(BaseModel):
    host_id: str = Field(min_length=1, max_length=255)
    batch_id: str | None = Field(default=None, min_length=1, max_length=64)
    schema_version: int = Field(default=1, ge=1, le=100)
    agent: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime | None = None
    sequence: int = Field(default=0, ge=0)
    metrics: dict[str, Any]
    events: list[EventIn] = Field(default_factory=list, max_length=500)
    logs: list[LogIn] = Field(default_factory=list, max_length=250)


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



def authenticate_admin(authorization: str | None = Header(default=None)):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Administrator access is not configured")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied or not secrets.compare_digest(supplied, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Administrator authentication required")
    return True

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
    # Explicit, temporary compatibility switch. Disabled by default because a shared
    # bootstrap secret must never authorize arbitrary host IDs in normal operation.
    if ALLOW_LEGACY_BOOTSTRAP_INGEST and secrets.compare_digest(token, BOOTSTRAP_TOKEN):
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
    host_id = f"{payload.hostname}-{hashlib.sha256(payload.machine_id.encode()).hexdigest()[:12]}"
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
    collected_at = payload.collected_at or now
    if collected_at.tzinfo is None:
        collected_at = collected_at.replace(tzinfo=timezone.utc)
    if (collected_at - now).total_seconds() > 300:
        collected_at = now
    if payload.batch_id:
        db.add(IngestedBatch(host_id=payload.host_id, batch_id=payload.batch_id))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return {
                "accepted": True, "duplicate": True,
                "host_id": payload.host_id, "events_received": 0,
            }

    latest_row = db.get(HostLatest, payload.host_id)
    if latest_row:
        latest_row.received_at = now
        latest_row.metrics = payload.metrics
    else:
        db.add(HostLatest(host_id=payload.host_id, received_at=now, metrics=payload.metrics))

    # Keep the live snapshot current while limiting historical writes.
    last_history = db.scalar(
        select(func.max(Telemetry.received_at)).where(Telemetry.host_id == payload.host_id)
    )
    if last_history is not None and last_history.tzinfo is None:
        last_history = last_history.replace(tzinfo=timezone.utc)
    if last_history is None or (now - last_history).total_seconds() >= HISTORY_INTERVAL_SECONDS:
        db.add(Telemetry(host_id=payload.host_id, received_at=now, metrics=payload.metrics))

    # Service snapshots are emitted by both platform collectors. Store only state
    # transitions so a fleet-wide poll does not create one row per service per cycle.
    service_payload = (payload.metrics or {}).get("services") or {}
    service_items = service_payload.get("items") if isinstance(service_payload, dict) else []
    if isinstance(service_items, list):
        # One bounded query per host/batch, rather than one query per service.
        latest_rows = db.scalars(
            select(ServiceStateHistory).where(
                ServiceStateHistory.host_id == payload.host_id
            ).order_by(desc(ServiceStateHistory.collected_at)).limit(2000)
        ).all()
        latest_by_name = {}
        for existing_state in latest_rows:
            latest_by_name.setdefault(existing_state.service_name, existing_state)
        for item in service_items[:500]:
            if not isinstance(item, dict):
                continue
            service_name = str(item.get("name") or item.get("service_name") or "")[:255].strip()
            state = str(item.get("status") or item.get("state") or "unknown")[:80].lower()
            if not service_name:
                continue
            latest_state = latest_by_name.get(service_name)
            if latest_state is not None:
                latest_time = latest_state.collected_at
                if latest_time.tzinfo is None:
                    latest_time = latest_time.replace(tzinfo=timezone.utc)
                if collected_at <= latest_time or latest_state.state == state:
                    continue
            new_state = ServiceStateHistory(
                host_id=payload.host_id, service_name=service_name,
                display_name=(str(item.get("display_name") or "")[:255] or None),
                state=state,
                sub_state=(str(item.get("sub_state") or "")[:80] or None),
                collected_at=collected_at, received_at=now,
                details={k: item.get(k) for k in
                         ("start_type", "username", "pid", "load_state")
                         if item.get(k) is not None},
            )
            db.add(new_state)
            latest_by_name[service_name] = new_state

    if payload.events:
        db.add_all([
            SecurityEvent(
                host_id=payload.host_id, event_type=event.event_type,
                severity=event.severity, message=event.message,
                details=event.details, created_at=now,
            )
            for event in payload.events
        ])

    logs_received = 0
    for item in payload.logs:
        occurred_at = _normalize_dt(item.timestamp) or collected_at
        if (occurred_at - now).total_seconds() > 300:
            occurred_at = now
        fingerprint = _log_fingerprint(payload.host_id, item, occurred_at)
        exists = db.scalar(select(LogRecord.id).where(
            LogRecord.host_id == payload.host_id,
            LogRecord.fingerprint == fingerprint,
        ))
        if exists:
            continue
        row = LogRecord(
            host_id=payload.host_id, fingerprint=fingerprint,
            source=item.source, channel=item.channel, severity=item.severity,
            event_id=item.event_id, record_id=item.record_id,
            message=item.message, details=item.details,
            occurred_at=occurred_at, received_at=now,
        )
        db.add(row)
        db.flush()
        _evaluate_log_rules(db, payload.host_id, row, now)
        logs_received += 1

    _evaluate_metric_rules(db, payload.host_id, payload.metrics or {}, now)
    if credential:
        credential.last_seen = now
    db.commit()
    return {
        "accepted": True, "host_id": payload.host_id,
        "events_received": len(payload.events), "logs_received": logs_received,
    }


def _normalize_dt(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _log_fingerprint(host_id: str, item: LogIn, occurred_at: datetime) -> str:
    stable = "|".join((
        host_id, item.source, item.channel or "", item.event_id or "",
        item.record_id or "", occurred_at.isoformat(), item.message,
    ))
    return hashlib.sha256(stable.encode("utf-8", errors="replace")).hexdigest()


def _upsert_incident(db: Session, host_id: str, incident_key: str, title: str,
                     severity: str, summary: str, evidence: dict[str, Any],
                     now: datetime):
    incident = db.scalar(select(Incident).where(
        Incident.host_id == host_id,
        Incident.incident_key == incident_key,
        Incident.status.in_(("open", "investigating")),
    ))
    if incident:
        incident.severity = severity
        incident.summary = summary[:2000]
        incident.last_seen = now
        incident.occurrence_count += 1
        current = list(incident.evidence or [])
        current.append(evidence)
        incident.evidence = current[-20:]
    else:
        incident = Incident(
            host_id=host_id, incident_key=incident_key, title=title[:255],
            severity=severity, status="open", summary=summary[:2000],
            evidence=[evidence], occurrence_count=1,
            first_seen=now, last_seen=now,
        )
        db.add(incident)
    return incident


def _resolve_incident_rule(db: Session, host_id: str, incident_key: str, now: datetime):
    rows = db.scalars(select(Incident).where(
        Incident.host_id == host_id,
        Incident.incident_key == incident_key,
        Incident.status.in_(("open", "investigating")),
    )).all()
    for incident in rows:
        incident.status = "resolved"
        incident.resolved_at = now
        incident.last_seen = now


def _evaluate_metric_rules(db: Session, host_id: str, metrics: dict[str, Any], now: datetime):
    """Conservative fixed rules; repeated samples update one active incident."""
    cpu = metrics.get("cpu_percent")
    if isinstance(cpu, (int, float)):
        key = "metric:cpu_high"
        if cpu >= 90:
            _upsert_incident(db, host_id, key, "Sustained high CPU utilization",
                             "critical" if cpu >= 95 else "high",
                             f"CPU utilization is {cpu:.1f}%. Review top processes and recent workload changes.",
                             {"rule": "cpu_percent>=90", "cpu_percent": cpu}, now)
        else:
            _resolve_incident_rule(db, host_id, key, now)

    memory = metrics.get("memory") or {}
    mem = memory.get("percent") if isinstance(memory, dict) else None
    if isinstance(mem, (int, float)):
        key = "metric:memory_high"
        if mem >= 90:
            _upsert_incident(db, host_id, key, "High memory utilization",
                             "critical" if mem >= 95 else "high",
                             f"Memory utilization is {mem:.1f}%. Inspect process memory and available capacity.",
                             {"rule": "memory.percent>=90", "memory_percent": mem}, now)
        else:
            _resolve_incident_rule(db, host_id, key, now)

    disk = metrics.get("disk") or {}
    if isinstance(disk, dict):
        for mountpoint, usage in list(disk.items())[:100]:
            if not isinstance(usage, dict) or not isinstance(usage.get("percent"), (int, float)):
                continue
            percent = usage["percent"]
            key = f"metric:disk:{str(mountpoint)[:180]}"
            if percent >= 80:
                _upsert_incident(db, host_id, key, f"Disk capacity warning: {str(mountpoint)[:150]}",
                                 "critical" if percent >= 95 else "high" if percent >= 90 else "medium",
                                 f"Disk usage on {mountpoint} is {percent:.1f}%. Review growth and clean-up options.",
                                 {"rule": "disk.percent>=80", "mountpoint": str(mountpoint), "percent": percent}, now)
            else:
                _resolve_incident_rule(db, host_id, key, now)


def _evaluate_log_rules(db: Session, host_id: str, log: LogRecord, now: datetime):
    if log.severity not in {"high", "critical", "error"}:
        return
    event_key = (log.event_id or log.source).replace(":", "_")[:80]
    key = f"log:{log.source[:100]}:{event_key}"
    _upsert_incident(db, host_id, key, f"High-severity log: {log.source[:100]}",
                     "critical" if log.severity == "critical" else "high",
                     log.message, {"source": log.source, "channel": log.channel,
                                   "event_id": log.event_id, "log_id": log.id,
                                   "message": log.message[:1000]}, now)


@app.get("/api/v1/logs")
def search_logs(host_id: str | None = Query(default=None, max_length=255),
                severity: str | None = Query(default=None, max_length=20),
                source: str | None = Query(default=None, max_length=128),
                q: str | None = Query(default=None, max_length=200),
                start: datetime | None = None, end: datetime | None = None,
                limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0),
                _admin: bool = Depends(authenticate_admin),
                db: Session = Depends(db_session)):
    """Search retained endpoint logs with bounded filters and pagination."""
    query = select(LogRecord)
    if host_id:
        query = query.where(LogRecord.host_id == host_id)
    if severity:
        query = query.where(LogRecord.severity == severity.lower())
    if source:
        query = query.where(LogRecord.source.ilike(f"%{source[:128]}%"))
    if q:
        query = query.where(LogRecord.message.ilike(f"%{q[:200]}%"))
    if start:
        query = query.where(LogRecord.occurred_at >= _normalize_dt(start))
    if end:
        query = query.where(LogRecord.occurred_at <= _normalize_dt(end))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(desc(LogRecord.occurred_at))
                      .offset(offset).limit(limit)).all()
    return {"count": len(rows), "total": total, "limit": limit, "offset": offset,
            "items": [{
                "id": row.id, "host_id": row.host_id, "source": row.source,
                "channel": row.channel, "severity": row.severity,
                "event_id": row.event_id, "record_id": row.record_id,
                "message": row.message, "details": row.details or {},
                "occurred_at": row.occurred_at, "received_at": row.received_at,
            } for row in rows]}


@app.get("/api/v1/incidents")
def list_incidents(host_id: str | None = Query(default=None, max_length=255),
                   status: str | None = Query(default=None, pattern="^(open|investigating|resolved)$"),
                   severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
                   limit: int = Query(default=100, ge=1, le=500),
                   offset: int = Query(default=0, ge=0),
                   _admin: bool = Depends(authenticate_admin),
                   db: Session = Depends(db_session)):
    query = select(Incident)
    if host_id:
        query = query.where(Incident.host_id == host_id)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(desc(Incident.last_seen))
                      .offset(offset).limit(limit)).all()
    return {"count": len(rows), "total": total, "items": [{
        "id": row.id, "host_id": row.host_id, "incident_key": row.incident_key,
        "title": row.title, "severity": row.severity, "status": row.status,
        "summary": row.summary, "evidence": row.evidence or [],
        "occurrence_count": row.occurrence_count, "first_seen": row.first_seen,
        "last_seen": row.last_seen, "resolved_at": row.resolved_at,
    } for row in rows]}


class IncidentStatusIn(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved)$")


@app.post("/api/v1/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, payload: IncidentStatusIn,
                           _admin: bool = Depends(authenticate_admin),
                           db: Session = Depends(db_session)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = payload.status
    incident.resolved_at = utcnow() if payload.status == "resolved" else None
    db.commit()
    db.refresh(incident)
    return {"id": incident.id, "host_id": incident.host_id,
            "status": incident.status, "severity": incident.severity,
            "resolved_at": incident.resolved_at}


@app.get("/api/v1/hosts/{host_id}/history/services")
def service_history(host_id: str, start: datetime | None = None, end: datetime | None = None,
                    limit: int = Query(default=500, ge=1, le=2000),
                    _admin: bool = Depends(authenticate_admin),
                    db: Session = Depends(db_session)):
    """Return state transitions for one machine, oldest first."""
    query = select(ServiceStateHistory).where(ServiceStateHistory.host_id == host_id)
    if start:
        query = query.where(ServiceStateHistory.collected_at >= _normalize_dt(start))
    if end:
        query = query.where(ServiceStateHistory.collected_at <= _normalize_dt(end))
    rows = db.scalars(query.order_by(desc(ServiceStateHistory.collected_at)).limit(limit)).all()
    return {"host_id": host_id, "count": len(rows), "items": [{
        "service_name": row.service_name, "display_name": row.display_name,
        "state": row.state, "sub_state": row.sub_state,
        "collected_at": row.collected_at, "received_at": row.received_at,
        "details": row.details or {},
    } for row in reversed(rows)]}


@app.get("/api/v1/hosts/{host_id}/history/processes")
def process_history(host_id: str, start: datetime | None = None, end: datetime | None = None,
                    limit: int = Query(default=100, ge=1, le=500),
                    _admin: bool = Depends(authenticate_admin),
                    db: Session = Depends(db_session)):
    """Read process snapshots already retained inside historical telemetry JSON."""
    query = select(Telemetry).where(Telemetry.host_id == host_id)
    if start:
        query = query.where(Telemetry.received_at >= _normalize_dt(start))
    if end:
        query = query.where(Telemetry.received_at <= _normalize_dt(end))
    rows = db.scalars(query.order_by(desc(Telemetry.received_at)).limit(limit)).all()
    samples = []
    for row in reversed(rows):
        processes = (row.metrics or {}).get("processes") or []
        if processes:
            samples.append({"recorded_at": row.received_at, "processes": processes[:200]})
    return {"host_id": host_id, "count": len(samples), "samples": samples}


@app.get("/api/v1/hosts/{host_id}/timeline")
def host_timeline(host_id: str, start: datetime | None = None, end: datetime | None = None,
                  limit: int = Query(default=500, ge=1, le=2000),
                  _admin: bool = Depends(authenticate_admin),
                  db: Session = Depends(db_session)):
    """Combine service transitions, security events and retained metric samples."""
    start_dt, end_dt = _normalize_dt(start), _normalize_dt(end)
    sq = select(ServiceStateHistory).where(ServiceStateHistory.host_id == host_id)
    eq = select(SecurityEvent).where(SecurityEvent.host_id == host_id)
    mq = select(Telemetry).where(Telemetry.host_id == host_id)
    if start_dt:
        sq = sq.where(ServiceStateHistory.collected_at >= start_dt)
        eq = eq.where(SecurityEvent.created_at >= start_dt)
        mq = mq.where(Telemetry.received_at >= start_dt)
    if end_dt:
        sq = sq.where(ServiceStateHistory.collected_at <= end_dt)
        eq = eq.where(SecurityEvent.created_at <= end_dt)
        mq = mq.where(Telemetry.received_at <= end_dt)
    services = db.scalars(sq.order_by(desc(ServiceStateHistory.collected_at)).limit(limit)).all()
    security = db.scalars(eq.order_by(desc(SecurityEvent.created_at)).limit(limit)).all()
    metrics = db.scalars(mq.order_by(desc(Telemetry.received_at)).limit(limit)).all()
    items = []
    for row in services:
        items.append({"timestamp": row.collected_at, "category": "service",
                      "name": row.service_name, "state": row.state,
                      "message": f"{row.service_name} changed to {row.state}"})
    for row in security:
        items.append({"timestamp": row.created_at, "category": "security",
                      "name": row.event_type, "state": row.severity, "message": row.message})
    for row in metrics:
        data = row.metrics or {}
        memory = data.get("memory") or {}
        items.append({"timestamp": row.received_at, "category": "metrics",
                      "name": "resource_sample", "state": "sample",
                      "message": f"CPU {data.get('cpu_percent', 'n/a')}%, memory {memory.get('percent', 'n/a')}%"})
    items.sort(key=lambda item: _normalize_dt(item["timestamp"]))
    return {"host_id": host_id, "count": len(items), "items": items[-limit:]}


@app.get("/api/v1/history/capabilities")
def history_capabilities(host_id: str | None = Query(default=None, max_length=255),
                         _admin: bool = Depends(authenticate_admin),
                         db: Session = Depends(db_session)):
    telemetry_q = select(func.count()).select_from(Telemetry)
    events_q = select(func.count()).select_from(SecurityEvent)
    services_q = select(func.count()).select_from(ServiceStateHistory)
    if host_id:
        telemetry_q = telemetry_q.where(Telemetry.host_id == host_id)
        events_q = events_q.where(SecurityEvent.host_id == host_id)
        services_q = services_q.where(ServiceStateHistory.host_id == host_id)
    return {"host_id": host_id, "sources": {
        "telemetry": db.scalar(telemetry_q) or 0,
        "security_events": db.scalar(events_q) or 0,
        "service_transitions": db.scalar(services_q) or 0,
    }, "process_history_note": "Process snapshots are available for retained telemetry rows containing a processes array."}


@app.get("/api/v1/hosts")
def hosts(response: Response, _admin: bool = Depends(authenticate_admin), limit: int = Query(default=100, ge=1, le=250),
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
    } for row in rows]


@app.get("/api/v1/summary")
def summary(_admin: bool = Depends(authenticate_admin), db: Session = Depends(db_session)):
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


@app.get("/api/v1/events")
def events(limit: int = Query(default=100, ge=1, le=500),
           _admin: bool = Depends(authenticate_admin),
           db: Session = Depends(db_session)):
    rows = db.scalars(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
    ).all()
    return [{
        "host_id": row.host_id,
        "event_type": row.event_type,
        "severity": row.severity,
        "message": row.message,
        "details": row.details,
        "created_at": row.created_at,
    } for row in rows]


@app.get("/api/v1/disk-history")
def disk_history(host_id: str = Query(min_length=1, max_length=255),
                 mountpoint: str = Query(min_length=1, max_length=1024),
                 limit: int = Query(default=120, ge=1, le=500),
                 _admin: bool = Depends(authenticate_admin),
                 db: Session = Depends(db_session)):
    rows = db.scalars(
        select(Telemetry).where(Telemetry.host_id == host_id)
        .order_by(desc(Telemetry.received_at)).limit(500)
    ).all()
    samples = []
    for row in reversed(rows):
        disk = (row.metrics or {}).get("disk") or {}
        volume = disk.get(mountpoint)
        if isinstance(volume, dict) and "percent" in volume:
            samples.append({
                "received_at": row.received_at,
                "percent": volume.get("percent"),
                "total_bytes": volume.get("total_bytes"),
                "used_bytes": volume.get("used_bytes"),
                "free_bytes": volume.get("free_bytes"),
            })
    return {"host_id": host_id, "mountpoint": mountpoint, "samples": samples[-limit:]}


@app.get("/api/v1/metrics/history")
def metrics_history(host_id: str = Query(min_length=1, max_length=255),
                    metric: str = Query(default="cpu", regex="^(cpu|memory|network)$"),
                    limit: int = Query(default=120, ge=2, le=500),
                    start: datetime | None = None, end: datetime | None = None,
                    _admin: bool = Depends(authenticate_admin),
                    db: Session = Depends(db_session)):
    """Return bounded historical CPU, memory or network samples for one host."""
    if metric not in {"cpu", "memory", "network"}:
        raise HTTPException(status_code=400, detail="metric must be cpu, memory, or network")
    limit = max(2, min(limit, 500))
    history_query = select(Telemetry).where(Telemetry.host_id == host_id)
    if start:
        history_query = history_query.where(Telemetry.received_at >= _normalize_dt(start))
    if end:
        history_query = history_query.where(Telemetry.received_at <= _normalize_dt(end))
    rows = db.scalars(history_query.order_by(desc(Telemetry.received_at)).limit(limit)).all()
    samples = []
    for row in reversed(rows):
        data = row.metrics or {}
        if metric == "cpu":
            value = data.get("cpu_percent")
            sample = {"recorded_at": row.received_at, "value": value}
        elif metric == "memory":
            memory = data.get("memory") or {}
            sample = {"recorded_at": row.received_at, "value": memory.get("percent")}
        else:
            interfaces = data.get("network_interfaces") or {}
            sample = {"recorded_at": row.received_at, "interfaces": interfaces}
        if metric == "network" or sample.get("value") is not None:
            samples.append(sample)
    return {"host_id": host_id, "metric": metric, "samples": samples}
